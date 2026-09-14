"""benchmark/run_eval.py — precision / recall / F1 per ablation arm (BRAIN.md D25).

A thin consumer of the engine (invariant 1): it loads saved `ScanResult` JSONs
(one per ablation arm) and a hand-verified `ground_truth.yaml`, joins every
finding to a known vulnerability, and prints precision/recall/F1 per arm through
`rich`.

Scoring — standard for a vulnerability benchmark, and defensible in a viva:

    TP = ground-truth vulns matched by >=1 finding        (each known vuln once)
    FP = findings that match NO ground-truth vuln
    FN = ground-truth vulns matched by no finding
    precision = TP / (TP + FP)
    recall    = TP / (TP + FN)
    F1        = 2 * P * R / (P + R)

Two things keep the numbers honest:

* Ground truth is filtered to each arm's TARGET (a VAmPI scan is never charged
  for crAPI's vulns, and vice-versa) — routing is by `ScanResult.target`.
* The ground truth lists vulns Doppel CANNOT yet detect (mass assignment,
  unauthorized password change, ...) as `detectable: false` with no matcher, so
  they always count as false negatives — recall is not silently inflated by
  pretending the tool's blind spots don't exist.

Run:  python benchmark/run_eval.py                     # all benchmark/results/*.json
      python benchmark/run_eval.py results/full.json   # specific arms
      python benchmark/run_eval.py --details           # also list TP/FP/FN per arm
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator
from rich.console import Console
from rich.table import Table

from doppel.core.models import Finding, ScanResult

HERE = Path(__file__).resolve().parent
DEFAULT_GROUND_TRUTH = HERE / "ground_truth.yaml"
DEFAULT_RESULTS_DIR = HERE / "results"


# --------------------------------------------------------------------------- #
# Ground-truth model
# --------------------------------------------------------------------------- #
class Match(BaseModel):
    """Predicates that join a Finding to a known vuln. ALL present ones must hold.

    A finding with scanner/path per-endpoint (injection, bola, bfla) is matched on
    `scanner` + `path`; a global finding (jwt, rate_limit) on `scanner` alone; the
    two misconfig sub-types are separated by `id_contains` (they share path "/").
    `owasp_id` is deliberately NOT a predicate: the tool maps SQLi to API8 while a
    purist would call it injection, and keying on owasp would spuriously un-match.
    """

    model_config = ConfigDict(extra="forbid")

    scanner: str | None = None
    path: str | None = None
    method: str | None = None
    id_contains: str | None = None
    path_contains: str | None = None

    @model_validator(mode="after")
    def _non_vacuous(self) -> "Match":
        if not any(
            v is not None
            for v in (self.scanner, self.path, self.method, self.id_contains, self.path_contains)
        ):
            raise ValueError("a match block must carry at least one predicate (else it matches everything)")
        return self

    def matches(self, f: Finding) -> bool:
        if self.scanner is not None and f.scanner != self.scanner:
            return False
        if self.path is not None and f.endpoint.path != self.path:
            return False
        if self.method is not None and f.endpoint.method.upper() != self.method.upper():
            return False
        if self.id_contains is not None and self.id_contains not in f.id:
            return False
        if self.path_contains is not None and self.path_contains not in f.endpoint.path:
            return False
        return True


class GroundTruthEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    target: str
    title: str
    owasp_id: str
    vuln_class: str
    detectable: bool
    match: Match | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _match_consistency(self) -> "GroundTruthEntry":
        # A detectable vuln needs a matcher; a non-detectable one must have none
        # (it is an inherent false negative — no finding may ever match it).
        if self.detectable and self.match is None:
            raise ValueError(f"{self.id!r}: detectable entry needs a `match` block")
        if not self.detectable and self.match is not None:
            raise ValueError(f"{self.id!r}: non-detectable entry must not have a `match` block")
        return self


class TargetRoute(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url_contains: str


class GroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: dict[str, TargetRoute]
    vulns: list[GroundTruthEntry]

    @model_validator(mode="after")
    def _known_targets(self) -> "GroundTruth":
        for v in self.vulns:
            if v.target not in self.targets:
                raise ValueError(f"{v.id!r}: unknown target {v.target!r} (not in `targets:`)")
        ids = [v.id for v in self.vulns]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate ground-truth ids: {sorted(dupes)}")
        return self

    def route(self, target_url: str) -> str | None:
        """Map a ScanResult.target URL to a ground-truth target key, or None."""
        for name, route in self.targets.items():
            if route.base_url_contains in target_url:
                return name
        return None

    def for_target(self, name: str) -> list[GroundTruthEntry]:
        return [v for v in self.vulns if v.target == name]


def load_ground_truth(path: Path = DEFAULT_GROUND_TRUTH) -> GroundTruth:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return GroundTruth.model_validate(data)


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
@dataclass
class ArmMetrics:
    arm: str
    target: str
    tp: int
    fp: int
    fn: int
    findings: int
    requests_sent: int
    matched_vuln_ids: list[str]
    missed_vuln_ids: list[str]  # false negatives
    fp_finding_ids: list[str]
    ambiguous: list[tuple[str, list[str]]]  # a finding that matched >1 vuln (matcher smell)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def evaluate(arm: str, result: ScanResult, gt: GroundTruth) -> ArmMetrics:
    target = gt.route(result.target)
    if target is None:
        raise ValueError(
            f"arm {arm!r}: target {result.target!r} matches no ground-truth target "
            f"({', '.join(gt.targets)})"
        )
    entries = gt.for_target(target)

    matched_vulns: set[str] = set()
    matched_findings: set[int] = set()
    ambiguous: list[tuple[str, list[str]]] = []

    for i, f in enumerate(result.findings):
        hits = [e for e in entries if e.match is not None and e.match.matches(f)]
        if hits:
            matched_findings.add(i)
            matched_vulns.update(e.id for e in hits)
            if len(hits) > 1:
                ambiguous.append((f.id, [e.id for e in hits]))

    tp = len(matched_vulns)
    fp = len(result.findings) - len(matched_findings)
    fn = len(entries) - len(matched_vulns)
    return ArmMetrics(
        arm=arm,
        target=target,
        tp=tp,
        fp=fp,
        fn=fn,
        findings=len(result.findings),
        requests_sent=result.requests_sent,
        matched_vuln_ids=sorted(matched_vulns),
        missed_vuln_ids=sorted(e.id for e in entries if e.id not in matched_vulns),
        fp_finding_ids=[f.id for i, f in enumerate(result.findings) if i not in matched_findings],
        ambiguous=ambiguous,
    )


def _pct(x: float) -> str:
    return f"{x:.2f}"


def render(metrics: list[ArmMetrics], gt: GroundTruth, console: Console, details: bool) -> None:
    table = Table(
        title="Doppel ablation - precision / recall / F1 vs ground truth",
        caption="precision=TP/(TP+FP)  recall=TP/(TP+FN)  Known=ground-truth vulns for that target",
    )
    table.add_column("Arm", style="bold", no_wrap=True)
    table.add_column("Target", no_wrap=True)
    table.add_column("Known", justify="right")  # ground-truth vulns for that target
    table.add_column("TP", justify="right", style="green")
    table.add_column("FP", justify="right", style="red")
    table.add_column("FN", justify="right", style="yellow")
    table.add_column("Prec", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right", style="bold")
    table.add_column("Req", justify="right")

    for m in metrics:
        known = len(gt.for_target(m.target))
        # requests_sent==0 means "not tracked" (e.g. the external ZAP arm), not zero requests.
        req = str(m.requests_sent) if m.requests_sent else "n/a"
        table.add_row(
            m.arm, m.target, str(known), str(m.tp), str(m.fp), str(m.fn),
            _pct(m.precision), _pct(m.recall), _pct(m.f1), req,
        )
    console.print(table)

    # Loud warning if a finding matched >1 vuln — that means the ground-truth
    # matchers overlap and TP is being double-counted.
    for m in metrics:
        for fid, vids in m.ambiguous:
            console.print(f"[red]! matcher overlap in {m.arm}: finding {fid} matched {vids}[/red]")

    if details:
        for m in metrics:
            console.print(f"\n[bold]{m.arm}[/bold] ({m.target})")
            console.print(f"  detected : {', '.join(m.matched_vuln_ids) or '(none)'}")
            console.print(f"  [yellow]missed   : {', '.join(m.missed_vuln_ids) or '(none)'}[/yellow]")
            if m.fp_finding_ids:
                console.print(f"  [red]false-pos: {', '.join(m.fp_finding_ids)}[/red]")


def _result_files(args_paths: list[str]) -> list[Path]:
    if args_paths:
        out = []
        for p in args_paths:
            path = Path(p)
            if not path.is_absolute() and not path.exists():
                # allow "results/full.json" or "full.json" relative to benchmark/
                alt = HERE / p
                path = alt if alt.exists() else (DEFAULT_RESULTS_DIR / Path(p).name)
            out.append(path)
        return out
    return sorted(p for p in DEFAULT_RESULTS_DIR.glob("*.json"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Precision/recall/F1 per ablation arm vs ground truth.")
    parser.add_argument("results", nargs="*", help="ScanResult JSON files (default: benchmark/results/*.json)")
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH), help="ground_truth.yaml path")
    parser.add_argument("--details", action="store_true", help="list detected/missed/false-positive vuln ids per arm")
    ns = parser.parse_args(argv)

    # Windows consoles default to cp1252 and mangle rich's box/em-dash/ellipsis
    # glyphs; force UTF-8 so the table renders cleanly for the demo/report.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    console = Console()
    gt = load_ground_truth(Path(ns.ground_truth))

    files = _result_files(ns.results)
    if not files:
        console.print("[red]no result files found[/red]")
        return 1

    metrics: list[ArmMetrics] = []
    for path in files:
        if not path.exists():
            console.print(f"[red]missing: {path}[/red]")
            continue
        result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        metrics.append(evaluate(path.stem, result, gt))

    if not metrics:
        return 1
    render(metrics, gt, console, ns.details)
    return 0


if __name__ == "__main__":
    sys.exit(main())
