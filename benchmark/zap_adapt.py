"""benchmark/zap_adapt.py — turn an OWASP ZAP report into a scorable arm (BRAIN.md D26).

ZAP is the EXTERNAL baseline in the Section-1 ablation. To judge it by the same
yardstick as APIGuard, this adapter converts ZAP's real JSON report into a
`ScanResult` (`benchmark/results/zap.json`) whose findings carry APIGuard's own
match keys, so `run_eval.py` scores ZAP with the identical ground-truth matcher.

The interpretive layer — the ONE place ZAP's world is mapped onto ours — is
`_classify()` below, and it is deliberately transparent: every ZAP alert is
printed with its disposition (which ground-truth class it was credited to, or
"FP" for a Low+ alert that matches no real vuln, or "skip" for informational
noise). Nothing is hidden; an examiner can re-derive every number.

Fairness rules (the same standard applied to APIGuard):
  * ZAP recall = how many of the target's ground-truth vulns ZAP detected.
  * ZAP false positives = Low-risk-or-above ZAP alerts that map to NO real vuln
    (the noise a user must triage). Informational (riskcode 0) alerts are excluded
    entirely — APIGuard emits no info-level findings either, so counting ZAP's
    would be unfair.
  * A ZAP alert instance's concrete URL (…/users/v1/name1) is normalised back to
    the spec's templated path (…/users/v1/{username}) so it can join by endpoint.

Run:  python benchmark/zap_adapt.py <zap_report.json> [--spec URL] [--out results/zap.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

from apiguard.core.models import Endpoint, Evidence, Finding, ScanResult, Severity
from apiguard.core.spec_parser import load_spec, parse_spec

HERE = Path(__file__).resolve().parent
DEFAULT_SPEC = "http://localhost:5000/openapi.json"
DEFAULT_OUT = HERE / "results" / "zap.json"

# --------------------------------------------------------------------------- #
# The interpretive layer: ZAP alert -> APIGuard ground-truth class.
#
# Keyed on ZAP's stable numeric pluginid. Each maps to a (scanner, id_slug) that
# lines up with a ground_truth.yaml `match` block:
#   injection + "sqli"                -> vampi-sqli-username    (path-scoped)
#   misconfig + "version-disclosure"  -> vampi-misconfig-version-disclosure (global)
#   misconfig + "missing-security-headers" -> vampi-misconfig-missing-headers (global)
# "skip" = informational noise (riskcode 0-ish), not counted either way.
# Anything unmapped and Low+ falls through to scanner="zap-unmapped" -> false positive.
# --------------------------------------------------------------------------- #
_SQLI_PLUGINS = {"40018", "40019", "40020", "40021", "40022", "40024", "40027"}
_HEADER_PLUGINS = {
    "10020",  # Missing Anti-clickjacking Header (X-Frame-Options)
    "10021",  # X-Content-Type-Options Header Missing
    "10035",  # Strict-Transport-Security Header Not Set
    "10038",  # Content Security Policy (CSP) Header Not Set
    "10063",  # Permissions Policy Header Not Set
}
_VERSION_PLUGINS = {
    "10036",  # Server Leaks Version Information via "Server" HTTP Response Header
    "10037",  # Server Leaks Information via "X-Powered-By"
}
# Real findings that fall OUTSIDE the 12 tracked ground-truth vulns. They are NOT
# false positives (VAmPI genuinely leaks these), so counting them against ZAP's
# precision would be unfair — they are excluded from scoring and reported
# separately. On this VAmPI run both fire on the /createdb reset endpoint's 500.
_OUT_OF_SCOPE_PLUGINS = {
    "10099",  # Source Code Disclosure - SQL (passive SQL leak on /createdb's 500,
              #   NOT the injectable /users/v1/{username} param — ZAP's active SQLi
              #   scanner 40018 never fired, so ZAP does NOT detect the real SQLi)
    "90022",  # Application Error Disclosure (verbose 500 error page)
}
# Informational alerts APIGuard would never emit — exclude from scoring entirely.
_SKIP_PLUGINS = {
    "10096",  # Timestamp Disclosure
    "10027",  # Information Disclosure - Suspicious Comments
    "10015",  # Re-examine Cache-control Directives
    "10049",  # Storable and Cacheable Content / Non-Storable Content
    "10050",  # Retrieved from Cache
    "90005",  # Sec-* / informational
    "10109",  # Modern Web Application
    "10112",  # Session Management Response Identified (informational)
}


def _classify(pluginid: str, name: str, riskcode: int) -> tuple[str, str, bool] | None:
    """Return (scanner, id_slug, path_scoped), or None to SKIP (not counted).

    The sentinel scanner "__oos__" means a real finding outside the tracked
    ground-truth set: reported, but neither a true positive nor a false positive.
    """
    if pluginid in _SKIP_PLUGINS or riskcode <= 0:
        return None  # informational noise
    if pluginid in _OUT_OF_SCOPE_PLUGINS:
        return ("__oos__", "out-of-scope", False)
    if pluginid in _SQLI_PLUGINS or "sql injection" in name.lower():
        return ("injection", "zap-sqli", True)
    if pluginid in _VERSION_PLUGINS or "version information" in name.lower():
        return ("misconfig", "zap-version-disclosure", False)
    if pluginid in _HEADER_PLUGINS or "header" in name.lower() and (
        "missing" in name.lower() or "not set" in name.lower()
    ):
        return ("misconfig", "zap-missing-security-headers", False)
    # Low+ alert that corresponds to no ground-truth vuln -> a false positive.
    slug = "zap-unmapped-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return ("zap-unmapped", slug, False)


_RISK = {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH}


def _templates(spec_source: str) -> list[Endpoint]:
    try:
        spec = asyncio.run(load_spec(spec_source))
        return parse_spec(spec)
    except Exception as exc:  # spec unreachable -> normalisation degrades gracefully
        print(f"[zap] warning: could not load spec {spec_source!r} ({exc}); "
              f"path normalisation disabled", file=sys.stderr)
        return []


def _normalise_path(concrete: str, templates: list[Endpoint]) -> str:
    """Map a concrete URL path (/users/v1/name1) to a spec template (/users/v1/{username})."""
    csegs = [s for s in concrete.strip("/").split("/") if s != ""]
    for ep in templates:
        tsegs = [s for s in ep.path.strip("/").split("/") if s != ""]
        if len(tsegs) != len(csegs):
            continue
        if all(t.startswith("{") or t == c for t, c in zip(tsegs, csegs)):
            return ep.path
    return concrete  # no template matched -> keep concrete (global findings don't care)


def _path_of(uri: str) -> str:
    # strip scheme://host and any query string
    m = re.match(r"^[a-z]+://[^/]+(/[^?]*)", uri)
    return (m.group(1) if m else uri).split("?", 1)[0] or "/"


def adapt(report: dict, templates: list[Endpoint], target_hint: str) -> tuple[ScanResult, list[dict]]:
    sites = report.get("site", [])
    site = next((s for s in sites if target_hint in s.get("@name", "")), sites[0] if sites else {})
    base = site.get("@name", target_hint).rstrip("/")

    findings: dict[str, Finding] = {}   # dedup by finding id
    dispositions: list[dict] = []

    for alert in site.get("alerts", []):
        pluginid = str(alert.get("pluginid", ""))
        name = alert.get("name") or alert.get("alert") or f"plugin-{pluginid}"
        riskcode = int(alert.get("riskcode", 0))
        disp = _classify(pluginid, name, riskcode)
        if disp is None:
            dispositions.append({"alert": name, "pluginid": pluginid, "risk": riskcode, "disposition": "skip (info)"})
            continue
        scanner, id_slug, path_scoped = disp
        if scanner == "__oos__":
            # Real, but outside the 12 tracked vulns -> neither TP nor FP.
            dispositions.append({"alert": name, "pluginid": pluginid, "risk": riskcode,
                                 "disposition": "out-of-scope (real, not in GT)"})
            continue

        instances = alert.get("instances") or [{}]
        paths = set()
        for inst in instances:
            uri = inst.get("uri", base)
            paths.add(_normalise_path(_path_of(uri), templates) if path_scoped else "/")
        for path in sorted(paths):
            fid = f"{id_slug}-{re.sub(r'[^a-z0-9]+', '-', path.lower()).strip('-')}" if path_scoped else id_slug
            if fid in findings:
                continue
            ev = Evidence(
                request_method="GET", request_url=f"{base}{path}",
                response_status=0, response_body=(alert.get("desc") or "")[:500],
                curl_repro=f"# ZAP alert {pluginid} ({name})\ncurl {base}{path}",
            )
            findings[fid] = Finding(
                id=fid, title=f"ZAP: {name}", scanner=scanner,
                endpoint=Endpoint(path=path, method="GET", parameters=[], request_body_schema=None, security=[]),
                severity=_RISK.get(riskcode, Severity.LOW),
                owasp_id="API8:2023",  # descriptive only; owasp is NOT a match predicate
                confidence=min(1.0, max(0.0, int(alert.get("confidence", 1)) / 3)),
                description=(alert.get("desc") or name)[:400],
                remediation=(alert.get("solution") or "See ZAP report.")[:400],
                evidence=ev, ai_trace=None,
            )
        credited = "FP (unmapped)" if scanner == "zap-unmapped" else f"{scanner}/{id_slug}"
        dispositions.append({"alert": name, "pluginid": pluginid, "risk": riskcode, "disposition": credited})

    result = ScanResult(
        target=base, spec_url=f"{base} (OWASP ZAP baseline)",
        model="owasp-zap", seed=0, payload_mode="static",
        endpoints=[], findings=list(findings.values()),
        requests_sent=0,  # ZAP's request count is not in the JSON report (shown as n/a)
    )
    return result, dispositions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Adapt an OWASP ZAP JSON report into a scorable arm.")
    parser.add_argument("report", help="ZAP JSON report (-J output)")
    parser.add_argument("--spec", default=DEFAULT_SPEC, help="OpenAPI spec URL for path normalisation")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="output ScanResult JSON")
    parser.add_argument("--target-hint", default="5000", help="substring identifying the scanned site")
    ns = parser.parse_args(argv)

    report = json.loads(Path(ns.report).read_text(encoding="utf-8"))
    templates = _templates(ns.spec)
    result, dispositions = adapt(report, templates, ns.target_hint)

    Path(ns.out).parent.mkdir(parents=True, exist_ok=True)
    Path(ns.out).write_text(result.model_dump_json(indent=2), encoding="utf-8")

    print(f"ZAP alerts -> disposition ({len(dispositions)} alerts):")
    for d in dispositions:
        print(f"  [{d['disposition']:28}] risk={d['risk']} plugin={d['pluginid']:6} {d['alert']}")
    mapped = [f for f in result.findings if f.scanner != "zap-unmapped"]
    fps = [f for f in result.findings if f.scanner == "zap-unmapped"]
    oos = sum(1 for d in dispositions if d["disposition"].startswith("out-of-scope"))
    skipped = sum(1 for d in dispositions if d["disposition"].startswith("skip"))
    print(f"\n-> {len(result.findings)} findings emitted "
          f"({len(mapped)} mapped to ground-truth classes, {len(fps)} false positives); "
          f"{oos} out-of-scope, {skipped} info skipped")
    print(f"saved: {ns.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
