"""APIGuard command-line interface (Typer).

Thin consumer of the engine — no business logic here (BRAIN.md invariant 1).
Exposes `parse` (table an OpenAPI spec) and `scan` (run the scanners + the
BOLA/BFLA engine, optionally writing a JSON result and/or an HTML report). All
output goes through `rich`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from apiguard import runner
from apiguard.core.http_engine import Cassette
from apiguard.core.models import Endpoint, ScanResult
from apiguard.core.scope import ScopeError
from apiguard.core.spec_parser import load_spec, parse_spec
from apiguard.settings import load_settings

app = typer.Typer(
    add_completion=False,
    help="APIGuard — AI-powered API vulnerability scanner.",
)
console = Console()


@app.callback()
def _root() -> None:
    """APIGuard — AI-powered API vulnerability scanner.

    A root callback keeps the subcommand style (`apiguard parse ...`,
    `apiguard scan ...`).
    """


@app.command()
def parse(
    source: str = typer.Argument(..., help="OpenAPI spec URL or file path."),
    confirm_authorized: bool = typer.Option(
        False,
        "--confirm-authorized",
        help="Authorize scanning a non-localhost target (invariant 7).",
    ),
) -> None:
    """Parse an OpenAPI spec and table every endpoint with its parameters."""
    try:
        spec = asyncio.run(load_spec(source, confirm_authorized=confirm_authorized))
    except ScopeError as exc:
        console.print(f"[bold red]Scope refused:[/bold red] {exc}")
        raise typer.Exit(code=2) from None
    except Exception as exc:  # network / file / invalid-spec errors, at the CLI boundary
        console.print(f"[bold red]Could not load spec[/bold red] ({source}): {exc}")
        raise typer.Exit(code=1) from None
    endpoints = parse_spec(spec)
    _render(endpoints, source)


def _render(endpoints: list[Endpoint], source: str) -> None:
    table = Table(title=f"Endpoints: {source}")
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("Path", style="white")
    table.add_column("Params (name:in:type, * = required)", style="green")
    table.add_column("Body", justify="center")
    table.add_column("Security", style="magenta")

    for ep in sorted(endpoints, key=lambda e: (e.path, e.method)):
        params = (
            ", ".join(
                f"{p.name}:{p.location}:{p.type_}{'*' if p.required else ''}"
                for p in ep.parameters
            )
            or "-"
        )
        table.add_row(
            ep.method,
            ep.path,
            params,
            "yes" if ep.request_body_schema else "-",
            ", ".join(ep.security) or "-",
        )

    console.print(table)
    console.print(f"[bold]{len(endpoints)}[/bold] endpoints parsed.")


@app.command()
def scan(
    spec: str = typer.Option(
        None, "--spec", help="OpenAPI spec URL or file path (optional with --replay)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Run the full pipeline without vulnerability scanners."
    ),
    confirm_authorized: bool = typer.Option(
        False, "--confirm-authorized", help="Authorize a non-localhost target (invariant 7)."
    ),
    config: str = typer.Option(
        "config.yaml", "--config", help="Config YAML path (defaults are used if absent)."
    ),
    payloads: str = typer.Option(
        "static", "--payloads", help="Payload source: static | ai | both."
    ),
    repair: bool = typer.Option(
        True, "--repair/--no-repair", help="Self-repair of validation-rejected payloads (ai/both)."
    ),
    bola: bool = typer.Option(
        False, "--bola/--no-bola", help="Run the BOLA engine (two-user object-authz testing; needs Ollama)."
    ),
    record: str = typer.Option(
        None, "--record", help="Record all HTTP into this cassette directory."
    ),
    replay: str = typer.Option(
        None, "--replay", help="Replay all HTTP from this cassette directory (offline)."
    ),
    out: str = typer.Option(None, "--out", help="Write the ScanResult JSON to this path."),
    report: str = typer.Option(None, "--report", help="Write a self-contained HTML report to this path."),
) -> None:
    """Scan an API for vulnerabilities. Use --dry-run for a plumbing-only pass."""
    settings = load_settings(config)

    if payloads not in ("static", "ai", "both"):
        console.print("[bold red]--payloads must be one of: static, ai, both.[/bold red]")
        raise typer.Exit(code=2)
    if record and replay:
        console.print("[bold red]Use either --record or --replay, not both.[/bold red]")
        raise typer.Exit(code=2)
    if dry_run and (record or replay):
        console.print("[bold red]Cassettes (--record/--replay) are not supported with --dry-run.[/bold red]")
        raise typer.Exit(code=2)

    if replay and not spec:  # a cassette records its own spec source
        try:
            spec = Cassette.read_meta(replay).get("spec_source")
        except Exception as exc:
            console.print(f"[bold red]Could not read cassette meta[/bold red] ({replay}): {exc}")
            raise typer.Exit(code=1) from None
    if not spec:
        console.print(
            "[bold red]--spec is required[/bold red] (except with --replay of a cassette that recorded it)."
        )
        raise typer.Exit(code=2)

    try:
        if dry_run:
            result = _run_dry_run(spec, settings, confirm_authorized)
        else:
            result = _run_scan(spec, settings, confirm_authorized, record, replay, payloads, repair, bola)
    except ScopeError as exc:
        console.print(f"[bold red]Scope refused:[/bold red] {exc}")
        raise typer.Exit(code=2) from None
    except Exception as exc:  # network / auth / spec errors, at the CLI boundary
        console.print(f"[bold red]Scan failed[/bold red] ({spec}): {exc}")
        raise typer.Exit(code=1) from None

    if dry_run:
        _render_scan_summary(result)
    else:
        _render_findings(result)
        if out:
            _write_result(out, result)
        if report:
            _write_report(report, result)


def _write_report(out: str, result: ScanResult) -> None:
    from datetime import datetime

    from apiguard.report.generator import write_report

    path = write_report(
        result, out, generated_at=datetime.now().isoformat(timespec="seconds")
    )
    console.print(f"[green]Wrote HTML report to {path}[/green]")


def _run_dry_run(spec: str, settings, confirm_authorized: bool) -> ScanResult:
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        state: dict[str, object] = {"task": None}

        def on_progress(index: int, total: int, description: str) -> None:
            if state["task"] is None:
                state["task"] = progress.add_task("Touching endpoints", total=total)
            progress.update(state["task"], completed=index, description=f"Touching {description}")

        return asyncio.run(
            runner.dry_run(
                spec, settings, confirm_authorized=confirm_authorized, on_progress=on_progress
            )
        )


def _render_scan_summary(result: ScanResult) -> None:
    table = Table(title="Dry-run summary")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("target", result.target)
    table.add_row("spec", result.spec_url)
    table.add_row("model / seed", f"{result.model} / {result.seed}")
    table.add_row("endpoints touched", str(len(result.endpoints)))
    table.add_row("requests sent", str(result.requests_sent))
    table.add_row("findings", str(len(result.findings)))
    console.print(table)
    console.print("[green]Dry-run complete. Week 1 plumbing works end to end.[/green]")


_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _run_scan(
    spec: str,
    settings,
    confirm_authorized: bool,
    record_dir: str | None = None,
    replay_dir: str | None = None,
    payload_mode: str = "static",
    repair_enabled: bool = True,
    bola_enabled: bool = False,
) -> ScanResult:
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        state: dict[str, object] = {"task": None}

        def on_progress(index: int, total: int, description: str) -> None:
            if state["task"] is None:
                state["task"] = progress.add_task("Scanning", total=total)
            progress.update(state["task"], completed=index, description=f"Scanning {description}")

        return asyncio.run(
            runner.scan(
                spec,
                settings,
                confirm_authorized=confirm_authorized,
                payload_mode=payload_mode,
                repair_enabled=repair_enabled,
                bola_enabled=bola_enabled,
                record_dir=record_dir,
                replay_dir=replay_dir,
                on_progress=on_progress,
            )
        )


def _write_result(out: str, result: ScanResult) -> None:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"[green]Saved result to {out}[/green]")


def _render_findings(result: ScanResult) -> None:
    table = Table(title=f"Findings: {result.target}")
    table.add_column("Severity", no_wrap=True)
    table.add_column("OWASP", style="magenta", no_wrap=True)
    table.add_column("Scanner", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Endpoint", style="white")
    table.add_column("Conf", justify="right")

    # result.findings is already deduped and severity-sorted by finalize().
    for finding in result.findings:
        sev = finding.severity.value
        table.add_row(
            f"[{_SEVERITY_STYLE.get(sev, 'white')}]{sev.upper()}[/]",
            finding.owasp_id,
            finding.scanner,
            finding.title,
            f"{finding.endpoint.method} {finding.endpoint.path}",
            f"{finding.confidence:.2f}",
        )

    console.print(table)
    counts = result.severity_counts()
    breakdown = ", ".join(f"{k}={v}" for k, v in counts.items() if v) or "none"
    console.print(
        f"[bold]{len(result.findings)}[/bold] findings ({breakdown}) across "
        f"{len(result.endpoints)} endpoints; {result.requests_sent} requests sent; "
        f"payloads={result.payload_mode}."
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
