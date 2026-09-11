"""APIGuard command-line interface (Typer).

Thin consumer of the engine — no business logic here (BRAIN.md invariant 1).
It fetches the spec through the core parser and renders it with `rich`.
Currently exposes `parse`; the `scan` command arrives on Day 6.
"""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from apiguard import runner
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

    A root callback keeps subcommand style (`apiguard parse ...`) even while
    `parse` is the only command; `scan` joins on Day 6.
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
    spec: str = typer.Option(..., "--spec", help="OpenAPI spec URL or file path."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Run the full pipeline without vulnerability scanners."
    ),
    confirm_authorized: bool = typer.Option(
        False, "--confirm-authorized", help="Authorize a non-localhost target (invariant 7)."
    ),
    config: str = typer.Option(
        "config.yaml", "--config", help="Config YAML path (defaults are used if absent)."
    ),
) -> None:
    """Scan an API for vulnerabilities. Use --dry-run for a plumbing-only pass."""
    settings = load_settings(config)
    try:
        if dry_run:
            result = _run_dry_run(spec, settings, confirm_authorized)
        else:
            result = _run_scan(spec, settings, confirm_authorized)
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


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _run_scan(spec: str, settings, confirm_authorized: bool) -> ScanResult:
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
                spec, settings, confirm_authorized=confirm_authorized, on_progress=on_progress
            )
        )


def _render_findings(result: ScanResult) -> None:
    table = Table(title=f"Findings: {result.target}")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Scanner", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Endpoint", style="white")
    table.add_column("Conf", justify="right")

    ordered = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity.value, 9), f.scanner),
    )
    for finding in ordered:
        sev = finding.severity.value
        table.add_row(
            f"[{_SEVERITY_STYLE.get(sev, 'white')}]{sev.upper()}[/]",
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
        f"{len(result.endpoints)} endpoints; {result.requests_sent} requests sent."
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
