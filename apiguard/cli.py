"""APIGuard command-line interface (Typer).

Thin consumer of the engine — no business logic here (BRAIN.md invariant 1).
It fetches the spec through the core parser and renders it with `rich`.
Currently exposes `parse`; the `scan` command arrives on Day 6.
"""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from apiguard.core.models import Endpoint
from apiguard.core.scope import ScopeError
from apiguard.core.spec_parser import load_spec, parse_spec

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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
