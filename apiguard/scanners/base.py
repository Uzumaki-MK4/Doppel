"""Scanner base class + auto-registration registry (BRAIN.md D7).

Every scanner subclasses `Scanner`, sets a `name`, and implements
`async def run(self, endpoint) -> list[Finding]`. Defining the subclass
registers it automatically (`__init_subclass__`); `discover_scanners()` imports
every module in the `apiguard.scanners` package so that dropping a new file
there is enough — adding a scanner never requires editing the CLI (Section 6).

A `ScanContext` (engine, base_url, settings, user sessions) is injected at
construction, so `run()` keeps the exact `(endpoint) -> list[Finding]` contract
while scanners still have the engine and, from Week 4, the two user sessions.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from apiguard.core.http_engine import HttpEngine
from apiguard.core.identity import Session
from apiguard.core.models import Endpoint, Finding
from apiguard.settings import Settings

_REGISTRY: dict[str, type["Scanner"]] = {}


@dataclass
class ScanContext:
    """Everything a scanner needs, injected at construction."""

    engine: HttpEngine
    base_url: str
    settings: Settings | None = None
    sessions: dict[str, Session] | None = None
    # Payload source for the injection scanner: "static" | "ai" | "both".
    payload_mode: str = "static"
    # A PayloadGenerator (duck-typed to avoid importing the ai layer here); None
    # means static-only (e.g. Ollama unavailable).
    payload_generator: object | None = None
    # A RepairLoop (duck-typed); None disables self-repair of rejected payloads.
    repair_loop: object | None = None


class Scanner(ABC):
    """Base class for all scanners. Subclasses set `name` and implement `run`."""

    name: ClassVar[str] = ""
    owasp_id: ClassVar[str] = ""

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Register only named (concrete) scanners; abstract intermediates leave
        # `name` unset. We can't check __abstractmethods__ here — ABCMeta sets
        # it after __init_subclass__ runs.
        if cls.name:
            existing = _REGISTRY.get(cls.name)
            if existing is not None and existing is not cls:
                raise ValueError(
                    f"Duplicate scanner name {cls.name!r}: "
                    f"{existing.__qualname__} vs {cls.__qualname__}"
                )
            _REGISTRY[cls.name] = cls

    @property
    def engine(self) -> HttpEngine:
        return self.context.engine

    @property
    def base_url(self) -> str:
        return self.context.base_url

    @abstractmethod
    async def run(self, endpoint: Endpoint) -> list[Finding]:
        """Attack one endpoint and return any findings (possibly empty)."""
        raise NotImplementedError


def discover_scanners(package: str = "apiguard.scanners") -> None:
    """Import every module in the scanners package so its subclasses register."""
    pkg = importlib.import_module(package)
    for module in pkgutil.iter_modules(pkg.__path__):
        if module.name != "base":
            importlib.import_module(f"{package}.{module.name}")


def registered_scanners() -> dict[str, type[Scanner]]:
    """Snapshot of the registry (name -> class)."""
    return dict(_REGISTRY)


def build_scanners(context: ScanContext, *, discover: bool = True) -> list[Scanner]:
    """Discover (optionally) and instantiate every registered scanner."""
    if discover:
        discover_scanners()
    return [cls(context) for cls in _REGISTRY.values()]
