"""Target scope guard — BRAIN.md invariant 7 (mandatory, never bypassed).

No request leaves APIGuard unless the target host is in the allowlist, and any
non-localhost host additionally requires explicit authorization
(`--confirm-authorized` at the CLI). This is the gate every outbound request
passes through, starting with the spec fetch on Day 3.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse

DEFAULT_ALLOWLIST: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class ScopeError(RuntimeError):
    """Raised when a target host is outside the authorized scope."""


class ScopeGuard:
    """Allowlist gate for outbound request targets."""

    def __init__(self, allowlist: Iterable[str] | None = None) -> None:
        hosts = allowlist if allowlist is not None else DEFAULT_ALLOWLIST
        self.allowlist: frozenset[str] = frozenset(h.lower() for h in hosts)

    @staticmethod
    def host_of(url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def check(self, url: str, *, confirm_authorized: bool = False) -> str:
        """Return the host if in scope, else raise ScopeError.

        Rules (invariant 7): the host must be in the allowlist; a non-localhost
        host must also carry an explicit authorization flag.
        """
        host = self.host_of(url)
        if not host:
            raise ScopeError(f"Cannot determine a host from URL: {url!r}")
        if host not in self.allowlist:
            raise ScopeError(
                f"Host {host!r} is not in the scope allowlist "
                f"{sorted(self.allowlist)}. Refusing to send a request."
            )
        if host not in _LOCAL_HOSTS and not confirm_authorized:
            raise ScopeError(
                f"Host {host!r} is non-localhost. Re-run with --confirm-authorized "
                f"only if you are authorized to test it."
            )
        return host
