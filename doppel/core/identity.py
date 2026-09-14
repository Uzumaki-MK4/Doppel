"""Two-user session manager (BRAIN.md D5).

Registers and logs in two independent users (User A / User B) and hands out
their auth headers. This is the foundation the BOLA/BFLA engine stands on in
Week 4: it needs two principals with valid, distinct credentials so it can make
User B replay a request for a resource owned by User A.

The auth flow is target-specific, so it is captured in `AuthFlow` (defaults to
VAmPI's register/login/JWT flow) rather than hardcoded in the logic. crAPI's
different flow (Week 4) becomes another `AuthFlow`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from doppel.core.http_engine import HttpEngine


class IdentityError(RuntimeError):
    """Raised when a user cannot be authenticated."""


class UserCredentials(BaseModel):
    """One principal's login credentials (username/password, optional email)."""

    username: str
    password: str
    email: str | None = None


class AuthFlow(BaseModel):
    """How to register and log in against a target. Defaults suit VAmPI."""

    register_path: str = "/users/v1/register"
    login_path: str = "/users/v1/login"
    username_field: str = "username"
    password_field: str = "password"
    email_field: str = "email"
    token_json_key: str = "auth_token"
    header_name: str = "Authorization"
    header_template: str = "Bearer {token}"


@dataclass
class Session:
    """One authenticated principal: its token and ready-to-use auth headers."""

    username: str
    token: str
    headers: dict[str, str] = field(default_factory=dict)


class IdentityManager:
    """Registers and logs in users against a target, caching their sessions."""

    def __init__(
        self,
        engine: HttpEngine,
        base_url: str,
        *,
        flow: AuthFlow | None = None,
    ) -> None:
        self._engine = engine
        self._base = base_url.rstrip("/")
        self._flow = flow or AuthFlow()
        self._sessions: dict[str, Session] = {}

    async def authenticate(self, creds: UserCredentials) -> Session:
        """Register (best-effort) then log in, returning a Session with a token."""
        flow = self._flow
        login_payload = {
            flow.username_field: creds.username,
            flow.password_field: creds.password,
        }
        register_payload = {
            **login_payload,
            flow.email_field: creds.email or f"{creds.username}@apiguard.test",
        }

        # Register is best-effort: on a re-run the user already exists, which is
        # fine. Login is the source of truth for the token.
        await self._engine.send(
            "POST", f"{self._base}{flow.register_path}", json_body=register_payload
        )

        login = await self._engine.send(
            "POST", f"{self._base}{flow.login_path}", json_body=login_payload
        )
        if login.status != 200:
            raise IdentityError(
                f"Login failed for {creds.username!r}: HTTP {login.status} "
                f"{login.response.text[:160]}"
            )

        try:
            token = login.response.json().get(flow.token_json_key)
        except ValueError as exc:  # non-JSON login response
            raise IdentityError(
                f"Login response for {creds.username!r} was not JSON: {exc}"
            ) from None
        if not token:
            raise IdentityError(
                f"No {flow.token_json_key!r} in login response for {creds.username!r}."
            )

        header_value = flow.header_template.format(token=token)
        return Session(
            username=creds.username,
            token=str(token),
            headers={flow.header_name: header_value},
        )

    async def setup(self, users: dict[str, UserCredentials]) -> dict[str, Session]:
        """Authenticate every named user and cache the sessions."""
        for name, creds in users.items():
            self._sessions[name] = await self.authenticate(creds)
        return dict(self._sessions)

    def session_for(self, name: str) -> Session:
        """Return a previously-established Session, or raise if unknown."""
        try:
            return self._sessions[name]
        except KeyError:
            raise IdentityError(
                f"No session for {name!r}; call setup() first."
            ) from None
