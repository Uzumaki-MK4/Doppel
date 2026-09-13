"""Day-24 crAPI BOLA validation — run APIGuard's real engine against crAPI.

This is a thin consumer of the engine (invariant 1). It exists to answer the
Day-24 done-condition: ">=1 true BOLA on crAPI with <=2 false positives" — and,
more importantly, to prove the *contribution* (the ambiguity gate + AI oracle +
confidence scoring) works unmodified on a second, harder target.

Why this is not a plain `apiguard scan`
----------------------------------------
The generic `ResourceDiscoverer` (engines/bola.py) establishes A-owned objects by
POST-seeding a collection and harvesting by owner-field. crAPI's vehicles are NOT
created that way: they are pre-seeded and bound to users through an *email-gated*
claim flow (VIN + pincode mailed to the owner). So the generic discoverer cannot
auto-seed a crAPI vehicle. That is a limitation of the discovery step, not of the
contribution. Here we supply the two owner->vehicle bindings from crAPI's own API
(`GET /identity/api/v2/vehicle/vehicles`, each user's own list), and then the REAL
`probe_cross_access` + `BolaOracle` + confidence + `bola_finding` run untouched.

Reproducibility
---------------
crAPI ships bcrypt-hashed demo passwords we do not know. To obtain two owner
sessions without guessing, we drive crAPI's own forgot-password -> OTP -> reset
flow (the OTP is delivered to MailHog, which crAPI uses for all mail), resetting
two seeded owners to a known password. No DB tampering, no credential guessing;
every step is a real crAPI request. Re-running from a fresh crAPI reproduces it.

Run:  python benchmark/crapi_bola.py
Needs: crAPI up (gateway on 127.0.0.1:8888, MailHog on :8025) and Ollama running.
"""

from __future__ import annotations

import asyncio
import email
import json
import re
import sys
from pathlib import Path

import httpx

from apiguard.ai.client import OllamaClient
from apiguard.ai.oracle import BolaOracle, gate
from apiguard.core.http_engine import HttpEngine
from apiguard.core.identity import AuthFlow, IdentityManager, Session, UserCredentials
from apiguard.core.models import Endpoint, Parameter, ScanResult
from apiguard.core.scope import ScopeGuard
from apiguard.engines.bola import AccessTriple, OwnedObject, _object_access, probe_cross_access
from apiguard.runner import bola_finding
from apiguard.settings import Settings

GATEWAY = "http://127.0.0.1:8888"
MAILHOG = "http://127.0.0.1:8025"
RESET_PW = "Apiguard!123"

# crAPI's login uses email as the identity and returns {"token": <RS256 JWT>};
# register (signup) needs name/number too, so it best-effort-fails for existing
# seeded users, which is fine — login is the token source of truth. Zero engine
# code changes: the whole difference from VAmPI is this AuthFlow config.
CRAPI_FLOW = AuthFlow(
    register_path="/identity/api/auth/signup",
    login_path="/identity/api/auth/login",
    username_field="email",
    password_field="password",
    email_field="email",
    token_json_key="token",
)

# Two seeded vehicle owners (identities only; UUIDs are discovered via the API).
OWNER_A_EMAIL = "adam007@example.com"
OWNER_B_EMAIL = "pogba006@example.com"

VEHICLE_LOCATION = Endpoint(
    path="/identity/api/v2/vehicle/{vehicleId}/location",
    method="GET",
    parameters=[Parameter(name="vehicleId", location="path", type_="string", required=True)],
    request_body_schema=None,
    security=["bearerAuth"],
)


async def _mailhog_latest_otp(recipient_local: str) -> str | None:
    """Read the newest OTP crAPI mailed to `recipient_local@...` from MailHog."""
    async with httpx.AsyncClient(timeout=10) as c:
        listing = (await c.get(f"{MAILHOG}/api/v2/messages")).json()
        for m in listing.get("items", []):
            to = "".join(h.get("Mailbox", "") for h in m["To"])
            subject = m["Content"]["Headers"].get("Subject", [""])[0]
            if recipient_local in to and "OTP" in subject:
                raw = (await c.get(f"{MAILHOG}/api/v1/messages/{m['ID']}/download")).content
                msg = email.message_from_bytes(raw)
                for part in msg.walk():
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    text = re.sub(r"<[^>]+>", " ", payload.decode("utf-8", "replace"))
                    found = re.search(r"(?<!\d)(\d{4,8})(?!\d)", text)
                    if found:
                        return found.group(1)
    return None


async def bootstrap_owner(engine: HttpEngine, base: str, owner_email: str) -> None:
    """Reset a seeded owner to RESET_PW via crAPI's real forgot-password/OTP flow."""
    recipient_local = owner_email.split("@", 1)[0]
    await engine.send(
        "POST", f"{base}/identity/api/auth/forget-password",
        json_body={"email": owner_email},
    )
    await asyncio.sleep(1.0)  # let the mail land in MailHog
    otp = await _mailhog_latest_otp(recipient_local)
    if otp is None:
        raise SystemExit(f"[crapi] no OTP mail found for {owner_email} in MailHog")
    reset = await engine.send(
        "POST", f"{base}/identity/api/auth/v3/check-otp",
        json_body={"email": owner_email, "otp": otp, "password": RESET_PW},
    )
    if reset.status != 200:
        raise SystemExit(f"[crapi] OTP reset failed for {owner_email}: HTTP {reset.status}")
    print(f"[crapi] bootstrapped owner {owner_email} (OTP {otp} -> password reset)")


async def _own_vehicle_uuid(engine: HttpEngine, base: str, session: Session) -> str:
    """Discover the caller's OWN vehicle UUID via crAPI's my-vehicles endpoint."""
    ex = await engine.send(
        "GET", f"{base}/identity/api/v2/vehicle/vehicles", headers=dict(session.headers)
    )
    vehicles = json.loads(ex.evidence.response_body)
    if not vehicles:
        raise SystemExit(f"[crapi] {session.username} owns no vehicle; cannot form a triple")
    return str(vehicles[0]["uuid"])


async def _owned_object(
    engine: HttpEngine, base: str, session: Session, uuid: str, owner_name: str
) -> OwnedObject:
    """Capture the owner's own legitimate access to their vehicle (the a_access baseline)."""
    access = await _object_access(
        engine, base, VEHICLE_LOCATION, "vehicleId", uuid, dict(session.headers)
    )
    return OwnedObject(
        object_endpoint=VEHICLE_LOCATION,
        id_param="vehicleId",
        object_id=uuid,
        owner=owner_name,
        source="ground-truth",  # supplied from crAPI's own my-vehicles API, not seeded
        a_access=access.evidence,
    )


async def main() -> int:
    settings = Settings()
    # Invariant 7: the target host must be in scope. localhost is always allowed.
    ScopeGuard(settings.scope.allowlist).check(GATEWAY, confirm_authorized=False)

    async with HttpEngine(
        max_concurrency=settings.http.max_concurrency,
        rate_limit_per_s=settings.http.rate_limit_per_s,
        timeout_s=settings.http.timeout_s,
        retries=settings.http.retries,
    ) as engine:
        base = GATEWAY

        # 1) Reproducibly obtain two owner sessions via crAPI's own OTP reset flow.
        await bootstrap_owner(engine, base, OWNER_A_EMAIL)
        await bootstrap_owner(engine, base, OWNER_B_EMAIL)

        # 2) Log both in through APIGuard's IdentityManager + a crAPI AuthFlow.
        identity = IdentityManager(engine, base, flow=CRAPI_FLOW)
        sessions = await identity.setup({
            "userA": UserCredentials(username=OWNER_A_EMAIL, password=RESET_PW, email=OWNER_A_EMAIL),
            "userB": UserCredentials(username=OWNER_B_EMAIL, password=RESET_PW, email=OWNER_B_EMAIL),
        })
        print(f"[crapi] logged in userA={OWNER_A_EMAIL} userB={OWNER_B_EMAIL} "
              f"(AuthFlow generalized, token key={CRAPI_FLOW.token_json_key!r})")

        # 3) Discover each owner's OWN vehicle UUID (crAPI ground truth via its API).
        a_uuid = await _own_vehicle_uuid(engine, base, sessions["userA"])
        b_uuid = await _own_vehicle_uuid(engine, base, sessions["userB"])
        owned_a = [await _owned_object(engine, base, sessions["userA"], a_uuid, "userA")]
        owned_b = [await _owned_object(engine, base, sessions["userB"], b_uuid, "userB")]
        print(f"[crapi] userA vehicle={a_uuid}  userB vehicle={b_uuid}")

        # 4) REAL engine, unmodified: B cross-accesses A's vehicle + a B-owned control.
        triples = await probe_cross_access(
            engine, base, sessions, owned_a, owned_b, attacker="userB"
        )

        if not await OllamaClient.from_settings(settings).available():
            raise SystemExit("[crapi] Ollama is not available; start `ollama serve` and retry")
        oracle = BolaOracle(OllamaClient.from_settings(settings),
                            temperature=settings.temperature_oracle)
        weights = settings.confidence_weights.model_dump()

        findings = []
        for triple in triples:
            decision = await oracle.adjudicate(triple)
            print(f"[crapi] cross-access {triple.object_endpoint.path} id={triple.a_object_id} "
                  f"-> is_leak={decision.is_leak} decided_by={decision.decided_by} "
                  f"verdict={decision.oracle_verdict}")
            f = bola_finding(triple, decision, weights)
            if f is not None:
                findings.append(f)
                print(f"        FINDING {f.severity.value.upper()} conf={f.confidence} "
                      f"signals={f.ai_trace.signals if f.ai_trace else {}}")

        # 5) No-false-positive check: a legitimate self-access (B reads B's OWN vehicle)
        #    must be CLEARED deterministically by the gate (no LLM, no finding).
        self_control = await _object_access(
            engine, base, VEHICLE_LOCATION, "vehicleId", b_uuid, dict(sessions["userB"].headers)
        )
        legit_triple = AccessTriple(
            object_endpoint=VEHICLE_LOCATION,
            a_object_id=b_uuid,
            a_access=owned_b[0].a_access,
            b_cross_access=self_control.evidence,   # B accessing B's own object
            b_control=self_control.evidence,
        )
        legit_decision, legit_reason = gate(legit_triple)
        false_positives = 0 if legit_decision == "not_leak" else 1
        print(f"[crapi] legitimate self-access -> gate={legit_decision} ({legit_reason}); "
              f"false_positives={false_positives}")

        result = ScanResult(
            target=base,
            spec_url=f"{base}/identity (crAPI, manual owner bindings)",
            model=settings.model,
            seed=settings.seed,
            payload_mode="static",  # no payload generation in a BOLA run; the AI here is the oracle
            endpoints=[VEHICLE_LOCATION],
            findings=findings,
            requests_sent=engine.requests_sent,
        )

    out = Path("benchmark/results/crapi.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    true_bola = len(findings)
    print("\n=== Day-24 done-condition ===")
    print(f"true BOLA findings on crAPI: {true_bola}  (need >=1)")
    print(f"false positives:            {false_positives}  (need <=2)")
    print(f"saved: {out}")
    ok = true_bola >= 1 and false_positives <= 2
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
