# APIGuard — Engineering Journal

One short entry per working day: what was built, what broke, what was decided.
(BRAIN.md Section 8 holds the live current-state; this is the running history.)

## Day 1 — 2026-09-12 — Environment & repo skeleton

**Built**
- Repo skeleton: `apiguard` package (`core`, `scanners`, `ai`, `engines`, `scoring`, `report`), plus `benchmark/`, `tests/`, `cassettes/`, `docs/`, `wordlists/`, `logs/llm/`.
- `pyproject.toml` — setuptools backend, `requires-python >=3.11`, the fixed BRAIN.md Section 3 stack. `apiguard` console script declared (`apiguard.cli:main`, comes online D6). `pytest`/`respx` in a `[dev]` extra.
- `config.example.yaml` — scope allowlist, pinned `seed: 42`, two temperatures, placeholder confidence weights (summing to 1.0, tuned D22-D24).
- `.gitignore`, `README.md`.
- `.venv` on Python 3.11.9 with all deps installed editable (`pip install -e ".[dev]"`).
- VAmPI in Docker (container `vampi`, port 5000).
- Ollama server running; `qwen3:8b` pulled (5.2 GB).
- `git init` (branch `main`), first commit of the skeleton.

**Verified — Day 1 done-conditions met**
- `curl http://localhost:5000/openapi.json` -> valid OpenAPI 3.0.1, title "VAmPI", 12 paths.
- `ollama run qwen3:8b "Return only JSON: {"ok": true}"` -> valid JSON `{"ok": true}`.
- Bonus, de-risking D13: schema-constrained ollama-python call (`format=<schema>`, `think=False`) -> clean `{"ok": true}`, pydantic-validated. The invariant-2 pattern works on this machine.

**Broke / learned**
- Docker client was installed but the Desktop engine was not running; had to launch Docker Desktop before `docker run` worked.
- `winget` had no working alias; used the full path to the x64 App Installer build to install Python.
- qwen3:8b thinks by default and ignores an inline `/no_think` through the CLI. The engine will pass `think=False`.

**Decided** — see BRAIN.md Section 9 (think=False, `[dev]` extra, model lock).

**Next** — Day 2: `core/models.py`.

## Day 2 — 2026-09-12 — Core data models

**Built**
- `apiguard/core/models.py`: `Severity` (StrEnum), `Parameter`, `Endpoint`, `Evidence`, `AITrace`, `Finding`, `ScanResult` — all pydantic v2, per BRAIN.md Section 5.
- `tests/test_models.py`: 6 tests — Finding round-trip, confidence bounds, `extra=forbid`, severity-as-string, AITrace optional/attaches, ScanResult counts + round-trip.

**Verified — Day 2 done-condition met**
- `pytest -q` -> 6 passed.
- A `Finding` builds in a REPL and `model_dump_json()` returns clean JSON.

**Decided** (see BRAIN.md Section 9)
- `ScanResult` shape (self-describing: model/seed/payload_mode/requests_sent) — not defined in Section 5.
- `Finding.id` required, no auto-uuid — deterministic IDs assigned at dedup (D11).
- `extra="forbid"` on all models; `confidence` bounded `[0,1]`.

**Most likely to break next**
- `$ref` resolution in D3. VAmPI's spec is small, but the resolver's output shape (fully-dereferenced dict) must map cleanly onto `Parameter`/`Endpoint`. `request_body_schema` stays a raw dict by design, so that part is low-risk.

**Next** — Day 3: `core/spec_parser.py`.

## Day 3 — 2026-09-12 — Spec parser, scope guard, parse CLI

**Built**
- `apiguard/core/spec_parser.py`: async `load_spec` (scope-guard -> httpx fetch / file read -> `openapi-spec-validator` -> internal `$ref` deref) and pure `parse_spec(dict) -> list[Endpoint]` mapping params, `requestBody`, and per-operation `security`.
- `apiguard/core/scope.py`: invariant-7 `ScopeGuard`. Host must be allowlisted; non-localhost also needs `--confirm-authorized`.
- `apiguard/cli.py`: thin `apiguard parse <url>` with a rich table and clean (traceback-free) error handling. Root callback keeps subcommand style.
- `tests/test_spec_parser.py`: inline parse, `$ref` deref, scope rules, respx HTTP load, out-of-scope block.

**Verified — Day 3 done-condition met**
- `apiguard parse http://localhost:5000/openapi.json` -> table of 14 VAmPI operations (12 paths) with params/body/security correctly extracted.
- `pytest -q` -> 12 passed.
- Scope guard refuses a non-localhost host cleanly (exit 2), and `--confirm-authorized` does not bypass the allowlist.

**Probed / learned**
- VAmPI's spec has zero `$ref`s; only `securitySchemes: {bearerAuth}`.
- `openapi-spec-validator` validates but does not dereference; `jsonschema-path` derefs on traversal but yields lazy objects. Chose a tiny internal resolver (user-approved). See BRAIN.md Section 9.
- Typer collapses a single-command app; a root callback restores `parse` as a subcommand.

**Decided** — see BRAIN.md Section 9 (internal ref resolver, early scope.py, minimal cli.py, async load_spec).

**Most likely to break next**
- D4 `http_engine.py`: the shared-`AsyncClient` lifecycle plus rate-limit/concurrency gating. Building a valid request from an `Endpoint` (path-param substitution, auth headers, example bodies) is where VAmPI's real responses will expose gaps. The `Evidence` curl-repro string must exactly reproduce the sent request.

**Next** — Day 4: `core/http_engine.py`.

## Day 4 — 2026-09-12 — Async HTTP engine

**Built**
- `apiguard/core/http_engine.py`: `HttpEngine` (one shared `httpx.AsyncClient`, concurrency semaphore, async min-interval rate limiter, transport-only retries, `requests_sent` counter) returning `HttpExchange` (raw response + `Evidence` with curl repro). Pure `build_request` (path/query placeholder fill + example JSON body) and `build_curl`.
- `tests/test_http_engine.py`: 8 tests — request building, example body, curl quoting, evidence capture, transport-error retry, probe, rate-limiter spacing.

**Verified — Day 4 done-condition met**
- Live probe of all 14 VAmPI operations returned statuses: 200 (public), 401 (authed, no token yet), and one 500. `/createdb` reset -> 200. `requests_sent` = 15 (14 + reset).
- `pytest -q` -> 20 passed.
- Sample curl repro reproduces a POST with body verbatim.

**Observed (not a finding yet)**
- `GET /books/v1` -> 500 unauthenticated instead of a clean 401. Real; surfaced by the probe. Revisit with auth (D5) and misconfig/scanners.

**Decided** — see BRAIN.md Section 9 (transport-only retries, no redirect-follow, placeholder probing, requests_sent counts attempts).

**Most likely to break next**
- D5 `identity.py`: VAmPI's exact register/login flow and token shape. Need to read the actual request/response bodies (username/password/email fields, where the JWT comes back) and confirm two independent users can each hold a token and hit `/me` -> 200. The current example-body placeholders won't satisfy real login; identity needs correct credentials.

**Next** — Day 5: `core/identity.py`.

## Day 5 — 2026-09-12 — Two-user identity manager

**Explored first (live against VAmPI)**
- Register `POST /users/v1/register` `{username,password,email}`; login `POST /users/v1/login` `{username,password}` -> `{auth_token: <JWT>}`; authed calls need `Authorization: Bearer <JWT>` (raw token rejected by the OpenAPI layer).
- Real footgun: a JSON POST without `Content-Type` gets 415 from VAmPI. Fixed by adding `HttpEngine.send(json_body=...)`.

**Built**
- `apiguard/core/identity.py`: `IdentityManager` (register best-effort -> login -> cached `Session` with Bearer headers), `session_for(name)`, and an `AuthFlow` config (VAmPI defaults) so the flow is not hardcoded. Engine injected (shared client).
- `apiguard/core/http_engine.py`: `send(json_body=...)`.
- `tests/test_identity.py` (6) + a `json_body` test (1).

**Verified — Day 5 done-condition met**
- Live: userA (`apiguard_a`) and userB (`apiguard_b`) each authenticate, hold distinct JWTs, and `GET /me` -> 200 returning their own username.
- `pytest -q` -> 27 passed.

**Decided** — see BRAIN.md Section 9 (AuthFlow config, best-effort register, json_body helper).

**Most likely to break next**
- D6 `scan --dry-run`: wiring parse + two-user login + touch-every-endpoint into one `rich`-progress command, and deciding where the two default users' credentials come from (a first cut of `settings.py`/config vs CLI flags). Keeping cli.py logic-free (invariant 1) while orchestrating is the design tension — the orchestration likely belongs in a small engine/runner the CLI calls.

**Next** — Day 6: `cli.py scan --dry-run` (closes Week 1).

## Day 6 — 2026-09-12 — settings + runner + scan --dry-run (WEEK 1 DONE)

**Built**
- `apiguard/settings.py`: pydantic-settings loader. `load_settings()` reads `config.yaml` or uses defaults (model/seed, scope allowlist, two disposable VAmPI users, http params, confidence weights). Zero-config so dry-run runs out of the box.
- `apiguard/runner.py` (new module, recorded in BRAIN Section 4): `dry_run()` parses the spec, logs in both users via `IdentityManager`, touches every endpoint as User A, returns a `ScanResult`. Progress via callback (rich stays in the CLI).
- `apiguard/cli.py`: `scan --spec <url> --dry-run` — thin wrapper with a rich progress bar and a summary table.
- `config.example.yaml`: users now carry passwords (match the defaults).
- Tests: settings (4), runner (3).

**Verified — Day 6 done-condition met; WEEK 1 COMPLETE**
- `apiguard scan --spec http://localhost:5000/openapi.json --dry-run` -> parsed, logged in both users, touched all 14 endpoints; summary shows 18 requests (4 auth + 14 probes), 0 findings. VAmPI reset -> 200.
- `pytest -q` -> 34 passed.

**Decided** — see BRAIN.md Section 9 (runner module, minimal settings.py, dry-run touches as User A / is not no-network).

**Week 1 retro**
- Plumbing is end to end: env -> models -> parser -> scope guard -> http engine (evidence + curl) -> two-user identity -> settings -> runner -> CLI. 34 tests, all green. No detection logic yet, by design.

**Most likely to break next**
- D7 `scanners/base.py`: getting auto-registration right (a registry that discovers `Scanner` subclasses without the CLI importing each one) and settling the `Scanner.run(endpoint) -> list[Finding]` contract so Week-2 scanners and the (future) real scan path in `runner.py` compose cleanly.

**Next** — Day 7 (Week 2): `scanners/base.py`.

## Day 7 — 2026-09-12 — Scanner ABC + registry (Week 2 begins)

**Built**
- `apiguard/scanners/base.py`: `Scanner` ABC (`async run(endpoint) -> list[Finding]`), `ScanContext` (engine/base_url/settings/sessions injected at construction), `__init_subclass__` auto-registration (gated on a non-empty `name`), `discover_scanners()` (imports every package module so a dropped file registers), `registered_scanners()`, `build_scanners()`.
- `tests/test_scanners_base.py`: 5 tests — auto-register, duplicate-name error, nameless-not-registered, build+run a dummy, discovery idempotent.

**Verified — Day 7 done-condition met**
- Live: a scanner file dropped into `apiguard/scanners/` was auto-discovered by `discover_scanners()` (registry `[]` -> `['dropped_demo']`) with no CLI/registry edit; temp file cleaned up.
- `pytest -q` -> 39 passed.

**Decided** — see BRAIN.md Section 9 (name-gated registration, ScanContext injection).

**Most likely to break next**
- D8 `scanners/injection.py`: sharing one loop for SQLi (error-signature + time-delay) and reflected XSS, mapping payloads onto real parameters (query/body), and reliably detecting VAmPI's known SQLi from response signatures. Also likely needs the real (non-dry) scan path in `runner.py` that fans endpoints across `build_scanners()` and collects findings — decide that scope at D8 start.

**Next** — Day 8: `scanners/injection.py`.

## Day 8 — 2026-09-12 — Injection scanner (SQLi + XSS)

**Explored first (live)**
- VAmPI SQLi is in `GET /users/v1/{username}` path param: a `'` -> 500 with `sqlalchemy.exc.OperationalError (sqlite3.OperationalError) unrecognized token` (and it leaks the SQL). Login body is NOT injectable.

**Built**
- `apiguard/scanners/injection.py`: `InjectionScanner` — one loop over path/query params. SQLi = error-signature match (present with payload, absent in baseline) + time-delay (secondary; won't fire on SQLite). XSS = marker reflected unescaped in an HTML content-type.
- `wordlists/sqli.txt`, `wordlists/xss.txt` (static payloads; built-in fallback).
- `tests/test_injection.py`: 6 tests (signature matcher, error-based SQLi, clean = no finding, HTML XSS, JSON echo not flagged).

**Verified — Day 8 done-condition met**
- Live: scanner over all VAmPI endpoints -> exactly 1 finding, HIGH conf 0.9, "SQL injection in path parameter 'username'" on GET /users/v1/{username}, with curl repro + the SQL error as evidence. No false positives.
- `pytest -q` -> 44 passed.

**Decided** — see BRAIN.md Section 9 (error-based primary, time-based secondary/SQLite-inert, API8 mapping).

**Most likely to break next**
- D9 `jwt_attacks.py`: needs a real JWT to tamper (from `ScanContext.sessions`); crafting `alg:none` and signature-strip variants and confirming VAmPI *accepts* one (the real weakness) means reading how VAmPI validates the token. `ssrf.py` will likely find nothing on VAmPI (no URL-fetching params) — report that honestly rather than inventing a finding.

**Next** — Day 9: `scanners/ssrf.py` + `scanners/jwt_attacks.py`.
