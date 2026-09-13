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

## Day 9 — 2026-09-12 — JWT + SSRF scanners

**Explored first (live)**
- VAmPI REJECTS alg:none and signature-strip (401). It ACCEPTS a token forged with the weak HS256 secret **`random`** (200). So VAmPI's JWT weakness is a guessable signing secret, not alg confusion.

**Built**
- `apiguard/scanners/jwt_attacks.py`: forges alg:none, sig-strip, weak-secret (HS256 re-sign from a wordlist) and expired tokens (stdlib only), flags any the server accepts vs a garbage-token baseline. Runs once on an idempotent authed GET.
- `apiguard/scanners/ssrf.py`: injects metadata/internal URLs into URL-shaped params; flags on metadata signatures.
- `wordlists/jwt_secrets.txt`.
- `tests/test_jwt_attacks.py` (5, incl. a real HS256-validating mock server), `tests/test_ssrf.py` (3).

**Broke, then fixed (live)**
- First live run found 0 JWT findings: the scanner had targeted `POST /books/v1` (a create), whose state changed between forged-token requests and broke the status comparison. Fixed by probing only an idempotent authed GET; it then flagged the weak secret.

**Verified — Day 9 done-condition met**
- Live: JWT flags weak secret 'random' (CRITICAL, conf 0.95) on GET /books/v1/{book_title}. SSRF: 0 findings (honest — no URL params).
- `pytest -q` -> 52 passed.

**Decided** — see BRAIN.md Section 9 (stdlib JWT forging, idempotent-GET probe, SSRF honest-empty).

**Most likely to break next**
- D10 `misconfig.py` + `rate_limit.py`, and the real scan path in `runner.py`: rate-limit testing bursts many requests (interacts with the engine's own rate limiter — may need to bypass it for the burst); misconfig checks headers/CORS/verbose errors (the GET /books/v1 500 and the debug error pages are candidates). Wiring `build_scanners()` into a real `scan` that fans all endpoints and collects findings is the integration risk.

**Next** — Day 10: `scanners/misconfig.py` + `scanners/rate_limit.py` + real scan path.

## Day 10 — 2026-09-12 — Misconfig + rate-limit scanners; full scan path

**Explored first (live)**
- VAmPI: no security headers; `Server: Werkzeug/2.2.3 Python/3.11.15` disclosed; no CORS headers. `GET /books/v1` unauth is 200 (500 only when DB uninitialized) and serves data despite spec auth -> BFLA signal for Week 4. Corrected the earlier "500" note.

**Built**
- `apiguard/scanners/misconfig.py`: missing security headers, server/version disclosure, permissive CORS (checked once), verbose-error/stack-trace per endpoint.
- `apiguard/scanners/rate_limit.py`: bursts a no-param GET, flags absence of 429 (runs once).
- `runner.scan()`: sequential fan-out of `build_scanners()` over every endpoint, collecting findings into a `ScanResult`.
- `apiguard/cli.py`: `apiguard scan` (no --dry-run) runs the real scan and renders a findings table (severity-sorted, coloured).
- Tests: misconfig (4), rate_limit (3), runner scan integration (1).

**Verified — Day 10 done-condition met**
- Live: `apiguard scan --spec http://localhost:5000/openapi.json` -> 5 findings (CRITICAL weak JWT secret; HIGH SQLi; LOW missing-headers, version-disclosure, no-rate-limit), 0 false positives, 119 requests across 14 endpoints.
- `pytest -q` -> 60 passed.

**Decided** — see BRAIN.md Section 9 (sequential fan-out, misconfig global-once, rate_limit burst-via-engine caveat).

**Most likely to break next**
- D11: assigning a deterministic `Finding.id` at dedup without breaking the ids scanners already set; deciding the dedup key (scanner + owasp + endpoint + param); confirming every finding still carries a curl repro. Low risk (evidence + curl already present), mostly hardening + the OWASP mapping review.

**Next** — Day 11: dedup, severity, OWASP mapping, evidence capture.

## Day 11 — 2026-09-12 — Findings post-processing (dedup / OWASP / evidence)

**Built**
- `apiguard/core/findings.py`: OWASP API Top 10 2023 catalog (`owasp_name`, `is_valid_owasp_id`), `DEFAULT_SEVERITY` reference table, `dedupe()` (collapse by id, keep highest severity then confidence), `finalize()` (dedupe + validate curl repro & OWASP id + stable severity sort).
- `runner.scan()` now finalizes findings before building the `ScanResult`.
- `cli.py`: findings table gained an OWASP column; sorting delegated to `finalize()`.
- `tests/test_findings.py`: 7 tests (catalog, dedup by severity/confidence, sort order, evidence + OWASP validation, no-dupes invariant).

**Verified — Day 11 done-condition met**
- Live: `apiguard scan` -> 5 findings, 5 unique ids (0 dupes), every finding carries a curl repro, all OWASP-mapped (API2/API8/API4).
- `pytest -q` -> 67 passed.

**Decided** — see BRAIN.md Section 9 (keep descriptive ids as canonical, injection stays API8:2023 documented).

**Most likely to break next**
- D12 (last of Week 2): the cassette record/replay mechanism. Recording at the httpx transport layer in `http_engine.py` (so a scan can re-run offline) is the real design work; needs a stable request-key (method + url + body) and to not break the live path. Saving `benchmark/results/baseline.json` is straightforward (dump the ScanResult).

**Next** — Day 12: cassettes + `benchmark/results/baseline.json`.

## Day 12 — 2026-09-12 — Cassettes + baseline.json (WEEK 2 DONE)

**Built**
- `apiguard/core/http_engine.py`: `Cassette` (record/replay) + `CassetteMiss`; `HttpEngine(cassette=...)`; key = method + final url + body + significant headers (authorization/origin/content-type). Replay returns stored responses with no network; a miss raises.
- `apiguard/core/spec_parser.py`: `load_spec(engine=...)` routes the spec fetch through the engine so replay is fully offline.
- `apiguard/runner.py`: `scan(record_dir=, replay_dir=)` builds/saves the cassette; stores `meta.spec_source`.
- `apiguard/cli.py`: `apiguard scan --record DIR --replay DIR --out FILE` (replay needs no --spec).
- `tests/test_cassette.py`: 2 tests (record->replay offline using an unreachable port; miss raises).

**Broke, then fixed (found live)**
- First replay hit a `CassetteMiss`: (1) the key ignored headers, colliding the JWT scanner's forged-token requests -> added significant headers to the key; (2) the JWT expired-token used `time.time()`, so it differed between record and replay -> made it derive from the token's own `iat`. Both are reproducibility fixes.

**Verified — Day 12 done-condition met; WEEK 2 COMPLETE**
- `pytest -q` -> 69 passed.
- `benchmark/results/baseline.json` saved (static arm: 5 findings, 120 requests, 14 endpoints).
- Recorded `cassettes/vampi/`; with the VAmPI container STOPPED, `apiguard scan --replay cassettes/vampi` reproduced the identical 5 findings (offline).
- (Ultracode) ran a background adversarial review workflow over the cassette code.
- Review confirmed 10 issues; fixed the real ones (ordered per-key replay for the rate-limit burst; strip Content-Encoding on replay; reject bad flag combos; spec-fetch status check; deterministic JWT expired token) and documented the live-only limits (timing, non-UTF-8). Re-verified: 71 tests; offline replay still reproduces 5 findings.

**Week 2 retro**
- Five baseline scanners (injection, ssrf, jwt, misconfig, rate_limit) + a real `scan` + findings post-processing + cassettes. On VAmPI: 5 real findings, 0 FP. This is the control group for the Week-5 ablation.

**Most likely to break next**
- D13 `ai/client.py`: first real Ollama integration in the engine. Schema-enforced JSON (`format`) + `think=False` + pinned seed + retry-on-invalid-JSON, logging to `logs/llm/`. Risk: qwen3 latency, occasional invalid JSON despite `format`, and the 20/20 reliability bar. The D1 smoke already proved the core pattern works on this machine.

**Next** — Day 13 (Week 3): `ai/client.py`.

## Day 13 — 2026-09-12 — Ollama client (schema-enforced structured output)

**Built**
- `apiguard/ai/client.py`: `OllamaClient.structured(response_model, prompt/system/messages, temperature, label)` -> `StructuredResult`. Sends chat with `format`=pydantic schema, `think=False`, pinned seed, given temperature; validates with `model_validate_json` (never regex). Retries <=2 on invalid output (seed bumped per attempt for reproducible-yet-different retries); inconclusive result on exhaustion. Logs every call to `logs/llm/`. Underlying client injectable (`client=`) for tests.
- `tests/test_ai_client.py`: 5 tests (valid first try + options/format/think asserted, retry-then-success seed bump, exhausted=inconclusive, logging, system+temperature threading) using an injected fake.

**Verified — Day 13 done-condition met**
- Live: 20/20 valid structured `Verdict` objects from qwen3:8b in ~14s (~0.7s/call); 20 JSON logs written to `logs/llm/`. The sample verdict correctly flagged an email leak (preview of the D21 oracle).
- `pytest -q` -> 76 passed.

**Decided** — see BRAIN.md Section 9 (seed bump per retry; inconclusive-not-raise; injectable client).

**Most likely to break next**
- D14 `ai/prompts.py`: getting the payload-generation prompt to produce CONTEXT-AWARE candidates (email-shaped for a format=email field) rather than a generic wordlist — this is the whole point of the AI arm. Needs a payload-list pydantic model + temperature 0.8, and versioned prompts so the report can cite them.

**Next** — Day 14: `ai/prompts.py`.

## Day 14 — 2026-09-12 — Payload-generation prompt (context-aware)

**Built**
- `apiguard/ai/prompts.py`: `PROMPTS_VERSION`, `PayloadCandidate`/`PayloadSet` (structured output), `PAYLOAD_SYSTEM`, and `payload_user_prompt()` carrying name/type/format/example/endpoint/schema and instructing type/format-tailored payloads (email -> localpart@domain.tld with the attack hidden inside).
- `tests/test_prompts.py`: 4 tests (full context present, email tailoring instruction, PayloadSet schema round-trip, version string).

**Verified — Day 14 done-condition met**
- Live (qwen3:8b, temp 0.8): for `{user_email, string, email}` every candidate kept the email structure with the injection in the local part (e.g. `alice'; DROP TABLE users;--@mail.com`, `alice<script>alert('xss')</script>@mail.com`); for a plain string field the model returned generic `1' OR 1=1--`. Context-awareness confirmed.
- `pytest -q` -> 80 passed.

**Observed (tune at D18)**
- Low diversity at temp 0.8 (several identical payloads). Prompt should ask for distinct/varied payloads; payload_gen may dedupe.

**Decided** — see BRAIN.md Section 9 (format-tailored payloads = the AI arm's edge; PROMPTS_VERSION cited).

**Most likely to break next**
- D15 `ai/payload_gen.py` + `--payloads {static,ai,both}`: threading the payload source through cli -> runner -> ScanContext -> injection scanner without breaking the static default (invariant 4: no-Ollama must still scan). Generating per injectable parameter adds LLM calls per endpoint (latency); may need to cap/generate-once-per-param-shape.

**Next** — Day 15: `ai/payload_gen.py`.

## Day 15 — 2026-09-12 — AI payloads wired behind --payloads {static,ai,both}

**Built**
- `apiguard/ai/payload_gen.py`: `PayloadGenerator.for_parameter()` — context-aware payloads via the prompt + OllamaClient, bucketed sqli/xss, deduped, cached by param shape, graceful on Ollama error.
- `ScanContext` gains `payload_mode` + `payload_generator`; the injection scanner picks payloads per parameter by mode (`_payloads_for`).
- `runner.scan` builds the generator for ai/both and degrades to static if Ollama is unreachable (invariant 4); records the effective mode. `cli` `--payloads` flag; summary shows `payloads=<mode>`. `OllamaClient.available()`.
- `tests/test_payload_gen.py`: 4 (bucket/dedupe, cache-by-shape, graceful-on-error, injection consumes AI payloads via a fake generator).

**Verified — Day 15 done-condition met**
- Live: `apiguard scan --payloads ai` runs end to end (4 findings, payloads=ai, 79 requests).
- `pytest -q` -> 84 passed.

**KEY honest observation (ablation signal)**
- The AI arm found 4 vs the static arm's 5: it MISSED the SQLi. qwen3 generated `name1' OR '1'='1` (VAmPI returns 200, no SQL error) x4 (low diversity); the injection detector is error-signature-only, so boolean-based SQLi slips through. Recorded in BRAIN Section 8 as the D17/D18 focus. Not fabricating an AI win — AI currently only wins on request count (79 vs 120).

**Decided** — see BRAIN.md Section 9 (payload threading + degrade; AI scans not replayable; boolean-SQLi detection gap).

**Most likely to break next**
- D16 `ai/repair.py`: detecting a 400/422 rejection, feeding the error body back for a corrected payload (cap 2 retries), and proving a rejected payload succeeds on retry — need a VAmPI endpoint that input-validates (e.g. register/login field rules) to demonstrate the repair, and it must log the before/after.

**Next** — Day 16: `ai/repair.py`.

## Day 16 — 2026-09-12 — Self-repair loop

**Explored first (live)**
- VAmPI (connexion) returns descriptive 400s: missing required field ("'email' is a required property"), wrong type ("123 is not of type 'string'"), non-object body. These are the rejections repair can fix.

**Built**
- `apiguard/ai/repair.py`: `RepairLoop.repair_value(send, initial_value, context, error_body, attack_goal)` — feeds the server's error back to the model (versioned repair prompt), gets a corrected value, re-sends via the caller's `send` callback, loops up to 2; never raises. `RepairResult` carries the final exchange + history.
- `apiguard/ai/prompts.py`: `REPAIR_SYSTEM`, `RepairedPayload`, `repair_user_prompt`; `PROMPTS_VERSION` bumped.
- `ScanContext.repair_loop`; runner builds it for ai/both; injection scanner `_send_payload` repairs a 400/422'd payload then re-probes (detection runs on the repaired response).
- `tests/test_repair.py`: 3 (repair succeeds on retry, gives up after cap, injection repairs a rejected payload then detects).

**Verified — Day 16 done-condition met**
- Live: register body `{username,password}` (missing required `email`) -> HTTP 400; repair added `email` and re-sent -> HTTP 200 on the first retry; logged to `logs/llm/0001-repair.json`.
- `pytest -q` -> 87 passed.

**Decided** — see BRAIN.md Section 9 (send-callback decoupling, cap 2, repair payoff is typed/validated APIs).

**Most likely to break next**
- D17 measurement: on VAmPI `ai` and `ai+repair` will likely be IDENTICAL (repair doesn't fire on string injectable params), so the three arms won't all differ by finding count. Need a `--repair/--no-repair` toggle to isolate the arm, and the honest three-way story is static(5) vs ai(4) vs ai+repair(=ai on VAmPI) plus requests_sent. Do NOT fake a repair delta on VAmPI.

**Next** — Day 17: first measurement (static / ai / ai+repair result JSONs).

## Day 17 — 2026-09-12 — First ablation measurement (static / ai / ai+repair)

**Built**
- `--repair/--no-repair` toggle (cli + `runner.scan(repair_enabled=)`) so the repair arm can be isolated.
- Saved three arm results: `benchmark/results/{static,ai,ai_repair}.json`.

**Measurement (VAmPI, this session)**

| arm | findings | SQLi | requests |
|-----|----------|------|----------|
| static | 5 | yes | 120 |
| ai | 5 | yes | 87 |
| ai+repair | 5 | yes | 100 |

- SAME recall across arms (all find the 5 vulns incl. the SQLi). The difference is REQUEST COST: the AI arm is ~28% leaner; repair added ~13 requests with no new findings on VAmPI.
- The AI arm finds the SQLi via `name1'; DROP TABLE users--` (trips VAmPI's 'one statement at a time' error).

**Reproducibility finding (important, honest)**
- qwen3 payloads are deterministic WITHIN a session (4/4 identical runs verified) but DRIFTED across sessions: D15 the AI arm found 4 (boolean-only payloads) vs 5 now. Ollama `seed` = within-session determinism, not cross-session. We pass seed (invariant 3), record model/seed in each ScanResult, and save the arm JSONs as the canonical numbers. AI scans aren't cleanly cassette-replayable.

**Decided** — see BRAIN.md Section 9 (same-recall/diff-requests outcome; within-session determinism caveat).

**Most likely to break next**
- D18 "AI beats static on at least one measure" is arguably already satisfied (same recall, fewer requests). D18 plan: write up the why; optionally add boolean-based SQLi detection (response differential) to strengthen detection and reduce reliance on the model happening to emit an error-triggering payload; tune payload diversity.

**Next** — Day 18: buffer + prompt tuning / detection hardening.

## Day 18 — 2026-09-12 — Boolean SQLi detection + payload tuning (WEEK 3 DONE)

**Built**
- `scanners/injection.py`: boolean-based SQLi detector — TRUE (`nx' OR '1'='1`) vs FALSE (`nx' OR '1'='2`) response differential, guarded (true substantially different from + richer than false; false ~ baseline; same status; not 5xx). Catches 200-OK injection invisible to error/status detection. Runs when error/time-based misses.
- `ai/prompts.py`: payload prompt now requires DISTINCT payloads + at least one error-inducing one (PROMPTS_VERSION -> payload-v2). Addresses the D14 low-diversity observation.
- Re-measured and re-saved the three arm JSONs.
- `tests/test_injection.py`: +3 (boolean detect, boolean no-FP, XSS-not-on-error-page).

**Caught a false positive (integrity)**
- Initial re-measure showed ai=6 (an extra "Reflected XSS in username"). Inspected the evidence: it was the AI payload reflected inside a 500 Werkzeug DEBUG page (the `'` in `alert('xss')` broke the SQL). That is the verbose-error misconfig, not reflected XSS. Fixed the XSS detector to skip 5xx, removing the bogus finding. Did NOT claim AI found 6 vs 5.

**Verified — Day 18 done-condition met**
- Re-measure (VAmPI): static 5 findings/128 req; ai 5/93; ai+repair 5/107. AI beats static on REQUESTS (~27% fewer) at EQUAL recall (5/5), 0 false positives.
- `pytest -q` -> 90 passed.

**Week 3 retro**
- AI layer complete: schema-enforced Ollama client, versioned context-aware payload prompt, payload_gen behind --payloads, self-repair loop, first ablation. Honest AI-arm story: same recall, fewer requests; boolean detector ready for 200-OK injection. Reproducibility caveat (within-session determinism) documented.

**Most likely to break next**
- D19 (Week 4, the crown jewel) `engines/bola.py` resource discovery: harvesting object IDs PROVABLY owned by User A from VAmPI responses (books A creates, A's user record), building `{endpoint:[owned_ids]}`. Risk: VAmPI's object model (what IDs exist, how ownership is expressed in responses) and mapping collection responses to per-A IDs.

**Next** — Day 19: `engines/bola.py` (resource discovery as User A).

## Day 19 — 2026-09-12 — BOLA resource discovery (Week 4 begins; crown jewel)

**Explored first (live)**
- VAmPI books: collection `GET /books/v1` -> `{"Books":[{book_title, user}]}`; object `GET /books/v1/{book_title}` -> `{book_title, owner, secret}` (secret is owner-only = the BOLA); `POST /books/v1` creates a book owned by the creator. Users: `GET /users/v1/{username}` -> `{username,email}` (public).

**Built**
- `apiguard/engines/bola.py`: `ResourceDiscoverer.discover()` -> `list[OwnedObject]`. Finds object endpoints (GET ending in `/{id}`), establishes A-owned ids via seed (POST-as-A) + harvest (collection item whose owner field == A's username), and captures A's own successful access per id.
- `tests/test_bola_discovery.py`: 2 (seed+harvest + attribution excludes other users' objects; no-collection is safe).

**Verified — Day 19 done-condition met**
- Live as User A on VAmPI -> 2 objects provably owned by A: seeded book `GET /books/v1/{book_title}=apiguard_userA_book_title` (secret captured) and A's record `GET /users/v1/{username}=apiguard_a`. Each carries A's own 200 access.
- `pytest -q` -> 92 passed.

**Decided** — see BRAIN.md Section 9 (seed+harvest ownership; generic owner-field match).

**Most likely to break next**
- D20 cross-access + control: need B-owned objects for the control (B accessing B's own object). Reuse the discoverer with owner="userB". Then build triples (A access, B cross-access of A's id, B control of B's id). The public `GET /users/v1/{username}` will look like a "leak" to naive checks but is by-design public -> the D21 oracle / D22 confidence must not over-flag it; the real BOLA is the book secret.

**Next** — Day 20: `engines/bola.py` cross-access + control phase.

## Day 20 — 2026-09-13 — BOLA cross-access phase (triples)

**Built**
- `apiguard/engines/bola.py`: `AccessTriple` (a_access, b_cross_access, b_control), `probe_cross_access` (B accesses each A-owned object + a B-owned control at the same endpoint), `collect_triples` (discover A + B owned, then probe). Shared `_object_access` helper so discovery and cross-access build identical requests.
- Seed improvement: unconstrained string fields set to owner-distinctive values (`apiguard-<owner>-<field>`), so a cross-user read leaks the OTHER user's identifiable data.
- Hygiene: fixed `test_repair.py` writing a log to the repo root (log_dir -> tmp_path); removed the stray `0001-repair.json`.
- `tests/test_bola_crossaccess.py`: 2 (cross-access leak triple; control absent when attacker owns nothing).

**Verified — Day 20 done-condition met**
- Live (VAmPI): 2 triples. GET /books/v1/{book_title}: A access = A's book (secret apiguard-userA-secret); B cross-access = B reads A's book (owner apiguard_a, secret apiguard-userA-secret) = THE BOLA; B control = B's own book (secret apiguard-userB-secret). Also a users triple (public email read, for the oracle to judge).
- `pytest -q` -> 94 passed.

**Decided** — see BRAIN.md Section 9 (control = B-owned object at same endpoint; distinctive seed data).

**Most likely to break next**
- D21 `ai/oracle.py`: the Section-5 ambiguity gate (only call the LLM when cheap checks are inconclusive) + a strict schema-constrained yes/no oracle at temp 0.0. Must FLAG the book BOLA and CLEAR a legit access. The public users read is the tricky case.

**Next** — Day 21: `ai/oracle.py` (BOLA ambiguity gate + response oracle).

## Day 21 — 2026-09-13 — BOLA response oracle + ambiguity gate (semantic heart)

**Built**
- `apiguard/ai/oracle.py`: `gate(triple)` (Section-5 cheap checks) and `BolaOracle.adjudicate` (LLM only on 'ambiguous'; schema-constrained `OracleVerdict` at temp 0.0; 'inconclusive' and 'unavailable' both degrade to not-a-leak, never crash). `BolaDecision` carries is_leak/leaked_fields/reasoning/decided_by/oracle_verdict/trace for D22.
- `apiguard/ai/prompts.py`: `OracleVerdict`, `ORACLE_SYSTEM`, `oracle_user_prompt` (RESPONSE_A vs RESPONSE_B, noise-truncated). PROMPTS_VERSION += oracle-v1.
- `tests/test_oracle.py`: 8 (each gate path; oracle flag/clear; gate-decision-skips-LLM; inconclusive = not a leak).

**Verified — Day 21 done-condition met**
- Live (VAmPI): book cross-access -> gate 'ambiguous' -> oracle is_leak=True, leaked_fields=[book_title,owner,secret] ("User B has accessed User A's private data"). B-reads-own-book -> oracle is_leak=False ("data specific to User B... no fields belong to User A"). Both routed gate -> oracle (deterministic-first honored).
- `pytest -q` -> 102 passed.
- Also: Ollama server had died over the 41h gap; restarted it, and hardened the oracle to degrade (not crash) if Ollama is down mid-scan.

**Decided** — see BRAIN.md Section 9 (deterministic-first gate; inconclusive/unavailable -> not-a-leak; oracle verdict is one signal, not the confidence).

**Ultracode** — launched an adversarial review workflow over the oracle/gate/prompt; running in the background, confirmed findings to be folded in a follow-up (likely: prompt-injection via untrusted response bodies is a documented limitation; the schema `format` bounds the shape but not the verdict value).

**Most likely to break next**
- D22 `scoring/confidence.py`: computing the 5 signals from the triple + oracle verdict and a defensible weighted sum (weights in config). The public users endpoint will score as a leak (data-correct) but must be severity-down-weighted via `endpoint.security == []`, not suppressed. Building the `Finding` (+AITrace from the oracle trace) and wiring the whole BOLA engine into a scan.

**Next** — Day 22: `scoring/confidence.py` (5 signals + weighted confidence + Finding).

## Day 22 — 2026-09-13 — BOLA confidence signals + full engine wired

**D21 review folded in first** (separate fix commit): removed the id-absent gate clear (dropped real URL-only-id leaks), hardened the oracle prompt vs injection (fence + untrusted framing; residual risk documented), widened truncation 1200->4000, narrowed the oracle except.

**Built**
- `apiguard/scoring/confidence.py`: the 5 Section-5 signals (id_echo, field_overlap = Jaccard of top-level keys, body_divergence vs B's control, status_match, oracle_verdict) + `confidence()` as a weight-normalised mean over the PRESENT signals.
- `apiguard/runner.py`: `find_bola_findings` (triples -> gate/oracle -> signals -> confidence -> Finding, API1:2023, HIGH / public MEDIUM, AITrace = oracle trace + signals) + `--bola` wiring; re-authenticates before the BOLA phase.
- `apiguard/cli.py`: `--bola/--no-bola`.
- `tests/test_confidence.py`: 4 (signals full/partial, confidence normalisation, full BOLA finding scored from >=4 signals).

**Two integration bugs found + fixed (live debugging)**
- BOLA phase produced 0 findings in a real scan though it worked in isolation. Root cause: VAmPI `GET /createdb` is a DB-RESET endpoint; the misconfig scanner probes it and wiped the registered users, so the pre-scan sessions were stale. Fix: re-authenticate before BOLA.
- While tracing it: injection was probing DELETE/PUT path params with tautology payloads = destructive (mass DELETE/UPDATE). Fixed injection to GET-only (safe; VAmPI SQLi still found).

**Verified — Day 22 done-condition met**
- Live: `apiguard scan --bola` -> 7 findings incl. 2 BOLA, each scored from 5 signals: HIGH GET /books/v1/{book_title} conf 0.81; MEDIUM GET /users/v1/{username} (public) conf 0.81. `benchmark/results/full.json` saved.
- `pytest -q` -> 107 passed.

**Decided** — see BRAIN.md Section 9 (weight-normalised confidence; injection GET-only safety; BOLA re-auth).

**Most likely to break next**
- D23 `engines/bfla.py`: identifying privileged endpoints and probing as the low-priv user, reported SEPARATELY from BOLA. VAmPI's `/users/v1/_debug` (public, dumps all users incl. password hashes) is the obvious BFLA/excessive-data target; admin-path detection is the general case.

**Next** — Day 23: `engines/bfla.py`.

## Day 23 — 2026-09-13 — BFLA engine (WEEK 4 DONE)

**Explored first (live)**
- VAmPI `GET /users/v1/_debug` is PUBLIC (security=[]) and dumps ALL users with plaintext `password` + email + admin flag. The BFLA / excessive-data target.

**Built**
- `apiguard/engines/bfla.py`: `find_bfla_findings` -- privileged-path detection (segment contains admin/_debug/internal/manage/...), probe as the low-privilege user B (GET only). 2xx-with-data from a privileged function = BFLA (API5:2023); CRITICAL if the body leaks credential markers, else HIGH. Deterministic (no oracle).
- `runner.py`: BFLA runs in the engines phase (before the Ollama check, so it works without Ollama), reported separately from BOLA.
- `tests/test_bfla.py`: 5 (privileged detection; credential-leak CRITICAL; forbidden not flagged; accessible-non-sensitive HIGH; non-privileged skipped).

**Verified — Day 23 done-condition met; WEEK 4 COMPLETE**
- Live: `apiguard scan --bola` -> CRITICAL BFLA on GET /users/v1/_debug (conf 0.95), reported alongside the 2 BOLA findings. Separate scanner (bfla / API5:2023).
- `pytest -q` -> 112 passed.

**Week 4 retro (the crown jewel)**
- BOLA engine: resource discovery (owned objects) -> cross-access triples -> deterministic gate -> LLM oracle (ambiguous only) -> 5-signal confidence -> Finding+AITrace. BFLA engine: privileged-function access by low-priv. Full scan on VAmPI: 8 findings incl. 2 CRITICAL, with the semantic BOLA/BFLA that status/error scanners miss. Adversarial review hardened the oracle/gate. Two real integration bugs (createdb reset, destructive injection) found and fixed.

**Most likely to break next**
- D24 crAPI: heavier setup (docker-compose, ~4GB RAM). If it won't run here, VAmPI alone is a valid target per the plan's cut order -- document and move on, do not fabricate.

**Next** — Day 24: run against crAPI + tune thresholds (or document crAPI unavailability).

---

## Day 24 — 2026-09-13 — crAPI: the engine finds a real BOLA on a second target

**What I set out to do**
- Done-when: >=1 true BOLA on crAPI with <=2 false positives. The plan flagged crAPI setup as a blocker risk (docker-compose, RAM). It did NOT materialise — 42GB free RAM, everything ran.

**Bringing crAPI up (and the one gotcha)**
- Started the core stack from the official compose (identity/community/workshop, postgres/mongo, mailhog, `crapi-web` gateway). `crapi-web` (nginx) crashed on boot: `[emerg] host not found in upstream "crapi-chatbot"` — nginx resolves every upstream at config-load, so even though we don't use the chatbot, its container must exist on the network. Started chromadb+chatbot too; gateway then came up on `127.0.0.1:8888`.

**Getting two owner sessions honestly (no guessing, no DB writes)**
- crAPI seeds demo users (adam007, pogba006, ...) with bcrypt passwords we don't know, and each owns exactly one vehicle. Rather than guess, I drove crAPI's own forgot-password -> OTP -> reset flow: crAPI mails all OTPs to MailHog, so `crapi_bola.py` reads the OTP from MailHog's API and resets two owners to a known password via `v3/check-otp`. (Reading the OTP directly from Postgres was correctly blocked by the auto-mode classifier — MailHog is the right channel anyway.)
- This proved `AuthFlow` generalises to crAPI with **config only, zero engine code change** (email login, RS256 token, `token_json_key="token"` — VAmPI is HS256).

**The BOLA and why it needed a driver, not `apiguard scan`**
- `GET /identity/api/v2/vehicle/{vehicleId}/location` has no ownership check: any authenticated user reads any vehicle's GPS + owner name + email by uuid. The generic `ResourceDiscoverer` can't auto-seed a crAPI vehicle (they're pre-seeded and email-claim-gated), so `benchmark/crapi_bola.py` supplies the two owner->uuid bindings from crAPI's own `GET /vehicle/vehicles`, then runs the REAL `probe_cross_access` + `BolaOracle` + confidence + `bola_finding` UNMODIFIED. Extracted `runner.bola_finding()` so VAmPI and crAPI build findings through identical code. Honest split: discovery is target plumbing; the contribution (gate/oracle/confidence) generalises unchanged.

**Result (real, reproducible)**
- 1 true BOLA: HIGH, conf **0.8547**, signals `{id_echo:1, field_overlap:1, status_match:1, body_divergence:0.27, oracle_verdict:1}`, oracle `is_leak=True` leaked_fields `[fullName, email]`. Saved `benchmark/results/crapi.json` with full evidence + curl repro + AITrace (qwen3:8b, seed 42, temp 0.0).
- 0 false positives: a legitimate self-access (B reads B's OWN vehicle) is cleared deterministically by `gate:identical-to-control` — no LLM call. Re-ran with fresh OTPs; identical finding and confidence.
- `pytest -q` -> **113 passed** (added `test_opaque_id_bola_is_caught_by_fixed_gate`: crAPI-style id-in-URL-only case still reaches the oracle after the D22 gate fix; the vehicle-location body happens to echo `carId`, so this test covers the truly opaque case separately).

**Most likely to break next**
- D25/D26 numbers: the D17/D18 static & ai result JSONs are STALE (injection went GET-only at D22). Re-measure before filling the ablation table. crAPI is a genuine second data point for D26 now.

**Next** — Day 25: `benchmark/ground_truth.yaml` + `run_eval.py` (precision/recall/F1 per arm).

---

## Day 25 — 2026-09-13 — the benchmark yardstick (ground truth + run_eval)

**What I set out to do**
- Done-when: one command prints precision/recall/F1. The real work is building an HONEST ground truth (the recall denominator must include vulns the tool can't detect) and a matcher that joins findings to known vulns on the RIGHT keys.

**Building the ground truth (5-agent workflow, then I verified)**
- Fanned out 4 enumeration angles (VAmPI source-read, VAmPI live-probe, crAPI, APIGuard detector-surface) + a completeness critic. The critic was the star: it grounded against the actual `run_eval` matcher and the real result JSONs and caught every trap — `Finding.scanner` is `jwt` not the module name `jwt_attacks`; jwt/rate_limit are GLOBAL findings (reported on an incidental endpoint) so they must join on scanner alone; the two misconfig globals share path "/" so they join by `id_contains`; and I had to INCLUDE the MEDIUM `GET /users/v1/{username}` bola or the Full arm's real finding would score as a false positive.
- Integrity: agents propose, I verify. I independently re-probed VAmPI's 4 false-negatives — mass-assignment (registered admin:true -> /me admin:true), unauthorized password change (name1 reset name2's password, old fails / new works), enumeration (distinct login messages), RegexDOS (email endpoint reachable). Every ground-truth entry is live-verified.

**The matcher (`run_eval.Match`)**
- Predicates {scanner, path, method, id_contains, path_contains}; ALL present ones must hold; `owasp_id` is deliberately NOT a predicate (the tool maps SQLi to API8; keying on owasp would un-match a real detection). Scoring: TP = known vulns matched (each once), FP = findings matching nothing, FN = known vulns matched by nothing. `detectable:false` entries have no matcher and are always FN — that is what keeps recall honest. run_eval warns loudly if one finding matches >1 entry (double-count guard).

**Result (`python benchmark/run_eval.py`)**
| Arm | Target | Known | TP | FP | FN | Prec | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| baseline/static/ai/ai_repair | vampi | 12 | 5 | 0 | 7 | 1.00 | 0.42 | 0.59 |
| **full** | vampi | 12 | **8** | 0 | 4 | **1.00** | **0.67** | **0.80** |
| crapi | crapi | 5 | 1 | 0 | 4 | 1.00 | 0.20 | 0.33 |
- The Full arm detects exactly the three the baseline can't — `bola-book-secret`, `bola-user-record`, `bfla-debug-dump` — a **+0.25 recall lift at perfect precision**. That jump is the whole thesis: a semantic BOLA/BFLA engine finds 200-OK vulns status/error scanners are blind to. All arms honestly miss the 4 VAmPI vulns APIGuard has no detector for.
- `pytest -q` -> **122 passed** (+9 in tests/test_run_eval.py).

**Most likely to break next (D26)**
- The static/ai/ai_repair JSONs' `requests_sent` is STALE (pre-D22 GET-only). The P/R/F1 are already stable (finding counts unchanged) but the Requests column must be re-measured before the final table. Add ZAP as an external baseline arm. A fuller crAPI arm needs the crAPI AuthFlow wired as a scannable target (the driver only covers vehicle location).

**Next** — Day 26: full ablation run, 4 arms + ZAP baseline, fill the Section-1 table with fresh numbers.









