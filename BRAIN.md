# BRAIN.md — APIGuard Project Memory

> This file is the single source of truth for the APIGuard project.
> It is loaded at the start of every Claude Code session.
> Read Section 0 before doing anything else.

---

## 0. Session protocol — follow this every single session

**At session start:**
1. Read this entire file.
2. Read Section 8 (Current State) to find which day we are on and what is unfinished.
3. State back to me, in two lines: "We are on Day N. Last session finished X. Today's task is Y."
4. Do not start writing code until I confirm.

**During the session:**
- Work only on the current day's tasks from Section 7. Do not jump ahead.
- If a task from an earlier day is broken or incomplete, fix that first and say so.
- If you want to deviate from this plan, stop and ask me first. Explain the tradeoff.

**At session end (or when I say "wrap up"):**
1. Update Section 8 with what was completed, what is in progress, and what broke.
2. Append any architectural decision you made to Section 9.
3. Tick the checkboxes in Section 7 for anything genuinely finished.
4. Do not mark a day complete unless its "Done when" condition is actually met and verified by running something.

---

## 1. What this project is

**APIGuard** — an AI-powered API vulnerability scanner.

**One-liner:** Parse an OpenAPI spec, attack every endpoint, and use a locally-hosted LLM to (a) generate context-aware payloads and (b) adjudicate whether a cross-user access actually leaked data — detecting BOLA/IDOR flaws that return a normal 200 OK and are therefore invisible to status-code-based scanners.

**Context:** 3rd-semester academic mini project. 5 weeks, 30 working days. Author: Mayurdhvajsinh.

**What success looks like at the end:** not a demo, a *result*. A table like this:

| Arm | Recall vs ground truth | False positives | Requests sent |
|---|---|---|---|
| Static wordlist payloads | ? / 11 | ? | ? |
| AI-generated payloads | ? / 11 | ? | ? |
| AI + self-repair | ? / 11 | ? | ? |
| Full (incl. BOLA engine) | ? / 11 | ? | ? |
| OWASP ZAP (external baseline) | ? / 11 | ? | ? |

If we reach week 5 with a working tool but no filled-in table, the project has failed at its main goal.

**The three things that ARE the project** (never cut these): the BOLA engine, the AI response oracle, the benchmark harness. Everything else is supporting cast.

---

## 2. Hard invariants — never violate these

1. **The engine is a library, not a script.** All logic lives in the `apiguard` package. `cli.py`, `dashboard.py`, and `benchmark/` are thin consumers that import it. No business logic in any entry point.

2. **Never parse LLM free text.** Every LLM call uses Ollama's `format` parameter with a Pydantic-generated JSON schema, and the response is validated with `Model.model_validate_json()`. On validation failure, retry up to 2 times, then give up and record it as an inconclusive result. Never regex an LLM response.

3. **Pin the seed.** Every LLM call passes `seed` from config. Results must be reproducible; an examiner may ask us to re-run.

4. **Deterministic first, LLM second.** The model is only called on genuinely ambiguous cases. See Section 5 for the exact gate. A scan with Ollama switched off must still run and still find things.

5. **Confidence is computed, never asked for.** We never ask the model "how confident are you." Confidence is a weighted function of measurable signals plus the oracle's binary verdict. See Section 5.

6. **Every finding carries evidence.** Full request, full response, and a copy-pasteable `curl` reproduction string. No finding without evidence.

7. **Scope guard is mandatory.** No request leaves the tool unless the target host is in the config allowlist. Non-localhost targets require an explicit `--confirm-authorized` flag. This is not optional and is not to be stubbed out "for now."

8. **Async everywhere on the HTTP path.** `httpx.AsyncClient`, one shared client, global concurrency limit and rate limit from config.

9. **Type hints on every function.** Pydantic models for all structured data. No bare dicts crossing module boundaries.

---

## 3. Stack — fixed, do not substitute

| Purpose | Library |
|---|---|
| Language | Python 3.11+ |
| HTTP | `httpx` (async) |
| Spec parsing | `openapi-spec-validator` + `PyYAML` |
| Data models | `pydantic` v2 |
| Config | `pydantic-settings` + YAML |
| LLM runtime | Ollama (local) |
| LLM client | `ollama` python package |
| CLI | `typer` + `rich` |
| Dashboard | `streamlit` |
| Report | `jinja2` |
| Tests | `pytest` + `respx` |

**Model:** default `qwen3:8b`. Configurable via `settings.model`. Fallbacks: `qwen2.5-coder:7b` (6GB VRAM), `llama3.1:8b`, `phi4-mini` (CPU only).

**One model, two roles:**
- Payload generation: temperature 0.8
- Response oracle: temperature 0.0

Never load two models.

**Test targets:**
- VAmPI (primary): `docker run -d -p 5000:5000 erev0s/vampi` → spec at `http://localhost:5000/openapi.json`
- crAPI (secondary, week 4 onward): docker compose, needs ~4GB RAM

---

## 4. Architecture and file ownership

```
apiguard/
├── apiguard/
│   ├── cli.py                  Typer entry point. NO logic.
│   ├── runner.py               scan orchestration (parse + identity + touch). CLI calls this.
│   ├── settings.py             pydantic-settings config loader
│   ├── core/
│   │   ├── models.py           Finding, Endpoint, Parameter, ScanResult
│   │   ├── findings.py         dedup + OWASP catalog/mapping + evidence validation
│   │   ├── spec_parser.py      OpenAPI -> list[Endpoint]
│   │   ├── http_engine.py      async httpx wrapper, rate limit, retries, cassettes
│   │   ├── identity.py         two-user session manager
│   │   └── scope.py            target allowlist guard
│   ├── scanners/
│   │   ├── base.py             Scanner ABC + registry
│   │   ├── injection.py        SQLi + XSS, one shared loop
│   │   ├── ssrf.py
│   │   ├── jwt_attacks.py
│   │   ├── misconfig.py        headers, CORS, verbose errors
│   │   └── rate_limit.py
│   ├── ai/
│   │   ├── client.py           Ollama wrapper, schema enforcement, retry, logging
│   │   ├── prompts.py          all prompts, versioned, in one place
│   │   ├── payload_gen.py
│   │   ├── repair.py           self-repair loop
│   │   └── oracle.py           response adjudication
│   ├── engines/
│   │   ├── bola.py             THE CROWN JEWEL
│   │   └── bfla.py
│   ├── scoring/
│   │   └── confidence.py       signal-based scoring
│   └── report/
│       ├── generator.py
│       └── template.html
├── benchmark/
│   ├── ground_truth.yaml       known bugs in VAmPI + crAPI
│   ├── run_eval.py             precision / recall / F1 per arm
│   └── results/
├── cassettes/                  recorded HTTP for offline demo + fast tests
├── dashboard.py                Streamlit
├── docs/journal.md             one entry per working day
└── tests/
```

**Rule:** if you need a new module, add it here in BRAIN.md first, then create it.

---

## 5. Core contracts

### Data model (core/models.py)

```python
class Severity(StrEnum):
    INFO = "info"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class Parameter(BaseModel):
    name: str
    location: Literal["path", "query", "header", "cookie", "body"]
    type_: str
    format_: str | None
    required: bool
    example: Any | None

class Endpoint(BaseModel):
    path: str
    method: str
    parameters: list[Parameter]
    request_body_schema: dict | None
    security: list[str]
    operation_id: str | None

class Evidence(BaseModel):
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    request_body: str | None
    response_status: int
    response_headers: dict[str, str]
    response_body: str
    curl_repro: str

class AITrace(BaseModel):
    model: str
    seed: int
    temperature: float
    prompt: str
    raw_response: str
    signals: dict[str, float]

class Finding(BaseModel):
    id: str
    title: str
    scanner: str
    endpoint: Endpoint
    severity: Severity
    owasp_id: str          # e.g. "API1:2023"
    confidence: float      # 0.0 - 1.0, COMPUTED not asked for
    description: str
    remediation: str
    evidence: Evidence
    ai_trace: AITrace | None
```

### The BOLA ambiguity gate (engines/bola.py)

Only call the oracle when the cheap checks are inconclusive:

```
if b_response.status in (401, 403, 404):        -> NOT a leak, no LLM call
if b_response.body == b_control.body:            -> NOT a leak, no LLM call
if a_object_id not in b_response.body:           -> probably not, no LLM call
else:                                            -> AMBIGUOUS, call oracle
```

### Confidence signals (scoring/confidence.py)

Compute from these, never from the model's self-report:

| Signal | Meaning |
|---|---|
| `id_echo` | 1.0 if A's object ID appears in B's cross-access response |
| `field_overlap` | Jaccard similarity of top-level keys, A's response vs B's cross-access |
| `body_divergence` | 1 - similarity(B's cross-access, B's control) |
| `status_match` | 1.0 if B's cross-access returned the same status as A's own access |
| `oracle_verdict` | 1.0 / 0.0 from the LLM |

Weighted sum, weights in config so they are tunable and defensible.

---

## 6. Coding conventions

- `async def` on anything touching the network. One shared `AsyncClient`.
- Every scanner subclasses `Scanner` and implements `async def run(self, endpoint: Endpoint) -> list[Finding]`.
- Scanners self-register via the registry in `scanners/base.py`. Adding a scanner must not require editing the CLI.
- Output to the user goes through `rich`. Never bare `print()`.
- Log every LLM prompt and response to `logs/llm/` as JSON. This feeds the explainability trace and the report.
- Tests use `respx` to mock httpx. Tests must not need a live VAmPI.
- Small commits, conventional messages (`feat:`, `fix:`, `test:`, `docs:`).
- Write the test in the same session as the code. Do not defer testing to "later."

---

## 7. The 30-day roadmap

Six working days per week. Each day has a Done-when condition. Do not tick a box without verifying.

### Week 1 — Foundation
- [x] **D1** Repo, venv, deps, VAmPI in Docker, Ollama + model pulled. *Done when: `ollama run <model> "hi"` works and VAmPI's spec loads.* — **DONE 2026-09-12, verified.**
- [x] **D2** `core/models.py`. *Done when: a `Finding` can be built in a REPL and serialized.* — **DONE 2026-09-12, verified (6 tests pass).**
- [x] **D3** `core/spec_parser.py` incl. `$ref` resolution. *Done when: `apiguard parse <url>` tables every endpoint + params.* — **DONE 2026-09-12, verified (tables 14 VAmPI ops; 12 tests pass).**
- [x] **D4** `core/http_engine.py`. *Done when: every VAmPI endpoint can be hit and returns a status.* — **DONE 2026-09-12, verified (all 14 VAmPI ops hit; 20 tests pass).**
- [x] **D5** `core/identity.py`, two users. *Done when: both users hold valid tokens and can call an authed endpoint.* — **DONE 2026-09-12, verified (userA+userB each GET /me -> 200; 27 tests pass).**
- [x] **D6** `cli.py` + rich progress. *Done when: `apiguard scan --dry-run` parses, logs in both users, touches every endpoint.* — **DONE 2026-09-12, verified (touches all 14 VAmPI ops; 34 tests pass). WEEK 1 COMPLETE.**

### Week 2 — Baseline scanners (compressed on purpose, do not gold-plate)
- [x] **D7** `scanners/base.py` ABC + registry. *Done when: a dummy scanner is auto-discovered.* — **DONE 2026-09-12, verified (file-drop discovery; 39 tests pass).**
- [x] **D8** `scanners/injection.py` (SQLi + XSS). *Done when: finds VAmPI's known SQLi.* — **DONE 2026-09-12, verified (finds SQLi in GET /users/v1/{username}, 1 finding, 0 FP; 44 tests pass).**
- [x] **D9** `scanners/ssrf.py` + `scanners/jwt_attacks.py`. *Done when: JWT module flags a real weakness.* — **DONE 2026-09-12, verified (JWT flags weak secret 'random' on VAmPI, CRITICAL; 52 tests pass).**
- [x] **D10** `scanners/misconfig.py` + `scanners/rate_limit.py`. *Done when: full baseline scan produces a findings list.* — **DONE 2026-09-12, verified (`apiguard scan` -> 5 findings on VAmPI; 60 tests pass).**
- [x] **D11** Dedup, severity, OWASP mapping, evidence capture. *Done when: no dupes, every finding has a curl repro.* — **DONE 2026-09-12, verified (scan: 5 findings, 0 dupes, all curl+OWASP; 67 tests pass).**
- [x] **D12** pytest + respx, first cassettes. *Done when: pytest green, `benchmark/results/baseline.json` saved.* — **DONE 2026-09-12, verified (69 tests; baseline.json saved; offline replay reproduces 5 findings with VAmPI stopped). WEEK 2 COMPLETE.**

### Week 3 — AI layer
- [x] **D13** `ai/client.py` with schema enforcement + retry + logging. *Done when: 20/20 calls return valid objects.* — **DONE 2026-09-12, verified (20/20 valid from qwen3:8b in ~14s; 76 tests pass).**
- [ ] **D14** `ai/prompts.py` payload prompt with full parameter context. *Done when: an email-format field yields email-shaped candidates.*
- [ ] **D15** `ai/payload_gen.py` wired in behind `--payloads {static,ai,both}`. *Done when: `--payloads ai` runs end to end.*
- [ ] **D16** `ai/repair.py` self-repair loop, max 2 retries. *Done when: a 400-rejected payload succeeds on retry, with logs.*
- [ ] **D17** First measurement: static vs ai vs ai+repair on VAmPI. *Done when: three result JSONs with different numbers.*
- [ ] **D18** Buffer + prompt tuning. *Done when: AI arm beats static on at least one measure.*

### Week 4 — BOLA/BFLA engine (PROTECT THIS WEEK)
- [ ] **D19** `engines/bola.py` resource discovery as User A. *Done when: we have IDs provably owned by A.*
- [ ] **D20** Cross-access phase + control requests. *Done when: we have (A response, B cross-access, B control) triples.*
- [ ] **D21** `ai/oracle.py`. *Done when: flags VAmPI's known BOLA, clears a legitimate access.*
- [ ] **D22** `scoring/confidence.py` with the 5 signals. *Done when: every BOLA finding scored from >=4 measurable signals.*
- [ ] **D23** `engines/bfla.py`. *Done when: BFLA probe runs and reports separately.*
- [ ] **D24** Run against crAPI, tune thresholds. *Done when: >=1 true BOLA on crAPI with <=2 false positives.*

### Week 5 — Proof, polish, presentation
- [ ] **D25** `benchmark/ground_truth.yaml` + `run_eval.py`. *Done when: one command prints precision/recall/F1.*
- [ ] **D26** Full ablation run, 4 arms + ZAP baseline. *Done when: the Section 1 table is filled in with real numbers.*
- [ ] **D27** HTML report generator incl. AI trace. *Done when: `--report out.html` produces something presentable.*
- [ ] **D28** Streamlit dashboard, cassette-backed. *Done when: full demo runs with wifi off.*
- [ ] **D29** README, docstrings, cleanup, tag v1.0. *Done when: a stranger could clone and run it.*
- [ ] **D30** Demo recording + report writeup. *Done when: video recorded, report drafted.*

**If behind schedule, cut in this order:** BFLA (D23) → rate_limit + SSRF scanners → Streamlit (demo from CLI instead) → crAPI (VAmPI alone is valid).

---

## 8. CURRENT STATE

> Claude Code: update this section at the end of every session. Keep it short and factual.

**Current day:** Day 13 — complete and verified. (Week 3, day 1 of 6 — the AI layer.)
**Last session:** 2026-09-12 — Day 13 `ai/client.py` (Ollama schema-enforced client).
**Completed:** D1–D13. `ai/client.py`: `OllamaClient.structured()` (format=pydantic schema, think=False, pinned seed, temperature; validates via model_validate_json; retries <=2 bumping seed; inconclusive on failure; logs to logs/llm/). 76 tests pass. Live: 20/20 valid structured objects from qwen3:8b in ~14s.
**In progress:** nothing.
**Blocked / broken:** nothing.
**Next action:** Day 14 — `ai/prompts.py`: the payload-generation prompt, versioned, in one place. It must receive parameter name, declared type, format, example, endpoint path, and surrounding schema. Done when: given `{"name":"user_email","type":"string","format":"email"}` it yields email-shaped injection candidates (not generic ones). Use `OllamaClient.structured()` with a payload-list pydantic model and `temperature_payload` (0.8). Keep prompts versioned so the report can cite the prompt version.

**AI client facts:**
- `OllamaClient.from_settings(settings)` builds it (model/host/seed from config). `structured(response_model, prompt=, system=, temperature=, label=)` -> `StructuredResult(ok, value, …, inconclusive)`.
- qwen3:8b with `format`=schema is fast (~0.7s/call) and reliable: 20/20 first-try valid in the smoke. Seed bumps by attempt on retry.

**Cassette facts:**
- `cassettes/vampi/cassette.json` (~120 interactions, meta.spec_source) replays the whole VAmPI scan offline: `apiguard scan --replay cassettes/vampi` (no --spec, no live target). Re-record with `--record cassettes/vampi` after behavior changes.
- Replay is deterministic ONLY because scanners avoid wall-clock in request content (fixed the JWT expired-token to derive from the token's own iat). Any new time/random in a request path will break replay — keep requests reproducible.

**VAmPI JWT facts (Week-4 / report):**
- Signing secret is the guessable **`random`** (HS256). alg:none and signature-strip are correctly REJECTED. So VAmPI's JWT weakness is the weak secret, not alg confusion. With the secret, tokens can be forged for any user (path to BFLA/account takeover).

**VAmPI misconfig facts (corrects the earlier "GET /books/v1 500" note):**
- `GET /books/v1` returns 500 ONLY when the DB is uninitialized; after `/createdb` it returns **200 and serves the book list unauthenticated despite its spec requiring `bearerAuth`** — an auth-not-enforced / BFLA signal for Week 4, not a generic 500.
- No security headers; `Server: Werkzeug/2.2.3 Python/3.11.15` disclosed; no CORS headers; no rate limiting. These are the LOW findings the misconfig/rate_limit scanners report.

**Scanner contract (D7):** subclass `Scanner`, set `name` (and `owasp_id`), implement `async def run(self, endpoint) -> list[Finding]`. Construction takes a `ScanContext`. Access the engine via `self.engine` / `self.base_url`. Just adding a file under `apiguard/scanners/` registers it (no CLI edit).

**VAmPI auth facts (for Week-4 BOLA):**
- Register: `POST /users/v1/register` JSON `{username,password,email}`. Login: `POST /users/v1/login` JSON `{username,password}` -> `{auth_token: <JWT>, ...}`. Auth header: `Authorization: Bearer <JWT>` (raw token is rejected by the OpenAPI layer).
- JSON POSTs MUST send `Content-Type: application/json` or VAmPI returns 415. (Engine `json_body` handles this.)

**Observations (not yet findings — revisit when scanners land):**
- VAmPI `GET /books/v1` returns **500** when unauthenticated (rather than a clean 401). Real, surfaced by the engine probe.
- VAmPI `GET /users/v1/{username}` has **no security** — any user record is readable unauthenticated. BOLA-relevant surface for Week 4.

**Known limitations to wire later:**
- `settings.py` not built yet: scope allowlist is the hardcoded localhost default; non-localhost scanning not yet possible (safe for VAmPI). Wire a configurable allowlist into `load_spec`/engine when settings lands.
- `load_spec` still uses its own one-shot `AsyncClient` (bootstrap). Fine, but could route through the shared engine later.
- Cassette record/replay deferred to D12; auth/session is D5.
- `apiguard` console script live; only `parse` exists. `scan` arrives D6.

**Environment facts discovered:**
- GPU / VRAM: NVIDIA RTX 4070, 12 GB (~10.8 GB free). Ollama runs on CUDA (compute 8.9). Integrated Intel UHD 770 is ignored by Ollama.
- Model actually in use: `qwen3:8b` (5.2 GB, Q4). This is `settings.model` default.
- **qwen3:8b has thinking ON by default.** The inline `/no_think` token is NOT honored through the `ollama run` CLI. The engine must pass `think=False` to the ollama-python `chat()` call. Verified: `format=<schema>` + `think=False` returns clean, schema-valid JSON (`{"ok": true}` -> pydantic-validated). This is the D13 pattern.
- VAmPI spec URL: `http://localhost:5000/openapi.json` — **VERIFIED.** OpenAPI 3.0.1, title "VAmPI", 12 paths.
- Python: 3.11.9 at `%LOCALAPPDATA%\Programs\Python\Python311\python.exe` (not on the global shell PATH). Project venv at `.venv\` (activate: `.venv\Scripts\Activate.ps1`).
- Docker: 29.3.1 (Docker Desktop engine, must be running). VAmPI container name: `vampi`.
- winget: usable only via the full path to the x64 App Installer build; the WindowsApps `winget` alias is missing on this machine.

---

## 9. Decision log

> Append one line per non-obvious decision. Format: `YYYY-MM-DD — decision — why`.

- 2026-09-12 — CLI engine + Streamlit shell rather than a web app — the engine is the contribution; a web app would consume two of five weeks on non-contribution work.
- 2026-09-12 — One model, two temperatures, rather than two models — halves VRAM for no capability loss.
- 2026-09-12 — Confidence computed from signals, not requested from the model — an LLM's stated confidence is a plausible token, not a probability, and claiming otherwise is indefensible in a viva.
- 2026-09-12 — Week 2 scanners deliberately compressed — they are commodity and exist only as the control group for the ablation.
- 2026-09-12 — LLM called with `think=False` + `format=<schema>`, not the inline `/no_think` token — qwen3:8b thinks by default and the CLI ignores the inline token; the API `think` flag is the reliable off switch and keeps oracle output deterministic and clean.
- 2026-09-12 — `pytest`+`respx` declared as a `[dev]` optional-dependencies extra, not runtime deps — same libraries as Section 3, only test-scoped; install with `pip install -e ".[dev]"`. Runtime install stays minimal.
- 2026-09-12 — Locked `qwen3:8b` on an RTX 4070 (12 GB) — measured hardware puts us in the recommended tier with headroom; matches Section 3 default.
- 2026-09-12 — `ScanResult` (Section 5 named it but didn't define it) made self-describing: embeds run `model`, `seed`, `payload_mode`, `requests_sent` — so each saved result file attributes to one ablation arm without external context (feeds Week-5 table).
- 2026-09-12 — `Finding.id` is required, no auto-uuid default — IDs are assigned deliberately at dedup (D11), ideally from a content hash, to keep re-runs reproducible; a random uuid per run would undercut invariant 3.
- 2026-09-12 — All models set `extra="forbid"` and `Finding.confidence` is bounded `[0,1]` — a mistyped field is a loud error, and a computed confidence cannot silently leave range.
- 2026-09-12 — **Internal `$ref` resolver instead of a library resolver (D3, user-approved deviation from the plan line)** — probing showed `openapi-spec-validator` only validates and `jsonschema-path` returns lazy nested objects needing recursive materialization; a ~15-line internal JSON-Pointer resolver over the plain dict is simpler, fully testable, and sufficient because OpenAPI refs are internal `#/...` pointers. We still validate with `openapi-spec-validator` first. VAmPI has zero refs; this is for crAPI.
- 2026-09-12 — `core/scope.py` built on D3, ahead of its (unnumbered) slot — the spec fetch is the tool's first outbound request, so invariant 7 must hold now; a real guard, not a stub. Semantics: host must be in the allowlist AND, if non-localhost, carry `--confirm-authorized` (the flag is an extra requirement, never an allowlist bypass).
- 2026-09-12 — Minimal `cli.py` (`parse` only) on D3, user-approved — the done-condition names `apiguard parse <url>`; cli stays presentation-only, uses a root callback so subcommand style holds with one command, and expands with `scan` on D6.
- 2026-09-12 — `load_spec` is async (`httpx.AsyncClient`) and the CLI wraps it in `asyncio.run` — honors invariant 8 from the first request.
- 2026-09-12 — HTTP engine retries transport/timeout errors only, never HTTP statuses (D4) — a 401/500 is a real answer the scanners must see, not a failure; retrying it would corrupt evidence and inflate request counts.
- 2026-09-12 — `follow_redirects=False` on the engine — a security tool must see the raw 3xx status, not the followed destination.
- 2026-09-12 — Baseline probes fill params with example-or-type placeholders and synthesize an example JSON body from the schema (D4) — enough to "touch" an endpoint and get a status; real attack payloads are the scanners' job (D8+). Mutating probes are fine against VAmPI (disposable) and we reset via `/createdb`.
- 2026-09-12 — `requests_sent` counts every attempt incl. retries — this is the ablation's "requests sent" metric (Section 1 table), so it must reflect real network cost.
- 2026-09-12 — Target auth flow captured in an `AuthFlow` config, not hardcoded (D5) — register/login paths, field names, token key and header format vary per target; VAmPI defaults now, crAPI becomes another `AuthFlow` in Week 4 without touching identity logic.
- 2026-09-12 — `IdentityManager.authenticate` registers best-effort then logs in — register is idempotent-friendly (re-runs hit an existing user), login is the token source of truth.
- 2026-09-12 — Added `HttpEngine.send(json_body=...)` after a real 415 in exploration — a raw JSON body without `Content-Type` is rejected by VAmPI; the helper serializes and sets the header so no JSON caller repeats the trap. `IdentityManager` gets the engine injected (one shared client, invariant 8).
- 2026-09-12 — New module `apiguard/runner.py` (added to Section 4) holds scan orchestration — keeps `cli.py` logic-free (invariant 1); the CLI passes a progress callback so `rich` stays out of the runner. Week 2+ grows a real scan path here.
- 2026-09-12 — `settings.py` is a minimal pydantic-settings loader with zero-config defaults incl. two disposable VAmPI users (user-approved) — `scan --dry-run` works with no config file; `config.yaml` (gitignored) overrides. Wires the scope allowlist from config, resolving the earlier localhost-only limitation. (Env-over-YAML precedence deferred.)
- 2026-09-12 — Dry-run touches endpoints authenticated as User A and still sends real baseline requests (not a no-network mode) — proves identity is wired into the pipeline; run only against a disposable target (VAmPI). Runner stays target-agnostic (no `/createdb` coupling); reset is the caller's concern.
- 2026-09-12 — Scanner auto-registration gates on a non-empty `name`, not on abstractness (D7) — `ABCMeta` sets `__abstractmethods__` after `__init_subclass__` runs, so it can't be checked there; abstract intermediates simply leave `name` unset and stay unregistered.
- 2026-09-12 — Scanners receive a `ScanContext` (engine, base_url, settings, sessions) at construction — keeps `run(endpoint)` to the exact Section-6 contract while giving scanners the engine now and the two user sessions the BOLA engine needs in Week 4. Small seam added deliberately to avoid reworking every scanner later.
- 2026-09-12 — Injection: error-signature matching is the primary SQLi detector (D8) — flags a SQL error present with the payload but absent in the benign baseline; VAmPI (SQLite/SQLAlchemy) leaks a clear `sqlite3.OperationalError: unrecognized token` on a `'`. Time-based is a secondary check and will NOT fire on SQLite (no SLEEP); kept for other engines/crAPI. XSS requires the marker to reflect unescaped in an HTML content-type, so JSON echoes are not false-flagged.
- 2026-09-12 — SQLi/XSS mapped to `owasp_id = "API8:2023"` — OWASP API Top 10 2023 has no standalone Injection category (folded into API8 Security Misconfiguration). Documented so it is defensible; revisit at D11 (OWASP mapping).
- 2026-09-12 — JWTs forged with the standard library (base64+hmac+hashlib), not PyJWT (D9) — avoids adding a dependency outside Section 3; alg:none, signature-strip and HS256 weak-secret forgery are all trivial to build by hand.
- 2026-09-12 — JWT scanner probes only an idempotent authed GET, once per run — a create/update endpoint changes state between forged-token requests and confounds the accept-vs-reject status comparison (caught live: it initially targeted POST /books/v1 and found nothing). The weak-secret finding is global; it is demonstrated on the chosen GET.
- 2026-09-12 — SSRF reports nothing on VAmPI and that is the correct result — VAmPI has no URL-fetching parameters; we do not invent a finding (invariant: never fabricate).
- 2026-09-12 — `runner.scan()` runs scanners SEQUENTIALLY over endpoints (D10) — scanners hold per-run guards (JWT/rate_limit probe once; misconfig checks globals once), which parallel execution would race; parallelising is a later optimisation, not needed for VAmPI-scale.
- 2026-09-12 — misconfig runs header/version/CORS checks once (first endpoint) and verbose-error per endpoint — those three are server-global, so one finding each avoids 14 duplicates; global finding ids are fixed strings so dedup (D11) is trivial.
- 2026-09-12 — rate_limit bursts one no-parameter GET via the shared engine — the engine's own rate limiter paces the burst (documented caveat: a very low configured rate could mask a server limit), but N requests with no 429 still proves VAmPI has no limiting.
- 2026-09-12 — Kept the scanners' deterministic descriptive `Finding.id` as canonical, dedup by it (D11) — adjusts the D2 note that ids would be content-hashed at dedup; descriptive ids (`injection-sqli-get-...-username`) are already reproducible and read better in tables/reports. `finalize()` also validates curl + OWASP id and sorts stably for reproducible result files.
- 2026-09-12 — OWASP: injection stays `API8:2023` (Security Misconfiguration), documented in `core/findings.py` — the 2023 list dropped standalone Injection (was API8:2019); nearest current bucket, attack name kept in the title. `DEFAULT_SEVERITY` per category is a reference/floor; scanners set their own severity.
- 2026-09-12 — Cassette key = method + final url + body + significant headers (authorization, origin, content-type) (D12) — keying on url+body alone collided the JWT scanner's forged-token requests (they vary only Authorization) and the CORS check (varies only Origin); found live via a replay miss.
- 2026-09-12 — JWT expired-token forge is derived from the token's own `iat` shifted into the past, not `time.time()` (D12) — wall-clock made the forged token differ between record and replay (cassette miss) and violated reproducibility; now deterministic.
- 2026-09-12 — Replay routes the spec fetch through the engine and stores `meta.spec_source` in the cassette — so `--replay <dir>` re-runs the entire scan (spec + auth + scanners) offline with no `--spec` and no live target. Proven by replaying with the VAmPI container stopped.
- 2026-09-12 — D12 cassette hardened after an adversarial review workflow (10 confirmed issues): each key now maps to an ORDERED LIST of responses (repeated identical requests like the rate-limit burst replay faithfully, not last-write-wins); Content-Encoding/Length stripped on replay (a stored gzip header would crash httpx re-decoding the already-decoded body); `--record`+`--replay` and `--dry-run`+cassette are rejected; `load_spec` engine path checks HTTP status. Documented live-only limits: cassettes capture responses, NOT timing (time-based SQLi is live-only, won't fire on replay) and non-UTF-8 bodies may not round-trip exactly.
- 2026-09-12 — AI client retries bump the seed per attempt (config seed + attempt) (D13) — with a pinned seed, re-calling identical input would reproduce the same invalid output, so a plain retry is useless; the bump stays reproducible (deterministic per attempt) while giving the retry a real chance. Exhaustion returns an inconclusive `StructuredResult` (never raises, never regexes) per invariant 2.

---

## 10. Never do

- Never scan a host that is not in the config allowlist.
- Never stub out or bypass the scope guard, even temporarily.
- Never regex an LLM response instead of using schema-constrained output.
- Never ask the model for a confidence number.
- Never call the LLM on a case the cheap heuristics already resolved.
- Never mark a roadmap day complete without running something that proves it.
- Never add a dependency that is not in Section 3 without asking first.
- Never invent findings, numbers, or benchmark results. If a run did not happen, say it did not happen.
- Never let the scope creep toward GraphQL, gRPC, React, Celery, Docker packaging, or scan history. All explicitly out of scope.

---

## 11. Commands

```bash
# environment
source .venv/bin/activate

# targets
docker run -d -p 5000:5000 erev0s/vampi

# run
apiguard parse http://localhost:5000/openapi.json
apiguard scan --spec http://localhost:5000/openapi.json --payloads both --report out.html
apiguard scan --replay cassettes/vampi/          # offline, for demos

# eval
python benchmark/run_eval.py

# tests
pytest -q

# dashboard
streamlit run dashboard.py
```
