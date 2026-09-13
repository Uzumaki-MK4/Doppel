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

| Arm | Recall vs ground truth | Precision | False positives | Requests sent |
|---|---|---|---|---|
| Static wordlist payloads | 5/12 (0.42) | 1.00 | 0 | 71 |
| AI-generated payloads | 5/12 (0.42) | 1.00 | 0 | 63 |
| AI + self-repair | 5/12 (0.42) | 1.00 | 0 | 63 |
| **Full (incl. BOLA engine)** | **8/12 (0.67)** | **1.00** | **0** | 82 |
| OWASP ZAP (external baseline) | 2/12 (0.17) | 0.50 | 2 | n/a |

*(VAmPI, measured D26 2026-09-14; `python benchmark/run_eval.py`. crAPI second target: Full engine 1/5 (0.20) recall, 1.00 precision — a single-endpoint BOLA validation. The Full arm nearly QUADRUPLES ZAP's recall at perfect precision: the BOLA/BFLA engine finds the 3 authorization vulns — book-secret BOLA, public-user BOLA, `_debug` BFLA — that ZAP misses entirely even though it retrieved the password dump and cross-user data. AI matches static recall at ~11% fewer requests. ZAP also missed the SQLi: its active SQLi scanner never fired on the injectable param; it only passively noticed SQL leaking from `/createdb`'s 500.)*

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
else:                                            -> AMBIGUOUS, call oracle
```

**D21 review change (this supersedes the original 4th line):** the original gate had
`if a_object_id not in b_response.body: -> NOT a leak` — REMOVED. Many endpoints carry
the object id only in the URL (opaque ids), so that clear silently dropped real 200-OK
BOLA leaks (crAPI). Id presence is now the `id_echo` CONFIDENCE signal, never a hard
veto. The gate only clears on the two SAFE conditions above; everything else goes to
the oracle. (See Section 9, 2026-09-13.)

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
- [x] **D14** `ai/prompts.py` payload prompt with full parameter context. *Done when: an email-format field yields email-shaped candidates.* — **DONE 2026-09-12, verified (email field -> email-shaped payloads; plain field -> generic; 80 tests pass).**
- [x] **D15** `ai/payload_gen.py` wired in behind `--payloads {static,ai,both}`. *Done when: `--payloads ai` runs end to end.* — **DONE 2026-09-12, verified (`--payloads ai` runs, 4 findings; 84 tests pass). See the AI-misses-SQLi observation below.**
- [x] **D16** `ai/repair.py` self-repair loop, max 2 retries. *Done when: a 400-rejected payload succeeds on retry, with logs.* — **DONE 2026-09-12, verified (register body missing 'email' 400 -> repaired -> 200 on first retry, logged; 87 tests pass).**
- [x] **D17** First measurement: static vs ai vs ai+repair on VAmPI. *Done when: three result JSONs with different numbers.* — **DONE 2026-09-12: three JSONs saved; arms differ on requests_sent (120/87/100). HONEST caveat: finding COUNTS are equal (5/5/5 — same recall on VAmPI); difference is request cost, not recall.**
- [x] **D18** Buffer + prompt tuning. *Done when: AI arm beats static on at least one measure.* — **DONE 2026-09-12, verified (AI 5 findings/93 req vs static 5/128 = same recall, ~27% fewer requests; +boolean SQLi detector; fixed an XSS false positive; 90 tests). WEEK 3 COMPLETE.**

### Week 4 — BOLA/BFLA engine (PROTECT THIS WEEK)
- [x] **D19** `engines/bola.py` resource discovery as User A. *Done when: we have IDs provably owned by A.* — **DONE 2026-09-12, verified (2 A-owned objects: seeded book + A's user record, A-access captured; 92 tests pass).**
- [x] **D20** Cross-access phase + control requests. *Done when: we have (A response, B cross-access, B control) triples.* — **DONE 2026-09-13, verified (2 triples on VAmPI; book triple shows B reading A's secret = the BOLA; 94 tests pass).**
- [x] **D21** `ai/oracle.py`. *Done when: flags VAmPI's known BOLA, clears a legitimate access.* — **DONE 2026-09-13, verified (oracle flags the book BOLA is_leak=True [book_title,owner,secret]; clears B-reads-own-book is_leak=False; gate routes both; 102 tests pass).**
- [x] **D22** `scoring/confidence.py` with the 5 signals. *Done when: every BOLA finding scored from >=4 measurable signals.* — **DONE 2026-09-13, verified (`scan --bola` -> 2 BOLA findings each scored from 5 signals; HIGH book conf 0.81, MEDIUM public users conf 0.81; 107 tests pass).**
- [x] **D23** `engines/bfla.py`. *Done when: BFLA probe runs and reports separately.* — **DONE 2026-09-13, verified (CRITICAL BFLA on GET /users/v1/_debug, separate scanner=bfla/API5:2023; 112 tests pass). WEEK 4 COMPLETE.**
- [x] **D24** Run against crAPI, tune thresholds. *Done when: >=1 true BOLA on crAPI with <=2 false positives.* — **DONE 2026-09-13, verified (crAPI up; `benchmark/crapi_bola.py` -> 1 true BOLA on `GET /identity/api/v2/vehicle/{vehicleId}/location`, HIGH, conf 0.8547 from 5 signals, oracle is_leak=True; 0 false positives [legit self-access cleared by gate:identical-to-control]; reproducible across runs. 113 tests pass).**

### Week 5 — Proof, polish, presentation
- [x] **D25** `benchmark/ground_truth.yaml` + `run_eval.py`. *Done when: one command prints precision/recall/F1.* — **DONE 2026-09-13, verified (`python benchmark/run_eval.py` prints a rich P/R/F1 table over all arm JSONs. VAmPI baseline/static/ai/ai_repair: prec 1.00 recall 0.42 (5/12); FULL: prec 1.00 recall 0.67 (8/12) — the BOLA/BFLA engine is the +0.25 recall lift at 0 FP. crapi: prec 1.00 recall 0.20 (1/5, single-endpoint validation). 122 tests pass. Ground truth = 12 VAmPI + 5 crAPI vulns, every entry live-verified).**
- [x] **D26** Full ablation run, 4 arms + ZAP baseline. *Done when: the Section 1 table is filled in with real numbers.* — **DONE 2026-09-14, verified (Section 1 table filled: re-measured static/ai/ai+repair/full on VAmPI with fresh request counts; ran OWASP ZAP (docker, spec-driven api-scan) and adapted its real report via `benchmark/zap_adapt.py`. Full 8/12 recall @1.00 prec vs ZAP 2/12 @0.50 vs static 5/12 @1.00. 126 tests pass).**
- [x] **D27** HTML report generator incl. AI trace. *Done when: `--report out.html` produces something presentable.* — **DONE 2026-09-14, verified (`apiguard/report/generator.py` + `template.html`; `scan --report out.html` wired; self-contained HTML, inline CSS, opens offline; surfaces the AI oracle trace (model/seed/temp + signal bars + prompt/raw response) for BOLA findings; autoescaping tested (untrusted response bodies render inert). Visually verified in-browser on the 8-finding Full scan. 131 tests pass).**
- [x] **D28** Streamlit dashboard, cassette-backed. *Done when: full demo runs with wifi off.* — **DONE 2026-09-14, verified (`dashboard.py`: offline-by-construction — reads only committed `benchmark/results/*.json` + ground truth, Streamlit serves local assets, telemetry off. Tabs: Ablation (the table + recall chart), Findings explorer, BOLA deep-dive (oracle verdict + signal bars), Report (inline + download), About. Launched + viewed in-browser: full story renders with no live target/Ollama/network. 136 tests pass).**
- [x] **D29** README, docstrings, cleanup, tag v1.0. *Done when: a stranger could clone and run it.* — **DONE 2026-09-14, verified (full README rewrite with venv-aware commands + the PATH gotcha; v1.0-cleanup audit (4-agent workflow) fixed: dropped undeclared pandas from dashboard, docstrings on all public classes/functions, refreshed stale Day-N module docstrings, removed an unused import; re-recorded the cassette so `scan --replay` reproduces the static scan offline (verified with VAmPI stopped); `pip install -e ".[dev]"` clean, 136 tests pass, version bumped to 1.0.0, tagged v1.0).**
- [ ] **D30** Demo recording + report writeup. *Done when: video recorded, report drafted.*

**If behind schedule, cut in this order:** BFLA (D23) → rate_limit + SSRF scanners → Streamlit (demo from CLI instead) → crAPI (VAmPI alone is valid).

---

## 8. CURRENT STATE

> Claude Code: update this section at the end of every session. Keep it short and factual.

**Current day:** Day 29 — complete and verified. **v1.0 TAGGED.** (Week 5 — proof/polish — day 5 of 6.)
**Last session:** 2026-09-14 — Day 29 README + cleanup + v1.0 tag.
**Completed:** D1–D29. Full README rewrite (headline result table, how-it-works, venv-aware setup/usage incl. the Windows PATH gotcha, reproducibility, crAPI, layout). v1.0-cleanup audit (4-agent workflow, grounded against the live tree) — fixed: dropped the undeclared pandas import from `dashboard.py` (ablation table via list-of-dicts, recall/signal charts via `st.progress`), added docstrings to every public class/function that lacked one, refreshed the Day-N-era module docstrings (cli/runner/injection/http_engine), removed an unused import. Re-recorded `cassettes/vampi/` so `scan --replay` reproduces the static scan OFFLINE (proven with VAmPI stopped -> 5 findings). `pip install -e ".[dev]"` clean; all deps declared; version 1.0.0; **git tag v1.0**. 136 tests pass.
**In progress:** nothing.
**Blocked / broken:** nothing.
**Next action:** Day 30 — demo recording + report writeup (FINAL DAY). Done when: video recorded, report drafted. Suggested demo arc (all offline-capable): `apiguard parse` -> live `apiguard scan --bola --report out.html` (needs VAmPI+Ollama) OR `scan --replay` (offline) -> open the HTML report (AI trace) -> `python benchmark/run_eval.py` (the ablation table) -> `streamlit run dashboard.py` (BOLA deep-dive). The report writeup = the thesis (200-OK BOLA invisible to status scanners) + the measured result (Full 0.67 vs ZAP 0.17 @1.00 precision) + method (gate->oracle->computed confidence) + honest limitations (VAmPI-all-statically-findable so AI wins on requests not recall; crAPI single-endpoint; qwen3 cross-session drift). Everything needed is committed.

**D26 ablation (VAmPI, measured 2026-09-14) — THE RESULT:**
- static/ai/ai+repair: **prec 1.00, recall 0.42 (5/12)**, req 71/63/63. AI beats static on requests (~11% fewer) at equal recall; repair fired 0 extra requests on VAmPI (its payoff is typed crAPI fields).
- **FULL: prec 1.00, recall 0.67 (8/12)**, req 82 — the BOLA/BFLA engine adds book-secret BOLA + public-user BOLA + `_debug` BFLA. The +0.25 recall at 0 FP is the thesis, measured.
- **ZAP: prec 0.50, recall 0.17 (2/12)** — finds only missing-headers + version-disclosure; MISSES all BOLA/BFLA/jwt/rate-limit AND the SQLi (its active SQLi scanner never fired on the injectable param; it only passively saw SQL in `/createdb`'s 500). It retrieved the `_debug` password dump and cross-user data and flagged nothing. 2 FP = noise alerts (bare 500 code, unexpected content-type); 2 real-but-out-of-scope alerts (SQL/error disclosure on /createdb) are reported, NOT counted as FP (they're real).
- crapi: prec 1.00, recall 0.20 (1/5) — single-endpoint BOLA validation (D24), not a full scan.
- HEADLINE: APIGuard Full nearly QUADRUPLES ZAP's recall (0.67 vs 0.17) at perfect precision. ZAP JSON has no request count -> shown n/a. ZAP command: `docker run --add-host=host.docker.internal:host-gateway -v zapwrk:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t /zap/wrk/openapi_fixed.json -f openapi -J zap_report.json` (VAmPI's spec has `servers:[{url:""}]` so ZAP appends paths to the spec URL and 404s — MUST feed a local spec with servers set to the real base, and the /zap/wrk volume must be world-writable). Raw report: `benchmark/zap_report.json`.
- Matcher facts (viva): global findings (jwt, rate_limit) join on `scanner` ALONE; the 2 misconfig globals share path "/" so join by `id_contains`; `owasp_id` is NOT a match predicate (SQLi is API8 in-tool). `Finding.scanner` is the bare literal (`jwt`, not `jwt_attacks`).

**Full scan (VAmPI, verified D23):** 8 findings — CRITICAL jwt weak-secret + CRITICAL bfla _debug; HIGH bola book + HIGH injection sqli; MEDIUM bola users(public); 3x LOW misconfig/rate_limit. This is the "Full" arm for the Week-5 ablation table.

**crAPI facts (verified D24) — SECOND TARGET, engine-produced BOLA:**
- Stack: `benchmark/crapi-compose.yml` is NOT committed; it lives in the session scratchpad. Bring crAPI up with the official compose (owasp-crapi). Core services + gateway (`crapi-web`, host `127.0.0.1:8888`), MailHog (`127.0.0.1:8025`), identity/community/workshop, postgres/mongo, chromadb+chatbot. GOTCHA: `crapi-web` (nginx) refuses to start unless `crapi-chatbot` EXISTS on the network (it resolves the upstream at config-load) — so you must start chatbot+chromadb too even though we don't use them.
- Auth: login `POST /identity/api/auth/login` `{email,password}` -> `{token: <RS256 JWT>}` (VAmPI is HS256 — different alg, proves generality). Signup `POST /identity/api/auth/signup` needs `{name,email,number,password}`. Our `AuthFlow` covers crAPI with **config only, zero engine code change** (register/login paths, `username_field="email"`, `token_json_key="token"`).
- Seeded owners (bcrypt, passwords unknown): adam007/pogba006/robot001/test/admin @example.com, each owns ONE vehicle (uuid). To get sessions WITHOUT guessing: crAPI routes ALL mail to MailHog, so drive its real forgot-password -> OTP -> `POST /identity/api/auth/v3/check-otp` reset (OTP read from MailHog `/api/v1/messages/{id}/download`, HTML part). `benchmark/crapi_bola.py` automates this (idempotent). No DB tampering; note the OTP column read is blocked by the auto-mode classifier anyway (that's fine, MailHog is the right channel).
- THE BOLA: `GET /identity/api/v2/vehicle/{vehicleId}/location` has NO ownership check — any logged-in user (even a fresh signup owning nothing) reads ANY vehicle's `{carId, latitude, longitude, fullName, email}` by uuid. Body ECHOES `carId` (so id_echo=1.0 here; the opaque-id-not-echoed case is covered by the D22 gate fix + `test_opaque_id_bola_is_caught_by_fixed_gate`). Discover a user's own uuid via `GET /identity/api/v2/vehicle/vehicles`.
- WHY a driver, not `apiguard scan`: the generic `ResourceDiscoverer` seeds by POST + harvest; crAPI vehicles are pre-seeded & email-claim-gated, so the discoverer can't auto-seed one. `crapi_bola.py` supplies the two owner->uuid bindings from crAPI's own API, then the REAL `probe_cross_access`+oracle+confidence+`bola_finding` run UNMODIFIED. This is the honest split: discovery is target-specific, the CONTRIBUTION is not. Result saved `benchmark/results/crapi.json`.

**BOLA engine facts (VAmPI, verified D22):**
- `scan --bola` -> 2 findings: HIGH `GET /books/v1/{book_title}` (B reads A's book secret) conf 0.81; MEDIUM `GET /users/v1/{username}` public conf 0.81. Each scored from 5 signals. `AITrace.signals` holds the 5 signals (the explainability trace for D27).
- body_divergence is LOW (~0.03) here because A's and B's objects are structurally near-identical (only the owner/secret tokens differ) — the leak is carried by id_echo/field_overlap/oracle_verdict. Signal-based confidence combining works as intended (a weak signal lowers, doesn't dominate).
- IMPORTANT integration facts: (1) injection is now GET-ONLY (a tautology on a DELETE/PUT path param is destructive). (2) VAmPI `GET /createdb` is a DB-RESET endpoint; the misconfig scanner probes it and wipes registered users mid-scan, so the BOLA phase RE-AUTHENTICATES before running. (3) injection GET-only lowered request counts -> D17/D18 static/ai JSONs are STALE; re-measure at D26.

**Oracle facts (VAmPI):**
- Book cross-access -> gate 'ambiguous' -> oracle is_leak=True, leaked_fields=[book_title,owner,secret]. B-reads-own-book -> oracle is_leak=False. The gate resolves rejected/identical/id-absent WITHOUT the LLM (invariant 4).
- `BolaDecision.oracle_verdict` = 1.0/0.0 (LLM) or None (gate decided) — this is the D22 `oracle_verdict` signal. `BolaDecision.trace` (model/seed/temp/prompt/raw) feeds the `AITrace`.
- The public `GET /users/v1/{username}` triple: oracle WILL say is_leak=True (B does see A's email). That's data-correct; down-weight by severity at D22 (public endpoint), do not hack the oracle.

**BOLA facts (VAmPI):**
- Crown-jewel BOLA target: `GET /books/v1/{book_title}` returns `{book_title, owner, secret}` — the `secret` is owner-only; B reading A's book secret = the BOLA. A's seeded book: `apiguard_userA_book_title`.
- `GET /users/v1/{username}` returns `{username,email}` and is PUBLIC (no auth) — B reading A's record is by-design public (email leak, lower value than the book secret). Oracle/confidence must not over-flag this public read.
- Books collection `GET /books/v1` -> `{"Books":[{book_title, user}]}`; object owner field is `owner` (detail) / `user` (collection).

**!!! Reproducibility caveat (viva-critical):**
- qwen3 via Ollama is DETERMINISTIC WITHIN a session (verified 4/4 identical payloads for `username`, incl. `name1'; DROP TABLE users--` which trips VAmPI's 'one statement at a time' error -> SQLi found). But output DRIFTED across sessions: D15 the AI arm found 4 (only boolean `' OR '1'='1`, no SQL error) vs D17 found 5. Ollama `seed` pins within-session determinism, NOT guaranteed across server/model reloads. Story: we pass `seed` (invariant 3), record model/seed in every ScanResult, save the arm JSONs as the canonical measurement, and state the caveat. AI scans are not cleanly cassette-replayable (Ollama traffic isn't cassetted).

**!!! KEY OBSERVATION for D17/D18 (ablation narrative) — do NOT lose this:**
- On VAmPI the AI arm (`--payloads ai`) found **4** findings vs the static arm's **5**: it MISSED the SQLi. qwen3 generated a boolean-based `name1' OR '1'='1` (VAmPI returns 200, NO SQL error) with low diversity (4 identical), and our injection detector is error-signature-only, so it misses boolean-based SQLi. Two fixes available at D18: (a) tune the payload prompt for diversity + include an error-inducing bare-quote; (b) add boolean-based SQLi detection (true-vs-false response differential) to the injection scanner. This is ALSO the thesis in miniature: a 200-OK boolean SQLi is invisible to error/status detection — exactly why the Week-4 semantic oracle matters. AI arm currently wins only on requests (79 vs 120). D18 must make AI beat static on a real measure. NEVER fabricate an AI win; report the real numbers.

**Prompt facts:**
- `ai/prompts.py`: `payload_user_prompt(name,type_,format_,example,path,method,schema,count,attack_types)` + `PAYLOAD_SYSTEM`; call with `OllamaClient.structured(PayloadSet, ..., temperature=settings.temperature_payload)`. `PROMPTS_VERSION` = "2026-09-12.payload-v1" (bump on change; cite in report).
- Observed at temp 0.8: payloads are context-tailored but LOW DIVERSITY / duplicated. Tune the prompt (ask for distinct/varied payloads; maybe dedupe) at D18.

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
- 2026-09-12 — Payload prompt tailors to the declared type/format, not a generic wordlist (D14) — verified live (email field -> email-shaped payloads with the attack in the local part; plain field -> generic). This format-tailoring is the AI arm's intended edge over static payloads and the thing the ablation should show. `PROMPTS_VERSION` is bumped on any prompt change so results cite the exact prompt. Low payload diversity at temp 0.8 is a known D18 tuning item.
- 2026-09-12 — `--payloads {static,ai,both}` threaded cli -> runner -> ScanContext -> injection (D15); ai/both build a cached `PayloadGenerator`, and the runner DEGRADES to static (recording effective mode) if Ollama is unreachable so a scan still runs with Ollama off (invariant 4). AI scans are NOT offline-`--replay`able (Ollama traffic isn't cassetted) — documented limitation.
- 2026-09-12 — Injection's error-signature SQLi detector misses BOOLEAN-based SQLi (e.g. `' OR '1'='1` -> 200 with data, no error). Surfaced because the AI arm generated exactly that and missed VAmPI's SQLi. Candidate D18 fix: add true-vs-false response-differential detection. This is the project thesis in miniature (200-OK injection invisible to status/error detection).
- 2026-09-12 — Self-repair loop is decoupled via a `send` callback (D16) — the same `RepairLoop.repair_value` repairs an injection parameter payload (re-probe) and a whole request body (re-POST); it feeds the server's 400/422 error text back to the model and caps at 2 retries, never raising. Repair is built only for ai/both (shares the OllamaClient) and wired into the injection scanner's probe. On VAmPI some AI payloads DO 400 (repair fired, +13 req in the D17 ai+repair arm) but it yielded no new findings there; repair's real payoff is typed/validated fields (crAPI).
- 2026-09-12 — D17 honest outcome: on VAmPI the three arms reach the SAME recall (5 findings each) — the ablation difference is REQUESTS (static 120, ai 87, ai+repair 100), not recall. A recall gap needs a target with vulns static misses (crAPI) or detection that catches what static's crude payloads don't. Reported as-is; no invented finding-count spread. qwen3 determinism is within-session only (D15 ai=4 vs D17 ai=5) — documented caveat, seed still pinned.
- 2026-09-12 — Added boolean-based SQLi detection (D18): TRUE (`nx' OR '1'='1`) vs FALSE (`nx' OR '1'='2`) response differential, guarded (true richer than false, false ~ baseline, same status, not 5xx). Catches 200-OK injection invisible to error/status detection — the project thesis — and de-risks reliance on the model emitting an error-triggering payload. Runs only when error/time-based misses.
- 2026-09-12 — Fixed an XSS FALSE POSITIVE before it reached a result (D18): an AI payload with a quote triggered a 500 Werkzeug debug page that reflected the payload; the XSS detector fired on it. Reflection in a 5xx debug page IS the verbose-error misconfig (already flagged by misconfig), not reflected XSS — XSS detection now skips 5xx. Integrity: verified the finding, found it bogus, removed it rather than claim AI found 6 vs static 5.
- 2026-09-12 — D18 honest win: AI arm beats static on REQUESTS (93 vs 128, ~27% fewer) at EQUAL recall (5/5) and 0 FP. This is the defensible AI-arm story for the report (efficiency via targeted, context-aware payloads); recall parity is because VAmPI's vulns are all statically findable.
- 2026-09-12 — BOLA ownership is established two ways (D19): seed (POST-as-A creates an object A provably owns) and harvest (collection item whose owner field == A's username). Ownership detection is generic: an item is A's if any of its string values equals A's username. A's own access is captured per owned id as the cross-access baseline. Object endpoint = GET whose path ends in `/{id}`; collection = path minus that segment.
- 2026-09-13 — Cross-access control is a B-owned object at the SAME endpoint (D20) — not a re-fetch of A's; the control shows what a LEGITIMATE B access to that resource type looks like, so `body_divergence(b_cross, b_control)` is a real signal. B's own ids come from re-running the discoverer with owner="userB". `_object_access` is shared so discovery and cross-access send byte-identical requests (only the auth header differs).
- 2026-09-13 — Seed fills unconstrained string fields with owner-distinctive values `apiguard-<owner>-<field>` (D20) — so A's book secret ('apiguard-userA-secret') differs from B's ('apiguard-userB-secret'); a cross-user read then leaks the OTHER user's identifiable data, making the leak unambiguous for the oracle and giving real body-divergence. Formatted fields (e.g. email) keep the schema example to stay valid.
- 2026-09-13 — Oracle gate is strictly deterministic-first (D21): the LLM is called ONLY on 'ambiguous' triples; rejected(401/403/404)/identical-to-control are cleared with no model call (invariant 4). Oracle output is a schema-constrained `OracleVerdict` (is_leak/leaked_fields/reasoning) at temp 0.0, pinned seed, think=False (invariants 2/3/5). Inconclusive (retries exhausted) AND Ollama-unavailable both degrade to is_leak=False (conservative; never crash a scan). The oracle verdict is ONE D22 signal, never the confidence itself (invariant 5).
- 2026-09-13 — **DEVIATION from Section-5 gate (D21 adversarial review, user-visible):** removed the `a_object_id not in b_body -> not_leak` gate clear. Review (8 confirmed findings) showed it drops real 200-OK BOLA on endpoints that carry the id only in the URL (opaque ids; crAPI). Fix is strictly SAFER (escalates more to the oracle, never clears more); id presence is now the `id_echo` confidence signal. Also hardened the oracle prompt (fence + untrusted-data framing, partial injection defence — residual risk is a DOCUMENTED limitation), widened truncation 1200->4000, and narrowed the oracle's except so code defects surface. Public-endpoint reads still flag as leaks (data-correct) and are down-weighted by severity at D22, not suppressed.
- 2026-09-13 — Confidence is a WEIGHT-NORMALISED mean over the PRESENT signals (D22) — `sum(w_i*s_i)/sum(w_i)` — so a missing signal (no B-control, or gate-decided so no oracle_verdict) keeps the score in [0,1] instead of silently deflating it. BOLA findings currently always have all 5 (a leak comes only from the oracle). Confidence stays COMPUTED, never asked (invariant 5).
- 2026-09-13 — **SAFETY: injection probes GET only (D22)** — a tautology/boolean payload (`' OR 1=1--`) on a state-changing path param is destructive (`DELETE FROM users WHERE ... OR 1=1` wipes rows). VAmPI's SQLi is on a GET, still found. Testing write-endpoint SQLi safely needs error-only/OAST probes (out of scope for the compressed Week-2 scanner). This also lowered request counts (D17/D18 JSONs stale -> re-measure D26).
- 2026-09-13 — BOLA phase RE-AUTHENTICATES right before running (D22) — earlier scanners can disturb target state; specifically VAmPI's `GET /createdb` is a DB-reset endpoint that the misconfig scanner probes, wiping the registered users and invalidating the scan's start-of-run sessions. Re-`identity.setup()` re-registers + re-logs-in for fresh sessions. General principle: the BOLA engine owns its own fresh identity/objects rather than trusting pre-scan state.
- 2026-09-13 — BFLA is keyword-based privileged-endpoint detection + low-priv GET probe (D23) — deterministic (no oracle, runs without Ollama). Privileged = a path segment containing admin/_debug/debug/internal/manage/root/superuser/... Only GET is probed (never trigger a privileged write). Flag if the low-priv user gets 2xx-with-data; CRITICAL if the body leaks credential-like markers (password/secret/token/hash/...), else HIGH. Runs in the same engines phase as BOLA but reports separately (scanner=bfla, API5:2023). FP guard: a 403/401 (authz working) is NOT flagged.
- 2026-09-13 — **crAPI validated as a second target via a thin driver, NOT `apiguard scan` (D24)** — the generic `ResourceDiscoverer` seeds owned objects by POST+harvest; crAPI vehicles are pre-seeded and bound through an email-gated VIN/pincode claim flow, so the discoverer can't auto-seed one. `benchmark/crapi_bola.py` supplies the two owner->vehicle uuid bindings from crAPI's OWN API (`GET /vehicle/vehicles`), then calls the REAL `probe_cross_access` + `BolaOracle` + confidence + `bola_finding` UNMODIFIED. Honest split for the viva: *discovery* is target-specific plumbing; the *contribution* (gate + oracle + signal-based confidence) generalises unchanged. Extracted `runner.bola_finding(triple, decision, weights)` so the VAmPI and crAPI paths build findings through identical code.
- 2026-09-13 — crAPI owner sessions obtained via crAPI's OWN forgot-password/OTP flow, not credential guessing or DB writes (D24) — seeded demo passwords are bcrypt/unknown; crAPI mails all OTPs to MailHog, so the driver triggers `forget-password`, reads the OTP from MailHog, and resets via `v3/check-otp`. Reproducible, uses only real crAPI endpoints, tampers with nothing but the two disposable demo accounts' passwords (documented, acceptable on a throwaway target). Reading the OTP straight from Postgres is blocked by the auto-mode classifier — MailHog is the correct channel regardless.
- 2026-09-13 — Result (D24, real, reproducible): 1 true BOLA on crAPI `GET /identity/api/v2/vehicle/{vehicleId}/location` (HIGH, conf 0.8547, signals id_echo=1/field_overlap=1/status_match=1/body_divergence=0.27/oracle_verdict=1), 0 false positives (legit self-access cleared by `gate:identical-to-control`, no LLM). Meets the D24 done-condition (>=1 BOLA, <=2 FP). Note `carId` IS echoed here so id_echo=1; the opaque-id case (id in URL only) is separately locked by `test_opaque_id_bola_is_caught_by_fixed_gate`. The "crAPI won't run" blocker did not occur (ample RAM).
- 2026-09-13 — Ground truth is a match-block join, not string-equality, and `owasp_id` is deliberately NOT a match predicate (D25) — a finding joins a known vuln via any of {scanner, path, method, id_contains, path_contains}, ALL present predicates must hold. Global findings (jwt, rate_limit) are reported on an incidental endpoint so they join on `scanner` alone; the two misconfig globals share carried path "/" so they join by `id_contains` (fixed ids). owasp is excluded because the tool maps SQLi to API8 while a purist calls it injection — keying on owasp would spuriously un-match a real detection. `run_eval` warns if one finding matches >1 entry (matcher-overlap / TP double-count guard).
- 2026-09-13 — `detectable` flag splits the recall denominator honestly (D25): `detectable:true` = APIGuard demonstrably emits it (has a match block); `detectable:false` = a real known vuln with NO detector (no match block, always a false negative). Listing the 4 VAmPI blind spots (mass-assignment, unauthorized-password-change, enumeration, RegexDOS) as detectable:false is what makes recall meaningful — the Full arm's 0.67 is "8 of 12 real vulns", not "8 of the 8 we can find". Every ground-truth entry was independently verified against the live target before commit (integrity: a fabricated yardstick would invalidate every downstream number).
- 2026-09-13 — Ground-truth enumeration ran as a 5-agent workflow (D25): 4 parallel angles (VAmPI source-read, VAmPI live-probe, crAPI, APIGuard detector-surface) + a completeness critic grounded against the REAL run_eval matcher and saved result files. The critic caught the traps (scanner='jwt' not 'jwt_attacks'; jwt/rate_limit are global→scanner-only; misconfig globals→id_contains; the omitted MEDIUM `GET /users/v1/{username}` bola that would otherwise score as an FP; the `_debug`/rate-limit duplicate candidates; a phantom verbose-error entry APIGuard never emits on VAmPI). Agents PROPOSE, the author VERIFIES and owns the artifact.
- 2026-09-13 — crapi.json is scored as a targeted single-endpoint BOLA validation, not a full scan (D25) — only the vehicle-location BOLA is `detectable:true`; crAPI's other documented vulns (order/mechanic BOLA, jwt, mass-assignment) are honest false negatives (recall 0.20) because no full `apiguard scan` has run against crAPI yet. crAPI precision is the meaningful number (1.00); a fuller crAPI arm is optional D26 work (needs the crAPI AuthFlow wired as a scannable target, not just the driver).
- 2026-09-14 — ZAP is scored by the IDENTICAL harness via an adapter, not judged by hand (D26) — `benchmark/zap_adapt.py` converts ZAP's real JSON report into a `ScanResult` whose findings carry APIGuard's match keys (ZAP alert -> scanner class; concrete URL normalised to the spec template), so `run_eval` scores it with the same ground-truth matcher. The one interpretive layer (`_classify`) prints every alert's disposition for full auditability. Reproducible and defensible; nothing hand-counted.
- 2026-09-14 — ZAP's real-but-out-of-tracked-scope alerts are NOT counted as false positives (D26) — a THIRD bucket ("__oos__") for genuine findings outside the 12 tracked vulns (VAmPI's SQL/stack-trace disclosure on /createdb's 500). Counting a real finding as an FP would misrepresent ZAP; counting it as a TP would need it in the denominator. So they are reported and excluded from scoring. Only genuine noise (a bare 500 status flagged as an alert; "unexpected content-type") counts as ZAP FP. This keeps the comparison fair to the external baseline.
- 2026-09-14 — Ablation arms are a nested capability ladder (D26): static = static payloads; ai = ai payloads; ai+repair = +self-repair; full = ai+repair+BOLA/BFLA engine. Each adds exactly one capability so a recall delta attributes to that capability. The engine delta (ai+repair 0.42 -> full 0.67) is the crown jewel's measured contribution. Honest nuances recorded: on VAmPI ai==ai+repair in both recall AND requests (repair fired 0 extra requests — no 400s to repair), and ai beats static only on requests (63 vs 71), not recall (VAmPI's vulns are all statically findable). A recall gap between ai and static needs a target with validation-gated params (crAPI).
- 2026-09-14 — ZAP gotchas that cost real time, recorded so D28 demo/re-runs don't repeat them: (1) `-J`/file output REQUIRES `/zap/wrk` mounted AND world-writable (named volume is root-owned -> `chmod 777` it via a busybox one-shot). (2) VAmPI's OpenAPI `servers:[{url:""}]` makes ZAP resolve every path against the SPEC URL (`/openapi.json/users/...` -> 404, empty scan); `-O` override did NOT fix it — the reliable fix is to feed a LOCAL spec file with `servers` rewritten to the real base (`http://host.docker.internal:5000`). (3) Git Bash mangles container paths -> prefix docker commands with `MSYS_NO_PATHCONV=1`. The ZAP image is kept locally (3.7GB) for reproducibility.
- 2026-09-14 — HTML report is a jinja2 library consumer with autoescaping ON (D27) — `report/generator.py` renders `template.html`; the CLI's `--report` calls it. Autoescape is a SECURITY requirement, not cosmetics: findings embed real response bodies that can carry attacker markup (reflected XSS payloads, `<script>`), so the report must render them inert or it becomes an XSS vector when opened. `tests/test_report.py` asserts a `<script>` body escapes to `&lt;script&gt;`. Only `{{ }}`-escaped fields are rendered; request/response HEADERS are intentionally not rendered.
- 2026-09-14 — Report is a single self-contained HTML file, inline CSS only, no external fonts/scripts/CDN (D27) — it must open offline for the wifi-off demo (Week-5 requirement) and be emailable as one file. The AI oracle trace (model/seed/temp + the 5 confidence signals as bars + the prompt and raw schema-validated response in a collapsible) is the explainability centerpiece and is shown for every finding carrying an `ai_trace`. Confidence renders as a bar and is labelled "computed from signals" (invariant 5 messaging).
- 2026-09-14 — Dashboard is driven by SAVED artifacts, not a live scan (D28) — "cassette-backed / runs with wifi off" is satisfied most robustly by reading the committed result JSONs + ground truth (a live scan needs VAmPI+Ollama, and Ollama traffic isn't cassettable anyway, so a cassette replay couldn't show the BOLA/AI findings). The dashboard is offline-by-construction: no outbound calls in the code path, Streamlit serves its own local assets, launched with `--browser.gatherUsageStats false`. This also makes the demo deterministic (no qwen3 cross-session drift at demo time).
- 2026-09-14 — Streamlit testability: pure data-prep helpers live at module top (no `st.`), all UI inside `main()`, guarded by `if __name__ == "__main__"` (streamlit runs the script AS __main__, so main() fires under `streamlit run` but NOT on import) — so `tests/test_dashboard.py` imports the module and tests the helpers without a Streamlit runtime. streamlit is imported inside `main()` to keep import cheap.
- 2026-09-14 — Dropped pandas from the dashboard rather than declaring it (D29) — pandas was imported only by the dashboard and only transitively present via streamlit (undeclared direct dep). Since every value shown is in [0,1], `st.progress` bars replace the pandas bar charts (clearer, labelled) and `st.dataframe` takes a list-of-dicts directly. Net: one fewer dependency, no Section-3 change, and a better-looking chart. (Confirmed by the audit: pandas is now the ONLY case and it's gone; every other third-party import is declared.)
- 2026-09-14 — Re-recorded `cassettes/vampi/` at D29 — the D12 recording predated the D18 boolean-SQLi payloads, so `--replay` hit a cassette miss. Re-recorded a current STATIC scan (AI/BOLA traffic isn't cassettable — Ollama). Verified offline: `docker stop vampi` then `scan --replay` -> 5 findings. This is the offline demo backbone for D30.
- 2026-09-14 — v1.0 cleanup driven by a 4-agent audit workflow grounded against the LIVE tree (D29) — 3 parallel auditors (core/scanners, ai/engines/report, benchmark/tests/packaging) + a completeness/synthesis critic that re-ran the clone->install->run path in a fresh venv and confirmed no unresolved stranger-blocker. 16/19 items fixed, 2 false alarms (already-fixed pandas + README-stub, both stale vs the working tree), 1 stale test comment. Lesson re-confirmed: agents PROPOSE, the author fixes + verifies; the synthesis-against-current-state catch (not the audit's snapshot quotes) prevented re-opening resolved items.

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
