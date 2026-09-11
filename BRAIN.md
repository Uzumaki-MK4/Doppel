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
│   ├── settings.py             pydantic-settings config loader
│   ├── core/
│   │   ├── models.py           Finding, Endpoint, Parameter, ScanResult
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
- [ ] **D1** Repo, venv, deps, VAmPI in Docker, Ollama + model pulled. *Done when: `ollama run <model> "hi"` works and VAmPI's spec loads.*
- [ ] **D2** `core/models.py`. *Done when: a `Finding` can be built in a REPL and serialized.*
- [ ] **D3** `core/spec_parser.py` incl. `$ref` resolution. *Done when: `apiguard parse <url>` tables every endpoint + params.*
- [ ] **D4** `core/http_engine.py`. *Done when: every VAmPI endpoint can be hit and returns a status.*
- [ ] **D5** `core/identity.py`, two users. *Done when: both users hold valid tokens and can call an authed endpoint.*
- [ ] **D6** `cli.py` + rich progress. *Done when: `apiguard scan --dry-run` parses, logs in both users, touches every endpoint.*

### Week 2 — Baseline scanners (compressed on purpose, do not gold-plate)
- [ ] **D7** `scanners/base.py` ABC + registry. *Done when: a dummy scanner is auto-discovered.*
- [ ] **D8** `scanners/injection.py` (SQLi + XSS). *Done when: finds VAmPI's known SQLi.*
- [ ] **D9** `scanners/ssrf.py` + `scanners/jwt_attacks.py`. *Done when: JWT module flags a real weakness.*
- [ ] **D10** `scanners/misconfig.py` + `scanners/rate_limit.py`. *Done when: full baseline scan produces a findings list.*
- [ ] **D11** Dedup, severity, OWASP mapping, evidence capture. *Done when: no dupes, every finding has a curl repro.*
- [ ] **D12** pytest + respx, first cassettes. *Done when: pytest green, `benchmark/results/baseline.json` saved.*

### Week 3 — AI layer
- [ ] **D13** `ai/client.py` with schema enforcement + retry + logging. *Done when: 20/20 calls return valid objects.*
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

**Current day:** Day 0 — nothing built yet.
**Last session:** none.
**Completed:** nothing.
**In progress:** nothing.
**Blocked / broken:** nothing.
**Next action:** Day 1 setup.

**Environment facts discovered** (fill these in as we learn them):
- GPU / VRAM: *unknown — ask the user*
- Model actually in use: *not yet pulled*
- VAmPI spec URL: `http://localhost:5000/openapi.json` (unverified)
- Python version: *unverified*

---

## 9. Decision log

> Append one line per non-obvious decision. Format: `YYYY-MM-DD — decision — why`.

- 2026-09-12 — CLI engine + Streamlit shell rather than a web app — the engine is the contribution; a web app would consume two of five weeks on non-contribution work.
- 2026-09-12 — One model, two temperatures, rather than two models — halves VRAM for no capability loss.
- 2026-09-12 — Confidence computed from signals, not requested from the model — an LLM's stated confidence is a plausible token, not a probability, and claiming otherwise is indefensible in a viva.
- 2026-09-12 — Week 2 scanners deliberately compressed — they are commodity and exist only as the control group for the ablation.

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
