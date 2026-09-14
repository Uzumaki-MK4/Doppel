# Doppel — Execution Plan

3rd-semester mini project · 5 weeks · 30 working days

---

## Part 1 — What exactly are we building?

**A Python command-line tool, with a Streamlit dashboard bolted on top as a presentation layer, that outputs a self-contained HTML report.**

Not a website. Not a client-server web app. Here is why that choice is correct for you:

| Option | Verdict |
|---|---|
| Web app (FastAPI backend + React frontend) | Rejected. You would spend 2 of your 5 weeks on auth, CORS, state sync and deployment. None of that is the project. |
| CLI only | Correct engineering choice, but a terminal demo in a viva is weak. |
| Streamlit only | Fast to demo, but you cannot script it, cannot run it in CI, and cannot build an automated benchmark on top of it. |
| **CLI engine + Streamlit shell + HTML report** | **Pick this.** |

The important design rule: **the engine must be a library, not a script.** Everything lives in a package called `doppel`. The CLI imports it. Streamlit imports it. Your benchmark harness imports it. You write the logic once and get three faces for free.

```
                    +------------------+
                    |  doppel/core   |  <- all the real logic lives here
                    +--------+---------+
             +---------------+---------------+
             |               |               |
      +------v-----+  +------v------+  +----v--------+
      | cli.py     |  | dashboard.py|  | benchmark/  |
      | (Typer)    |  | (Streamlit) |  | (evaluation)|
      +------------+  +-------------+  +-------------+
```

**Three artifacts you hand in at the end:** the tool itself (GitHub repo), the HTML scan report, and a results table proving it works.

---

## Part 2 — Language and stack

### Language: Python 3.11+ and nothing else

No second language. The only non-Python files are a Jinja2 HTML template and a couple of YAML configs. Python 3.11 specifically because of `asyncio.TaskGroup` and `tomllib`, both of which you will use.

### Dependencies (keep this list short on purpose)

| Layer | Library | Why this one |
|---|---|---|
| HTTP client | `httpx` | Async, HTTP/2, connection pooling. You will fire hundreds of requests per scan. |
| Spec parsing | `openapi-spec-validator` + `PyYAML` | Do not hand-roll OpenAPI parsing. It has `$ref` resolution, which is genuinely painful. |
| Data models | `pydantic` v2 | Your `Finding`, `Endpoint`, `Parameter` objects. Also validates the LLM's JSON output, which is the key trick. |
| LLM runtime | Ollama | Local, free, one-line model swaps. |
| LLM client | `ollama` (official Python package) | Supports the `format` parameter for schema-constrained output. |
| CLI | `typer` + `rich` | `typer` gives you flags for free; `rich` gives you a live progress table that looks great on screen. |
| Dashboard | `streamlit` | Full UI in one file, roughly one day of work. |
| Report | `jinja2` | HTML template rendering. |
| Testing | `pytest` + `respx` | `respx` mocks `httpx` so your tests do not need a live target. |
| Config | `pydantic-settings` + YAML | Target URL, credentials, model name, scan profile. |

```
pip install httpx pydantic pydantic-settings openapi-spec-validator ollama \
            typer rich streamlit jinja2 pytest respx pyyaml
```

That is it. Resist adding more.

### Test targets

| Target | Use it for | Setup |
|---|---|---|
| **VAmPI** | Primary dev target. Small, fast, clear BOLA and SQLi bugs. | `docker run -p 5000:5000 erev0s/vampi` |
| **crAPI** | Secondary. OWASP official, more realistic, has real BFLA and SSRF. | `docker compose up` (heavier, ~4GB RAM) |

Start with VAmPI on day 1. Bring crAPI in during week 4. Do not try to run both from the start.

---

## Part 3 — Model selection

### The design decision most people get wrong

You have **two separate LLM jobs** with opposite requirements:

| Job | What it needs | Temperature |
|---|---|---|
| **Payload generator** | Creativity, variety, willingness to produce attack strings | 0.7 to 0.9 |
| **Response oracle** | Determinism, strict schema adherence, no creativity at all | 0.0 |

Do **not** use two different models. Use **one model with two system prompts and two temperature settings**. Loading two 7B models doubles your VRAM for no benefit, and the oracle job is a classification task that any decent instruct model handles.

### Which model to pull

Pick your row based on the GPU you actually have:

| Your hardware | Model | Ollama command | Notes |
|---|---|---|---|
| 8GB+ VRAM (RTX 3060 / 4060 and up) | **Qwen 3 8B** | `ollama pull qwen3:8b` | **Recommended default.** Best structured-JSON reliability in the 7-8B class. |
| 6GB VRAM (GTX 1660 / RTX 2060) | Qwen 2.5 Coder 7B | `ollama pull qwen2.5-coder:7b` | About 5GB at Q4. Strong on payload syntax. |
| 6GB VRAM, JSON trouble | Llama 3.1 8B | `ollama pull llama3.1:8b` | Safe all-rounder fallback. |
| No GPU / 8GB RAM laptop | Phi-4 Mini 3.8B | `ollama pull phi4-mini` | Works, but expect 5-10s per call and a noticeably weaker oracle. |
| 16GB+ VRAM (if you have access) | gpt-oss:20b | `ollama pull gpt-oss:20b` | Stronger reasoning. Only if the hardware is genuinely there. |

**Tell me your GPU and I will narrow this to one line.** Until then, `qwen3:8b` is the bet.

### The non-negotiable implementation detail

Never parse the model's free text. Use Ollama's `format` parameter with a JSON schema, and validate the result with Pydantic:

```python
class OracleVerdict(BaseModel):
    is_leak: bool
    leaked_fields: list[str]
    reasoning: str

response = ollama.chat(
    model=settings.model,
    messages=[...],
    format=OracleVerdict.model_json_schema(),   # token-level grammar constraint
    options={"temperature": 0.0, "seed": 42},
)
verdict = OracleVerdict.model_validate_json(response.message.content)
```

This single pattern eliminates roughly 80% of the pain people hit when wiring local models into tools. Set `seed` so your results are reproducible, because an examiner may ask you to re-run the scan.

---

## Part 4 — Repository structure

```
doppel/
├── pyproject.toml
├── README.md
├── config.example.yaml
│
├── doppel/
│   ├── __init__.py
│   ├── cli.py                    # Typer entry point
│   ├── settings.py               # pydantic-settings config loader
│   │
│   ├── core/
│   │   ├── models.py             # Finding, Endpoint, Parameter, ScanResult
│   │   ├── spec_parser.py        # OpenAPI -> list[Endpoint]
│   │   ├── http_engine.py        # async httpx wrapper, rate limiting, retries
│   │   ├── identity.py           # multi-user session manager (User A / User B)
│   │   └── scope.py              # target allowlist guard - see Part 6
│   │
│   ├── scanners/
│   │   ├── base.py               # Scanner ABC - every scanner subclasses this
│   │   ├── injection.py          # SQLi + XSS (share one code path)
│   │   ├── ssrf.py
│   │   ├── jwt_attacks.py
│   │   ├── misconfig.py          # headers, CORS, verbose errors
│   │   └── rate_limit.py
│   │
│   ├── ai/
│   │   ├── client.py             # Ollama wrapper + schema enforcement + retry
│   │   ├── prompts.py            # all prompts in one file, versioned
│   │   ├── payload_gen.py        # context-aware payload generation
│   │   ├── repair.py             # self-repair loop
│   │   └── oracle.py             # response adjudication
│   │
│   ├── engines/
│   │   ├── bola.py               # the crown jewel
│   │   └── bfla.py
│   │
│   ├── scoring/
│   │   └── confidence.py         # signal-based confidence - see Part 6
│   │
│   └── report/
│       ├── generator.py
│       └── template.html
│
├── benchmark/                     # your grade lives here
│   ├── ground_truth.yaml         # known bugs in VAmPI + crAPI
│   ├── run_eval.py               # computes precision / recall / F1
│   └── results/                  # generated tables
│
├── dashboard.py                   # Streamlit
├── tests/
└── cassettes/                     # recorded HTTP traffic for offline demo
```

Roughly 2,200 lines. Achievable in five weeks.

---

## Part 5 — Day-by-day plan

Six working days a week, one rest day. Each day has a **Done when** line. If you cannot say yes to it, do not move on.

### Week 1 — Foundation

| Day | Tasks | Done when |
|---|---|---|
| **1** | Create repo, `pyproject.toml`, venv, install deps. Run VAmPI in Docker. Install Ollama, pull your model. Open `/openapi.json` in a browser and read it. | `ollama run qwen3:8b "hi"` works and VAmPI's spec loads in your browser. |
| **2** | Write `core/models.py`: `Endpoint`, `Parameter`, `Finding`, `Severity`, `ScanResult` as Pydantic models. Design this carefully, everything depends on it. | You can construct a `Finding` in a REPL and call `.model_dump_json()` on it. |
| **3** | `core/spec_parser.py`. Parse VAmPI's spec into `list[Endpoint]`. Handle `$ref`, path params, query params, request bodies, security schemes. | `doppel parse <url>` prints a table of every endpoint with its parameters. |
| **4** | `core/http_engine.py`. Async httpx client: send a request built from an `Endpoint`, apply auth headers, timeout, retry, global rate limit. | You can fire every VAmPI endpoint and get a status code back for each. |
| **5** | `core/identity.py`. Register and log in two users programmatically, store their tokens, expose `session_for("userA")`. | Both users hold valid tokens and can call an authenticated endpoint. |
| **6** | `cli.py` skeleton with `typer`, `rich` progress bar. Wire days 3-5 into one `doppel scan --dry-run` command. | One command parses the spec, logs in both users, and touches every endpoint. |

**Week 1 deliverable:** the plumbing works end to end. No vulnerability detection yet, and that is fine.

---

### Week 2 — Baseline scanners (deliberately compressed)

These are commodity. They exist so you have something to compare the AI against. Do not gold-plate them.

| Day | Tasks | Done when |
|---|---|---|
| **7** | `scanners/base.py`: abstract `Scanner` class with `async def run(endpoint) -> list[Finding]`. Build a registry so scanners auto-discover. | A dummy scanner that always returns one finding is picked up by the CLI. |
| **8** | `scanners/injection.py`: SQL injection (error-signature matching + time-delay detection) and reflected XSS (marked input, check reflection) sharing one injection loop. Static wordlists in `wordlists/`. | Finds VAmPI's known SQLi. |
| **9** | `scanners/ssrf.py` (internal ranges, cloud metadata endpoints) and `scanners/jwt_attacks.py` (`alg:none`, signature strip, expired-token replay). | JWT module flags at least one weakness on VAmPI. |
| **10** | `scanners/misconfig.py` (security headers, permissive CORS, stack traces in error bodies) and `scanners/rate_limit.py` (burst N requests, check for 429). | Full baseline scan runs and produces a findings list. |
| **11** | Deduplication, severity assignment, OWASP API Top 10 mapping on `Finding`. Store full request and response evidence on every finding. | No duplicate findings; every finding carries a reproducible `curl` string. |
| **12** | `pytest` + `respx` tests for the parser, http engine, and one scanner. Record your first cassettes. | `pytest` green. Baseline result saved to `benchmark/results/baseline.json`. |

**Week 2 deliverable:** a working conventional scanner. This is your control group.

---

### Week 3 — The AI layer

| Day | Tasks | Done when |
|---|---|---|
| **13** | `ai/client.py`. Ollama wrapper with schema-constrained output, temperature control, seed pinning, timeout, retry-on-invalid-JSON. Log every prompt and response to disk. | Ask for a structured object 20 times; you get 20 valid objects. |
| **14** | `ai/prompts.py`. Write and version the payload-generation prompt. It must receive parameter name, declared type, format, example value, endpoint path, and surrounding schema. Context is what makes this better than a wordlist. | Given `{"name": "user_email", "type": "string", "format": "email"}` it returns email-shaped injection candidates, not generic ones. |
| **15** | `ai/payload_gen.py`. Wire generated payloads into the injection scanner as an alternative payload source, switchable via `--payloads {static,ai,both}`. | `doppel scan --payloads ai` runs end to end. |
| **16** | `ai/repair.py`. Self-repair loop: when a request returns 400/422, feed the error body back to the model, get a corrected payload, retry. Cap at 2 retries per parameter. | A payload initially rejected by input validation gets through on retry at least once, with logs to prove it. |
| **17** | First measurement. Run three scans on VAmPI: static, AI, AI+repair. Save all three to `benchmark/results/`. | Three JSON result files exist with different finding counts. |
| **18** | Buffer and prompt tuning based on day 17 numbers. Write up what you changed and why; this becomes a section of your report. | The AI arm beats the static arm on at least one measure. |

**Week 3 deliverable:** measurable evidence that context-aware generation helps.

---

### Week 4 — BOLA/BFLA engine (this is the project)

Protect this week. If earlier weeks slip, cut scanners, not this.

| Day | Tasks | Done when |
|---|---|---|
| **19** | `engines/bola.py`, resource discovery phase. As User A, call every POST/GET collection endpoint and harvest object IDs from responses. Build a map of `{endpoint: [owned_ids]}`. | You have a list of object IDs that provably belong to User A. |
| **20** | Cross-access phase. For every ID owned by A, replay the matching GET/PUT/DELETE as User B. Record both responses side by side. Include a control request (B accessing B's own object) as your comparison baseline. | You have triples of (A's response, B's cross-access response, B's control response). |
| **21** | `ai/oracle.py`. Prompt the model with the two response bodies, noise stripped, and ask a strict yes/no: does response 2 contain data belonging to a different principal? Schema-constrained, temperature 0. | Oracle correctly flags VAmPI's known BOLA and correctly clears a legitimate access. |
| **22** | `scoring/confidence.py`. Compute confidence from observable signals, not the model's self-report: field-name overlap, whether A's object ID appears in B's response, Jaccard similarity of the two bodies, status-code delta, response-length delta. Combine with the oracle verdict as one weighted vote. | Every BOLA finding carries a score derived from at least four measurable signals. |
| **23** | `engines/bfla.py`. Identify likely privileged endpoints (path contains `admin`, or the spec's security requirements differ) and probe them with the low-privilege user. | BFLA probe runs and reports separately from BOLA. |
| **24** | Run the full engine against crAPI. Fix what breaks on a bigger, messier API. Tune thresholds. | At least one true BOLA found on crAPI with no more than two false positives. |

**Week 4 deliverable:** automated multi-identity authorization testing with calibrated scoring.

---

### Week 5 — Proof, polish, presentation

| Day | Tasks | Done when |
|---|---|---|
| **25** | `benchmark/ground_truth.yaml`: hand-write the known vulnerability list for VAmPI and crAPI from their docs. `benchmark/run_eval.py`: compute precision, recall, F1 per scanner arm. | One command prints your results table. |
| **26** | The ablation run. Four arms: (a) static payloads only, (b) AI payloads, (c) AI + self-repair, (d) full including BOLA engine. Also run OWASP ZAP against the same target as an external baseline. | You have a five-column comparison table with real numbers in it. |
| **27** | `report/generator.py` + `template.html`. Findings grouped by severity, OWASP mapping, full request/response evidence, the AI's reasoning trace per finding, copy-paste `curl` repro. | `doppel scan --report out.html` produces something you would be happy to show. |
| **28** | `dashboard.py`, Streamlit. Config form, live progress, findings table, click-through detail, embedded results chart. Load from saved cassettes so the demo works offline. | Full demo runs from the browser with wifi switched off. |
| **29** | README with install steps and screenshots. Docstrings. `--help` text. Delete dead code. Tag v1.0. | A stranger could clone and run it from the README alone. |
| **30** | Record the demo. Write the project report around your results table. Rehearse the viva answers in Part 8. | Demo video recorded, report drafted. |

---

## Part 6 — Eight upgrades that will meaningfully improve your grade

Ordered by return on effort. The first three matter most.

### 1. The evaluation harness (highest value in the entire project)

Almost every student mini project ends at "here is my tool, watch it run." Yours should end at:

> Against VAmPI's 11 documented vulnerabilities: static payloads recalled 6, AI-generated payloads recalled 9, AI + self-repair recalled 9 using 31% fewer requests. The BOLA engine found 4 authorization flaws that ZAP's baseline scan found 0 of, at 2 false positives.

That paragraph is the difference between a good project and a distinction. It converts a demo into a result. Build `benchmark/` in week 5 and treat it as a first-class deliverable, not a nice-to-have.

### 2. Deterministic first, LLM second

Do not call the model on every request. Call it only where cheap heuristics are ambiguous.

- B's cross-access returns 401/403 -> not a leak. No LLM call.
- B's response is byte-identical to B's control response -> not a leak. No LLM call.
- B's response contains A's object ID and fields absent from B's control -> ambiguous, call the oracle.

This cuts scan time by an order of magnitude, makes the tool usable without a GPU, and gives you a clean answer when the examiner asks "what if the model is unavailable?" It degrades to a heuristic scanner and still works.

### 3. Derive confidence, never ask for it

Your original plan promised "92% confidence." An LLM asked for a confidence number produces a plausible-looking token, not a probability. If an examiner knows this and you claim otherwise, it is the worst moment of your viva.

Compute it instead from signals you can defend, then show a calibration check: bucket your findings by predicted confidence and report what fraction in each bucket were actually true positives. Even a rough calibration table from 20 findings is a genuinely sophisticated thing for a 3rd-semester project to contain.

### 4. Record/replay cassettes

Save every request/response pair from a real scan to disk. Add `--replay cassettes/vampi/` so the entire scan re-runs from disk with zero network access. Two payoffs: your tests run in milliseconds, and your live demo cannot be killed by bad wifi or a Docker container that dies five minutes before your presentation.

### 5. A scope guard

`core/scope.py`: the tool refuses to send a single request unless the target host matches an explicit allowlist in the config, and requires a `--confirm-authorized` flag for any non-localhost target.

This costs you 40 lines. It tells an examiner you understand you have built an offensive tool and thought about misuse before they had to ask. It also stops you accidentally scanning your college network while debugging at 2am.

### 6. An explainability trace

Every AI-derived finding stores the exact prompt sent, the model and seed used, the raw response, and the signal values that fed the confidence score. Render this in a collapsible section of the HTML report.

The standard criticism of any LLM-in-the-loop system is "it is a black box." Being able to open the box on stage neutralizes that completely.

### 7. Quantization ablation

A cheap bonus result. Run the oracle at Q4 and Q8 of the same model and report the accuracy difference. Thirty minutes of work, and it gives you a second results table plus a real finding about local-model deployment tradeoffs.

### 8. Keep an engineering journal

`docs/journal.md`, one short entry per working day: what you built, what broke, what you decided and why. Come report-writing time in week 5, your methodology section is already written. Come viva time, you can answer "why did you choose X?" without improvising.

---

## Part 7 — Risk management

**If you fall behind, cut in this order:**

1. BFLA detector (day 23) - BOLA alone is enough
2. Rate limit and SSRF scanners - least interesting findings
3. Streamlit dashboard - demo from the CLI with `rich`, it still looks good
4. crAPI - VAmPI alone is a valid evaluation target

**Never cut:** the BOLA engine, the oracle, or the benchmark harness. Those three are the project.

**Known trouble spots:**

| Risk | Mitigation |
|---|---|
| `$ref` resolution in OpenAPI specs eats a day | Use the library's resolver, do not hand-roll it |
| Model returns malformed JSON | Schema-constrained `format` parameter + Pydantic + retry (day 13) |
| BOLA engine cannot find object IDs to test | Add a manual `seed_objects` config section as a fallback |
| crAPI will not run on your machine | Needs ~4GB RAM and several containers. Test it early in week 4, not on day 24. |
| False positives flood the results | Tune the ambiguity gate from upgrade 2, not the oracle prompt |

---

## Part 8 — Three questions you will be asked, and your answers

**"How do you know your AI payloads are actually better?"**
Point at the ablation table. Static vs AI vs AI+repair, same target, same ground truth, seeds pinned.

**"Isn't the LLM just guessing?"**
Show the explainability trace and the calibration table. The verdict is one weighted signal among five measurable ones, and here is how often each confidence band was correct.

**"Doesn't Akto already do BOLA detection?"**
Yes, and say so immediately, because pretending otherwise is fatal. Your contribution is narrower and defensible: semantic response adjudication using a local model for the ambiguous cases that status-code heuristics cannot resolve, with a calibrated confidence score and a published evaluation against ground truth. Nobody has published that evaluation for a locally-hosted 8B model.

---

## Day 1 starts here

```bash
mkdir doppel && cd doppel
python3.11 -m venv .venv && source .venv/bin/activate
pip install httpx pydantic pydantic-settings openapi-spec-validator ollama \
            typer rich streamlit jinja2 pytest respx pyyaml

docker run -d -p 5000:5000 erev0s/vampi
curl http://localhost:5000/openapi.json | python -m json.tool | head -50

ollama pull qwen3:8b
ollama run qwen3:8b "Return only JSON: {\"ok\": true}"
```

If all four of those work, you have finished day 1.
