# Doppel — Detecting 200-OK Authorization Flaws with a Local LLM Oracle

**A semantic BOLA/IDOR scanner for REST APIs**
Author: **Mayurdhvajsinh** · 3rd-semester mini-project · v1.0

---

## Abstract

Broken Object Level Authorization (BOLA, a.k.a. IDOR) is the #1 risk in the OWASP
API Security Top 10, and it is uniquely hard to detect automatically: a successful
cross-user data leak returns a perfectly normal `200 OK`, so scanners that reason
about HTTP status codes or error signatures are blind to it. **Doppel** parses an
OpenAPI specification, authenticates as two independent users, and — instead of
guessing from the status code — uses a **locally-hosted LLM as a semantic oracle**
to adjudicate whether one user's cross-access actually returned another user's data.
Crucially, the model is called **only on genuinely ambiguous cases** (deterministic
gates resolve the rest), its output is **schema-constrained** (never free-text
parsed), and the reported **confidence is computed from measurable signals**, never
asked of the model. On the VAmPI benchmark, against a hand-verified ground truth of
12 known vulnerabilities, Doppel's full pipeline achieves **0.67 recall at 1.00
precision** — nearly **4× the recall of OWASP ZAP (0.17)** — with the entire gain
coming from three authorization / data-exposure flaws that return `200 OK`. The same engine, run
unmodified, confirms a real BOLA on the OWASP crAPI target.

---

## 1. Introduction

Modern applications are increasingly thin clients over REST/JSON APIs, and the
attack surface has moved with them. The OWASP API Security Top 10 (2023) ranks
**API1: Broken Object Level Authorization** first. A BOLA flaw exists when an
endpoint uses a client-supplied object identifier (`/books/v1/{title}`,
`/vehicle/{uuid}/location`) to fetch a resource **without checking that the caller
is authorized to access that specific object**. The attacker simply substitutes
another user's identifier and receives their data.

What makes BOLA pernicious for *automated* detection is that a successful attack is
indistinguishable, at the HTTP layer, from a legitimate request: same method, same
shape of response, and a `200 OK`. There is no error to grep for and no status code
to branch on. Generic scanners — which are built around request/response signatures,
error strings, and status codes — therefore miss it. Confirming a BOLA requires
**semantic** reasoning: *did User B, by requesting User A's object, actually receive
User A's data?*

**Contribution.** This project contributes three things, treated as inseparable:

1. **A BOLA engine** that discovers objects provably owned by one user, replays the
   access as a second user, and adjudicates the result.
2. **An AI response oracle** — a local LLM used, under strict controls, to make the
   semantic *leak / not-a-leak* judgment that status codes cannot.
3. **A benchmark harness** that scores the tool against a hand-verified ground truth
   and against an external baseline (OWASP ZAP), turning the claim "we detect BOLA"
   into a measured precision/recall result.

Everything else — the baseline SQLi/XSS/JWT/misconfig scanners — exists as the
*control group* for that measurement.

---

## 2. Background

**BOLA / IDOR.** Broken Object Level Authorization is the authorization failure
above; IDOR (Insecure Direct Object Reference) is the classic name for the same bug.
It is an *authorization* defect, not an *authentication* one: the caller is a valid,
logged-in user — just not the owner of the object they are reading.

**Why status/error scanners miss it.** Injection flaws often surface as a database
error (`sqlite3.OperationalError`) or a `500`; a missing security header is directly
observable; a weak JWT is testable by forging a token and checking for acceptance.
BOLA has none of these tells. The only evidence is the *content* of a `200 OK`
response and whether it belongs to a different user — a judgment about meaning.

**LLMs as a security oracle — and the risks.** A language model can make that
content judgment, but naively wiring an LLM into a scanner is indefensible: models
hallucinate, their free-text output is unparseable, their stated "confidence" is a
plausible token rather than a probability, and their responses are non-deterministic.
Doppel's design is largely a set of guardrails that make LLM use *defensible* (§3).

**Test targets.** [VAmPI](https://github.com/erev0s/VAmPI) (a deliberately
Vulnerable API) is the primary benchmark; [OWASP crAPI](https://github.com/OWASP/crAPI)
is a second, harder target used to show the engine generalizes.

---

## 3. Design and Architecture

```
OpenAPI spec ─► parse ─► two-user login ─► baseline scanners ─► BOLA/BFLA engine ─► report
                                          (SQLi, XSS, JWT,      (the contribution:
                                           misconfig, rate-limit) discover→cross-access
                                                                  →gate→oracle→confidence)
```

### 3.1 Hard invariants

The system is built around nine invariants that make it defensible in a viva:

- **The engine is a library.** All logic lives in the `doppel` package; the CLI,
  the dashboard, and the benchmark are thin consumers.
- **Never parse LLM free text.** Every model call uses a Pydantic-generated JSON
  schema (Ollama's `format` parameter) and is validated with
  `model_validate_json()`; on failure it retries, then records an inconclusive
  result. No regexes over model output.
- **Pin the seed.** Every LLM call passes a fixed seed; every saved result records
  its model and seed, so runs are reproducible.
- **Deterministic first, LLM second.** The model is invoked *only* on genuinely
  ambiguous cases (§3.3). A scan with the LLM switched off still runs and still
  finds things.
- **Confidence is computed, never asked.** It is a weighted function of measurable
  signals plus the oracle's binary verdict (§3.4).
- **Every finding carries evidence** — full request, full response, and a
  copy-pasteable `curl` reproduction.
- **Scope guard is mandatory** — no request leaves the tool unless the target host
  is in the allowlist; non-localhost targets require an explicit flag.
- **Async everywhere** on the HTTP path (one shared client, rate-limited).
- **Type hints and Pydantic models** on everything crossing a module boundary.

### 3.2 The BOLA engine

For an object endpoint (a `GET` whose path ends in a single `{id}` segment), the
engine establishes ownership two ways: **seeding** (a `POST`-as-A creates an object
A provably owns, with owner-distinctive field values) and **harvesting** (a
collection item whose owner field equals A's username). For each A-owned object it
builds an **access triple**:

- `a_access` — A reading A's own object (the reference for what the data is),
- `b_cross_access` — the attacker B reading A's object (the potential leak),
- `b_control` — B reading B's *own* object at the same endpoint (a legitimate baseline).

### 3.3 The ambiguity gate — deterministic first

The oracle is expensive and fallible, so cheap deterministic checks resolve the
clear cases with **no LLM call**:

```
if b_cross_access.status in (401, 403, 404):    → NOT a leak   (authorization worked)
if b_cross_access.body == b_control.body:        → NOT a leak   (B just saw B's own data)
else:                                            → AMBIGUOUS → call the oracle
```

A design note worth recording: the original gate also cleared a case where the
object id did not appear in B's response body. An adversarial review removed that
clear, because many real endpoints carry the id only in the URL (opaque UUIDs, as in
crAPI), and the shortcut silently dropped genuine `200 OK` leaks. Id presence became
a *confidence signal* (`id_echo`) instead of a hard veto — strictly safer.

### 3.4 The oracle and computed confidence

Only ambiguous triples reach the **oracle**: a schema-constrained yes/no at
temperature 0, with a fixed seed, over the two response bodies (A's own vs B's
cross-access), which are fenced and framed as *untrusted data* in the prompt. The
model returns a validated `{is_leak, leaked_fields, reasoning}` object.

The reported **confidence** is then *computed* — never taken from the model — as a
weight-normalised mean over five measurable signals:

| Signal | Meaning | Weight |
|---|---|---|
| `id_echo` | A's object id appears in B's cross-access response | 0.30 |
| `field_overlap` | Jaccard similarity of top-level keys (A vs B-cross) | 0.20 |
| `body_divergence` | 1 − similarity(B-cross, B-control) | 0.20 |
| `status_match` | B-cross returned the same status as A's own access | 0.10 |
| `oracle_verdict` | the LLM's binary 1.0 / 0.0 | 0.20 |

Weights live in config, so the scoring is tunable and defensible. The oracle is one
signal among five — it can never *be* the confidence.

### 3.5 BFLA

A companion engine detects **Broken Function Level Authorization** (API5): it flags
privileged endpoints (path segments like `admin`, `_debug`, `internal`) reachable by
a low-privilege user, escalating to CRITICAL when the response leaks credential-like
fields. It is deterministic (no oracle) and reported separately.

---

## 4. Implementation

**Stack (fixed):** Python 3.11, `httpx` (async), Pydantic v2, `pydantic-settings`,
Ollama + the `ollama` client, Typer + Rich (CLI), Jinja2 (report), Streamlit
(dashboard), `pytest` + `respx` (tests). **Model:** `qwen3:8b`, one model in two
roles — payload generation at temperature 0.8, the oracle at temperature 0.0.

Two implementation details were essential for reliability. First, `qwen3:8b` "thinks"
by default and the inline `/no_think` token is ignored through the CLI; the engine
passes `think=False` to the API call, which — with `format=<schema>` — yields clean,
schema-valid JSON. Second, HTTP is recorded to **cassettes**, so a whole scan (spec
fetch + auth + scanners) can be re-run **offline** with the target stopped; this
backs the demo and the fast tests (which use `respx` and never touch a live target).

The codebase is roughly two dozen modules with **136 tests**. An HTML report generator renders each
finding — with, for AI-adjudicated findings, the full oracle trace (model, seed,
temperature, the five signals, the prompt and the raw response) — as a single
self-contained, autoescaped HTML file that opens offline.

---

## 5. Evaluation

### 5.1 Methodology

Detection quality is measured against **`benchmark/ground_truth.yaml`**, a
hand-verified list of the target's real vulnerabilities. Each entry was confirmed
against the live target (e.g. the mass-assignment flaw by registering `admin:true`
and observing `admin:true` on `/me`; the unauthorized password change by having one
user reset another's password). Crucially, the ground truth **includes vulnerabilities
Doppel cannot detect** (mass assignment, unauthorized password change, user/password
enumeration, RegexDOS) as honest false negatives — so recall is not inflated by
pretending the tool's blind spots do not exist. VAmPI's ground truth is 12 vulns; 8
are within Doppel's detection classes and 4 are inherent false negatives.

A single command, `python benchmark/run_eval.py`, joins each scan's findings to the
ground truth — global findings (JWT, rate-limit) match on scanner alone; the two
misconfiguration findings by a stable id substring; the object-level findings by
scanner + endpoint — and computes, per arm:

> **TP** = known vulns matched · **FP** = findings matching no known vuln ·
> **FN** = known vulns unmatched · **precision** = TP/(TP+FP) · **recall** =
> TP/(TP+FN).

The four Doppel arms form a **nested capability ladder**, each adding one
capability, so a recall delta attributes to that capability:

1. **Static** — static wordlist payloads.
2. **AI** — LLM-generated, context-tailored payloads.
3. **AI + repair** — plus a self-repair loop that fixes validation-rejected payloads.
4. **Full** — plus the BOLA/BFLA engine (the contribution).

**OWASP ZAP** is the external baseline, run in Docker with its spec-driven API scan
(the same OpenAPI spec Doppel uses) and scored through the *identical* harness via
an adapter that maps each ZAP alert to the ground-truth classes and prints every
alert's disposition for audit.

### 5.2 Results (VAmPI)

| Arm | Recall | Precision | F1 | Requests |
|---|---|---|---|---|
| Static wordlist payloads | 5/12 (0.42) | 1.00 | 0.59 | 71 |
| AI-generated payloads | 5/12 (0.42) | 1.00 | 0.59 | 63 |
| AI + self-repair | 5/12 (0.42) | 1.00 | 0.59 | 63 |
| **Full (incl. BOLA engine)** | **8/12 (0.67)** | **1.00** | **0.80** | 82 |
| OWASP ZAP (external baseline) | 2/12 (0.17) | 0.50 | 0.25 | n/a |

### 5.3 Discussion

**The BOLA/BFLA engine is the entire recall gain.** All four Doppel arms find the
same five statically-detectable vulns (weak JWT secret, SQLi, two misconfigurations,
missing rate-limiting) at perfect precision. The Full arm adds exactly three findings
— a book-secret BOLA, a public-user-record BOLA, and an `_debug` BFLA — lifting recall
from 0.42 to **0.67 at 1.00 precision**. All three return `200 OK`; none is visible
to a status/error scanner.

**Versus OWASP ZAP.** ZAP achieves 0.17 recall: it finds the missing headers and
version disclosure, but **misses every authorization flaw**, the SQLi (its active
injection scanner produced no alert on the vulnerable parameter — it only passively
noticed SQL leaking from a `500` on the DB-reset endpoint), the weak JWT, and
rate-limiting. Most tellingly, ZAP
*retrieved the `/users/v1/_debug` endpoint that dumps every user's password, and the
cross-user data, and flagged nothing* — because it has no notion that those responses
are unauthorized. Its two false positives are low-signal noise (a bare `500` flagged
as an alert; an unexpected content-type). Doppel's Full arm nearly **quadruples**
ZAP's recall at double its precision.

**The AI payload arm's honest story.** On VAmPI the AI arm reaches the *same* recall
as static (all of VAmPI's injectable flaws are findable with generic payloads); its
measured advantage is **efficiency** — ~11% fewer requests (63 vs 71) via targeted,
context-tailored payloads. The self-repair loop fired zero extra requests here (no
payloads were rejected); its payoff is on targets with typed/validated fields.

**A second target — crAPI.** The same oracle + confidence engine, run unmodified,
confirmed a real BOLA on crAPI's `GET /identity/api/v2/vehicle/{vehicleId}/location`
— any authenticated user reads any vehicle's GPS, owner name and email by UUID. The
engine flagged it `is_leak=True`, HIGH, **confidence 0.8547** from all five signals,
with **zero false positives** (a legitimate self-access was cleared by the gate with
no LLM call). Because crAPI's objects are email-gated rather than POST-created, the
generic discoverer cannot auto-seed them, so the two owner→object bindings were
supplied from crAPI's own API and the *contribution* (gate + oracle + scoring) ran
untouched — an honest split between target-specific plumbing and the general engine.

---

## 6. Limitations and threats to validity

- **VAmPI's non-BOLA vulns are all statically findable**, so the AI payload arm
  cannot show a *recall* advantage there (only an efficiency one). A target with
  validation-gated parameters would be needed to demonstrate an AI recall gain.
- **The crAPI result is a single validated endpoint**, not a full scan (recall
  0.20 of its documented set). Object *discovery* on crAPI is target-specific; the
  adjudication engine is not.
- **LLM determinism is within-session.** A pinned seed makes a run reproducible, but
  outputs can drift across model/server reloads; the committed result files are
  therefore the canonical measurements, and the dashboard reads those.
- **The offline cassette replay covers the deterministic scanners only.** Ollama
  traffic is not recorded, so the AI-payload and BOLA arms are not cassette-replayable
  and need Ollama live; their committed result files are the canonical measurements.
- **Ground truth is hand-authored** for two targets; the absolute recall numbers are
  relative to that labelling (though it was independently verified and deliberately
  includes the tool's blind spots).
- **Residual prompt-injection surface.** Response bodies are fenced and framed as
  untrusted in the oracle prompt, which is a mitigation, not a proof; this is a
  documented limitation.

---

## 7. Reproducibility

Every LLM call pins a seed; every saved result records its model and seed. The full
**offline** story — `pytest` (respx-mocked), `python benchmark/run_eval.py`,
`streamlit run dashboard.py`, and `doppel scan --replay cassettes/vampi/` (verified
with VAmPI stopped) — runs with no network and no Ollama. The live path
(`doppel scan --bola`) needs VAmPI (`docker run -d -p 5000:5000 erev0s/vampi`) and
Ollama with `qwen3:8b`. Install is `pip install -e ".[dev]"`; the tool, tests, and
data are all in the repository at tag **v1.0**.

The `apiguard_*` identifiers that remain in the code (the seeded test usernames, the
BOLA seed prefix, the `@apiguard.test` domain, the `apiguardXSS` marker) are retained
legacy naming from before the APIGuard→Doppel rename, preserved intentionally so the
recorded cassette and the committed benchmark results stay valid — they are test-fixture
data, not the product name.

---

## 8. Conclusion and future work

Doppel demonstrates that a **locally-hosted LLM, used under strict guardrails**
(deterministic-first gating, schema-constrained output, computed-not-asked
confidence), turns the hardest-to-automate API vulnerability class — the `200 OK`
authorization leak — into a measurable, evidence-backed finding. On VAmPI it detects
**8 of 12** known vulnerabilities at **perfect precision**, versus **2 of 12** for
OWASP ZAP, with the entire difference being authorization flaws that generic scanners
are structurally blind to.

**Future work:** generalize object discovery to email-gated resource models (to lift
the crAPI recall beyond a single endpoint); add write-side authorization testing
(the current engine adjudicates cross-user *reads*); and evaluate additional local
models to quantify the oracle's sensitivity to model choice.

---

## References

1. OWASP API Security Top 10 (2023). https://owasp.org/API-Security/
2. VAmPI — a Vulnerable API (erev0s). https://github.com/erev0s/VAmPI
3. OWASP crAPI — Completely Ridiculous API. https://github.com/OWASP/crAPI
4. OWASP ZAP. https://www.zaproxy.org/
5. Ollama. https://ollama.com/

*Full engineering log: `BRAIN.md` (design + decisions) and `docs/journal.md`
(one entry per working day).*
