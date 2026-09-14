# 🛡️ Doppel

**An AI-powered API authorization scanner that finds the flaws mature scanners miss.**

Doppel parses an OpenAPI spec, attacks every endpoint, and uses a **locally-hosted
LLM** to (a) generate context-aware attack payloads and (b) adjudicate whether a
cross-user access actually *leaked data* — detecting **BOLA / IDOR** flaws that
return a normal `200 OK` and are therefore invisible to status-code-based scanners.

> 3rd-semester academic mini-project. Author: **Mayurdhvajsinh**.
> The full design + execution log lives in [`BRAIN.md`](BRAIN.md) and [`docs/journal.md`](docs/journal.md).

---

## The result

Measured on [VAmPI](https://github.com/erev0s/VAmPI) against a hand-verified ground
truth of 12 known vulnerabilities (`benchmark/ground_truth.yaml`), scored by one
command (`python benchmark/run_eval.py`):

| Arm | Recall | Precision | Requests |
|---|---|---|---|
| Static wordlist payloads | 5/12 (0.42) | 1.00 | 71 |
| AI-generated payloads | 5/12 (0.42) | 1.00 | 63 |
| AI + self-repair | 5/12 (0.42) | 1.00 | 63 |
| **Full (incl. BOLA engine)** | **8/12 (0.67)** | **1.00** | 82 |
| OWASP ZAP (external baseline) | 2/12 (0.17) | 0.50 | n/a |

The **BOLA/BFLA engine lifts recall from 0.42 to 0.67 at perfect precision** — nearly
**4× OWASP ZAP** — by catching three authorization flaws (a book-secret BOLA, a
public-user BOLA, and an `_debug` BFLA) that return `200 OK`. ZAP retrieved the
`/users/v1/_debug` password dump and cross-user data and flagged *nothing*: it cannot
reason about authorization. That gap is the whole point of this project.

---

## How it works

```
OpenAPI spec ─► parse ─► two-user login ─► baseline scanners ─► BOLA/BFLA engine ─► report
                                          (SQLi, XSS, JWT,      (the crown jewel)
                                           misconfig, rate-limit)
```

The **BOLA engine** is the contribution. For an object owned by User A it builds a
triple — *A's own access, B's cross-access, B's control* — and runs a **deterministic
gate first**: a rejected cross-access (401/403/404) or a body identical to B's own
control is cleared with **no LLM call**. Only genuinely ambiguous `200 OK` cases go to
the **oracle** — a schema-constrained yes/no at temperature 0, pinned seed. Confidence
is then **computed** from five measurable signals (`id_echo`, `field_overlap`,
`body_divergence`, `status_match`, `oracle_verdict`) — never asked of the model.

**Design invariants** (see `BRAIN.md` §2): the engine is a library (`cli.py`,
`dashboard.py`, `benchmark/` are thin consumers); LLM output is always schema-validated
JSON, never regexed; every LLM call pins a seed; the model is called only on ambiguous
cases; every finding carries full evidence + a `curl` reproduction; no request leaves
the tool unless the target host is in the config allowlist.

---

## Requirements

- **Python 3.11+**
- **[Ollama](https://ollama.com)** running locally, with a model pulled (default `qwen3:8b`)
- **Docker** (for the VAmPI test target)

## Setup

```bash
# 1. Create and ACTIVATE a virtual environment (activation is important — see the note below)
python -m venv .venv
#    Windows (PowerShell):   .\.venv\Scripts\Activate.ps1
#    Linux / macOS:          source .venv/bin/activate

# 2. Install the package (editable) with test tools
pip install -e ".[dev]"

# 3. Start the test target and pull the model
docker run -d -p 5000:5000 --name vampi erev0s/vampi
ollama pull qwen3:8b

# 4. (optional) copy the config template; the built-in defaults already target VAmPI
cp config.example.yaml config.yaml
```

> **Windows / PATH note (important).** The `doppel`, `pytest` and `streamlit`
> commands are installed **inside `.venv\Scripts`**, not on your global PATH. **Activate
> the venv first** (step 1) and they work as written below. If PowerShell blocks
> activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once, or
> call the tools by full path without activating, e.g.
> `.\.venv\Scripts\streamlit.exe run dashboard.py`.

## Usage

```bash
# List every endpoint + its parameters
doppel parse http://localhost:5000/openapi.json

# Full scan: AI payloads + self-repair + the BOLA/BFLA engine, write an HTML report
doppel scan --spec http://localhost:5000/openapi.json --payloads ai --repair --bola --report out.html

# Baseline scan (static payloads, no engine)
doppel scan --spec http://localhost:5000/openapi.json --payloads static --no-repair

# Offline demo — replay a recorded scan with the target stopped
doppel scan --replay cassettes/vampi/

# Score every saved arm against the ground truth (the ablation table above)
python benchmark/run_eval.py            # add --details for per-arm detected/missed lists

# Interactive dashboard (offline — reads the committed results)
streamlit run dashboard.py
```

`scan` flags: `--payloads {static,ai,both}`, `--repair/--no-repair`,
`--bola/--no-bola`, `--out result.json`, `--report out.html`, `--record DIR` /
`--replay DIR` (offline cassettes), `--confirm-authorized` (required for any
non-localhost target — the scope guard is not optional).

## Tests

```bash
pytest -q          # 136 tests; uses respx to mock HTTP — no live VAmPI needed
```

---

## Reproducibility

Every LLM call passes a fixed `seed`, and every saved result records its `model` and
`seed`, so a run can be re-created and an examiner can re-run it. Caveat: Ollama is
deterministic *within* a session but output can drift across model/server reloads — so
the committed `benchmark/results/*.json` are the canonical measurements, and the
dashboard reads those (it never re-scans) so the demo is stable and works offline.

> **Note on `apiguard_*` names.** A few identifiers in the code — the seeded test
> usernames (`apiguard_a`/`apiguard_b`), the BOLA seed prefix (`apiguard-<owner>-<field>`),
> the `@apiguard.test` email domain, and the `apiguardXSS` marker — are **retained legacy
> naming from before the APIGuard→Doppel rename**, kept deliberately so the recorded
> cassette and the committed benchmark results stay valid. They are test-fixture data, not
> the product name.

## A second target: crAPI (optional)

The BOLA oracle + confidence engine generalize to [crAPI](https://github.com/OWASP/crAPI).
`benchmark/crapi_bola.py` validates a real crAPI BOLA
(`GET /identity/api/v2/vehicle/{vehicleId}/location` leaks any user's location) through
the *unmodified* engine — see `BRAIN.md` §8 for the crAPI setup notes.

## Project layout

```
doppel/            the engine (library)
  core/              models, spec parser, http engine, identity, scope guard, findings
  scanners/          injection (SQLi/XSS), jwt, ssrf, misconfig, rate_limit  (auto-registered)
  ai/                Ollama client, prompts, payload generation, self-repair, the ORACLE
  engines/           bola.py (the crown jewel), bfla.py
  scoring/           confidence.py (signal-based scoring)
  report/            generator.py + template.html (self-contained HTML report)
  runner.py          scan orchestration        cli.py  the Typer CLI (no logic)
benchmark/           ground_truth.yaml, run_eval.py, zap_adapt.py, results/
cassettes/vampi/     recorded HTTP for offline replay
dashboard.py         Streamlit demo (offline)  tests/  pytest + respx
```

## Acknowledgements & license

Test targets: **VAmPI** (erev0s) and **crAPI** (OWASP). Baseline comparison: **OWASP
ZAP**. Vulnerability taxonomy: the **OWASP API Security Top 10 (2023)**.
Licensed under the **MIT License**.
