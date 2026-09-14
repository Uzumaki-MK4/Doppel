# Doppel

**AI-powered API authorization scanner.**

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-136%20passing-brightgreen.svg)](#quick-start)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%20%282023%29-000000.svg)](#owasp-api-top-10-coverage)

Doppel parses an OpenAPI spec, logs in as **two** users, and uses a **locally-hosted
LLM** to decide whether one user can read the other's data — catching **Broken Object
Level Authorization (BOLA / IDOR)** flaws that return a normal `200 OK` and are therefore
invisible to status-code-based scanners. The name is from *doppelgänger*: it checks
whether the API can tell two users apart.

<!-- TODO(screenshot): hero image — the HTML report showing a BOLA finding with its AI oracle trace -->

## The problem — a leak that looks like success

The #1 risk in the OWASP API Security Top 10 is **BOLA**: an endpoint serves an object
by a client-supplied id without checking that the caller owns it. The catch for
*automated* detection is that a successful attack is indistinguishable from a normal
request — same shape, same `200 OK`. There is no error to grep for and no status code to
branch on; confirming a leak requires reasoning about the *content* of the response.

```http
# Bob, authenticated as himself, requests Alice's object by its id:
GET /books/v1/alices-private-note        Authorization: Bearer <Bob's own token>

# The API answers 200 OK — and hands Bob Alice's private data:
HTTP/1.1 200 OK
{ "title": "alices-private-note", "owner": "alice", "secret": "alice-only-data" }
```

A status/error scanner sees `200 OK` and moves on. Doppel logs in as both users, replays
Bob's cross-access, and asks an LLM oracle — under strict controls — *did Bob just receive
Alice's data?*

## Results

Measured on [VAmPI](https://github.com/erev0s/VAmPI) against a hand-verified ground truth
of 12 known vulnerabilities, scored by one command (`python benchmark/run_eval.py`):

| Arm | Recall | Precision | Requests |
|---|---|---|---|
| Static wordlist payloads | 5 / 12 (0.42) | 1.00 | 71 |
| AI-generated payloads | 5 / 12 (0.42) | 1.00 | 63 |
| AI + self-repair | 5 / 12 (0.42) | 1.00 | 63 |
| **Full (incl. BOLA engine)** | **8 / 12 (0.67)** | **1.00** | 82 |
| OWASP ZAP (external baseline) | 2 / 12 (0.17) | 0.50 | n/a |

The BOLA/BFLA engine lifts recall from **0.42 to 0.67 at perfect precision** — nearly **4×
OWASP ZAP** — and the entire gain is authorization flaws that return `200 OK`. ZAP
retrieved the endpoint that dumps every user's password, and the cross-user data, and
flagged nothing: it cannot reason about authorization.

<!-- TODO(screenshot): the `python benchmark/run_eval.py` ablation table, or the dashboard's BOLA deep-dive -->

## Requirements

- **Python 3.11+**
- **Docker Desktop** — to run the VAmPI / crAPI test targets locally (step 4 below)
- **[Ollama](https://ollama.com)** running locally, with a model pulled (default `qwen3:8b`, step 5)

## Quick start

Install to first scan in under ten commands. **The `/createdb` step is required** — VAmPI
serves 500s until its database is seeded.

> **Windows:** use `curl.exe` (not `curl`) for the `/createdb` step — PowerShell aliases
> `curl` to `Invoke-WebRequest`, which does not accept these arguments and will fail.

```bash
# 1. clone + enter
git clone https://github.com/Uzumaki-MK4/Doppel.git && cd Doppel

# 2. virtual environment
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1   |   Linux/macOS: source .venv/bin/activate

# 3. install (editable, with test tools)
pip install -e ".[dev]"

# 4. start the test target and seed its DB (required!)
docker run -d -p 5000:5000 --name vampi erev0s/vampi
curl http://localhost:5000/createdb

# 5. pull the local model (default qwen3:8b) — needs Ollama running
ollama pull qwen3:8b

# 6. scan: baseline scanners + the BOLA/BFLA engine, write an HTML report
doppel scan --spec http://localhost:5000/openapi.json --payloads ai --repair --bola --report out.html
```

More:

```bash
doppel parse http://localhost:5000/openapi.json   # list every endpoint + params
python benchmark/run_eval.py                       # the ablation table above
streamlit run dashboard.py                         # interactive dashboard (offline)
doppel scan --replay cassettes/vampi/              # offline demo — no target, no Ollama
python -m pytest -q                                # 136 tests (respx-mocked, no live target)
```

## How it works

```
OpenAPI spec ─► parse ─► log in two users ─► baseline scanners ─► BOLA/BFLA engine ─► report
                                            (SQLi, XSS, JWT, SSRF, (the contribution)
                                             misconfig, rate-limit)
```

The BOLA engine is the contribution. For an object owned by **User A** it builds an
**access triple**:

- **A's own access** — A reading A's object (the reference for what the data is),
- **B's cross-access** — the attacker B reading A's object (the potential leak),
- **B's control** — B reading B's *own* object at the same endpoint (a legitimate baseline).

Then three safeguards, in order:

1. **Deterministic first.** A cheap gate resolves the clear cases with **no LLM call**: a
   rejected cross-access (401/403/404), or a response byte-identical to B's own control, is
   not a leak. Only genuinely ambiguous `200 OK` cases reach the oracle.
2. **Schema-constrained AI.** The oracle returns a validated `{is_leak, leaked_fields,
   reasoning}` object at temperature 0 with a pinned seed — never free text that must be parsed.
3. **Confidence is computed, never asked.** The score is a weighted blend of five
   measurable signals (`id_echo`, `field_overlap`, `body_divergence`, `status_match`, and the
   oracle's binary verdict) — the model is one signal among five, never the confidence itself.

These choices are what make LLM use defensible: the tool still runs (and still finds things)
with the model switched off, and every finding carries full evidence plus a copy-paste `curl`.
Full design record in [BRAIN.md](BRAIN.md); day-by-day log in [docs/journal.md](docs/journal.md);
the technical write-up in [docs/report.md](docs/report.md).

## OWASP API Top 10 coverage

| # | Category (2023) | Doppel |
|---|---|---|
| API1 | Broken Object Level Authorization | ✅ **BOLA engine** (the crown jewel) |
| API2 | Broken Authentication | ✅ JWT scanner (weak secret, `alg:none`, signature strip) |
| API3 | Broken Object Property Level Auth / excessive data | 🟡 partial — public-record / debug exposure flagged, no dedicated detector |
| API4 | Unrestricted Resource Consumption | ✅ rate-limit scanner |
| API5 | Broken Function Level Authorization | ✅ **BFLA engine** (privileged endpoints reachable by low-priv users) |
| API6 | Unrestricted Access to Sensitive Business Flows | ❌ not covered |
| API7 | Server-Side Request Forgery | 🟡 partial — SSRF scanner ships, but its positive-detection path is unverified (never run against a target with a real SSRF flaw) |
| API8 | Security Misconfiguration | ✅ misconfig (headers, CORS, version, verbose errors) + injection (SQLi/XSS) |
| API9 | Improper Inventory Management | ❌ not covered |
| API10 | Unsafe Consumption of APIs | ❌ not covered |

## ⚠️ Authorized use only

Doppel **sends real attack traffic** — SQL injection payloads, forged JWTs, cross-user
access attempts. Only run it against systems you **own** or are **explicitly authorized**
to test.

- The **scope guard** blocks any request to a host not in the config allowlist. Non-localhost
  targets require an explicit `--confirm-authorized` flag — this is deliberate and is not
  optional.
- Scanning systems you do not own or have written permission to test is **illegal**. In
  **India** it is an offence under the **Information Technology Act, 2000 — section 43
  (unauthorised access and damage) and section 66 (computer-related offences)**; other
  jurisdictions have equivalents, such as the US Computer Fraud and Abuse Act (CFAA) and the
  UK Computer Misuse Act. You are responsible for how you use this tool.

The bundled targets ([VAmPI](https://github.com/erev0s/VAmPI),
[crAPI](https://github.com/OWASP/crAPI)) are deliberately vulnerable practice apps meant to
be attacked locally.

## Authors

A joint project by:

- **Mayurdhvajsinh** — [github.com/Uzumaki-MK4](https://github.com/Uzumaki-MK4)
- **Aachal** — [github.com/AachalGodse](https://github.com/AachalGodse)

## License

[MIT](LICENSE) © 2026 Mayurdhvajsinh and Aachal.
