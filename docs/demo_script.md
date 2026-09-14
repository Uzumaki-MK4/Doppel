# Doppel — Demo Recording Script

A ~5-minute screen recording. Every command is copy-paste ready. Two paths are
marked: **[LIVE]** (needs VAmPI + Ollama up) and **[OFFLINE]** (works with wifi off,
target stopped). Record the LIVE path if everything is running; the OFFLINE path tells
the same story, but its BOLA/BFLA and AI-trace parts come from the **committed results**
(the dashboard, the saved report, `run_eval`) — the offline `--replay` scan itself only
reproduces the deterministic scanners. See "What actually needs Ollama" below.

## Before you hit record (setup checklist)

```powershell
# From the project root, in PowerShell:
.\.venv\Scripts\Activate.ps1          # activate the venv (so doppel/streamlit/pytest resolve)
docker start vampi                     # [LIVE only] start the target
ollama serve                           # [LIVE only] in a separate window, if not already running
Get-Process ollama, vampi -ErrorAction SilentlyContinue   # sanity check
```

Have two things open: a **terminal** (venv activated) and a **browser**. Maximise the
terminal font for legibility. Reset VAmPI once so the demo is clean:
`curl http://localhost:5000/createdb` **[LIVE]**.

**What actually needs Ollama.** Ollama is required for **exactly one scene: Scene 3
[LIVE]** — the live scan that runs the AI payload generation and the BOLA oracle (and,
by extension, the `out.html` that scan produces for Scene 4 [LIVE]). Everything else —
`parse`, the offline `--replay`, `run_eval`, the dashboard, and the committed report —
runs **without Ollama**. The BOLA detections and the AI oracle trace can still be shown
offline, but from the **committed results** (Scenes 5–6), not from the offline replay:
`scan --replay` reproduces only the deterministic scanners, because the recorded
cassette is a *static* scan and AI/BOLA traffic is not cassettable.

---

## Scene 1 — The problem (≈30s, talk over a title slide or the README)

> "The #1 API security risk is Broken Object Level Authorization — one user reading
> another user's data. The catch: a successful attack returns a normal `200 OK`, so
> scanners that look at status codes or error messages are blind to it. Doppel uses
> a local LLM as a semantic oracle to catch exactly these flaws — and I measured it."

## Scene 2 — It understands the API (≈20s)

```powershell
doppel parse http://localhost:5000/openapi.json
```

> "It parses the OpenAPI spec and enumerates every endpoint, parameter, and which
> ones require auth — that's the map it attacks from."

## Scene 3 — The scan + the crown jewel (≈60s)

**[LIVE]** — the full pipeline, writing an HTML report:

```powershell
doppel scan --spec http://localhost:5000/openapi.json --payloads ai --repair --bola --report out.html
```

**[OFFLINE]** — same tool, replayed from a cassette with the target stopped:

```powershell
doppel scan --replay cassettes/vampi/
```

> **[LIVE]** "It logs in as two users, runs the baseline scanners, then the BOLA/BFLA
> engine. **Eight findings — two CRITICAL.** Note the two BOLA findings and the
> `_debug` BFLA: those all return `200 OK`. A status scanner sees nothing there."

> **[OFFLINE]** the replay reproduces only the **five deterministic findings** (JWT,
> SQLi, two misconfig, rate-limit) — **no BOLA/BFLA and no AI trace**, because the
> recorded cassette is a *static* scan and the AI/BOLA arms are not cassettable. Say so
> honestly, and show the BOLA/BFLA detections and the AI trace from the committed
> results in Scenes 5–6 instead.

## Scene 4 — Explainability: the AI oracle trace (≈60s)

**[LIVE]** open `out.html` (produced by the Scene-3 live scan) in the browser.
**[OFFLINE]** the replay produces no such report — use the committed one instead: the
dashboard's **Report** tab (Scene 6), or pre-generate it from the saved `full.json` (see
Fallback notes). Either way, scroll to a **BOLA** finding and expand the **AI oracle
trace**.

> "This is what makes it defensible. For each BOLA finding we show the model, the
> pinned seed, the temperature — so it's reproducible — and the five *measurable*
> signals the confidence is computed from. We never ask the model how confident it
> is; we compute it. And the deterministic gate means the LLM is only called on
> genuinely ambiguous cases."

## Scene 5 — The result: the ablation (≈60s) — the money shot

```powershell
python benchmark/run_eval.py
```

> "This is the point of the project. Against a hand-verified ground truth of 12 VAmPI
> vulnerabilities: the baseline scanners get 5 of 12. Adding the BOLA engine — the
> Full arm — gets 8 of 12, at perfect precision. OWASP ZAP, the industry baseline,
> gets 2 of 12. We nearly quadruple ZAP's recall — and the entire gain is the
> authorization flaws that return `200 OK`. ZAP literally fetched the password-dump
> endpoint and flagged nothing."

Optionally show the honest denominator with `python benchmark/run_eval.py --details`.

## Scene 6 — The dashboard (≈45s)

```powershell
streamlit run dashboard.py
```

(If `streamlit` isn't found, the venv isn't active — use
`.\.venv\Scripts\streamlit.exe run dashboard.py`.)

> "Everything in one place, and it runs offline from the committed results. Here's the
> ablation, and the BOLA deep-dive — the oracle's verdict, the confidence signals, and
> the actual leaked response."

Click the **BOLA deep-dive** tab; show the LEAK verdict and the signal bars. Then open
the **Report** tab to show the inline HTML report (this doubles as Scene 4 for the
OFFLINE path).

## Scene 7 — Close (≈20s)

> "Local LLM, strict guardrails, a measured result: 8 of 12 at perfect precision
> versus ZAP's 2 of 12. 136 tests, fully reproducible, tagged v1.0. Thank you."

---

## Fallback notes

- If Ollama is slow/unavailable, use the **[OFFLINE]** commands throughout — Scenes 5
  and 6 need no network or Ollama at all, and Scene 4 uses the committed report in the
  dashboard's Report tab.
- To pre-generate the report shown in Scene 4 without a live scan:
  `python -c "from doppel.core.models import ScanResult; from doppel.report.generator import write_report; write_report(ScanResult.model_validate_json(open('benchmark/results/full.json').read()), 'out.html')"`
- Keep the recording under ~5 minutes; Scenes 3–5 are the core, the rest is framing.
