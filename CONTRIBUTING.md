# Contributing to Doppel

Thanks for your interest. Doppel is a small, opinionated codebase — the design
invariants below are what keep it defensible, so please keep changes within them.

## Setup & tests

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1   |   Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q          # 136 tests; respx-mocked — no live target or Ollama needed
```

> On Windows, run `python -m pytest` (not bare `pytest`) if the venv was moved —
> the `.exe` shims bake in an absolute interpreter path.

Write the test in the **same change** as the code (the suite mocks HTTP with `respx`,
so tests never need a live VAmPI or Ollama). Keep commits small with conventional
messages (`feat:`, `fix:`, `test:`, `docs:`).

## Design invariants (do not violate)

1. **The engine is a library.** All logic lives in the `doppel` package; `cli.py`,
   `dashboard.py`, and `benchmark/` are thin consumers.
2. **Never parse LLM free text.** Every model call is schema-constrained JSON,
   validated with Pydantic; retry, then record inconclusive. No regex over model output.
3. **Pin the seed.** Every LLM call passes a fixed seed; every result records model + seed.
4. **Deterministic first, LLM second.** The model is called only on genuinely ambiguous
   cases. A scan with Ollama off must still run and still find things.
5. **Confidence is computed, never asked.** It is a weighted function of measurable
   signals plus the oracle's binary verdict — never the model's self-reported confidence.
6. **Every finding carries evidence** — full request, full response, and a copy-paste `curl`.
7. **Scope guard is mandatory.** No request leaves the tool unless the host is in the
   config allowlist; non-localhost targets require `--confirm-authorized`. Never stub it out.
8. **Async everywhere on the HTTP path** (one shared `httpx.AsyncClient`, rate-limited).
9. **Type hints on every function; Pydantic models for structured data** (no bare dicts
   crossing module boundaries).

## A note on `apiguard_*` names

A few test-fixture identifiers (seeded usernames, the BOLA seed prefix, `apiguardXSS`)
are legacy naming retained from before the APIGuard→Doppel rename, kept so the committed
cassette and benchmark results stay valid. They are data, not the product name — leave them.

## Authorized use only

Doppel sends real attack traffic. Only run it against systems you own or are explicitly
authorized to test. See the "Authorized use only" section of the README.
