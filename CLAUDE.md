# APIGuard

Project memory and full execution plan live in the file imported below.
Read it fully at the start of every session and follow its Section 0 protocol.

@BRAIN.md

## Quick facts
- Python 3.11+, async httpx, pydantic v2, local Ollama model.
- The engine is a library. `cli.py`, `dashboard.py` and `benchmark/` only consume it.
- Never parse LLM free text. Schema-constrained JSON output only.
- Never send a request to a host outside the config allowlist.
