# APIGuard — Engineering Journal

One short entry per working day: what was built, what broke, what was decided.
(BRAIN.md Section 8 holds the live current-state; this is the running history.)

## Day 1 — 2026-09-12 — Environment & repo skeleton

**Built**
- Repo skeleton: `apiguard` package (`core`, `scanners`, `ai`, `engines`, `scoring`, `report`), plus `benchmark/`, `tests/`, `cassettes/`, `docs/`, `wordlists/`, `logs/llm/`.
- `pyproject.toml` — setuptools backend, `requires-python >=3.11`, the fixed BRAIN.md Section 3 stack. `apiguard` console script declared (`apiguard.cli:main`, comes online D6). `pytest`/`respx` in a `[dev]` extra.
- `config.example.yaml` — scope allowlist, pinned `seed: 42`, two temperatures, placeholder confidence weights (summing to 1.0, tuned D22-D24).
- `.gitignore`, `README.md`.
- `.venv` on Python 3.11.9 with all deps installed editable (`pip install -e ".[dev]"`).
- VAmPI in Docker (container `vampi`, port 5000).
- Ollama server running; `qwen3:8b` pulled (5.2 GB).
- `git init` (branch `main`), first commit of the skeleton.

**Verified — Day 1 done-conditions met**
- `curl http://localhost:5000/openapi.json` -> valid OpenAPI 3.0.1, title "VAmPI", 12 paths.
- `ollama run qwen3:8b "Return only JSON: {"ok": true}"` -> valid JSON `{"ok": true}`.
- Bonus, de-risking D13: schema-constrained ollama-python call (`format=<schema>`, `think=False`) -> clean `{"ok": true}`, pydantic-validated. The invariant-2 pattern works on this machine.

**Broke / learned**
- Docker client was installed but the Desktop engine was not running; had to launch Docker Desktop before `docker run` worked.
- `winget` had no working alias; used the full path to the x64 App Installer build to install Python.
- qwen3:8b thinks by default and ignores an inline `/no_think` through the CLI. The engine will pass `think=False`.

**Decided** — see BRAIN.md Section 9 (think=False, `[dev]` extra, model lock).

**Next** — Day 2: `core/models.py`.

## Day 2 — 2026-09-12 — Core data models

**Built**
- `apiguard/core/models.py`: `Severity` (StrEnum), `Parameter`, `Endpoint`, `Evidence`, `AITrace`, `Finding`, `ScanResult` — all pydantic v2, per BRAIN.md Section 5.
- `tests/test_models.py`: 6 tests — Finding round-trip, confidence bounds, `extra=forbid`, severity-as-string, AITrace optional/attaches, ScanResult counts + round-trip.

**Verified — Day 2 done-condition met**
- `pytest -q` -> 6 passed.
- A `Finding` builds in a REPL and `model_dump_json()` returns clean JSON.

**Decided** (see BRAIN.md Section 9)
- `ScanResult` shape (self-describing: model/seed/payload_mode/requests_sent) — not defined in Section 5.
- `Finding.id` required, no auto-uuid — deterministic IDs assigned at dedup (D11).
- `extra="forbid"` on all models; `confidence` bounded `[0,1]`.

**Most likely to break next**
- `$ref` resolution in D3. VAmPI's spec is small, but the resolver's output shape (fully-dereferenced dict) must map cleanly onto `Parameter`/`Endpoint`. `request_body_schema` stays a raw dict by design, so that part is low-risk.

**Next** — Day 3: `core/spec_parser.py`.
