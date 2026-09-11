# APIGuard

AI-powered API vulnerability scanner. It parses an OpenAPI spec, attacks every
endpoint, and uses a locally-hosted LLM to (a) generate context-aware payloads
and (b) adjudicate whether a cross-user access actually leaked data — detecting
BOLA/IDOR flaws that return a normal `200 OK` and are therefore invisible to
status-code-based scanners.

> 3rd-semester academic mini project. Author: Mayurdhvajsinh.
> Project plan and memory live in `BRAIN.md` and `APIGuard_Execution_Plan.md`.

## Status

Day 1 — environment and repository skeleton. No detection logic yet.

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) with a pulled model (default `qwen3:8b`)
- Docker (for the VAmPI test target)

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
# Linux / macOS:         source .venv/bin/activate

# 2. Install the package (editable) with dev/test tools
pip install -e ".[dev]"

# 3. Start the test target
docker run -d -p 5000:5000 --name vampi erev0s/vampi

# 4. Copy and edit the config
cp config.example.yaml config.yaml
```

## Usage

The `apiguard` command is built out over the roadmap in `BRAIN.md` Section 7.
Planned entry points:

```bash
apiguard parse http://localhost:5000/openapi.json
apiguard scan --spec http://localhost:5000/openapi.json --payloads both --report out.html
```

## Tests

```bash
pytest -q
```
