"""Tests for doppel.ai.client — schema enforcement, retry, logging (Day 13).

No live Ollama: a fake chat client is injected.
"""

import asyncio
import json
import types

from pydantic import BaseModel

from doppel.ai.client import OllamaClient


class Verdict(BaseModel):
    is_leak: bool
    reason: str


class FakeOllama:
    """Returns queued contents in order (repeating the last); records call kwargs."""

    def __init__(self, contents):
        self._contents = list(contents)
        self.calls = []

    async def chat(self, **kwargs):
        self.calls.append(kwargs)
        content = self._contents.pop(0) if len(self._contents) > 1 else self._contents[0]
        return types.SimpleNamespace(message=types.SimpleNamespace(content=content))


def _client(contents, tmp_path, **kw):
    return OllamaClient(
        model="qwen3:8b",
        seed=42,
        log_dir=str(tmp_path),
        client=FakeOllama(contents),
        **kw,
    )


def test_valid_first_try(tmp_path):
    client = _client(['{"is_leak": true, "reason": "echoed id"}'], tmp_path)
    result = asyncio.run(client.structured(Verdict, prompt="...", temperature=0.0))
    assert result.ok
    assert result.value.is_leak is True
    assert result.attempts == 1
    # schema enforcement + pinned options were sent
    call = client._client.calls[0]
    assert call["format"] == Verdict.model_json_schema()
    assert call["think"] is False
    assert call["options"] == {"temperature": 0.0, "seed": 42}


def test_retry_then_success_bumps_seed(tmp_path):
    client = _client(["not json", '{"is_leak": false, "reason": "same data"}'], tmp_path)
    result = asyncio.run(client.structured(Verdict, prompt="...", temperature=0.0))
    assert result.ok
    assert result.attempts == 2
    assert result.value.is_leak is False
    # second attempt bumped the seed deterministically
    assert client._client.calls[0]["options"]["seed"] == 42
    assert client._client.calls[1]["options"]["seed"] == 43


def test_exhausted_is_inconclusive(tmp_path):
    client = _client(["nope"], tmp_path, max_retries=2)
    result = asyncio.run(client.structured(Verdict, prompt="...", temperature=0.0))
    assert not result.ok
    assert result.inconclusive
    assert result.value is None
    assert result.attempts == 3  # initial + 2 retries
    assert result.error


def test_logs_every_call(tmp_path):
    client = _client(['{"is_leak": true, "reason": "x"}'], tmp_path)
    asyncio.run(client.structured(Verdict, prompt="hello", temperature=0.8, label="oracle"))
    logs = list(tmp_path.glob("*.json"))
    assert len(logs) == 1
    record = json.loads(logs[0].read_text(encoding="utf-8"))
    assert record["ok"] is True
    assert record["label"] == "oracle"
    assert "hello" in record["prompt"]
    assert record["temperature"] == 0.8


def test_system_and_temperature_threaded(tmp_path):
    client = _client(['{"is_leak": false, "reason": "r"}'], tmp_path)
    asyncio.run(
        client.structured(Verdict, prompt="u", system="you are strict", temperature=0.0)
    )
    msgs = client._client.calls[0]["messages"]
    assert msgs[0] == {"role": "system", "content": "you are strict"}
    assert msgs[1] == {"role": "user", "content": "u"}
