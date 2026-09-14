"""Configuration loader (pydantic-settings).

`load_settings()` reads `config.yaml` if present, otherwise uses defaults that
work out of the box against a local VAmPI (including two disposable test users),
so `doppel scan --dry-run` needs no config file. Environment variables prefixed
`DOPPEL_` can override top-level fields; full env precedence over YAML is a
later refinement.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScopeConfig(BaseModel):
    allowlist: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "::1"])


class HttpConfig(BaseModel):
    timeout_s: float = 15.0
    max_concurrency: int = 10
    rate_limit_per_s: float = 20.0
    retries: int = 2


class UserConfig(BaseModel):
    username: str
    password: str
    email: str | None = None


class ConfidenceWeights(BaseModel):
    id_echo: float = 0.30
    field_overlap: float = 0.20
    body_divergence: float = 0.20
    status_match: float = 0.10
    oracle_verdict: float = 0.20


def _default_users() -> dict[str, UserConfig]:
    # Disposable users for the local VAmPI target. Override in config.yaml.
    return {
        "userA": UserConfig(username="apiguard_a", password="PwA_12345", email="a@apiguard.test"),
        "userB": UserConfig(username="apiguard_b", password="PwB_67890", email="b@apiguard.test"),
    }


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DOPPEL_",
        env_nested_delimiter="__",
        extra="ignore",
        protected_namespaces=(),
    )

    model: str = "qwen3:8b"
    seed: int = 42
    temperature_payload: float = 0.8
    temperature_oracle: float = 0.0
    ollama_host: str = "http://127.0.0.1:11434"
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    users: dict[str, UserConfig] = Field(default_factory=_default_users)
    confidence_weights: ConfidenceWeights = Field(default_factory=ConfidenceWeights)


def load_settings(config_path: str | Path = "config.yaml") -> Settings:
    """Load settings from a YAML file if it exists, else use defaults."""
    path = Path(config_path)
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return Settings(**data)
    return Settings()
