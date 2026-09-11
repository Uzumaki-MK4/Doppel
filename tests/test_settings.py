"""Tests for apiguard.settings (Day 6)."""

from apiguard.settings import Settings, load_settings


def test_defaults_are_usable():
    s = Settings()
    assert s.model == "qwen3:8b"
    assert s.seed == 42
    assert "localhost" in s.scope.allowlist
    assert set(s.users) == {"userA", "userB"}
    assert s.users["userA"].username == "apiguard_a"
    assert s.users["userA"].password  # non-empty


def test_confidence_weights_sum_to_one():
    w = Settings().confidence_weights
    total = w.id_echo + w.field_overlap + w.body_divergence + w.status_match + w.oracle_verdict
    assert abs(total - 1.0) < 1e-9


def test_load_missing_file_uses_defaults(tmp_path):
    s = load_settings(tmp_path / "nope.yaml")
    assert s.model == "qwen3:8b"


def test_load_yaml_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "model: llama3.1:8b\n"
        "seed: 7\n"
        "scope:\n"
        "  allowlist: [localhost, 10.0.0.5]\n"
        "users:\n"
        "  userA: {username: u1, password: p1}\n"
        "  userB: {username: u2, password: p2}\n",
        encoding="utf-8",
    )
    s = load_settings(cfg)
    assert s.model == "llama3.1:8b"
    assert s.seed == 7
    assert s.scope.allowlist == ["localhost", "10.0.0.5"]
    assert s.users["userB"].username == "u2"
