"""Tests for dashboard.py's pure helpers (Day 28).

Only the non-Streamlit data-prep functions are tested (main() needs the Streamlit
runtime). Importing dashboard is cheap: streamlit is imported inside main(), not at
module top, and the `if __name__ == "__main__"` guard keeps main() from running on
import. These exercise the committed result JSONs + ground truth.
"""

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dashboard", _ROOT / "dashboard.py")
dashboard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dashboard)

run_eval = dashboard._load_run_eval()
GT = run_eval.load_ground_truth()


def test_parse_oracle_valid_and_invalid():
    assert dashboard.parse_oracle('{"is_leak": true, "leaked_fields": ["secret"]}')["is_leak"] is True
    assert dashboard.parse_oracle("not json") == {}
    assert dashboard.parse_oracle(None) == {}


def test_arm_result_paths_exist_and_ordered():
    paths = dashboard.arm_result_paths()
    stems = [p.stem for p in paths]
    assert stems, "no arm result files found"
    assert all(s in dashboard.ARM_ORDER for s in stems)
    # order follows ARM_ORDER
    assert stems == [s for s in dashboard.ARM_ORDER if s in stems]


def test_load_result_full_arm():
    full = _ROOT / "benchmark" / "results" / "full.json"
    result = dashboard.load_result(full)
    assert result.target.endswith(":5000")
    assert len(result.findings) == 8


def test_bola_findings_have_ai_trace():
    result = dashboard.load_result(_ROOT / "benchmark" / "results" / "full.json")
    bolas = dashboard.bola_findings(result)
    assert len(bolas) == 2  # book-secret + public-user BOLA
    assert all(f.ai_trace is not None and f.ai_trace.signals for f in bolas)


def test_ablation_rows_tell_the_story():
    rows = dashboard.ablation_rows(run_eval, GT, dashboard.arm_result_paths())
    by = {r["_stem"]: r for r in rows}
    assert set(r for r in ("static", "full", "zap")).issubset(by)
    # required columns present
    for col in ("Arm", "Target", "Recall", "Precision", "F1", "TP", "FP", "FN", "Requests"):
        assert col in rows[0]
    # the headline: Full > static > zap on recall; Full and static are clean
    assert by["full"]["Recall"] > by["static"]["Recall"] > by["zap"]["Recall"]
    assert by["full"]["Precision"] == 1.0 and by["full"]["FP"] == 0
    assert by["zap"]["Requests"] is None  # ZAP request count not tracked -> n/a
