"""Signal-based confidence for BOLA findings (BRAIN.md D22, Section 5).

Confidence is COMPUTED from measurable signals plus the oracle's binary verdict —
never asked of the model (invariant 5). The weighted sum is normalised over the
signals actually present, so a missing signal (e.g. no B-control) keeps the score
in [0, 1] instead of silently deflating it.
"""

from __future__ import annotations

import json
from difflib import SequenceMatcher

from apiguard.engines.bola import AccessTriple


def _top_level_keys(body: str) -> set[str]:
    try:
        obj = json.loads(body)
    except ValueError:
        return set()
    return set(obj.keys()) if isinstance(obj, dict) else set()


def _jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a[:2000], b[:2000]).ratio()


def compute_signals(triple: AccessTriple, oracle_verdict: float | None) -> dict[str, float]:
    """The measurable BOLA signals (Section 5). Absent signals are omitted."""
    a = triple.a_access
    cross = triple.b_cross_access

    signals: dict[str, float] = {
        # A's object id appears in B's cross-access response.
        "id_echo": 1.0 if triple.a_object_id in cross.response_body else 0.0,
        # Jaccard of top-level keys: A's response vs B's cross-access.
        "field_overlap": _jaccard(_top_level_keys(a.response_body), _top_level_keys(cross.response_body)),
        # B's cross-access returned the same status as A's own access.
        "status_match": 1.0 if cross.response_status == a.response_status else 0.0,
    }
    if triple.b_control is not None:
        # How different B's cross-access is from B's OWN legitimate access.
        signals["body_divergence"] = 1.0 - _similarity(
            cross.response_body, triple.b_control.response_body
        )
    if oracle_verdict is not None:
        signals["oracle_verdict"] = float(oracle_verdict)
    return signals


def confidence(signals: dict[str, float], weights: dict[str, float]) -> float:
    """Weighted mean of the present signals, normalised by their weights."""
    numerator = sum(weights.get(name, 0.0) * value for name, value in signals.items())
    denominator = sum(weights.get(name, 0.0) for name in signals)
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)
