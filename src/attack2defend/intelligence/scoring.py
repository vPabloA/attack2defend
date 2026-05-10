"""Deterministic candidate scoring for the Intelligence Factory.

Scoring is intentionally minimal for Iteration 2:
- no LLM calls
- no graph impact heuristics
- no novelty/risk invention
- pure evidence + confidence math
"""

from __future__ import annotations

from typing import Any


CONFIDENCE_SCORE = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
    "unknown": 0.0,
    "": 0.0,
}


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def evidence_score(candidate: dict[str, Any]) -> float:
    """Return 1.0/0.5/0.0 based on auditable evidence presence."""
    evidence = candidate.get("evidence") or []
    if not isinstance(evidence, list) or not evidence:
        return 0.0

    has_ref = False
    has_excerpt = False
    for item in evidence:
        if not isinstance(item, dict):
            continue
        if any(_has_text(item.get(k)) for k in ("source_url", "source_ref", "url", "evidence_url")):
            has_ref = True
        if any(_has_text(item.get(k)) for k in ("evidence_excerpt", "evidence_summary", "excerpt", "summary")):
            has_excerpt = True

    edge = candidate.get("proposed_edge") or {}
    if isinstance(edge, dict) and any(_has_text(edge.get(k)) for k in ("source_ref", "source_url", "evidence_url")):
        has_ref = True

    if has_ref and has_excerpt:
        return 1.0
    if has_ref or has_excerpt:
        return 0.5
    return 0.0


def confidence_score(candidate: dict[str, Any]) -> float:
    """Return deterministic confidence score from candidate/proposed_edge."""
    confidence = ""
    edge = candidate.get("proposed_edge") or {}
    if isinstance(edge, dict):
        confidence = str(edge.get("confidence") or "").lower().strip()
    if not confidence:
        confidence = str(candidate.get("confidence") or "unknown").lower().strip()
    return CONFIDENCE_SCORE.get(confidence, 0.0)


def score_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    """Attach a deterministic score object to a candidate dict copy."""
    e_score = evidence_score(candidate)
    c_score = confidence_score(candidate)
    final = round((0.7 * e_score) + (0.3 * c_score), 3)
    scored = dict(candidate)
    scored["score"] = {
        "evidence_score": e_score,
        "confidence_score": c_score,
        "final_score": final,
        "formula": "round((0.7 * evidence_score) + (0.3 * confidence_score), 3)",
        "reasons": [
            f"evidence_score={e_score}",
            f"confidence_score={c_score}",
        ],
    }
    return scored
