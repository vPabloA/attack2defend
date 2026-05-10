from __future__ import annotations

from attack2defend.intelligence.promotion_policy import PromotionPolicy, evaluate_candidate_policy
from attack2defend.intelligence.scoring import score_candidate


def _candidate(confidence: str = "high") -> dict:
    return {
        "candidate_id": "cand-test-001",
        "run_id": "run-test",
        "candidate_type": "mapping_edge",
        "model": "gpt-5-nano",
        "provider": "openai",
        "generated_at": "2026-01-01T00:00:00Z",
        "evidence": [
            {
                "url": "https://example.test/evidence",
                "excerpt": "evidence summary",
                "confidence": confidence,
                "retrieved_at": "2026-01-01T00:00:00Z",
            }
        ],
        "proposed_edge": {
            "source": "CVE-1",
            "target": "CWE-1",
            "relationship": "vulnerability_has_weakness",
            "confidence": confidence,
            "source_ref": "https://example.test/evidence",
        },
        "deterministic": False,
        "inferred": True,
    }


def test_score_candidate_is_deterministic_and_minimal() -> None:
    scored = score_candidate(_candidate("high"))
    assert scored["score"]["evidence_score"] == 1.0
    assert scored["score"]["confidence_score"] == 1.0
    assert scored["score"]["final_score"] == 1.0
    assert "formula" in scored["score"]


def test_policy_auto_promotes_when_all_gates_pass() -> None:
    policy = PromotionPolicy(promotion_mode="policy_auto", min_score=0.75, allowed_confidence=["high"])
    candidate = score_candidate(_candidate("high"))
    decision = evaluate_candidate_policy(candidate, policy, known_node_ids={"CVE-1", "CWE-1"})
    assert decision["decision"] == "auto_promoted"
    assert decision["blocking"] is False
    assert decision["timeout_waited_for_human"] is False


def test_policy_auto_queues_low_confidence_without_blocking() -> None:
    policy = PromotionPolicy(promotion_mode="policy_auto", min_score=0.75, allowed_confidence=["high"])
    candidate = score_candidate(_candidate("medium"))
    decision = evaluate_candidate_policy(candidate, policy, known_node_ids={"CVE-1", "CWE-1"})
    assert decision["decision"] == "queued_for_review"
    assert decision["blocking"] is False


def test_review_queue_mode_never_blocks() -> None:
    policy = PromotionPolicy(promotion_mode="review_queue")
    candidate = score_candidate(_candidate("high"))
    decision = evaluate_candidate_policy(candidate, policy, known_node_ids={"CVE-1", "CWE-1"})
    assert decision["decision"] == "queued_for_review"
    assert decision["blocking"] is False


def test_emergency_block_records_block_without_human_wait() -> None:
    policy = PromotionPolicy(promotion_mode="emergency_block")
    candidate = score_candidate(_candidate("high"))
    decision = evaluate_candidate_policy(candidate, policy, known_node_ids={"CVE-1", "CWE-1"})
    assert decision["decision"] == "blocked"
    assert decision["blocking"] is False
    assert decision["timeout_waited_for_human"] is False
