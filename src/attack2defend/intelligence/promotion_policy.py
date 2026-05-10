"""Policy-driven, non-blocking candidate promotion engine.

This module is designed for CLI, CI, SOAR, MCP and future API use:
- no input()
- no human wait
- no polling
- deterministic decisions
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_ALLOWED_RELATIONSHIPS = [
    "vulnerability_has_weakness",
    "weakness_enables_attack_pattern",
    "attack_pattern_maps_to_technique",
    "technique_mitigated_by_countermeasure",
    "validated_by_detection",
    "protected_by_control",
    "affects_product_or_platform",
]

PROMOTION_MODES = {"dry_run", "policy_auto", "review_queue", "emergency_block"}
POLICY_DECISIONS = {"dry_run", "auto_promoted", "queued_for_review", "rejected_by_policy", "blocked"}


@dataclass(frozen=True)
class PromotionPolicy:
    policy_version: str = "0.1.0"
    promotion_mode: str = "dry_run"
    min_score: float = 0.75
    allowed_confidence: list[str] = field(default_factory=lambda: ["high"])
    allowed_relationships: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_RELATIONSHIPS))
    require_evidence: bool = True
    require_existing_nodes: bool = True
    allow_new_nodes: bool = False
    block_if_secret_detected: bool = True
    max_candidates_per_run: int = 50
    timeout_policy: str = "never_wait_for_human"

    @classmethod
    def from_file(cls, path: Path | str | None) -> "PromotionPolicy":
        if path is None:
            return cls.from_env(cls())
        p = Path(path)
        if not p.exists():
            return cls.from_env(cls())
        data = json.loads(p.read_text(encoding="utf-8"))
        known = cls.__dataclass_fields__.keys()  # type: ignore[attr-defined]
        policy = cls(**{k: v for k, v in data.items() if k in known})
        return cls.from_env(policy)

    @classmethod
    def from_env(cls, policy: "PromotionPolicy") -> "PromotionPolicy":
        mode = os.getenv("A2D_PROMOTION_MODE", "").strip()
        if mode:
            return cls(**{**policy.to_dict(), "promotion_mode": mode})
        return policy

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "promotion_mode": self.promotion_mode,
            "min_score": self.min_score,
            "allowed_confidence": self.allowed_confidence,
            "allowed_relationships": self.allowed_relationships,
            "require_evidence": self.require_evidence,
            "require_existing_nodes": self.require_existing_nodes,
            "allow_new_nodes": self.allow_new_nodes,
            "block_if_secret_detected": self.block_if_secret_detected,
            "max_candidates_per_run": self.max_candidates_per_run,
            "timeout_policy": self.timeout_policy,
        }


def evaluate_candidate_policy(
    candidate: dict[str, Any],
    policy: PromotionPolicy,
    *,
    known_node_ids: set[str] | None = None,
    secret_detected: bool = False,
) -> dict[str, Any]:
    """Return a non-blocking policy decision for one candidate."""
    mode = policy.promotion_mode
    reasons: list[str] = []

    if mode not in PROMOTION_MODES:
        return _decision("blocked", [f"invalid_promotion_mode:{mode}"], policy)
    if policy.timeout_policy != "never_wait_for_human":
        return _decision("blocked", ["timeout_policy_must_be_never_wait_for_human"], policy)
    if mode == "emergency_block":
        return _decision("blocked", ["emergency_block_enabled"], policy)
    if mode == "dry_run":
        return _decision("dry_run", ["dry_run_mode"], policy)
    if mode == "review_queue":
        return _decision("queued_for_review", ["review_queue_mode"], policy)

    edge = candidate.get("proposed_edge") or {}
    if not isinstance(edge, dict):
        return _decision("rejected_by_policy", ["missing_proposed_edge"], policy)

    score = _final_score(candidate)
    confidence = str(edge.get("confidence") or candidate.get("confidence") or "unknown").lower().strip()
    relationship = str(edge.get("relationship") or "").strip()
    source = str(edge.get("source") or "").strip()
    target = str(edge.get("target") or "").strip()

    if score < policy.min_score:
        reasons.append(f"score_below_threshold:{score}<{policy.min_score}")
    if confidence not in policy.allowed_confidence:
        reasons.append(f"confidence_not_allowed:{confidence}")
    if relationship not in policy.allowed_relationships:
        reasons.append(f"relationship_not_allowed:{relationship}")
    if policy.require_evidence and not _has_evidence(candidate):
        reasons.append("missing_evidence")
    if policy.block_if_secret_detected and secret_detected:
        reasons.append("secret_detected")
    if policy.require_existing_nodes and known_node_ids is not None:
        missing = [n for n in (source, target) if n and n not in known_node_ids]
        if missing and not policy.allow_new_nodes:
            reasons.append("missing_existing_nodes:" + ",".join(missing))
    if not source or not target or not relationship:
        reasons.append("incomplete_edge")

    if reasons:
        reviewable = {"score_below_threshold", "confidence_not_allowed", "missing_existing_nodes"}
        if any(r.split(":", 1)[0] in reviewable for r in reasons):
            return _decision("queued_for_review", reasons, policy)
        return _decision("rejected_by_policy", reasons, policy)

    return _decision("auto_promoted", ["policy_gates_passed"], policy)


def _decision(decision: str, reasons: list[str], policy: PromotionPolicy) -> dict[str, Any]:
    return {
        "decision": decision,
        "policy_version": policy.policy_version,
        "policy_reason": reasons,
        "blocking": False,
        "timeout_waited_for_human": False,
        "promotion_mode": policy.promotion_mode,
    }


def _final_score(candidate: dict[str, Any]) -> float:
    score = candidate.get("score") or {}
    if isinstance(score, dict):
        try:
            return float(score.get("final_score", 0.0))
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _has_evidence(candidate: dict[str, Any]) -> bool:
    evidence = candidate.get("evidence") or []
    if not isinstance(evidence, list) or not evidence:
        return False
    for item in evidence:
        if not isinstance(item, dict):
            continue
        if any(str(item.get(k) or "").strip() for k in ("source_ref", "source_url", "url", "evidence_url")):
            return True
    return False
