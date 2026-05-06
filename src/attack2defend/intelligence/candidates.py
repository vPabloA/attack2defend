"""Candidate proposal data model.

Every AI output MUST be a CandidateProposal.
Candidates are written to data/candidates/ for human review.
No candidate is ever merged into the bundle without explicit promotion.

Invariants:
  - candidate_id is globally unique and timestamped
  - every proposed_edge must have source_ref (evidence URL)
  - status starts as PENDING; only promote_candidates.py may change it
  - no_source_ref == no_edge (enforced at promotion time, not here)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class CandidateStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_EVIDENCE = "needs_evidence"


class CandidateType(str, Enum):
    MAPPING_EDGE = "mapping_edge"
    COVERAGE_GAP = "coverage_gap"
    MISSING_DEFENSE = "missing_defense"
    BACKLOG_ITEM = "backlog_item"


@dataclass
class EvidenceRef:
    """A single piece of evidence supporting a candidate proposal."""

    url: str
    excerpt: str
    confidence: str  # high | medium | low
    retrieved_at: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceRef":
        return cls(
            url=d["url"],
            excerpt=d["excerpt"],
            confidence=d["confidence"],
            retrieved_at=d["retrieved_at"],
        )


@dataclass
class ProposedEdge:
    """A candidate mapping edge awaiting human review.

    source_ref is REQUIRED — a candidate with no source_ref must be
    status=NEEDS_EVIDENCE and cannot be promoted.
    """

    source: str
    target: str
    relationship: str
    confidence: str  # high | medium | low
    source_ref: str  # evidence URL — MUST NOT be empty on promotion
    source_kind: str = "ai_candidate"
    owner: str = ""
    priority: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ProposedEdge":
        known = {
            "source", "target", "relationship", "confidence",
            "source_ref", "source_kind", "owner", "priority",
        }
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_mapping_record(self) -> dict:
        """Convert to backbone-compatible mapping record for promotion."""
        rec: dict = {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "source_ref": self.source_ref,
            "source_kind": "ai_promoted",
            "evidence_url": self.source_ref,
        }
        if self.owner:
            rec["owner"] = self.owner
        if self.priority:
            rec["priority"] = self.priority
        return rec


@dataclass
class BacklogItem:
    """A SOC/CTEM action item derived from a gap analysis."""

    item_id: str
    title: str
    description: str
    owner: str  # soc | ctem | appsec | infra | detection-engineer
    priority: str  # critical | high | medium | low
    gap_context: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "BacklogItem":
        known = {
            "item_id", "title", "description", "owner",
            "priority", "gap_context", "references",
        }
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class CandidateProposal:
    """An AI-generated mapping proposal awaiting human review.

    This is the unit of work in the curation pipeline.
    Nothing in this object ever touches the bundle directly.
    """

    candidate_id: str
    generated_at: str
    model: str
    run_id: str
    status: CandidateStatus
    candidate_type: CandidateType
    input_id: str
    gap_explanation: str
    justification: str
    evidence: list[EvidenceRef] = field(default_factory=list)
    proposed_edge: Optional[ProposedEdge] = None
    backlog_items: list[BacklogItem] = field(default_factory=list)
    requires_human_review: bool = True
    promotion_notes: Optional[str] = None
    promoted_by: Optional[str] = None
    promoted_at: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Factory                                                              #
    # ------------------------------------------------------------------ #

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        model: str,
        candidate_type: CandidateType,
        input_id: str,
        gap_explanation: str,
        justification: str,
        evidence: list[EvidenceRef] | None = None,
        proposed_edge: ProposedEdge | None = None,
        backlog_items: list[BacklogItem] | None = None,
        status: CandidateStatus = CandidateStatus.PENDING,
    ) -> "CandidateProposal":
        ts = datetime.now(timezone.utc)
        return cls(
            candidate_id=f"cand-{ts.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
            generated_at=ts.isoformat(),
            model=model,
            run_id=run_id,
            status=status,
            candidate_type=candidate_type,
            input_id=input_id,
            gap_explanation=gap_explanation,
            justification=justification,
            evidence=evidence or [],
            proposed_edge=proposed_edge,
            backlog_items=backlog_items or [],
        )

    # ------------------------------------------------------------------ #
    # Serialization                                                        #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["candidate_type"] = self.candidate_type.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CandidateProposal":
        d = dict(d)
        d["status"] = CandidateStatus(d["status"])
        d["candidate_type"] = CandidateType(d["candidate_type"])
        d["evidence"] = [EvidenceRef.from_dict(e) for e in d.get("evidence", [])]
        if d.get("proposed_edge"):
            d["proposed_edge"] = ProposedEdge.from_dict(d["proposed_edge"])
        d["backlog_items"] = [BacklogItem.from_dict(b) for b in d.get("backlog_items", [])]
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "CandidateProposal":
        return cls.from_dict(json.loads(s))

    # ------------------------------------------------------------------ #
    # Validation helpers (used by promote_candidates)                     #
    # ------------------------------------------------------------------ #

    def promotion_errors(self) -> list[str]:
        """Return human-readable errors that block promotion."""
        errors: list[str] = []
        if self.status == CandidateStatus.REJECTED:
            errors.append("candidate is rejected")
        if self.status == CandidateStatus.NEEDS_EVIDENCE:
            errors.append("candidate needs evidence before promotion")
        if self.proposed_edge is None:
            errors.append("no proposed_edge to promote")
        elif not self.proposed_edge.source_ref.strip():
            errors.append("proposed_edge.source_ref is empty (no source = no edge)")
        if not self.evidence:
            errors.append("evidence list is empty (no evidence = no promotion)")
        return errors

    def is_promotable(self) -> bool:
        return len(self.promotion_errors()) == 0


# ------------------------------------------------------------------ #
# Batch I/O helpers                                                    #
# ------------------------------------------------------------------ #


def load_candidates_from_dir(candidates_dir: Path) -> list[CandidateProposal]:
    """Load all candidate JSON files from a directory tree."""
    if not candidates_dir.exists():
        return []
    result: list[CandidateProposal] = []
    for f in sorted(candidates_dir.rglob("*.json")):
        try:
            result.append(CandidateProposal.from_json(f.read_text(encoding="utf-8")))
        except Exception:
            pass  # skip malformed files silently
    return result


def write_candidate_batch(
    candidates: list[CandidateProposal],
    output_dir: Path,
    run_id: str,
) -> list[Path]:
    """Write a batch of candidates as individual JSON files under output_dir/run_id/."""
    batch_dir = output_dir / run_id
    batch_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for c in candidates:
        path = batch_dir / f"{c.candidate_id}.json"
        path.write_text(c.to_json(), encoding="utf-8")
        written.append(path)
    return written
