"""Defense Intelligence Navigator — AI-assisted offline curation layer.

Static-first principle preserved:
  - the UI never calls public APIs at runtime
  - the bundle stays deterministic and validator-gated
  - every AI output is a *candidate*, never a direct bundle edit
  - no source → no edge | no evidence → no promotion | validator wins

This package is optional and gated behind explicit invocation.
Core modules (resolver, contracts) never import from here.
"""

from .candidates import (
    BacklogItem,
    CandidateProposal,
    CandidateStatus,
    CandidateType,
    EvidenceRef,
    ProposedEdge,
    load_candidates_from_dir,
    write_candidate_batch,
)
from .config import CuratorConfig

__all__ = [
    "BacklogItem",
    "CandidateProposal",
    "CandidateStatus",
    "CandidateType",
    "CuratorConfig",
    "EvidenceRef",
    "ProposedEdge",
    "load_candidates_from_dir",
    "write_candidate_batch",
]
