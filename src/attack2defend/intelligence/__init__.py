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
from .curated_route import (
    CURATED_ROUTE_LIMITS,
    build_curated_route,
    build_official_context_pack,
    validate_curated_route,
)
from .llm_cherry_picker import (
    ALLOWED_PROVIDERS,
    DEFAULT_MODELS,
    AiCherryPickerConfig,
    DisabledLLMClient,
    build_llm_system_prompt,
    build_llm_user_prompt,
    cherry_pick_route,
)

__all__ = [
    "ALLOWED_PROVIDERS",
    "BacklogItem",
    "CURATED_ROUTE_LIMITS",
    "CandidateProposal",
    "CandidateStatus",
    "CandidateType",
    "CuratorConfig",
    "DEFAULT_MODELS",
    "DisabledLLMClient",
    "EvidenceRef",
    "ProposedEdge",
    "AiCherryPickerConfig",
    "build_curated_route",
    "build_llm_system_prompt",
    "build_llm_user_prompt",
    "build_official_context_pack",
    "cherry_pick_route",
    "load_candidates_from_dir",
    "validate_curated_route",
    "write_candidate_batch",
]
