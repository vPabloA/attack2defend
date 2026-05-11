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
from .route_narrative import (
    apply_route_narrative,
    build_deterministic_route_narrative,
    build_route_narrative,
    validate_route_narrative,
)
from .llm_cherry_picker import (
    ALLOWED_PROVIDERS,
    AUTO_PROVIDER_ORDER,
    DEFAULT_MODELS,
    AiCherryPickerConfig,
    AnthropicMessagesJsonClient,
    DisabledLLMClient,
    GeminiJsonClient,
    MissingAPIKeyClient,
    MissingAPIKeyError,
    OpenAIResponsesJsonClient,
    ProviderCallError,
    ProviderTransportError,
    build_llm_client_from_env,
    build_llm_system_prompt,
    build_llm_user_prompt,
    build_provider_client,
    cherry_pick_route,
    extract_anthropic_text,
    extract_openai_text,
    parse_json_object,
    sanitize_url,
    sanitize_body,
)

__all__ = [
    "ALLOWED_PROVIDERS",
    "AUTO_PROVIDER_ORDER",
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
    "AnthropicMessagesJsonClient",
    "apply_route_narrative",
    "GeminiJsonClient",
    "MissingAPIKeyClient",
    "MissingAPIKeyError",
    "OpenAIResponsesJsonClient",
    "ProviderCallError",
    "ProviderTransportError",
    "build_curated_route",
    "build_deterministic_route_narrative",
    "build_llm_client_from_env",
    "build_llm_system_prompt",
    "build_llm_user_prompt",
    "build_official_context_pack",
    "build_route_narrative",
    "build_provider_client",
    "cherry_pick_route",
    "extract_anthropic_text",
    "extract_openai_text",
    "load_candidates_from_dir",
    "parse_json_object",
    "sanitize_body",
    "sanitize_url",
    "validate_curated_route",
    "validate_route_narrative",
    "write_candidate_batch",
]
