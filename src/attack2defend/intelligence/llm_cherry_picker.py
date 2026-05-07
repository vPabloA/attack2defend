"""Validator-gated LLM cherry-picker adapter.

This module is deliberately provider-light. It defines the safe contract for
using Gemini, OpenAI, or Anthropic in offline/build-time curation without adding
mandatory SDK dependencies or browser/runtime calls.

LLM output is never trusted directly:
  1. deterministic full graph builds the official context pack;
  2. the LLM may only select IDs already present in that context pack;
  3. the curated route schema and no-invention validator decide final validity;
  4. on any error, fallback is deterministic prefilter.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from .curated_route import CURATED_ROUTE_LIMITS, build_curated_route, validate_curated_route


DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash-lite",
    "openai": "gpt-5-nano",
    "anthropic": "claude-3-5-haiku-latest",
}
ALLOWED_PROVIDERS = tuple(DEFAULT_MODELS)


@dataclass(frozen=True)
class AiCherryPickerConfig:
    mode: str
    provider: str
    model: str
    temperature: float
    max_output_tokens: int
    require_validation: bool
    allow_external_knowledge: bool
    runtime_public_api_calls: bool

    @classmethod
    def from_env(cls) -> "AiCherryPickerConfig":
        provider = os.getenv("A2D_AI_PROVIDER", "gemini").strip().lower() or "gemini"
        if provider not in DEFAULT_MODELS:
            provider = "gemini"
        model_env = {
            "gemini": "A2D_GEMINI_MODEL",
            "openai": "A2D_OPENAI_MODEL",
            "anthropic": "A2D_ANTHROPIC_MODEL",
        }[provider]
        return cls(
            mode=os.getenv("A2D_CHERRY_PICKER_MODE", "deterministic").strip().lower() or "deterministic",
            provider=provider,
            model=os.getenv(model_env, DEFAULT_MODELS[provider]).strip() or DEFAULT_MODELS[provider],
            temperature=float(os.getenv("A2D_CHERRY_PICKER_TEMPERATURE", "0") or "0"),
            max_output_tokens=int(os.getenv("A2D_CHERRY_PICKER_MAX_OUTPUT_TOKENS", "4000") or "4000"),
            require_validation=parse_bool(os.getenv("A2D_CHERRY_PICKER_REQUIRE_VALIDATION", "true")),
            allow_external_knowledge=parse_bool(os.getenv("A2D_CHERRY_PICKER_ALLOW_EXTERNAL_KNOWLEDGE", "false")),
            runtime_public_api_calls=parse_bool(os.getenv("A2D_CHERRY_PICKER_RUNTIME_PUBLIC_API_CALLS", "false")),
        )


class JsonLLMClient(Protocol):
    """Minimal provider abstraction for future SDK-backed clients."""

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        """Return a JSON object shaped like a curated route."""


class DisabledLLMClient:
    """Safe default client: never calls a provider."""

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        raise RuntimeError("LLM provider execution is disabled; deterministic fallback required")


def build_llm_system_prompt() -> str:
    return """
You are Attack2Defend's constrained cherry-picker.
You must select only IDs present in the provided official context pack.
You must not invent IDs, facts, relationships, affected products, impact, or coverage.
You must not use external knowledge.
You must return only JSON matching the curated route schema.
Validator wins.
""".strip()


def build_llm_user_prompt(official_context_pack: dict[str, Any]) -> str:
    payload = {
        "task": "Select a defensive curated route from the official context pack only.",
        "limits": CURATED_ROUTE_LIMITS,
        "rules": [
            "Allowed IDs only.",
            "Do not invent relationships or coverage.",
            "Every selected item needs reason_es.",
            "Preserve full_traceability_counts.",
            "Set selection_method to llm_cherry_picker.",
            "Set runtime_public_api_calls to false.",
        ],
        "official_context_pack": official_context_pack,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def cherry_pick_route(
    capability_response: dict[str, Any],
    official_context_pack: dict[str, Any],
    *,
    config: AiCherryPickerConfig | None = None,
    client: JsonLLMClient | None = None,
) -> dict[str, Any]:
    """Return a validator-gated curated route.

    If mode is not `llm`, if provider execution fails, or if the provider output
    fails validation, the deterministic curated route is returned with explicit
    fallback metadata. No invalid LLM output escapes this function.
    """

    cfg = config or AiCherryPickerConfig.from_env()
    deterministic = build_curated_route(capability_response, official_context_pack)
    deterministic.setdefault("llm_adapter", {})
    if cfg.mode != "llm":
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="mode_not_llm")
        return deterministic
    if cfg.allow_external_knowledge or cfg.runtime_public_api_calls:
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="unsafe_external_knowledge_or_runtime_api")
        return deterministic

    llm_client = client or DisabledLLMClient()
    try:
        proposed = llm_client.complete_json(
            system_prompt=build_llm_system_prompt(),
            user_prompt=build_llm_user_prompt(official_context_pack),
            config=cfg,
        )
    except Exception as exc:  # pragma: no cover - provider availability varies
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason=f"provider_error:{type(exc).__name__}")
        return deterministic

    proposed["selection_method"] = "llm_cherry_picker"
    proposed["runtime_public_api_calls"] = False
    errors = validate_curated_route(proposed, official_context_pack)
    if errors:
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="validation_failed", errors=errors)
        return deterministic

    proposed["validation"] = {
        "status": "pass",
        "errors": [],
        "validator": "a2d_curated_route_validator",
    }
    proposed["llm_adapter"] = adapter_metadata(cfg, used=True, fallback_reason="")
    return proposed


def adapter_metadata(
    config: AiCherryPickerConfig,
    *,
    used: bool,
    fallback_reason: str,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "used": used,
        "mode": config.mode,
        "provider": config.provider,
        "model": config.model,
        "temperature": config.temperature,
        "max_output_tokens": config.max_output_tokens,
        "require_validation": config.require_validation,
        "allow_external_knowledge": config.allow_external_knowledge,
        "runtime_public_api_calls": config.runtime_public_api_calls,
        "fallback_reason": fallback_reason,
        "errors": errors or [],
    }


def parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}
