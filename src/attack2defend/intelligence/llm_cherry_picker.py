"""Validator-gated LLM cherry-picker adapter.

This module is build-time/offline only. It can call Gemini, OpenAI, or
Anthropic when --llm is explicitly requested and the matching API key exists.
The UI never imports this module and never calls providers.

LLM output is never trusted directly:
  1. deterministic full graph builds the official context pack;
  2. the LLM may only select IDs already present in that context pack;
  3. the curated route schema and no-invention validator decide final validity;
  4. on any error, fallback is deterministic prefilter.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .curated_route import CURATED_ROUTE_LIMITS, build_curated_route, validate_curated_route


DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash-lite",
    "openai": "gpt-5-nano",
    "anthropic": "claude-3-5-haiku-latest",
}
ALLOWED_PROVIDERS = tuple(DEFAULT_MODELS)
JsonTransport = Callable[[str, dict[str, str], dict[str, Any], float], dict[str, Any]]


class MissingAPIKeyError(RuntimeError):
    """Raised when LLM mode is requested but the configured provider has no key."""


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
    timeout_seconds: float

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
            timeout_seconds=float(os.getenv("A2D_CHERRY_PICKER_TIMEOUT_SECONDS", "60") or "60"),
        )


class JsonLLMClient(Protocol):
    """Minimal provider abstraction for SDK-free build-time clients."""

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        """Return a JSON object shaped like a curated route."""


class MissingAPIKeyClient:
    """Safe client used when provider keys are absent."""

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        raise MissingAPIKeyError(f"missing API key for provider {config.provider}")


class DisabledLLMClient(MissingAPIKeyClient):
    """Backward-compatible safe default client: never calls a provider."""


class GeminiJsonClient:
    def __init__(self, *, api_key: str, endpoint_template: str | None = None, transport: JsonTransport | None = None) -> None:
        self.api_key = api_key
        self.endpoint_template = endpoint_template or "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        self.transport = transport or post_json

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        url = self.endpoint_template.format(model=config.model, api_key=self.api_key)
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": config.temperature,
                "maxOutputTokens": config.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }
        response = self.transport(url, {"Content-Type": "application/json"}, payload, config.timeout_seconds)
        text = response["candidates"][0]["content"]["parts"][0]["text"]
        return parse_json_object(text)


class OpenAIResponsesJsonClient:
    def __init__(self, *, api_key: str, endpoint: str | None = None, transport: JsonTransport | None = None) -> None:
        self.api_key = api_key
        self.endpoint = endpoint or "https://api.openai.com/v1/responses"
        self.transport = transport or post_json

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        payload = {
            "model": config.model,
            "instructions": system_prompt,
            "input": user_prompt,
            "max_output_tokens": config.max_output_tokens,
            "text": {"format": {"type": "json_object"}},
        }
        response = self.transport(
            self.endpoint,
            {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            payload,
            config.timeout_seconds,
        )
        return parse_json_object(extract_openai_text(response))


class AnthropicMessagesJsonClient:
    def __init__(self, *, api_key: str, endpoint: str | None = None, transport: JsonTransport | None = None) -> None:
        self.api_key = api_key
        self.endpoint = endpoint or "https://api.anthropic.com/v1/messages"
        self.transport = transport or post_json

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        payload = {
            "model": config.model,
            "max_tokens": config.max_output_tokens,
            "temperature": config.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        response = self.transport(
            self.endpoint,
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            payload,
            config.timeout_seconds,
        )
        return parse_json_object(extract_anthropic_text(response))


def build_llm_client_from_env(config: AiCherryPickerConfig, *, transport: JsonTransport | None = None) -> JsonLLMClient:
    """Build a real provider client only when the matching key is present."""

    if config.provider == "gemini":
        key = first_env("GEMINI_API_KEY", "GOOGLE_API_KEY")
        if not key:
            return MissingAPIKeyClient()
        return GeminiJsonClient(
            api_key=key,
            endpoint_template=os.getenv("A2D_GEMINI_ENDPOINT_TEMPLATE") or None,
            transport=transport,
        )
    if config.provider == "openai":
        key = first_env("OPENAI_API_KEY")
        if not key:
            return MissingAPIKeyClient()
        return OpenAIResponsesJsonClient(
            api_key=key,
            endpoint=os.getenv("A2D_OPENAI_RESPONSES_ENDPOINT") or None,
            transport=transport,
        )
    if config.provider == "anthropic":
        key = first_env("ANTHROPIC_API_KEY")
        if not key:
            return MissingAPIKeyClient()
        return AnthropicMessagesJsonClient(
            api_key=key,
            endpoint=os.getenv("A2D_ANTHROPIC_MESSAGES_ENDPOINT") or None,
            transport=transport,
        )
    return MissingAPIKeyClient()


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

    llm_client = client or build_llm_client_from_env(cfg)
    try:
        proposed = llm_client.complete_json(
            system_prompt=build_llm_system_prompt(),
            user_prompt=build_llm_user_prompt(official_context_pack),
            config=cfg,
        )
    except MissingAPIKeyError:
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="missing_api_key")
        return deterministic
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


def post_json(url: str, headers: dict[str, str], payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit provider endpoint from config/env.
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover - depends on provider runtime.
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"provider HTTP {exc.code}: {detail}") from exc


def parse_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if not match:
            raise
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("provider response did not contain a JSON object")
    return parsed


def extract_openai_text(response: dict[str, Any]) -> str:
    if isinstance(response.get("output_text"), str):
        return response["output_text"]
    for item in response.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                return content["text"]
    raise ValueError("OpenAI response did not contain output_text")


def extract_anthropic_text(response: dict[str, Any]) -> str:
    parts = response.get("content", [])
    for part in parts:
        if part.get("type") == "text" and isinstance(part.get("text"), str):
            return part["text"]
    raise ValueError("Anthropic response did not contain text content")


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


def first_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}
