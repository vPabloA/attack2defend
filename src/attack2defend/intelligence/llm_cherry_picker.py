"""Validator-gated LLM cherry-picker adapter.

This module is build-time/offline only. It can call Gemini, OpenAI, or
Anthropic when --llm is explicitly requested and the matching API key exists.
The UI never imports this module and never calls providers.

LLM output is never trusted directly:
  1. deterministic full graph builds the official context pack;
  2. the LLM may only select IDs already present in that context pack;
  3. the curated route schema and no-invention validator decide final validity;
  4. on any error, fallback is deterministic prefilter.

Error handling guarantees:
  - No API keys, bearer tokens, or secrets are ever surfaced in error output.
  - Every provider error is classified (ssl / dns / timeout / http_4xx / etc.)
    and carries actionable diagnostic context without exposing credentials.
  - If provider="auto", providers are tried in order; the first validated
    result wins; all per-provider errors are accumulated for diagnostics.
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .curated_route import CURATED_ROUTE_LIMITS, build_curated_route, validate_curated_route


DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash-lite",
    "openai": "gpt-5-nano",
    "anthropic": "claude-3-5-haiku-latest",
}
# Ordered by cost-efficiency for auto mode
AUTO_PROVIDER_ORDER: tuple[str, ...] = ("gemini", "openai", "anthropic")
ALLOWED_PROVIDERS = tuple(DEFAULT_MODELS)
JsonTransport = Callable[[str, dict[str, str], dict[str, Any], float], dict[str, Any]]

# Regex patterns that identify secrets in text — used for sanitization only
_SECRET_PATTERNS = (
    re.compile(r'"(?:key|api_key|token|secret|password|Authorization)"\s*:\s*"[^"]{4,}"', re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-_.~+/]{8,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
    re.compile(r"AQ\.[A-Za-z0-9_\-]{10,}"),
)


# ---------------------------------------------------------------------------
# Typed exception hierarchy — no secrets ever stored in these objects
# ---------------------------------------------------------------------------

class MissingAPIKeyError(RuntimeError):
    """Raised when LLM mode is requested but the configured provider has no key."""


class ProviderTransportError(Exception):
    """Low-level network/HTTP error from post_json. Never contains secrets.

    Attributes
    ----------
    endpoint_sanitized : URL with key/token query params stripped.
    http_status        : HTTP response code, or None for network-layer errors.
    error_type         : One of ssl | dns | timeout | network | http_400 |
                         http_401 | http_403 | http_404 | http_429 |
                         http_5xx | http_other | parse_error | unknown.
    message            : Human-readable, sanitized description.
    response_body      : Truncated, sanitized response body when available.
    """

    def __init__(
        self,
        *,
        endpoint_sanitized: str,
        http_status: int | None,
        error_type: str,
        message: str,
        response_body: str | None = None,
    ) -> None:
        super().__init__(f"[{error_type}] {message}")
        self.endpoint_sanitized = endpoint_sanitized
        self.http_status = http_status
        self.error_type = error_type
        self.message = message
        self.response_body = response_body


class ProviderCallError(Exception):
    """Full provider call error with provider/model context. Never contains secrets."""

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        endpoint_sanitized: str,
        http_status: int | None,
        error_type: str,
        message: str,
        response_body: str | None = None,
    ) -> None:
        super().__init__(f"{provider}/{model} [{error_type}] {message}")
        self.provider = provider
        self.model = model
        self.endpoint_sanitized = endpoint_sanitized
        self.http_status = http_status
        self.error_type = error_type
        self.message = message
        self.response_body = response_body

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "endpoint_sanitized": self.endpoint_sanitized,
            "http_status": self.http_status,
            "error_type": self.error_type,
            "message": self.message,
            "response_body_sanitized": self.response_body,
        }


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

def sanitize_url(url: str) -> str:
    """Strip API-key-like query parameters from a URL. Returns safe string."""
    return re.sub(
        r"([?&](?:key|api_key|token|access_token|secret)=)[^&]*",
        r"\1[REDACTED]",
        url,
        flags=re.IGNORECASE,
    )


def sanitize_body(body: str, max_length: int = 500) -> str:
    """Truncate and redact secrets from a response body."""
    truncated = body[:max_length]
    for pattern in _SECRET_PATTERNS:
        truncated = pattern.sub("[REDACTED]", truncated)
    return truncated


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

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
    timeout_seconds: float = 60.0
    provider_order: tuple[str, ...] = AUTO_PROVIDER_ORDER

    @classmethod
    def from_env(cls) -> "AiCherryPickerConfig":
        provider = os.getenv("A2D_AI_PROVIDER", "gemini").strip().lower() or "gemini"
        if provider not in (*DEFAULT_MODELS, "auto"):
            provider = "gemini"

        # model is resolved per-provider; for auto mode use gemini's default as a placeholder
        model_env_key = {
            "gemini": "A2D_GEMINI_MODEL",
            "openai": "A2D_OPENAI_MODEL",
            "anthropic": "A2D_ANTHROPIC_MODEL",
        }.get(provider, "A2D_GEMINI_MODEL")
        default_model = DEFAULT_MODELS.get(provider, DEFAULT_MODELS["gemini"])

        raw_order = os.getenv("A2D_PROVIDER_ORDER", "").strip()
        if raw_order:
            order: tuple[str, ...] = tuple(
                p.strip().lower() for p in raw_order.split(",") if p.strip().lower() in DEFAULT_MODELS
            )
        else:
            order = AUTO_PROVIDER_ORDER

        return cls(
            mode=os.getenv("A2D_CHERRY_PICKER_MODE", "deterministic").strip().lower() or "deterministic",
            provider=provider,
            model=os.getenv(model_env_key, default_model).strip() or default_model,
            temperature=float(os.getenv("A2D_CHERRY_PICKER_TEMPERATURE", "0") or "0"),
            max_output_tokens=int(os.getenv("A2D_CHERRY_PICKER_MAX_OUTPUT_TOKENS", "4000") or "4000"),
            require_validation=parse_bool(os.getenv("A2D_CHERRY_PICKER_REQUIRE_VALIDATION", "true")),
            allow_external_knowledge=parse_bool(os.getenv("A2D_CHERRY_PICKER_ALLOW_EXTERNAL_KNOWLEDGE", "false")),
            runtime_public_api_calls=parse_bool(os.getenv("A2D_CHERRY_PICKER_RUNTIME_PUBLIC_API_CALLS", "false")),
            timeout_seconds=float(os.getenv("A2D_CHERRY_PICKER_TIMEOUT_SECONDS", "60") or "60"),
            provider_order=order,
        )


# ---------------------------------------------------------------------------
# Provider client protocol and implementations
# ---------------------------------------------------------------------------

class JsonLLMClient(Protocol):
    """Minimal provider abstraction for SDK-free build-time clients."""

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        """Return a JSON object shaped like a curated route.

        Raises ProviderCallError on any provider failure (network, HTTP, parse).
        Raises MissingAPIKeyError if no key is configured.
        """


class MissingAPIKeyClient:
    """Safe client used when provider keys are absent."""

    def complete_json(self, *, system_prompt: str, user_prompt: str, config: AiCherryPickerConfig) -> dict[str, Any]:
        raise MissingAPIKeyError(f"missing API key for provider {config.provider!r}")


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
        try:
            response = self.transport(url, {"Content-Type": "application/json"}, payload, config.timeout_seconds)
            text = response["candidates"][0]["content"]["parts"][0]["text"]
            return parse_json_object(text)
        except ProviderTransportError as pte:
            raise ProviderCallError(
                provider="gemini",
                model=config.model,
                endpoint_sanitized=pte.endpoint_sanitized,
                http_status=pte.http_status,
                error_type=pte.error_type,
                message=pte.message,
                response_body=pte.response_body,
            ) from pte
        except (KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderCallError(
                provider="gemini",
                model=config.model,
                endpoint_sanitized=sanitize_url(url),
                http_status=None,
                error_type="parse_error",
                message=f"unexpected response shape: {exc}",
            ) from exc


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
        try:
            response = self.transport(
                self.endpoint,
                {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                payload,
                config.timeout_seconds,
            )
            return parse_json_object(extract_openai_text(response))
        except ProviderTransportError as pte:
            raise ProviderCallError(
                provider="openai",
                model=config.model,
                endpoint_sanitized=pte.endpoint_sanitized,
                http_status=pte.http_status,
                error_type=pte.error_type,
                message=pte.message,
                response_body=pte.response_body,
            ) from pte
        except (KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderCallError(
                provider="openai",
                model=config.model,
                endpoint_sanitized=sanitize_url(self.endpoint),
                http_status=None,
                error_type="parse_error",
                message=f"unexpected response shape: {exc}",
            ) from exc


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
        try:
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
        except ProviderTransportError as pte:
            raise ProviderCallError(
                provider="anthropic",
                model=config.model,
                endpoint_sanitized=pte.endpoint_sanitized,
                http_status=pte.http_status,
                error_type=pte.error_type,
                message=pte.message,
                response_body=pte.response_body,
            ) from pte
        except (KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderCallError(
                provider="anthropic",
                model=config.model,
                endpoint_sanitized=sanitize_url(self.endpoint),
                http_status=None,
                error_type="parse_error",
                message=f"unexpected response shape: {exc}",
            ) from exc


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def build_provider_client(
    provider: str,
    *,
    transport: JsonTransport | None = None,
) -> JsonLLMClient:
    """Build a real client for *provider*. Returns MissingAPIKeyClient when no key."""
    if provider == "gemini":
        key = first_env("GEMINI_API_KEY", "GOOGLE_API_KEY")
        if not key:
            return MissingAPIKeyClient()
        return GeminiJsonClient(
            api_key=key,
            endpoint_template=os.getenv("A2D_GEMINI_ENDPOINT_TEMPLATE") or None,
            transport=transport,
        )
    if provider == "openai":
        key = first_env("OPENAI_API_KEY")
        if not key:
            return MissingAPIKeyClient()
        return OpenAIResponsesJsonClient(
            api_key=key,
            endpoint=os.getenv("A2D_OPENAI_RESPONSES_ENDPOINT") or None,
            transport=transport,
        )
    if provider == "anthropic":
        key = first_env("ANTHROPIC_API_KEY")
        if not key:
            return MissingAPIKeyClient()
        return AnthropicMessagesJsonClient(
            api_key=key,
            endpoint=os.getenv("A2D_ANTHROPIC_MESSAGES_ENDPOINT") or None,
            transport=transport,
        )
    return MissingAPIKeyClient()


def build_llm_client_from_env(config: AiCherryPickerConfig, *, transport: JsonTransport | None = None) -> JsonLLMClient:
    """Build a real provider client only when the matching key is present.

    For provider='auto' the returned object is a MissingAPIKeyClient; callers
    should use cherry_pick_route() which implements the full auto-loop.
    """
    if config.provider == "auto":
        return MissingAPIKeyClient()
    return build_provider_client(config.provider, transport=transport)


def _model_for_provider(provider: str) -> str:
    env_key = {"gemini": "A2D_GEMINI_MODEL", "openai": "A2D_OPENAI_MODEL", "anthropic": "A2D_ANTHROPIC_MODEL"}.get(provider)
    if env_key:
        return os.getenv(env_key, DEFAULT_MODELS[provider]).strip() or DEFAULT_MODELS[provider]
    return DEFAULT_MODELS.get(provider, "unknown")


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Core cherry-pick logic with multi-provider auto mode
# ---------------------------------------------------------------------------

def cherry_pick_route(
    capability_response: dict[str, Any],
    official_context_pack: dict[str, Any],
    *,
    config: AiCherryPickerConfig | None = None,
    client: JsonLLMClient | None = None,
) -> dict[str, Any]:
    """Return a validator-gated curated route.

    If mode is not ``llm``, if provider execution fails for all attempted
    providers, or if the output fails validation, the deterministic curated
    route is returned with explicit fallback metadata and sanitized errors.

    When provider='auto', providers are tried in ``config.provider_order``
    order; only providers with a configured API key are attempted.
    No invalid LLM output escapes this function.
    """
    cfg = config or AiCherryPickerConfig.from_env()
    deterministic = build_curated_route(capability_response, official_context_pack)
    deterministic.setdefault("llm_adapter", {})

    if cfg.mode != "llm":
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="mode_not_llm")
        return deterministic

    if cfg.allow_external_knowledge or cfg.runtime_public_api_calls:
        deterministic["llm_adapter"] = adapter_metadata(
            cfg, used=False, fallback_reason="unsafe_external_knowledge_or_runtime_api"
        )
        return deterministic

    # Build the provider attempt list -------------------------------------------
    # If a test injects a client directly, wrap it as a single-provider attempt.
    if client is not None:
        providers_to_try: list[tuple[str, str, JsonLLMClient]] = [(cfg.provider, cfg.model, client)]
    elif cfg.provider == "auto":
        providers_to_try = []
        for p in cfg.provider_order:
            c = build_provider_client(p, transport=None)
            if not isinstance(c, MissingAPIKeyClient):
                providers_to_try.append((p, _model_for_provider(p), c))
        if not providers_to_try:
            deterministic["llm_adapter"] = adapter_metadata(
                cfg, used=False, fallback_reason="missing_api_key",
                providers_attempted=list(cfg.provider_order),
            )
            return deterministic
    else:
        single = build_llm_client_from_env(cfg)
        if isinstance(single, MissingAPIKeyClient):
            # Trigger MissingAPIKeyError so we get the right fallback_reason
            try:
                single.complete_json(system_prompt="", user_prompt="", config=cfg)
            except MissingAPIKeyError:
                deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="missing_api_key")
                return deterministic
        providers_to_try = [(cfg.provider, cfg.model, single)]

    # Attempt providers in order ------------------------------------------------
    provider_errors: list[ProviderCallError] = []
    proposed: dict[str, Any] | None = None
    used_provider: str = cfg.provider
    used_model: str = cfg.model

    system_prompt = build_llm_system_prompt()
    user_prompt = build_llm_user_prompt(official_context_pack)

    for provider_name, model_name, provider_client in providers_to_try:
        # Build a per-provider config view (same params, different provider/model)
        per_cfg = _config_for_provider(cfg, provider_name, model_name)
        try:
            proposed = provider_client.complete_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                config=per_cfg,
            )
            used_provider = provider_name
            used_model = model_name
            break
        except MissingAPIKeyError:
            # Guard — should not happen since we filtered above
            continue
        except ProviderCallError as pce:
            provider_errors.append(pce)
            continue
        except Exception as exc:  # pragma: no cover — unexpected errors
            provider_errors.append(ProviderCallError(
                provider=provider_name,
                model=model_name,
                endpoint_sanitized="unknown",
                http_status=None,
                error_type=type(exc).__name__,
                message=sanitize_body(str(exc), max_length=200),
            ))
            continue

    if proposed is None:
        first_type = provider_errors[0].error_type if provider_errors else "unknown"
        deterministic["llm_adapter"] = adapter_metadata(
            cfg,
            used=False,
            fallback_reason=f"provider_error:{first_type}",
            provider_errors=provider_errors,
            providers_attempted=[p for p, _, _ in providers_to_try],
        )
        return deterministic

    # Validate the proposed output ---------------------------------------------
    proposed["selection_method"] = "llm_cherry_picker"
    proposed["runtime_public_api_calls"] = False
    errors = validate_curated_route(proposed, official_context_pack)
    if errors:
        deterministic["llm_adapter"] = adapter_metadata(
            cfg,
            used=False,
            fallback_reason="validation_failed",
            errors=errors,
            provider_errors=provider_errors,
            providers_attempted=[p for p, _, _ in providers_to_try],
            used_provider=used_provider,
            used_model=used_model,
        )
        return deterministic

    proposed["validation"] = {
        "status": "pass",
        "errors": [],
        "validator": "a2d_curated_route_validator",
    }
    proposed["llm_adapter"] = adapter_metadata(
        cfg,
        used=True,
        fallback_reason="",
        provider_errors=provider_errors,
        providers_attempted=[p for p, _, _ in providers_to_try],
        used_provider=used_provider,
        used_model=used_model,
    )
    return proposed


# ---------------------------------------------------------------------------
# Transport layer
# ---------------------------------------------------------------------------

def post_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: float,
    *,
    _transport: JsonTransport | None = None,
) -> dict[str, Any]:
    """POST *payload* as JSON to *url*, returning the parsed response dict.

    Raises ProviderTransportError (never RuntimeError) with a sanitized,
    classified error for all failure modes:
      ssl       — TLS/certificate errors
      dns       — hostname resolution failures
      timeout   — connect or read timeout
      network   — other URLError (proxy, refused connection, etc.)
      http_400  — bad request
      http_401  — unauthorized (key problem; body truncated, no key echoed)
      http_403  — forbidden
      http_404  — not found / model does not exist
      http_429  — rate limit / quota
      http_5xx  — server-side error
      http_other — other HTTP status

    The *_transport* kwarg is for testing only. When provided it replaces the
    urllib.request.urlopen call. A test transport may raise urllib.error.HTTPError
    or urllib.error.URLError to exercise the classification logic, or return a
    dict directly to simulate a successful response.
    """
    safe_url = sanitize_url(url)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        if _transport is not None:
            return _transport(url, headers, payload, timeout_seconds)
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8", errors="replace")
        body_sanitized = sanitize_body(raw_body)
        status = exc.code
        error_type = _http_error_type(status)
        # For 401/403, do not echo the body (may contain hints about the key)
        safe_body = None if status in (401, 403) else body_sanitized
        raise ProviderTransportError(
            endpoint_sanitized=safe_url,
            http_status=status,
            error_type=error_type,
            message=f"HTTP {status}: {exc.reason}",
            response_body=safe_body,
        ) from exc
    except urllib.error.URLError as exc:
        error_type, message = _classify_url_error(exc)
        raise ProviderTransportError(
            endpoint_sanitized=safe_url,
            http_status=None,
            error_type=error_type,
            message=message,
        ) from exc
    except TimeoutError as exc:
        raise ProviderTransportError(
            endpoint_sanitized=safe_url,
            http_status=None,
            error_type="timeout",
            message=f"connection timed out after {timeout_seconds}s",
        ) from exc


def _http_error_type(status: int) -> str:
    mapping = {400: "http_400", 401: "http_401", 403: "http_403", 404: "http_404", 429: "http_429"}
    if status in mapping:
        return mapping[status]
    if 500 <= status < 600:
        return "http_5xx"
    return "http_other"


def _classify_url_error(exc: urllib.error.URLError) -> tuple[str, str]:
    """Return (error_type, human_message) for a URLError. Never exposes secrets."""
    reason = exc.reason
    reason_str = str(reason).lower()
    if isinstance(reason, ssl.SSLError):
        return "ssl", f"TLS/certificate error: {reason.strerror or reason_str}"
    if isinstance(reason, socket.gaierror):
        return "dns", f"DNS resolution failed: {reason.strerror or reason_str}"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout", "connection timed out"
    if "ssl" in reason_str or "certificate" in reason_str:
        return "ssl", f"TLS error: {reason_str[:120]}"
    if "name or service not known" in reason_str or "getaddrinfo" in reason_str:
        return "dns", f"DNS error: {reason_str[:120]}"
    if "timed out" in reason_str:
        return "timeout", f"timeout: {reason_str[:120]}"
    return "network", f"network error: {reason_str[:200]}"


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------

def adapter_metadata(
    config: AiCherryPickerConfig,
    *,
    used: bool,
    fallback_reason: str,
    errors: list[str] | None = None,
    provider_errors: list[ProviderCallError] | None = None,
    providers_attempted: list[str] | None = None,
    used_provider: str | None = None,
    used_model: str | None = None,
) -> dict[str, Any]:
    return {
        "used": used,
        "mode": config.mode,
        "provider": used_provider or config.provider,
        "model": used_model or config.model,
        "temperature": config.temperature,
        "max_output_tokens": config.max_output_tokens,
        "require_validation": config.require_validation,
        "allow_external_knowledge": config.allow_external_knowledge,
        "runtime_public_api_calls": config.runtime_public_api_calls,
        "fallback_reason": fallback_reason,
        "errors": errors or [],
        "provider_errors": [e.as_dict() for e in (provider_errors or [])],
        "providers_attempted": providers_attempted or [],
    }


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _config_for_provider(cfg: AiCherryPickerConfig, provider: str, model: str) -> AiCherryPickerConfig:
    """Return a config view with provider/model overridden (all other fields preserved)."""
    return AiCherryPickerConfig(
        mode=cfg.mode,
        provider=provider,
        model=model,
        temperature=cfg.temperature,
        max_output_tokens=cfg.max_output_tokens,
        require_validation=cfg.require_validation,
        allow_external_knowledge=cfg.allow_external_knowledge,
        runtime_public_api_calls=cfg.runtime_public_api_calls,
        timeout_seconds=cfg.timeout_seconds,
        provider_order=cfg.provider_order,
    )


def first_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}
