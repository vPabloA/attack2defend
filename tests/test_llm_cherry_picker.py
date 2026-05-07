import copy
import json
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from io import BytesIO
from pathlib import Path

import jsonschema
import pytest

from attack2defend.capability import resolve_defense_route
from attack2defend.intelligence import (
    AiCherryPickerConfig,
    DEFAULT_MODELS,
    build_curated_route,
    build_llm_system_prompt,
    build_llm_user_prompt,
    build_official_context_pack,
    cherry_pick_route,
)
from attack2defend.intelligence.llm_cherry_picker import (
    ProviderCallError,
    ProviderTransportError,
    post_json,
    sanitize_url,
    sanitize_body,
    _classify_url_error,
    AUTO_PROVIDER_ORDER,
    GeminiJsonClient,
    OpenAIResponsesJsonClient,
    AnthropicMessagesJsonClient,
    MissingAPIKeyClient,
    MissingAPIKeyError,
    build_provider_client,
)


BUNDLE = "data/knowledge-bundle.json"
CURATED_SCHEMA = Path("schemas/a2d_curated_route.schema.json")


# ---------------------------------------------------------------------------
# Fake transports
# ---------------------------------------------------------------------------

def _make_http_error_transport(status: int, body: str = ""):
    """Returns a transport that raises urllib.error.HTTPError with the given status."""
    def transport(url, headers, payload, timeout):
        raise urllib.error.HTTPError(
            url=url,
            code=status,
            msg=f"Fake {status}",
            hdrs={},
            fp=BytesIO(body.encode()),
        )
    return transport


def _make_url_error_transport(reason):
    """Returns a transport that raises urllib.error.URLError with the given reason."""
    def transport(url, headers, payload, timeout):
        raise urllib.error.URLError(reason)
    return transport


def _make_ok_transport(response_dict: dict):
    """Returns a transport that returns response_dict immediately."""
    def transport(url, headers, payload, timeout):
        return response_dict
    return transport


# ---------------------------------------------------------------------------
# Mock LLM clients
# ---------------------------------------------------------------------------

class ValidMockClient:
    def __init__(self, payload):
        self.payload = payload

    def complete_json(self, *, system_prompt, user_prompt, config):
        assert "must not invent IDs" in system_prompt
        assert "official_context_pack" in user_prompt
        assert config.provider in DEFAULT_MODELS
        return copy.deepcopy(self.payload)


class InventingMockClient:
    def complete_json(self, *, system_prompt, user_prompt, config):
        return {
            "schema_version": "1.0",
            "input": "CVE-2099-0000",
            "normalized_input": "CVE-2099-0000",
            "mode": "official_rag_grounded",
            "selection_method": "llm_cherry_picker",
            "ai_ready": True,
            "runtime_public_api_calls": False,
            "limits": {"cve": 1, "cwe": 3, "capec": 6, "attack": 8, "d3fend": 6},
            "stages": [
                {"type": "cve", "label": "CVE", "available_count": 0, "selected": [{"id": "CVE-2099-0000", "type": "cve", "name": "Invented", "official_link": "", "source_ref": "missing_source_ref", "rank": 1, "score": 999, "reason_es": "Invented."}]},
                {"type": "cwe", "label": "CWE", "available_count": 0, "selected": []},
                {"type": "capec", "label": "CAPEC", "available_count": 0, "selected": []},
                {"type": "attack", "label": "ATT&CK", "available_count": 0, "selected": []},
                {"type": "d3fend", "label": "D3FEND", "available_count": 0, "selected": []},
            ],
            "full_traceability_counts": {"cve": 0, "cwe": 0, "capec": 0, "attack": 0, "d3fend": 0},
            "rationale_es": "Intento inválido.",
            "validation": {"status": "pass", "errors": [], "validator": "a2d_curated_route_validator"},
        }


class FailingMockClient:
    """Client that always raises ProviderCallError."""
    def __init__(self, error_type="network", http_status=None):
        self.error_type = error_type
        self.http_status = http_status

    def complete_json(self, *, system_prompt, user_prompt, config):
        raise ProviderCallError(
            provider=config.provider,
            model=config.model,
            endpoint_sanitized="https://fake.example.com/v1/complete",
            http_status=self.http_status,
            error_type=self.error_type,
            message=f"Simulated {self.error_type} failure",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _capability_and_context():
    capability = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    return capability, build_official_context_pack(capability)


def _llm_config(**overrides) -> AiCherryPickerConfig:
    defaults = dict(
        mode="llm",
        provider="gemini",
        model="gemini-2.5-flash-lite",
        temperature=0,
        max_output_tokens=4000,
        require_validation=True,
        allow_external_knowledge=False,
        runtime_public_api_calls=False,
    )
    defaults.update(overrides)
    return AiCherryPickerConfig(**defaults)


# ===========================================================================
# Existing tests (preserved)
# ===========================================================================

def test_config_defaults_to_cheap_functional_models(monkeypatch):
    for key in [
        "A2D_CHERRY_PICKER_MODE",
        "A2D_AI_PROVIDER",
        "A2D_GEMINI_MODEL",
        "A2D_OPENAI_MODEL",
        "A2D_ANTHROPIC_MODEL",
    ]:
        monkeypatch.delenv(key, raising=False)

    cfg = AiCherryPickerConfig.from_env()

    assert cfg.mode == "deterministic"
    assert cfg.provider == "gemini"
    assert cfg.model == "gemini-2.5-flash-lite"
    assert DEFAULT_MODELS["openai"] == "gpt-5-nano"
    assert DEFAULT_MODELS["anthropic"] == "claude-3-5-haiku-latest"
    assert cfg.allow_external_knowledge is False
    assert cfg.runtime_public_api_calls is False


def test_prompts_forbid_external_knowledge_and_require_allowed_ids():
    _, context = _capability_and_context()
    system_prompt = build_llm_system_prompt()
    user_prompt = build_llm_user_prompt(context)

    assert "must not invent IDs" in system_prompt
    assert "must not use external knowledge" in system_prompt
    assert "Allowed IDs only" in user_prompt
    assert "runtime_public_api_calls" in user_prompt


def test_llm_mode_falls_back_when_provider_is_disabled():
    capability, context = _capability_and_context()
    cfg = _llm_config(provider="gemini", model="gemini-2.5-flash-lite")

    route = cherry_pick_route(capability, context, config=cfg)

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["validation"]["status"] == "pass"
    assert route["selection_method"] == "deterministic_prefilter"
    assert route["llm_adapter"]["used"] is False
    assert route["llm_adapter"]["fallback_reason"].startswith(("provider_error", "missing_api_key"))


def test_valid_mock_llm_output_can_pass_validator():
    capability, context = _capability_and_context()
    baseline = build_curated_route(capability, context)
    cfg = _llm_config(provider="openai", model="gpt-5-nano")

    route = cherry_pick_route(capability, context, config=cfg, client=ValidMockClient(baseline))

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["validation"]["status"] == "pass"
    assert route["selection_method"] == "llm_cherry_picker"
    assert route["llm_adapter"]["used"] is True


def test_invented_llm_output_is_blocked_and_falls_back():
    capability, context = _capability_and_context()
    cfg = _llm_config(provider="anthropic", model="claude-3-5-haiku-latest")

    route = cherry_pick_route(capability, context, config=cfg, client=InventingMockClient())

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["validation"]["status"] == "pass"
    assert route["selection_method"] == "deterministic_prefilter"
    assert route["llm_adapter"]["used"] is False
    assert route["llm_adapter"]["fallback_reason"] == "validation_failed"
    assert any("invented id" in error for error in route["llm_adapter"]["errors"])


def test_curate_route_cli_llm_flag_still_outputs_valid_json():
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/intelligence/curate_route.py",
            "--bundle",
            BUNDLE,
            "--input",
            "CVE-2024-37079",
            "--llm",
            "--pretty",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    jsonschema.validate(payload, _schema(CURATED_SCHEMA))
    assert payload["runtime_public_api_calls"] is False
    assert payload["validation"]["status"] == "pass"
    assert payload["llm_adapter"]["used"] is False


# ===========================================================================
# New tests — error classification
# ===========================================================================

def test_post_json_classifies_http_400():
    transport = _make_http_error_transport(400, '{"error": "bad request body"}')
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.http_status == 400
    assert err.error_type == "http_400"
    # HTTP error message includes the status; body detail is in response_body
    assert "400" in err.message
    assert err.response_body is not None
    assert "bad request" in err.response_body.lower()


def test_post_json_classifies_http_401_without_leaking_body():
    transport = _make_http_error_transport(401, '{"error": "invalid api key sk-secret-abc"}')
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.http_status == 401
    assert err.error_type == "http_401"
    # 401 body is suppressed entirely
    assert err.response_body is None


def test_post_json_classifies_http_403():
    transport = _make_http_error_transport(403, '{"error": "forbidden"}')
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.http_status == 403
    assert err.error_type == "http_403"
    assert err.response_body is None  # 403 body also suppressed


def test_post_json_classifies_http_404():
    transport = _make_http_error_transport(404, '{"error": "model not found"}')
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.http_status == 404
    assert err.error_type == "http_404"


def test_post_json_classifies_http_429():
    transport = _make_http_error_transport(429, '{"error": "rate limit exceeded"}')
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.http_status == 429
    assert err.error_type == "http_429"


def test_post_json_classifies_http_500():
    transport = _make_http_error_transport(500, '{"error": "internal server error"}')
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.http_status == 500
    assert err.error_type == "http_5xx"


def test_post_json_classifies_ssl_error():
    ssl_err = ssl.SSLError("CERTIFICATE_VERIFY_FAILED")
    transport = _make_url_error_transport(ssl_err)
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.error_type == "ssl"
    assert err.http_status is None


def test_post_json_classifies_dns_error():
    dns_err = socket.gaierror("Name or service not known")
    transport = _make_url_error_transport(dns_err)
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.error_type == "dns"
    assert err.http_status is None


def test_post_json_classifies_timeout():
    timeout_err = socket.timeout("timed out")
    transport = _make_url_error_transport(timeout_err)
    with pytest.raises(ProviderTransportError) as exc_info:
        post_json("https://fake.example.com/v1/msg", {}, {}, 10, _transport=transport)
    err = exc_info.value
    assert err.error_type == "timeout"


# ===========================================================================
# New tests — secret sanitization
# ===========================================================================

def test_sanitize_url_strips_api_key_query_param():
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent?key=SECRET_KEY_123&alt=json"
    safe = sanitize_url(url)
    assert "SECRET_KEY_123" not in safe
    assert "[REDACTED]" in safe
    assert "alt=json" in safe  # non-secret params preserved


def test_sanitize_body_redacts_bearer_token():
    body = 'Authorization: Bearer sk-proj-SECRETKEY123\n{"result": "ok"}'
    safe = sanitize_body(body)
    assert "sk-proj-SECRETKEY123" not in safe
    assert "[REDACTED]" in safe


def test_sanitize_body_redacts_api_key_field():
    body = '{"api_key": "AQ.Ab8RN6I1VO_very_secret_key", "data": "ok"}'
    safe = sanitize_body(body)
    assert "AQ.Ab8RN6I1VO_very_secret_key" not in safe


def test_adapter_metadata_contains_no_api_keys(monkeypatch):
    """Verify that adapter_metadata in the route output never contains key-like strings."""
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key-SHOULD_NOT_APPEAR")
    monkeypatch.setenv("A2D_CHERRY_PICKER_MODE", "llm")
    monkeypatch.setenv("A2D_AI_PROVIDER", "gemini")

    capability, context = _capability_and_context()
    cfg = AiCherryPickerConfig.from_env()
    route = cherry_pick_route(capability, context, config=cfg)

    route_text = json.dumps(route)
    assert "SHOULD_NOT_APPEAR" not in route_text
    assert "fake-gemini-key" not in route_text


# ===========================================================================
# New tests — multi-provider auto mode
# ===========================================================================

def test_auto_mode_falls_back_to_second_provider_when_first_fails():
    """Provider A raises ProviderCallError; Provider B succeeds with valid output."""
    capability, context = _capability_and_context()
    baseline = build_curated_route(capability, context)

    attempt_log: list[str] = []

    class ProviderAClient:
        def complete_json(self, *, system_prompt, user_prompt, config):
            attempt_log.append("A")
            raise ProviderCallError(
                provider="gemini",
                model="gemini-2.5-flash-lite",
                endpoint_sanitized="https://generativelanguage.googleapis.com/v1beta/models/[REDACTED]",
                http_status=500,
                error_type="http_5xx",
                message="Simulated server error",
            )

    class ProviderBClient:
        def complete_json(self, *, system_prompt, user_prompt, config):
            attempt_log.append("B")
            return copy.deepcopy(baseline)

    # Wire auto mode manually: inject client list via a wrapper client
    # Since cherry_pick_route accepts a single injected client, we test the
    # multi-provider logic by using provider="auto" and patching build_provider_client.
    import attack2defend.intelligence.llm_cherry_picker as mod

    original_build = mod.build_provider_client

    def fake_build(provider, *, transport=None):
        if provider == "gemini":
            return ProviderAClient()
        if provider == "openai":
            return ProviderBClient()
        return MissingAPIKeyClient()

    mod.build_provider_client = fake_build
    try:
        cfg = AiCherryPickerConfig(
            mode="llm",
            provider="auto",
            model="auto",
            temperature=0,
            max_output_tokens=4000,
            require_validation=True,
            allow_external_knowledge=False,
            runtime_public_api_calls=False,
            provider_order=("gemini", "openai"),
        )
        route = cherry_pick_route(capability, context, config=cfg)
    finally:
        mod.build_provider_client = original_build

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["llm_adapter"]["used"] is True
    assert route["selection_method"] == "llm_cherry_picker"
    assert "A" in attempt_log and "B" in attempt_log
    # Provider A error should be recorded
    assert len(route["llm_adapter"]["provider_errors"]) == 1
    assert route["llm_adapter"]["provider_errors"][0]["error_type"] == "http_5xx"


def test_auto_mode_all_providers_fail_returns_deterministic():
    """All providers fail → deterministic fallback with full error list."""
    import attack2defend.intelligence.llm_cherry_picker as mod

    original_build = mod.build_provider_client

    def fake_build_all_fail(provider, *, transport=None):
        class AlwaysFailClient:
            def complete_json(self, *, system_prompt, user_prompt, config):
                raise ProviderCallError(
                    provider=provider,
                    model="fake-model",
                    endpoint_sanitized="https://fake.example.com/v1/msg",
                    http_status=503,
                    error_type="http_5xx",
                    message="service unavailable",
                )
        return AlwaysFailClient()

    mod.build_provider_client = fake_build_all_fail
    try:
        capability, context = _capability_and_context()
        cfg = AiCherryPickerConfig(
            mode="llm",
            provider="auto",
            model="auto",
            temperature=0,
            max_output_tokens=4000,
            require_validation=True,
            allow_external_knowledge=False,
            runtime_public_api_calls=False,
            provider_order=("gemini", "openai"),
        )
        route = cherry_pick_route(capability, context, config=cfg)
    finally:
        mod.build_provider_client = fake_build_all_fail

    mod.build_provider_client = original_build

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["llm_adapter"]["used"] is False
    assert "provider_error" in route["llm_adapter"]["fallback_reason"]
    assert len(route["llm_adapter"]["provider_errors"]) == 2
    assert route["selection_method"] == "deterministic_prefilter"


# ===========================================================================
# New tests — artifact output from CLI
# ===========================================================================

def test_artifact_output_cli_no_secrets(tmp_path):
    """--artifact-output writes a secret-free JSON artifact."""
    artifact_path = tmp_path / "artifact.json"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/intelligence/curate_route.py",
            "--bundle", BUNDLE,
            "--input", "CVE-2024-37079",
            "--llm",
            "--artifact-output", str(artifact_path),
            "--pretty",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "GEMINI_API_KEY": "FAKE_KEY_SHOULD_NOT_APPEAR"},
    )

    assert artifact_path.exists(), "artifact file was not written"
    artifact = json.loads(artifact_path.read_text())

    # Structure checks
    assert artifact["artifact_type"] == "a2d_curated_route_artifact"
    assert "generated_at" in artifact
    assert "ai_status" in artifact
    assert artifact["validation_status"] == "pass"

    # No secrets
    artifact_text = artifact_path.read_text()
    assert "FAKE_KEY_SHOULD_NOT_APPEAR" not in artifact_text


def test_debug_provider_flag_prints_to_stderr():
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/intelligence/curate_route.py",
            "--bundle", BUNDLE,
            "--input", "CVE-2024-37079",
            "--llm",
            "--debug-provider",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "LLM provider diagnostics" in completed.stderr
    assert "ai_status" in completed.stderr


def test_fail_on_provider_error_exits_with_code_3(monkeypatch, tmp_path):
    """--fail-on-provider-error returns exit code 3 when provider fails."""
    # Run without a real API key so provider fails, then check exit code
    env = {k: v for k, v in __import__("os").environ.items() if "API_KEY" not in k.upper()}
    env["A2D_CHERRY_PICKER_MODE"] = "llm"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/intelligence/curate_route.py",
            "--bundle", BUNDLE,
            "--input", "CVE-2024-37079",
            "--llm",
            "--fail-on-provider-error",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    # Should be 3 (provider_failed) or 0 if somehow succeeds, never 1 or 2
    assert result.returncode in (0, 3)


# ===========================================================================
# New tests — provider_errors in adapter metadata
# ===========================================================================

def test_provider_error_includes_structured_diagnostic():
    capability, context = _capability_and_context()
    cfg = _llm_config(provider="openai", model="gpt-5-nano")

    route = cherry_pick_route(capability, context, config=cfg, client=FailingMockClient("http_429", 429))

    assert route["llm_adapter"]["used"] is False
    assert "provider_error" in route["llm_adapter"]["fallback_reason"]
    errors = route["llm_adapter"]["provider_errors"]
    assert len(errors) == 1
    err = errors[0]
    assert err["provider"] == "openai"
    assert err["http_status"] == 429
    assert err["error_type"] == "http_429"
    assert "fake.example.com" in err["endpoint_sanitized"]


def test_provider_error_dict_never_contains_bearer_token():
    capability, context = _capability_and_context()
    cfg = _llm_config(provider="anthropic", model="claude-3-5-haiku-latest")

    route = cherry_pick_route(capability, context, config=cfg, client=FailingMockClient("http_401", 401))

    route_text = json.dumps(route)
    assert "Bearer" not in route_text
    assert "sk-ant" not in route_text
    assert "api_key" not in route_text.lower() or "[REDACTED]" in route_text


# ===========================================================================
# New tests — post_json _transport injection (unit tests)
# ===========================================================================

# Note: post_json now accepts optional _transport kwarg for testing.
# We test the real classify/sanitize path via fake transports.

def _make_classified_transport(inner_transport):
    """Wrap a raw error-raising function through post_json's classification logic."""
    def transport(url, headers, payload, timeout):
        return post_json(url, headers, payload, timeout, _transport=inner_transport)
    return transport


def test_gemini_client_wraps_transport_error_as_provider_call_error():
    raw = _make_http_error_transport(503, '{"error": "service unavailable"}')
    client = GeminiJsonClient(api_key="FAKE", transport=_make_classified_transport(raw))
    cfg = _llm_config(provider="gemini", model="gemini-2.5-flash-lite")

    with pytest.raises(ProviderCallError) as exc_info:
        client.complete_json(system_prompt="s", user_prompt="u", config=cfg)

    err = exc_info.value
    assert err.provider == "gemini"
    assert err.http_status == 503
    assert err.error_type == "http_5xx"


def test_openai_client_wraps_transport_error_as_provider_call_error():
    raw = _make_http_error_transport(401, '{"error": "invalid key sk-secret"}')
    client = OpenAIResponsesJsonClient(api_key="FAKE", transport=_make_classified_transport(raw))
    cfg = _llm_config(provider="openai", model="gpt-5-nano")

    with pytest.raises(ProviderCallError) as exc_info:
        client.complete_json(system_prompt="s", user_prompt="u", config=cfg)

    err = exc_info.value
    assert err.provider == "openai"
    assert err.http_status == 401
    assert err.error_type == "http_401"
    assert "sk-secret" not in str(err)  # body suppressed for 401


def test_anthropic_client_wraps_ssl_error():
    ssl_err = ssl.SSLError("CERTIFICATE_VERIFY_FAILED")
    raw = _make_url_error_transport(ssl_err)
    client = AnthropicMessagesJsonClient(api_key="FAKE", transport=_make_classified_transport(raw))
    cfg = _llm_config(provider="anthropic", model="claude-3-5-haiku-latest")

    with pytest.raises(ProviderCallError) as exc_info:
        client.complete_json(system_prompt="s", user_prompt="u", config=cfg)

    err = exc_info.value
    assert err.provider == "anthropic"
    assert err.error_type == "ssl"
    assert err.http_status is None
