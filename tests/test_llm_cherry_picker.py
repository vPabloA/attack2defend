import copy
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

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


BUNDLE = "data/knowledge-bundle.json"
CURATED_SCHEMA = Path("schemas/a2d_curated_route.schema.json")


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


def _schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _capability_and_context():
    capability = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    return capability, build_official_context_pack(capability)


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
    cfg = AiCherryPickerConfig(
        mode="llm",
        provider="gemini",
        model="gemini-2.5-flash-lite",
        temperature=0,
        max_output_tokens=4000,
        require_validation=True,
        allow_external_knowledge=False,
        runtime_public_api_calls=False,
    )

    route = cherry_pick_route(capability, context, config=cfg)

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["validation"]["status"] == "pass"
    assert route["selection_method"] == "deterministic_prefilter"
    assert route["llm_adapter"]["used"] is False
    assert route["llm_adapter"]["fallback_reason"].startswith("provider_error")


def test_valid_mock_llm_output_can_pass_validator():
    capability, context = _capability_and_context()
    baseline = build_curated_route(capability, context)
    cfg = AiCherryPickerConfig(
        mode="llm",
        provider="openai",
        model="gpt-5-nano",
        temperature=0,
        max_output_tokens=4000,
        require_validation=True,
        allow_external_knowledge=False,
        runtime_public_api_calls=False,
    )

    route = cherry_pick_route(capability, context, config=cfg, client=ValidMockClient(baseline))

    jsonschema.validate(route, _schema(CURATED_SCHEMA))
    assert route["validation"]["status"] == "pass"
    assert route["selection_method"] == "llm_cherry_picker"
    assert route["llm_adapter"]["used"] is True


def test_invented_llm_output_is_blocked_and_falls_back():
    capability, context = _capability_and_context()
    cfg = AiCherryPickerConfig(
        mode="llm",
        provider="anthropic",
        model="claude-3-5-haiku-latest",
        temperature=0,
        max_output_tokens=4000,
        require_validation=True,
        allow_external_knowledge=False,
        runtime_public_api_calls=False,
    )

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
