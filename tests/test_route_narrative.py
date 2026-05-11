from __future__ import annotations

import copy

from attack2defend.capability import resolve_defense_route
from attack2defend.intelligence import (
    AiCherryPickerConfig,
    build_curated_route,
    build_deterministic_route_narrative,
    build_official_context_pack,
    build_route_narrative,
    validate_route_narrative,
)


BUNDLE = "data/knowledge-bundle.json"


class MockNarrativeClient:
    def __init__(self, payload: dict):
        self.payload = payload

    def complete_json(self, *, system_prompt, user_prompt, config):
        assert "must not invent IDs" in system_prompt
        assert "official_context_pack" in user_prompt
        return copy.deepcopy(self.payload)


def _fixture():
    capability = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    context = build_official_context_pack(capability)
    curated_route = build_curated_route(capability, context)
    return capability, context, curated_route


def _llm_config() -> AiCherryPickerConfig:
    return AiCherryPickerConfig(
        mode="llm",
        provider="openai",
        model="gpt-4o-mini",
        temperature=0,
        max_output_tokens=4000,
        require_validation=True,
        allow_external_knowledge=False,
        runtime_public_api_calls=False,
    )


def test_deterministic_route_narrative_validates():
    capability, context, curated_route = _fixture()

    narrative = build_deterministic_route_narrative(capability, context, curated_route)
    validation = validate_route_narrative(narrative, curated_route=curated_route)

    assert narrative["status"] == "deterministic_fallback"
    assert narrative["summary_es"]
    assert narrative["node_reason_by_id"]
    assert validation["status"] == "pass"


def test_valid_mock_llm_route_narrative_passes_validation():
    capability, context, curated_route = _fixture()
    deterministic = build_deterministic_route_narrative(capability, context, curated_route)
    proposed = copy.deepcopy(deterministic)
    proposed["status"] = "llm_polished"
    proposed["summary_es"] = "Resumen defensivo pulido con trazabilidad oficial."
    proposed["executive_summary_es"] = "Síntesis ejecutiva pulida con lenguaje consultivo."
    proposed["decision_context_es"] = "Contexto decisional alineado con la ruta curada."
    proposed["risk_rationale_es"] = "Riesgo formulado sobre la evidencia ya seleccionada."

    narrative = build_route_narrative(capability, context, curated_route, config=_llm_config(), client=MockNarrativeClient(proposed))

    assert narrative["status"] == "llm_polished"
    assert narrative["llm_adapter"]["used"] is True
    assert narrative["summary_es"] == proposed["summary_es"]
    assert narrative["node_reason_by_id"]


def test_invented_ids_force_deterministic_fallback():
    capability, context, curated_route = _fixture()
    deterministic = build_deterministic_route_narrative(capability, context, curated_route)
    proposed = copy.deepcopy(deterministic)
    proposed["status"] = "llm_polished"
    proposed["summary_es"] = "CVE-2999-0001 aparece aquí y debe invalidarse."
    proposed["node_reasons"].append({"id": "CVE-2999-0001", "reason_es": "Nodo inventado."})
    proposed["node_reason_by_id"]["CVE-2999-0001"] = "Nodo inventado."

    narrative = build_route_narrative(capability, context, curated_route, config=_llm_config(), client=MockNarrativeClient(proposed))

    assert narrative["status"] == "deterministic_fallback"
    assert narrative["llm_adapter"]["used"] is False
    assert narrative["llm_adapter"]["fallback_reason"] == "validation_failed"
    assert any("invented id" in error for error in narrative["llm_adapter"]["errors"])
