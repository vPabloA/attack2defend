from __future__ import annotations

from attack2defend.api.schemas import API_ENDPOINTS
from attack2defend.automation.schemas import MCP_TOOL_NAMES, SOAR_SAFE_FIELDS, SOC_ACTION_PACK_FIELDS
from attack2defend.automation.service import AutomationService
from attack2defend.mcp.tools import run_tool, tool_definitions


def assert_soar_safe(payload: dict) -> None:
    for field in SOAR_SAFE_FIELDS:
        assert field in payload
    assert payload["blocking"] is False
    assert payload["timeout_waited_for_human"] is False


def test_soc_action_pack_contract_is_soar_safe() -> None:
    service = AutomationService()
    payload = service.build_soc_action_pack("CVE-2021-44228")
    assert_soar_safe(payload)
    assert payload["audit"]["source_of_truth"] == "knowledge-bundle.json"
    assert payload["audit"]["external_calls"] is False
    for field in SOC_ACTION_PACK_FIELDS:
        assert field in payload["soc_pack"]


def test_missing_route_returns_gaps_not_hallucinated_success() -> None:
    service = AutomationService()
    payload = service.build_soc_action_pack("A2D-NON-EXISTENT-ID")
    assert_soar_safe(payload)
    assert payload["status"] == "completed_with_gaps"
    assert payload["coverage_gaps"]


def test_mcp_tool_registry_matches_contracts() -> None:
    tools = tool_definitions()
    names = {tool["name"] for tool in tools}
    assert names == set(MCP_TOOL_NAMES)
    for tool in tools:
        assert tool["description"]
        assert tool["input_schema"]["type"] == "object"


def test_mcp_tools_are_soar_safe() -> None:
    samples = {
        "defense_route": {"id": "CVE-2021-44228"},
        "batch_defense_route": {"ids": ["CVE-2021-44228"]},
        "export_soc_pack": {"id": "CVE-2021-44228"},
        "explain_d3fend_for_soc": {"id": "D3-WAF"},
        "get_top_mitigations": {"id": "CVE-2021-44228"},
        "intelligence_factory_status": {},
        "candidate_query": {},
        "golden_evaluation": {},
        "graph_explore": {"id": "CVE-2021-44228", "depth": 2},
        "policy_inspect": {},
        "provenance_audit": {"id": "CVE-2021-44228"},
    }
    for name, args in samples.items():
        assert_soar_safe(run_tool(name, args))


def test_api_contract_endpoint_list_contains_ga_surface() -> None:
    assert "GET /api/v1/health" in API_ENDPOINTS
    assert "GET /api/v1/soc-pack/{id}" in API_ENDPOINTS
    assert "POST /api/v1/route/batch" in API_ENDPOINTS
    assert "GET /api/v1/graph/quality" in API_ENDPOINTS
