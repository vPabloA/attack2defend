#!/usr/bin/env python3
"""Validate Attack2Defend MCP tool registry and outputs."""
from __future__ import annotations

from attack2defend.automation.schemas import MCP_TOOL_NAMES, SOAR_SAFE_FIELDS
from attack2defend.mcp.tools import run_tool, tool_definitions


def assert_soar_safe(payload: dict) -> None:
    for field in SOAR_SAFE_FIELDS:
        assert field in payload, f"missing SOAR-safe field: {field}"
    assert payload["blocking"] is False
    assert payload["timeout_waited_for_human"] is False


def main() -> int:
    defs = tool_definitions()
    names = {tool["name"] for tool in defs}
    assert names == set(MCP_TOOL_NAMES), f"tool mismatch: {sorted(names ^ set(MCP_TOOL_NAMES))}"
    for tool in defs:
        assert tool.get("description"), f"missing description for {tool['name']}"
        assert tool.get("input_schema", {}).get("type") == "object", f"bad schema for {tool['name']}"
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
        payload = run_tool(name, args)
        assert_soar_safe(payload)
    print("validate-mcp: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
