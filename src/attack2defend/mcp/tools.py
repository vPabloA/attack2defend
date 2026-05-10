"""Read-only MCP-style tool registry for Attack2Defend."""
from __future__ import annotations

from typing import Any

from attack2defend.automation.service import AutomationService
from attack2defend.automation.schemas import MCP_TOOL_NAMES


def tool_definitions() -> list[dict[str, Any]]:
    return [
        _tool("defense_route", "Resolve a deterministic defense route for one CVE/CWE/CAPEC/ATT&CK/D3FEND/control/detection ID.", {"id": "string"}),
        _tool("batch_defense_route", "Resolve multiple defense routes for SOAR-style batch enrichment.", {"ids": "array[string]"}),
        _tool("export_soc_pack", "Build a SOC-actionable D3FEND output package for one ID.", {"id": "string"}),
        _tool("explain_d3fend_for_soc", "Explain a D3FEND countermeasure as SOC controls, detections, evidence, gaps and actions.", {"id": "string"}),
        _tool("get_top_mitigations", "Return deterministic top 3 mitigation recommendations from local route data.", {"id": "string"}),
        _tool("intelligence_factory_status", "Return the local Intelligence Factory report.", {}),
        _tool("candidate_query", "Query local candidate/audit records.", {"status": "string?", "run_id": "string?"}),
        _tool("golden_evaluation", "Return local golden-route evaluation artifact.", {}),
        _tool("graph_explore", "Explore local graph adjacency without requiring Neo4j.", {"id": "string", "depth": "integer?", "direction": "string?"}),
        _tool("policy_inspect", "Return active promotion policy.", {}),
        _tool("provenance_audit", "Audit source references and provenance gaps for a route.", {"id": "string"}),
    ]


def _tool(name: str, description: str, properties: dict[str, str]) -> dict[str, Any]:
    required = [k for k, v in properties.items() if not v.endswith("?")]
    schema_props = {}
    for key, value in properties.items():
        base = value.rstrip("?")
        if base == "array[string]":
            schema_props[key] = {"type": "array", "items": {"type": "string"}}
        elif base == "integer":
            schema_props[key] = {"type": "integer"}
        else:
            schema_props[key] = {"type": "string"}
    return {"name": name, "description": description, "input_schema": {"type": "object", "properties": schema_props, "required": required}}


def run_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    args = arguments or {}
    service = AutomationService()
    if name not in MCP_TOOL_NAMES:
        return {"status": "error", "blocking": False, "timeout_waited_for_human": False, "errors": [f"Unknown MCP tool {name}"]}
    if name == "defense_route":
        return service.resolve_route(str(args.get("id", "")))
    if name == "batch_defense_route":
        return service.batch_resolve_route([str(i) for i in args.get("ids", [])])
    if name == "export_soc_pack":
        return service.build_soc_action_pack(str(args.get("id", "")))
    if name == "explain_d3fend_for_soc":
        return service.explain_d3fend_for_soc(str(args.get("id", "")))
    if name == "get_top_mitigations":
        return service.get_top_mitigations(str(args.get("id", "")))
    if name == "intelligence_factory_status":
        return service.get_factory_status()
    if name == "candidate_query":
        return service.query_candidates(status=args.get("status"), run_id=args.get("run_id"))
    if name == "golden_evaluation":
        return service.get_golden_evaluation()
    if name == "graph_explore":
        return service.graph_explore(str(args.get("id", "")), depth=int(args.get("depth", 2)), direction=str(args.get("direction", "both")))
    if name == "policy_inspect":
        return service.policy_inspect()
    if name == "provenance_audit":
        return service.audit_provenance(str(args.get("id", "")))
    return {"status": "error", "blocking": False, "timeout_waited_for_human": False, "errors": [f"Unhandled MCP tool {name}"]}
