"""Lightweight schema contracts for the automation layer.

The implementation intentionally uses plain dictionaries to avoid making Pydantic
or FastAPI mandatory for the core package.
"""

SOC_ACTION_PACK_FIELDS = [
    "executive_summary",
    "defensive_objective",
    "threat_chain",
    "defense_readiness",
    "top_3_recommendations",
    "integration_hints",
    "operational_metadata",
]

SOAR_SAFE_FIELDS = ["status", "blocking", "timeout_waited_for_human", "errors", "warnings"]

MCP_TOOL_NAMES = [
    "defense_route",
    "batch_defense_route",
    "export_soc_pack",
    "explain_d3fend_for_soc",
    "get_top_mitigations",
    "intelligence_factory_status",
    "candidate_query",
    "golden_evaluation",
    "graph_explore",
    "policy_inspect",
    "provenance_audit",
]
