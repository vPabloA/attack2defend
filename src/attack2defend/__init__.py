"""Attack2Defend core package."""

from .contracts import (
    CoverageRecord,
    CoverageStatus,
    KnowledgeEdge,
    KnowledgeNode,
    NodeType,
    RouteAnalysis,
    RouteRequest,
    RouteResult,
)
from .resolver import RouteResolver, infer_node_type
from .capability import resolve_defense_route

__all__ = [
    "CoverageRecord",
    "CoverageStatus",
    "KnowledgeEdge",
    "KnowledgeNode",
    "NodeType",
    "RouteAnalysis",
    "RouteRequest",
    "RouteResult",
    "RouteResolver",
    "infer_node_type",
    "resolve_defense_route",
]
