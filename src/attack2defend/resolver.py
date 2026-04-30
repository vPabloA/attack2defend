"""Deterministic route resolver for Attack2Defend.

This resolver is intentionally small and dependency-free. It operates over a
prebuilt knowledge bundle and does not call public APIs at runtime.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable

from .contracts import KnowledgeEdge, KnowledgeNode, NodeType, RouteRequest, RouteResult


class RouteResolver:
    """Resolve framework routes from a local graph snapshot."""

    def __init__(self, nodes: Iterable[KnowledgeNode], edges: Iterable[KnowledgeEdge]) -> None:
        self.nodes: dict[str, KnowledgeNode] = {node.id.upper(): node for node in nodes}
        self.edges: list[KnowledgeEdge] = list(edges)
        self.adjacency: dict[str, list[KnowledgeEdge]] = {}
        for edge in self.edges:
            self.adjacency.setdefault(edge.source.upper(), []).append(edge)

    def resolve(self, request: RouteRequest) -> RouteResult:
        start = request.input_id.upper().strip()
        if start not in self.nodes:
            return RouteResult(
                input_id=request.input_id,
                nodes=[],
                edges=[],
                warnings=[f"Input not found in local knowledge bundle: {request.input_id}"],
            )

        visited_nodes: set[str] = {start}
        visited_edges: list[KnowledgeEdge] = []
        parent: dict[str, str] = {}
        queue: deque[tuple[str, int]] = deque([(start, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= request.max_depth:
                continue
            for edge in self.adjacency.get(current, []):
                target = edge.target.upper()
                visited_edges.append(edge)
                if target not in visited_nodes:
                    visited_nodes.add(target)
                    parent[target] = current
                    queue.append((target, depth + 1))

        ordered_path = self._best_ordered_path(start, visited_nodes, parent)
        result_nodes = [self.nodes[node_id] for node_id in sorted(visited_nodes)]
        return RouteResult(
            input_id=request.input_id,
            nodes=result_nodes,
            edges=visited_edges,
            ordered_path=ordered_path,
            warnings=[],
        )

    def _best_ordered_path(self, start: str, visited_nodes: set[str], parent: dict[str, str]) -> list[str]:
        """Return a simple representative path from the start node to the deepest node.

        This is not meant to be a complete graph algorithm. It provides a clean
        MVP path for the UI while the full node/edge set remains available.
        """
        if not visited_nodes:
            return []
        deepest = max(visited_nodes, key=lambda node_id: self._depth(node_id, parent))
        path = [deepest]
        while path[-1] != start and path[-1] in parent:
            path.append(parent[path[-1]])
        return list(reversed(path))

    @staticmethod
    def _depth(node_id: str, parent: dict[str, str]) -> int:
        depth = 0
        current = node_id
        while current in parent:
            depth += 1
            current = parent[current]
        return depth


def infer_node_type(identifier: str) -> NodeType | None:
    value = identifier.strip().upper()
    if value.startswith("CVE-"):
        return NodeType.CVE
    if value.startswith("CWE-"):
        return NodeType.CWE
    if value.startswith("CAPEC-"):
        return NodeType.CAPEC
    if value.startswith("T") and len(value) >= 5 and value[1:5].isdigit():
        return NodeType.ATTACK
    if value.startswith("D3-"):
        return NodeType.D3FEND
    return None
