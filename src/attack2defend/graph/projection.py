"""Graph projection: RouteCoherenceArtifact → graph.json.

Assigns x/y coordinates for a layered left-to-right layout.
Each type maps to a column (xLayer 0–4).
Within each column, nodes are distributed evenly by y position.
"""

from __future__ import annotations

from typing import Any

from ..coherence.schema import GraphEdge, GraphNode, RouteCoherenceArtifact

_LAYER_X_CENTER: dict[int, int] = {0: 100, 1: 300, 2: 500, 3: 700, 4: 920}
_NODE_WIDTH = 170
_NODE_HEIGHT = 52
_ROW_SPACING = 75
_MIN_HEIGHT = 500
_HEADER_HEIGHT = 90
_LEGEND_HEIGHT = 60


def build_graph_json(artifact: RouteCoherenceArtifact) -> dict[str, Any]:
    """Return a graph JSON object ready for UI rendering and Mermaid/SVG export."""
    nodes = artifact.graph_nodes
    edges = artifact.graph_edges

    # Group nodes by xLayer for y positioning
    by_layer: dict[int, list[GraphNode]] = {}
    for node in nodes:
        by_layer.setdefault(node.x_layer, []).append(node)

    max_per_layer = max((len(v) for v in by_layer.values()), default=1)
    canvas_height = max(max_per_layer * _ROW_SPACING + _HEADER_HEIGHT + _LEGEND_HEIGHT, _MIN_HEIGHT)
    canvas_width = 1100

    node_positions: dict[str, dict[str, float]] = {}
    for layer, layer_nodes in by_layer.items():
        x_center = _LAYER_X_CENTER.get(layer, layer * 200 + 100)
        total_height = len(layer_nodes) * _ROW_SPACING
        y_start = (_MIN_HEIGHT - total_height) / 2 + _HEADER_HEIGHT
        for i, node in enumerate(layer_nodes):
            cy = y_start + i * _ROW_SPACING + _ROW_SPACING / 2
            node_positions[node.id] = {"x": float(x_center), "y": cy}

    nodes_out = []
    for node in nodes:
        pos = node_positions.get(node.id, {"x": 0.0, "y": 0.0})
        nodes_out.append({
            **node.to_dict(),
            "x": pos["x"],
            "y": pos["y"],
        })

    return {
        "canvas": {"width": canvas_width, "height": canvas_height},
        "nodes": nodes_out,
        "edges": [e.to_dict() for e in edges],
        "layout": "layered-lr",
        "node_width": _NODE_WIDTH,
        "node_height": _NODE_HEIGHT,
    }
