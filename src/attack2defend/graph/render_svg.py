"""SVG renderer for Route Coherence Knowledge Graph.

Generates a standalone SVG from a graph JSON. No external dependencies required —
uses Python's built-in xml.etree.ElementTree.

Layout matches the reference image:
  - Dark navy background (#0f172a)
  - Colored nodes by type (CVE=red, CWE=amber, CAPEC=violet, ATT&CK=blue, D3FEND=green)
  - Bezier curve edges with arrowheads
  - Edge styles vary by mapping_basis (solid/dashed/dotted)
  - Header with title + subtitle
  - Legend at bottom
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

_TYPE_FILL: dict[str, str] = {
    "cve":    "#ef4444",
    "cwe":    "#f59e0b",
    "capec":  "#7c3aed",
    "attack": "#2563eb",
    "d3fend": "#16a34a",
}
_TYPE_STROKE: dict[str, str] = {
    "cve":    "#fca5a5",
    "cwe":    "#fde68a",
    "capec":  "#c4b5fd",
    "attack": "#93c5fd",
    "d3fend": "#86efac",
}
_BG = "#0f172a"
_TEXT_MAIN = "#f1f5f9"
_TEXT_SUB = "#94a3b8"
_EDGE_COLORS: dict[str, str] = {
    "official_explicit":   "#94a3b8",
    "official_related":    "#64748b",
    "analytical_inferred": "#64748b",
    "conditional":         "#475569",
    "unverified":          "#ef4444",
}
_EDGE_DASH: dict[str, str] = {
    "official_explicit":   "none",
    "official_related":    "none",
    "analytical_inferred": "6 3",
    "conditional":         "4 4",
    "unverified":          "3 3",
}
_EDGE_WIDTH: dict[str, str] = {
    "official_explicit":   "2",
    "official_related":    "1.5",
    "analytical_inferred": "1.5",
    "conditional":         "1.2",
    "unverified":          "1",
}
_NODE_W = 170
_NODE_H = 52
_RX = 8


def build(graph: dict[str, Any], title: str = "", subtitle: str = "") -> str:
    """Return SVG string for the given graph JSON."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    canvas = graph.get("canvas", {})
    width = int(canvas.get("width", 1100))
    height = int(canvas.get("height", 600))

    svg = ET.Element("svg", {
        "xmlns": "http://www.w3.org/2000/svg",
        "width": str(width),
        "height": str(height),
        "viewBox": f"0 0 {width} {height}",
        "style": f"background:{_BG};font-family:Inter,system-ui,sans-serif",
    })

    defs = ET.SubElement(svg, "defs")
    _add_markers(defs)
    _add_gradient(defs)

    # Background
    ET.SubElement(svg, "rect", {"width": str(width), "height": str(height), "fill": _BG})

    # Header
    _add_header(svg, title, subtitle, width)

    # Build node position map
    node_map: dict[str, dict[str, Any]] = {n["id"]: n for n in nodes}

    # Draw edges first (under nodes)
    for edge in edges:
        _draw_edge(svg, edge, node_map)

    # Draw nodes
    for node in nodes:
        _draw_node(svg, node)

    # Legend
    _add_legend(svg, width, height)

    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(svg, encoding="unicode")


def _add_markers(defs: ET.Element) -> None:
    for basis, color in _EDGE_COLORS.items():
        marker_id = f"arrow_{basis}"
        marker = ET.SubElement(defs, "marker", {
            "id": marker_id,
            "markerWidth": "8",
            "markerHeight": "6",
            "refX": "8",
            "refY": "3",
            "orient": "auto",
        })
        ET.SubElement(marker, "polygon", {
            "points": "0 0, 8 3, 0 6",
            "fill": color,
        })


def _add_gradient(defs: ET.Element) -> None:
    grad = ET.SubElement(defs, "radialGradient", {
        "id": "bg_glow",
        "cx": "15%", "cy": "0%", "r": "50%",
    })
    ET.SubElement(grad, "stop", {"offset": "0%", "stop-color": "#1e3a5f", "stop-opacity": "0.6"})
    ET.SubElement(grad, "stop", {"offset": "100%", "stop-color": _BG, "stop-opacity": "1"})


def _add_header(svg: ET.Element, title: str, subtitle: str, width: int) -> None:
    cx = width // 2
    if title:
        ET.SubElement(svg, "text", {
            "x": str(cx), "y": "32",
            "text-anchor": "middle",
            "fill": _TEXT_MAIN,
            "font-size": "20",
            "font-weight": "700",
        }).text = title
    if subtitle:
        ET.SubElement(svg, "text", {
            "x": str(cx), "y": "52",
            "text-anchor": "middle",
            "fill": _TEXT_SUB,
            "font-size": "13",
        }).text = subtitle

    note = "① Mapeo explícito: CVE → CWE  |  Mapeo analítico defensible: CWE → CAPEC → ATT&CK → D3FEND"
    ET.SubElement(svg, "text", {
        "x": str(cx), "y": "70",
        "text-anchor": "middle",
        "fill": "#475569",
        "font-size": "11",
    }).text = note


def _draw_node(svg: ET.Element, node: dict[str, Any]) -> None:
    x = float(node.get("x", 0))
    y = float(node.get("y", 0))
    cx = x
    cy = y
    rx_pos = cx - _NODE_W / 2
    ry_pos = cy - _NODE_H / 2
    node_type = node.get("type", "cve")

    fill = _TYPE_FILL.get(node_type, "#64748b")
    stroke = _TYPE_STROKE.get(node_type, "#94a3b8")

    g = ET.SubElement(svg, "g")
    ET.SubElement(g, "rect", {
        "x": _f(rx_pos), "y": _f(ry_pos),
        "width": str(_NODE_W), "height": str(_NODE_H),
        "rx": str(_RX),
        "fill": fill,
        "stroke": stroke,
        "stroke-width": "1.5",
    })

    # ID label (bold)
    ET.SubElement(g, "text", {
        "x": _f(cx), "y": _f(cy - 7),
        "text-anchor": "middle",
        "fill": "#ffffff",
        "font-size": "12",
        "font-weight": "700",
    }).text = node["id"]

    # Name label (smaller)
    name = node.get("title") or node.get("label") or ""
    if name and name != node["id"]:
        ET.SubElement(g, "text", {
            "x": _f(cx), "y": _f(cy + 11),
            "text-anchor": "middle",
            "fill": "rgba(255,255,255,0.85)",
            "font-size": "10",
        }).text = _truncate(name, 24)


def _draw_edge(svg: ET.Element, edge: dict[str, Any], node_map: dict[str, dict[str, Any]]) -> None:
    src_node = node_map.get(edge.get("source", ""))
    tgt_node = node_map.get(edge.get("target", ""))
    if not src_node or not tgt_node:
        return

    sx = float(src_node.get("x", 0)) + _NODE_W / 2
    sy = float(src_node.get("y", 0))
    tx = float(tgt_node.get("x", 0)) - _NODE_W / 2
    ty = float(tgt_node.get("y", 0))

    mx = (sx + tx) / 2

    basis = edge.get("mapping_basis", "unverified")
    color = _EDGE_COLORS.get(basis, "#64748b")
    dash = _EDGE_DASH.get(basis, "none")
    width = _EDGE_WIDTH.get(basis, "1.5")
    marker = f"url(#arrow_{basis})"

    attrs: dict[str, str] = {
        "d": f"M {_f(sx)},{_f(sy)} C {_f(mx)},{_f(sy)} {_f(mx)},{_f(ty)} {_f(tx)},{_f(ty)}",
        "fill": "none",
        "stroke": color,
        "stroke-width": width,
        "marker-end": marker,
    }
    if dash != "none":
        attrs["stroke-dasharray"] = dash

    ET.SubElement(svg, "path", attrs)


def _add_legend(svg: ET.Element, width: int, height: int) -> None:
    items = [
        ("CVE", "cve"),
        ("CWE", "cwe"),
        ("CAPEC", "capec"),
        ("ATT&CK", "attack"),
        ("D3FEND", "d3fend"),
    ]
    total_items = len(items)
    item_width = 110
    total_width = total_items * item_width
    start_x = (width - total_width) / 2
    y = height - 30

    for i, (label, node_type) in enumerate(items):
        x = start_x + i * item_width
        fill = _TYPE_FILL.get(node_type, "#64748b")
        ET.SubElement(svg, "rect", {
            "x": _f(x), "y": _f(y - 8),
            "width": "14", "height": "14",
            "rx": "3",
            "fill": fill,
        })
        ET.SubElement(svg, "text", {
            "x": _f(x + 18), "y": _f(y + 3),
            "fill": _TEXT_SUB,
            "font-size": "12",
        }).text = label


def _f(v: float) -> str:
    return f"{v:.1f}"


def _truncate(text: str, max_len: int) -> str:
    return text[:max_len] + "…" if len(text) > max_len else text
