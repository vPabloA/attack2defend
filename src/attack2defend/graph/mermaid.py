"""Mermaid flowchart export for Route Coherence graph.

Produces a Mermaid flowchart LR diagram from a graph JSON.
Edge styles vary by mapping_basis:
  official_explicit  → solid thick arrow
  official_related   → solid arrow
  analytical_inferred→ dashed arrow
  conditional        → dotted arrow
  unverified         → dashed thin arrow
"""

from __future__ import annotations

from typing import Any

_BASIS_STYLE: dict[str, str] = {
    "official_explicit": "-->",
    "official_related": "-->",
    "analytical_inferred": "-.->",
    "conditional": "-.->",
    "unverified": "-.->",
}

_TYPE_COLORS: dict[str, str] = {
    "cve": "fill:#ef4444,stroke:#fca5a5,color:#fff",
    "cwe": "fill:#f59e0b,stroke:#fde68a,color:#fff",
    "capec": "fill:#7c3aed,stroke:#c4b5fd,color:#fff",
    "attack": "fill:#2563eb,stroke:#93c5fd,color:#fff",
    "d3fend": "fill:#16a34a,stroke:#86efac,color:#fff",
}


def build(graph: dict[str, Any]) -> str:
    """Return a Mermaid flowchart LR string from a graph JSON object."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    lines = ["flowchart LR"]

    # Node definitions: ID["label\\nname"]
    for node in nodes:
        node_id = _mmd_id(node["id"])
        label = node["id"]
        title = node.get("title", "")
        if title and title != node["id"]:
            display = f"{label}\\n{_truncate(title, 22)}"
        else:
            display = label
        shape_open, shape_close = _shape(node.get("type", ""))
        lines.append(f'    {node_id}{shape_open}"{display}"{shape_close}')

    lines.append("")

    # Edge definitions
    for edge in edges:
        src = _mmd_id(edge["source"])
        tgt = _mmd_id(edge["target"])
        basis = edge.get("mapping_basis", "unverified")
        arrow = _BASIS_STYLE.get(basis, "-.->")
        label_text = _edge_label(basis)
        if label_text:
            lines.append(f"    {src} {arrow}|{label_text}| {tgt}")
        else:
            lines.append(f"    {src} {arrow} {tgt}")

    lines.append("")

    # Style classes
    for node_type, style in _TYPE_COLORS.items():
        class_name = f"cls_{node_type}"
        lines.append(f"    classDef {class_name} {style}")

    lines.append("")

    # Apply classes
    by_type: dict[str, list[str]] = {}
    for node in nodes:
        by_type.setdefault(node.get("type", ""), []).append(_mmd_id(node["id"]))

    for node_type, ids in by_type.items():
        if ids:
            lines.append(f"    class {','.join(ids)} cls_{node_type}")

    return "\n".join(lines)


def _mmd_id(node_id: str) -> str:
    return node_id.replace("-", "_").replace(".", "_")


def _truncate(text: str, max_len: int) -> str:
    return text[:max_len] + "…" if len(text) > max_len else text


def _shape(node_type: str) -> tuple[str, str]:
    if node_type == "cve":
        return "(", ")"
    if node_type == "d3fend":
        return "([", "])"
    return "[", "]"


def _edge_label(basis: str) -> str:
    labels = {
        "official_explicit": "oficial",
        "official_related": "",
        "analytical_inferred": "inferido",
        "conditional": "condicional",
        "unverified": "no verificado",
    }
    return labels.get(basis, "")
