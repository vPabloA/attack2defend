from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attack2defend import KnowledgeEdge, KnowledgeNode, NodeType, RouteRequest, RouteResolver


SEED_NODES = [
    KnowledgeNode(id="CVE-2021-44228", type=NodeType.CVE, name="Apache Log4j2 JNDI RCE"),
    KnowledgeNode(id="CWE-917", type=NodeType.CWE, name="Expression Language Injection"),
    KnowledgeNode(id="CAPEC-136", type=NodeType.CAPEC, name="LDAP Injection"),
    KnowledgeNode(id="T1190", type=NodeType.ATTACK, name="Exploit Public-Facing Application"),
    KnowledgeNode(id="D3-NTA", type=NodeType.D3FEND, name="Network Traffic Analysis"),
    KnowledgeNode(id="T1567", type=NodeType.ATTACK, name="Exfiltration Over Web Service"),
    KnowledgeNode(id="D3-DNSDL", type=NodeType.D3FEND, name="DNS Denylisting"),
    KnowledgeNode(id="CVE-2024-37079", type=NodeType.CVE, name="Curated seed CVE-2024-37079"),
    KnowledgeNode(id="CWE-79", type=NodeType.CWE, name="Cross-site Scripting"),
    KnowledgeNode(id="CAPEC-63", type=NodeType.CAPEC, name="XSS"),
    KnowledgeNode(id="T1059", type=NodeType.ATTACK, name="Command and Scripting Interpreter"),
    KnowledgeNode(id="D3-MFA", type=NodeType.D3FEND, name="Multi-factor Authentication"),
]

SEED_EDGES = [
    KnowledgeEdge(source="CVE-2021-44228", target="CWE-917", relationship="has_weakness"),
    KnowledgeEdge(source="CWE-917", target="CAPEC-136", relationship="may_enable_attack_pattern"),
    KnowledgeEdge(source="CAPEC-136", target="T1190", relationship="may_map_to_attack_technique"),
    KnowledgeEdge(source="T1190", target="D3-NTA", relationship="may_be_detected_by"),
    KnowledgeEdge(source="T1567", target="D3-DNSDL", relationship="may_be_detected_by"),
    KnowledgeEdge(source="CVE-2024-37079", target="CWE-79", relationship="has_weakness"),
    KnowledgeEdge(source="CWE-79", target="CAPEC-63", relationship="may_enable_attack_pattern"),
    KnowledgeEdge(source="CAPEC-63", target="T1059", relationship="may_map_to_attack_technique"),
    KnowledgeEdge(source="T1059", target="D3-MFA", relationship="may_be_detected_by"),
]

SEED_INPUTS = ["CVE-2021-44228", "T1567", "CVE-2024-37079", "CWE-79", "D3-MFA"]


def _node_to_json(node: KnowledgeNode) -> dict:
    raw = asdict(node)
    raw["type"] = node.type.value
    return raw


def _edge_to_json(edge: KnowledgeEdge) -> dict:
    return asdict(edge)


def main() -> None:
    repo_root = REPO_ROOT
    data_dir = repo_root / "data"
    public_data_dir = repo_root / "app" / "navigator-ui" / "public" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    public_data_dir.mkdir(parents=True, exist_ok=True)

    nodes = [_node_to_json(node) for node in SEED_NODES]
    edges = [_edge_to_json(edge) for edge in SEED_EDGES]

    node_ids = {n["id"].upper() for n in nodes}
    broken_edges = [e for e in edges if e["source"].upper() not in node_ids or e["target"].upper() not in node_ids]
    if broken_edges:
        raise ValueError(f"Broken edges found: {broken_edges}")

    resolver = RouteResolver(SEED_NODES, SEED_EDGES)
    routes = {}
    for seed in SEED_INPUTS:
        route = resolver.resolve(RouteRequest(input_id=seed))
        routes[seed] = {
            "found": route.found,
            "ordered_path": route.ordered_path,
            "warnings": route.warnings,
        }

    indexes = {
        "node_ids": sorted(node_ids),
        "by_type": {
            node_type.value: sorted([n["id"] for n in nodes if n["type"] == node_type.value])
            for node_type in NodeType
        },
    }
    coverage = {
        "version": 1,
        "records": [
            {
                "target_id": "D3-MFA",
                "status": "unknown",
                "controls": [],
                "detections": [],
                "evidence": [],
                "gaps": ["Owner and evidence not assigned yet"],
                "owners": [],
            }
        ],
    }
    metadata = {
        "bundle_version": "0.1.0-mvp",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "curation_status": "seed_curated",
        "seed_inputs": SEED_INPUTS,
        "counts": {"nodes": len(nodes), "edges": len(edges)},
    }
    bundle = {
        "metadata": metadata,
        "nodes": nodes,
        "edges": edges,
        "indexes": indexes,
        "coverage": coverage,
        "routes": routes,
    }

    outputs = {
        "nodes.json": nodes,
        "edges.json": edges,
        "indexes.json": indexes,
        "coverage.json": coverage,
        "routes.json": routes,
        "metadata.json": metadata,
        "knowledge-bundle.json": bundle,
    }
    for filename, payload in outputs.items():
        (data_dir / filename).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    (public_data_dir / "knowledge-bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    snapshot_dir = data_dir / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_path = snapshot_dir / f"knowledge-bundle-{timestamp}.json"
    snapshot_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
