#!/usr/bin/env python3
"""Export Attack2Defend knowledge-bundle.json into graph sidecar artifacts.

Graph Sidecar principles:
- knowledge-bundle.json remains the source of truth
- no Neo4j runtime required
- deterministic CSV/Cypher/JSON outputs
- provenance fields are preserved on edges
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
NODE_TYPES_DEFENSE = {"d3fend", "control", "detection", "evidence", "gap", "action"}
NODE_TYPES_EVIDENCE = {"evidence"}
WEAK_CONFIDENCE = {"", "low", "unknown", "none", "null"}


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def relationship_type(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9]+", "_", value or "RELATED_TO").strip("_").upper()
    return clean or "RELATED_TO"


def node_label(node_type: str) -> str:
    mapping = {
        "cve": "CVE",
        "cwe": "CWE",
        "capec": "CAPEC",
        "attack": "ATTACK",
        "d3fend": "D3FEND",
        "control": "Control",
        "detection": "Detection",
        "evidence": "Evidence",
        "gap": "Gap",
        "action": "Action",
        "artifact": "Artifact",
    }
    return mapping.get((node_type or "").lower(), "KnowledgeNode")


def get_node_id(node: dict[str, Any]) -> str:
    return safe_text(node.get("id")).strip()


def get_node_type(node: dict[str, Any]) -> str:
    return safe_text(node.get("type") or "unknown").lower().strip()


def edge_source(edge: dict[str, Any]) -> str:
    return safe_text(edge.get("source") or edge.get("from") or "").strip()


def edge_target(edge: dict[str, Any]) -> str:
    return safe_text(edge.get("target") or edge.get("to") or "").strip()


def edge_relationship(edge: dict[str, Any]) -> str:
    return safe_text(edge.get("relationship") or edge.get("type") or "RELATED_TO").strip()


def build_adjacency(edges: list[dict[str, Any]]) -> dict[str, list[str]]:
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        s, t = edge_source(edge), edge_target(edge)
        if s and t:
            adjacency[s].append(t)
    return adjacency


def reachable_types(root: str, adjacency: dict[str, list[str]], node_types: dict[str, str]) -> set[str]:
    seen = {root}
    q: deque[str] = deque([root])
    found: set[str] = set()
    while q:
        cur = q.popleft()
        found.add(node_types.get(cur, "unknown"))
        for nxt in adjacency.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return found


def graph_quality(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    node_ids = {get_node_id(n) for n in nodes if get_node_id(n)}
    node_types = {get_node_id(n): get_node_type(n) for n in nodes if get_node_id(n)}
    incoming = Counter(edge_target(e) for e in edges if edge_target(e))
    outgoing = Counter(edge_source(e) for e in edges if edge_source(e))
    orphan_nodes = sorted(n for n in node_ids if incoming[n] == 0 and outgoing[n] == 0)
    weak_edges = [e for e in edges if safe_text(e.get("confidence")).lower().strip() in WEAK_CONFIDENCE]
    missing_source_ref = [e for e in edges if not safe_text(e.get("source_ref") or e.get("source_url")).strip()]
    ai_promoted_edges = [e for e in edges if safe_text(e.get("source_feed") or e.get("source_kind")).lower().strip() in {"ai_promoted", "ai_candidate"}]
    broken_edges = [e for e in edges if edge_source(e) not in node_ids or edge_target(e) not in node_ids]

    adjacency = build_adjacency(edges)
    route_roots = sorted(n for n, t in node_types.items() if t in {"cve", "artifact", "cwe", "capec", "attack"})
    with_defense, missing_defense, missing_evidence = [], [], []
    for root in route_roots:
        types = reachable_types(root, adjacency, node_types)
        if types & NODE_TYPES_DEFENSE:
            with_defense.append(root)
        else:
            missing_defense.append(root)
        if "detection" in types and not (types & NODE_TYPES_EVIDENCE):
            missing_evidence.append(root)

    gap_inbound = Counter()
    for edge in edges:
        target = edge_target(edge)
        if node_types.get(target) == "gap":
            gap_inbound[target] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "orphan_node_count": len(orphan_nodes),
        "weak_edge_count": len(weak_edges),
        "missing_source_ref_count": len(missing_source_ref),
        "broken_edge_count": len(broken_edges),
        "routes_with_defense_path": len(with_defense),
        "routes_missing_defense_path": len(missing_defense),
        "routes_missing_evidence": len(missing_evidence),
        "ai_promoted_edge_count": len(ai_promoted_edges),
        "top_structural_gaps": [{"gap_id": gap, "inbound_paths": count} for gap, count in gap_inbound.most_common(10)],
        "samples": {
            "orphan_nodes": orphan_nodes[:20],
            "routes_missing_defense_path": missing_defense[:20],
            "routes_missing_evidence": missing_evidence[:20],
            "broken_edges": [{"source": edge_source(e), "target": edge_target(e), "relationship": edge_relationship(e)} for e in broken_edges[:20]],
        },
    }


def write_nodes_csv(path: Path, nodes: list[dict[str, Any]]) -> None:
    fields = ["id", "type", "label", "name", "description", "url", "source_ref", "source_feed", "metadata_json"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for node in sorted(nodes, key=lambda n: get_node_id(n)):
            node_type = get_node_type(node)
            writer.writerow({
                "id": get_node_id(node),
                "type": node_type,
                "label": node_label(node_type),
                "name": safe_text(node.get("name") or node.get("title") or get_node_id(node)),
                "description": safe_text(node.get("description")),
                "url": safe_text(node.get("url")),
                "source_ref": safe_text(node.get("source_ref") or node.get("source_url")),
                "source_feed": safe_text(node.get("source_feed") or node.get("source_kind")),
                "metadata_json": safe_text(node.get("metadata") or {}),
            })


def write_edges_csv(path: Path, edges: list[dict[str, Any]]) -> None:
    fields = ["source", "target", "relationship", "relationship_type", "confidence", "source_ref", "source_feed", "source_kind", "deterministic", "inferred", "retrieved_at", "transform_version", "metadata_json"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for edge in sorted(edges, key=lambda e: (edge_source(e), edge_relationship(e), edge_target(e))):
            rel_name = edge_relationship(edge)
            writer.writerow({
                "source": edge_source(edge),
                "target": edge_target(edge),
                "relationship": rel_name,
                "relationship_type": relationship_type(rel_name),
                "confidence": safe_text(edge.get("confidence")),
                "source_ref": safe_text(edge.get("source_ref") or edge.get("source_url")),
                "source_feed": safe_text(edge.get("source_feed")),
                "source_kind": safe_text(edge.get("source_kind")),
                "deterministic": safe_text(edge.get("deterministic")),
                "inferred": safe_text(edge.get("inferred")),
                "retrieved_at": safe_text(edge.get("retrieved_at")),
                "transform_version": safe_text(edge.get("transform_version")),
                "metadata_json": safe_text({k: v for k, v in edge.items() if k not in {"source", "target", "relationship"}}),
            })


def write_schema(path: Path) -> None:
    path.write_text("""// Attack2Defend Graph Sidecar schema
CREATE CONSTRAINT a2d_node_id IF NOT EXISTS FOR (n:KnowledgeNode) REQUIRE n.id IS UNIQUE;
CREATE INDEX a2d_node_type IF NOT EXISTS FOR (n:KnowledgeNode) ON (n.type);
CREATE INDEX a2d_node_label IF NOT EXISTS FOR (n:KnowledgeNode) ON (n.label);
CREATE INDEX a2d_edge_confidence IF NOT EXISTS FOR ()-[r]-() ON (r.confidence);
CREATE INDEX a2d_edge_source_feed IF NOT EXISTS FOR ()-[r]-() ON (r.source_feed);
""", encoding="utf-8")


def write_import_cypher(path: Path) -> None:
    path.write_text("""// Import with: cypher-shell -f schema.cypher && cypher-shell -f import.cypher
LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
MERGE (n:KnowledgeNode {id: row.id})
SET n.type = row.type,
    n.label = row.label,
    n.name = row.name,
    n.description = row.description,
    n.url = row.url,
    n.source_ref = row.source_ref,
    n.source_feed = row.source_feed,
    n.metadata_json = row.metadata_json
FOREACH (_ IN CASE row.label WHEN 'CVE' THEN [1] ELSE [] END | SET n:CVE)
FOREACH (_ IN CASE row.label WHEN 'CWE' THEN [1] ELSE [] END | SET n:CWE)
FOREACH (_ IN CASE row.label WHEN 'CAPEC' THEN [1] ELSE [] END | SET n:CAPEC)
FOREACH (_ IN CASE row.label WHEN 'ATTACK' THEN [1] ELSE [] END | SET n:ATTACK)
FOREACH (_ IN CASE row.label WHEN 'D3FEND' THEN [1] ELSE [] END | SET n:D3FEND)
FOREACH (_ IN CASE row.label WHEN 'Control' THEN [1] ELSE [] END | SET n:Control)
FOREACH (_ IN CASE row.label WHEN 'Detection' THEN [1] ELSE [] END | SET n:Detection)
FOREACH (_ IN CASE row.label WHEN 'Evidence' THEN [1] ELSE [] END | SET n:Evidence)
FOREACH (_ IN CASE row.label WHEN 'Gap' THEN [1] ELSE [] END | SET n:Gap)
FOREACH (_ IN CASE row.label WHEN 'Action' THEN [1] ELSE [] END | SET n:Action);

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
MATCH (s:KnowledgeNode {id: row.source})
MATCH (t:KnowledgeNode {id: row.target})
CALL apoc.merge.relationship(s, row.relationship_type, {}, {
  relationship: row.relationship,
  confidence: row.confidence,
  source_ref: row.source_ref,
  source_feed: row.source_feed,
  source_kind: row.source_kind,
  deterministic: row.deterministic,
  inferred: row.inferred,
  retrieved_at: row.retrieved_at,
  transform_version: row.transform_version,
  metadata_json: row.metadata_json
}, t) YIELD rel
RETURN count(rel) AS imported_relationships;
""", encoding="utf-8")


def write_queries(path: Path) -> None:
    path.write_text("""// Attack2Defend Neo4j query pack

// 1) Full CVE defense route
MATCH p=(c:CVE {id:$cve_id})-[*1..8]->(n:KnowledgeNode)
WHERE n.type IN ['cwe','capec','attack','d3fend','control','detection','evidence','gap','action']
RETURN p LIMIT 50;

// 2) Orphan nodes
MATCH (n:KnowledgeNode)
WHERE NOT (n)--()
RETURN n.id, n.type, n.name LIMIT 100;

// 3) Weak / unknown confidence edges
MATCH (s:KnowledgeNode)-[r]->(t:KnowledgeNode)
WHERE coalesce(r.confidence,'') IN ['', 'low', 'unknown']
RETURN s.id, type(r), t.id, r.confidence, r.source_ref LIMIT 100;

// 4) Missing provenance
MATCH (s:KnowledgeNode)-[r]->(t:KnowledgeNode)
WHERE coalesce(r.source_ref,'') = '' AND coalesce(r.source_feed,'') = ''
RETURN s.id, type(r), t.id, r.confidence LIMIT 100;

// 5) ATT&CK techniques missing defensive path
MATCH (a:ATTACK)
WHERE NOT (a)-[*1..4]->(:D3FEND) AND NOT (a)-[*1..4]->(:Control) AND NOT (a)-[*1..4]->(:Detection)
RETURN a.id, a.name LIMIT 100;

// 6) Detections missing evidence
MATCH (d:Detection)
WHERE NOT (d)-[*1..3]->(:Evidence)
RETURN d.id, d.name LIMIT 100;

// 7) Top gaps by inbound paths
MATCH (n:KnowledgeNode)-[r]->(g:Gap)
RETURN g.id, g.name, count(r) AS inbound_paths
ORDER BY inbound_paths DESC LIMIT 25;

// 8) AI promoted edges
MATCH (s:KnowledgeNode)-[r]->(t:KnowledgeNode)
WHERE r.source_feed IN ['ai_promoted','ai_candidate'] OR r.source_kind IN ['ai_promoted','ai_candidate']
RETURN s.id, type(r), t.id, r.confidence, r.source_ref LIMIT 100;

// 9) Coverage by framework
MATCH (n:KnowledgeNode)
RETURN n.type AS type, count(n) AS nodes
ORDER BY nodes DESC;

// 10) Route quality summary from CVEs
MATCH (c:CVE)
OPTIONAL MATCH (c)-[*1..8]->(d:Detection)
OPTIONAL MATCH (c)-[*1..8]->(e:Evidence)
OPTIONAL MATCH (c)-[*1..8]->(g:Gap)
RETURN c.id, count(DISTINCT d) AS detections, count(DISTINCT e) AS evidence, count(DISTINCT g) AS gaps
ORDER BY detections DESC, evidence DESC;
""", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Attack2Defend graph sidecar artifacts")
    parser.add_argument("--bundle", type=Path, default=ROOT / "data" / "knowledge-bundle.json")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "data" / "graph")
    args = parser.parse_args(argv)

    bundle = load_json(args.bundle)
    nodes = bundle.get("nodes", [])
    edges = bundle.get("edges", [])
    args.out_dir.mkdir(parents=True, exist_ok=True)

    write_nodes_csv(args.out_dir / "nodes.csv", nodes)
    write_edges_csv(args.out_dir / "edges.csv", edges)
    write_schema(args.out_dir / "schema.cypher")
    write_import_cypher(args.out_dir / "import.cypher")
    write_queries(args.out_dir / "neo4j_queries.cypher")

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_bundle": rel(args.bundle),
        "output_dir": rel(args.out_dir),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_types": dict(Counter(get_node_type(n) for n in nodes)),
        "relationship_types": dict(Counter(edge_relationship(e) for e in edges)),
        "artifacts": ["nodes.csv", "edges.csv", "schema.cypher", "import.cypher", "neo4j_queries.cypher", "graph-summary.json", "graph-quality-report.json"],
        "sidecar_policy": "Neo4j optional; knowledge-bundle.json remains source of truth.",
    }
    quality = graph_quality(nodes, edges)
    (args.out_dir / "graph-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.out_dir / "graph-quality-report.json").write_text(json.dumps(quality, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"graph-export: nodes={len(nodes)} edges={len(edges)} out={rel(args.out_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
