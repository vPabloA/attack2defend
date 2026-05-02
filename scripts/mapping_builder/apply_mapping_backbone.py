#!/usr/bin/env python3
"""Apply Attack2Defend static mapping backbone to a generated bundle.

Builder-time only. The UI still consumes only local knowledge-bundle.json.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONTRACT_VERSION = "attack2defend.knowledge_bundle.v2"
BACKBONE_VERSION = "0.2.0"
VALID_NODE_TYPES = {"cve", "cwe", "capec", "attack", "d3fend", "artifact", "control", "detection", "evidence", "gap", "action"}
TYPE_ORDER = ["cve", "cwe", "capec", "attack", "artifact", "d3fend", "control", "detection", "evidence", "gap", "action"]
PAIR_REL = {
    ("cve", "cwe"): "vulnerability_has_weakness",
    ("cve", "artifact"): "affects_product_or_platform",
    ("cwe", "capec"): "weakness_enables_attack_pattern",
    ("capec", "attack"): "attack_pattern_maps_to_technique",
    ("attack", "d3fend"): "technique_mitigated_by_countermeasure",
    ("attack", "artifact"): "affects_or_requires_artifact",
    ("capec", "artifact"): "affects_or_requires_artifact",
    ("artifact", "control"): "protected_by_control",
    ("control", "detection"): "validated_by_detection",
    ("detection", "evidence"): "requires_evidence",
    ("evidence", "gap"): "missing_evidence_creates_gap",
    ("gap", "action"): "closed_by_action",
}
ALIASES = {
    "has_weakness": "vulnerability_has_weakness",
    "has_related_weakness": "vulnerability_has_weakness",
    "may_enable_attack_pattern": "weakness_enables_attack_pattern",
    "may_map_to_attack_technique": "attack_pattern_maps_to_technique",
    "may_be_defended_by": "technique_mitigated_by_countermeasure",
    "affects_artifact": "affects_or_requires_artifact",
    "abuses_artifact": "affects_or_requires_artifact",
    "targets_artifact": "affects_or_requires_artifact",
    "protects_artifact": "protected_by_control",
    "implemented_by": "protected_by_control",
    "may_be_detected_by": "validated_by_detection",
    "enables_detection": "validated_by_detection",
}
SEMANTIC_RELS = set(PAIR_REL.values()) | set(ALIASES.values())


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def nid(value: Any) -> str:
    return str(value or "").strip().upper()


def ntype(value: Any, node_id: str = "") -> str:
    explicit = str(value or "").strip().lower()
    if explicit in VALID_NODE_TYPES:
        return explicit
    item = nid(node_id)
    if item.startswith("CVE-"):
        return "cve"
    if item.startswith("CWE-"):
        return "cwe"
    if item.startswith("CAPEC-"):
        return "capec"
    if item.startswith("T") and len(item) >= 5 and item[1:5].isdigit():
        return "attack"
    if item.startswith("D3-"):
        return "d3fend"
    if item.startswith("CTRL-"):
        return "control"
    if item.startswith("DET-"):
        return "detection"
    if item.startswith("EV-"):
        return "evidence"
    if item.startswith("GAP-"):
        return "gap"
    if item.startswith("ACT-"):
        return "action"
    return "artifact"


def rel(value: Any, source_type: str, target_type: str) -> str:
    raw = str(value or "").strip().lower()
    if raw:
        return ALIASES.get(raw, raw)
    return PAIR_REL.get((source_type, target_type), "related_to")


def load(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def upsert_node(nodes: dict[str, dict[str, Any]], raw: dict[str, Any]) -> None:
    node_id = nid(raw.get("id"))
    if not node_id:
        return
    node_type = ntype(raw.get("type"), node_id)
    node = {"id": node_id, "type": node_type, "name": str(raw.get("name") or node_id)}
    for key in ("description", "url"):
        if raw.get(key):
            node[key] = str(raw[key])
    if isinstance(raw.get("metadata"), dict):
        node["metadata"] = raw["metadata"]
    if node_id in nodes:
        merged = dict(nodes[node_id])
        for key, value in node.items():
            if key == "metadata" and isinstance(value, dict):
                meta = dict(merged.get("metadata", {}))
                meta.update(value)
                merged["metadata"] = meta
            elif key not in merged or merged[key] in (None, "", [], {}):
                merged[key] = value
        nodes[node_id] = merged
    else:
        nodes[node_id] = node


def upsert_edge(edges: dict[tuple[str, str, str], dict[str, Any]], raw: dict[str, Any]) -> None:
    source = nid(raw.get("source") or raw.get("from"))
    target = nid(raw.get("target") or raw.get("to"))
    if not source or not target:
        return
    source_type = ntype(raw.get("source_type") or raw.get("from_type"), source)
    target_type = ntype(raw.get("target_type") or raw.get("to_type"), target)
    relationship = rel(raw.get("relationship"), source_type, target_type)
    edge = {"source": source, "target": target, "relationship": relationship, "source_type": source_type, "target_type": target_type}
    for key in ("confidence", "source_ref", "source_kind", "curation_status", "mapping_file", "license", "owner", "priority", "evidence_url"):
        if raw.get(key):
            edge[key] = raw[key]
    edges[(source, relationship, target)] = {**edges.get((source, relationship, target), {}), **edge}


def records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [item for item in (payload.get("mappings") or payload.get("edges") or []) if isinstance(item, dict)]
    return []


def merge_lists(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    out = dict(existing)
    for key, value in incoming.items():
        if isinstance(value, list):
            out[key] = sorted({str(item) for item in out.get(key, []) + value if str(item).strip()})
        elif value:
            out[key] = value
    return out


def ingest_mapping_file(path: Path, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], coverage: dict[str, dict[str, Any]]) -> int:
    payload = load(path)
    source_kind = "curated" if "/curated/" in path.as_posix() else "public-compatible"
    source_ref = path.as_posix()
    license_name = payload.get("license", "attack2defend-curated") if isinstance(payload, dict) else "attack2defend-curated"
    for node in payload.get("nodes", []) if isinstance(payload, dict) else []:
        if isinstance(node, dict):
            node.setdefault("metadata", {})
            if isinstance(node["metadata"], dict):
                node["metadata"].setdefault("source_kind", source_kind)
                node["metadata"].setdefault("source_ref", source_ref)
            upsert_node(nodes, node)
    count = 0
    for item in records(payload):
        source = nid(item.get("source") or item.get("from"))
        target = nid(item.get("target") or item.get("to"))
        source_type = ntype(item.get("source_type") or item.get("from_type"), source)
        target_type = ntype(item.get("target_type") or item.get("to_type"), target)
        upsert_node(nodes, {"id": source, "type": source_type, "name": item.get("source_name") or item.get("from_name") or source, "metadata": {"source_kind": source_kind, "source_ref": source_ref}})
        upsert_node(nodes, {"id": target, "type": target_type, "name": item.get("target_name") or item.get("to_name") or target, "metadata": {"source_kind": source_kind, "source_ref": source_ref}})
        upsert_edge(edges, {**item, "source": source, "target": target, "source_type": source_type, "target_type": target_type, "source_ref": item.get("source_ref") or source_ref, "source_kind": item.get("source_kind") or source_kind, "curation_status": item.get("curation_status") or source_kind, "confidence": item.get("confidence") or ("high" if source_kind == "curated" else "medium"), "mapping_file": source_ref, "license": item.get("license") or license_name})
        count += 1
    if isinstance(payload, dict) and isinstance(payload.get("coverage"), dict):
        for target_id, record in payload["coverage"].items():
            if isinstance(record, dict):
                coverage[nid(target_id)] = merge_lists(coverage.get(nid(target_id), {}), record)
    return count


def add_index(mapping: dict[str, list[str]], source: str, target: str) -> None:
    source_id = nid(source)
    target_id = nid(target)
    if not source_id or not target_id:
        return
    mapping.setdefault(source_id, [])
    if target_id not in mapping[source_id]:
        mapping[source_id].append(target_id)


def build_indexes(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], route_inputs: set[str]) -> dict[str, Any]:
    by_type: dict[str, list[str]] = {}
    outgoing: dict[str, list[dict[str, str]]] = {}
    incoming: dict[str, list[dict[str, str]]] = {}
    search: list[dict[str, str]] = []
    relationships: dict[str, int] = {}
    forward: dict[str, dict[str, list[str]]] = {
        "cve_to_cwe": {},
        "cve_to_cpe": {},
        "cwe_to_capec": {},
        "capec_to_attack": {},
        "attack_to_d3fend": {},
    }
    reverse: dict[str, dict[str, list[str]]] = {
        "cwe_to_cve": {},
        "cpe_to_cve": {},
        "capec_to_cwe": {},
        "attack_to_capec": {},
        "d3fend_to_attack": {},
    }
    cpe_to_cve: dict[str, list[str]] = {}
    kev: dict[str, dict[str, Any]] = {}

    node_map = {nid(node.get("id")): node for node in nodes}
    for node in nodes:
        node_id = nid(node.get("id"))
        node_type = ntype(node.get("type"), node_id)
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        by_type.setdefault(node_type, []).append(node_id)
        search.append({"id": node_id, "type": metadata.get("framework", node_type), "name": str(node.get("name") or node_id), "text": f"{node_id} {node.get('name','')} {metadata.get('vendor','')} {metadata.get('product','')}".lower()})
        if node_type == "cve" and (metadata.get("kev") is True or metadata.get("kev_status") in {"kev", "known_exploited"}):
            kev[node_id] = {"id": node_id, "name": node.get("name", node_id), "vendor": metadata.get("vendor"), "product": metadata.get("product"), "date_added": metadata.get("kev_date_added"), "required_action": metadata.get("required_action")}

    for edge in edges:
        source = nid(edge.get("source"))
        target = nid(edge.get("target"))
        relationship = str(edge.get("relationship") or "related_to")
        source_type = ntype(node_map.get(source, {}).get("type") or edge.get("source_type"), source)
        target_type = ntype(node_map.get(target, {}).get("type") or edge.get("target_type"), target)
        target_metadata = node_map.get(target, {}).get("metadata") if isinstance(node_map.get(target, {}).get("metadata"), dict) else {}
        outgoing.setdefault(source, []).append({"target": target, "relationship": relationship})
        incoming.setdefault(target, []).append({"source": source, "relationship": relationship})
        relationships[relationship] = relationships.get(relationship, 0) + 1

        if source_type == "cve" and target_type == "cwe" and relationship == "vulnerability_has_weakness":
            add_index(forward["cve_to_cwe"], source, target)
            add_index(reverse["cwe_to_cve"], target, source)
        elif source_type == "cve" and target_type == "artifact" and relationship == "affects_product_or_platform":
            add_index(forward["cve_to_cpe"], source, target)
            if str(target).startswith("CPE:2.3") or target_metadata.get("framework") == "cpe":
                add_index(cpe_to_cve, target, source)
                add_index(reverse["cpe_to_cve"], target, source)
        elif source_type == "cwe" and target_type == "capec" and relationship == "weakness_enables_attack_pattern":
            add_index(forward["cwe_to_capec"], source, target)
            add_index(reverse["capec_to_cwe"], target, source)
        elif source_type == "capec" and target_type == "attack" and relationship == "attack_pattern_maps_to_technique":
            add_index(forward["capec_to_attack"], source, target)
            add_index(reverse["attack_to_capec"], target, source)
        elif source_type == "attack" and target_type == "d3fend" and relationship == "technique_mitigated_by_countermeasure":
            add_index(forward["attack_to_d3fend"], source, target)
            add_index(reverse["d3fend_to_attack"], target, source)

    return {
        "by_type": {key: sorted(value) for key, value in sorted(by_type.items())},
        "outgoing": {key: sorted(value, key=lambda item: (item["relationship"], item["target"])) for key, value in sorted(outgoing.items())},
        "incoming": {key: sorted(value, key=lambda item: (item["relationship"], item["source"])) for key, value in sorted(incoming.items())},
        "relationships": dict(sorted(relationships.items())),
        "route_inputs": sorted({nid(item) for item in route_inputs if nid(item)}),
        "search": sorted(search, key=lambda item: (item["type"], item["id"])),
        "forward": {key: {k: sorted(v) for k, v in sorted(value.items())} for key, value in sorted(forward.items())},
        "reverse": {key: {k: sorted(v) for k, v in sorted(value.items())} for key, value in sorted(reverse.items())},
        "cpe_to_cve": {key: sorted(value) for key, value in sorted(cpe_to_cve.items())},
        "kev": dict(sorted(kev.items())),
    }


def route_status(types: set[str]) -> str:
    if len(types) <= 1:
        return "unresolved"
    if {"cve", "cwe", "capec", "attack", "artifact", "control", "detection", "evidence", "gap", "action"}.issubset(types):
        return "complete"
    if {"attack", "artifact", "control", "detection", "evidence"}.issubset(types):
        return "partial-defense"
    if {"cve", "cwe", "capec", "attack", "d3fend"}.intersection(types) and not {"control", "detection", "evidence"}.intersection(types):
        return "catalog-only"
    return "partial"


def resolve_route(root: str, nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    root_id = nid(root)
    if root_id not in nodes:
        return {"root": root_id, "coverage_status": "unresolved", "confidence_score": 0.0, "nodes": [], "edges": [], "missing_segments": TYPE_ORDER}
    selected = {root_id}
    selected_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    by_source: dict[str, list[dict[str, Any]]] = {}
    by_target: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        by_source.setdefault(nid(edge.get("source")), []).append(edge)
        by_target.setdefault(nid(edge.get("target")), []).append(edge)
    for direction, index in (("down", by_source), ("up", by_target)):
        queue = [root_id]
        for _ in range(len(TYPE_ORDER) + 2):
            nxt = []
            for current in queue:
                for edge in index.get(current, [])[:30]:
                    relationship = str(edge.get("relationship") or "")
                    if relationship not in SEMANTIC_RELS:
                        continue
                    other = nid(edge.get("target" if direction == "down" else "source"))
                    selected.add(other)
                    selected_edges[(nid(edge.get("source")), relationship, nid(edge.get("target")))] = edge
                    nxt.append(other)
            nxt = sorted(set(nxt) - set(queue))
            if not nxt:
                break
            queue = nxt
    ordered = sorted(selected, key=lambda item: (TYPE_ORDER.index(ntype(nodes[item].get("type"), item)), item))
    edge_list = sorted(selected_edges.values(), key=lambda item: (nid(item.get("source")), str(item.get("relationship")), nid(item.get("target"))))
    types = {ntype(nodes[item].get("type"), item) for item in ordered}
    missing = [item for item in TYPE_ORDER if item not in types]
    status = route_status(types)
    score = 0.0 if not edge_list else round(min(1.0, max(0.0, sum({"high": 1.0, "medium": 0.72, "low": 0.42, "public_source": 0.66}.get(str(edge.get("confidence") or "medium").lower(), 0.55) for edge in edge_list) / len(edge_list) + (0.08 if status == "complete" else -0.10 if status in {"unresolved", "catalog-only"} else 0))), 2)
    return {"root": root_id, "root_type": ntype(nodes[root_id].get("type"), root_id), "coverage_status": status, "confidence_score": score, "nodes": ordered, "edges": edge_list, "missing_segments": missing, "generated_by": "semantic_route_resolver.v1"}


def apply_mapping_backbone(bundle_path: Path, mappings_dir: Path, ui_public_dir: Path | None, output_path: Path | None, last_good: bool) -> int:
    bundle = load(bundle_path)
    nodes = {nid(node.get("id")): dict(node) for node in bundle.get("nodes", []) if isinstance(node, dict)}
    edges = {(nid(edge.get("source")), rel(edge.get("relationship"), ntype(edge.get("source_type"), edge.get("source")), ntype(edge.get("target_type"), edge.get("target"))), nid(edge.get("target"))): dict(edge) for edge in bundle.get("edges", []) if isinstance(edge, dict)}
    coverage = dict(bundle.get("coverage", {})) if isinstance(bundle.get("coverage"), dict) else {}
    files = sorted(path for path in mappings_dir.rglob("*.json") if path.is_file())
    if not files:
        raise FileNotFoundError(f"No mapping JSON files found under {mappings_dir}")
    mapping_records = sum(ingest_mapping_file(path, nodes, edges, coverage) for path in files)
    node_list = sorted(nodes.values(), key=lambda node: (TYPE_ORDER.index(ntype(node.get("type"), node.get("id"))), nid(node.get("id"))))
    edge_list = sorted(edges.values(), key=lambda edge: (nid(edge.get("source")), str(edge.get("relationship")), nid(edge.get("target"))))
    route_inputs = set(bundle.get("indexes", {}).get("route_inputs", [])) if isinstance(bundle.get("indexes"), dict) else set()
    route_inputs.update(route.get("input") for route in bundle.get("routes", []) if isinstance(route, dict) and route.get("input"))
    route_inputs.update(["CVE-2021-44228", "CVE-2024-37079", "CVE-2023-34362", "CWE-79", "CAPEC-63", "T1190", "T1567", "D3-MFA"])
    bundle["nodes"] = node_list
    bundle["edges"] = edge_list
    bundle["coverage"] = {nid(k): v for k, v in sorted(coverage.items())}
    bundle["indexes"] = build_indexes(node_list, edge_list, route_inputs)
    node_map = {nid(node.get("id")): node for node in node_list}
    bundle["semantic_routes"] = [resolve_route(root, node_map, edge_list) for root in sorted(bundle["indexes"]["route_inputs"]) if root in node_map]
    by_status: dict[str, int] = {}
    for route in bundle["semantic_routes"]:
        by_status[route["coverage_status"]] = by_status.get(route["coverage_status"], 0) + 1
    bundle["coverage_summary"] = {"routes_by_status": dict(sorted(by_status.items()))}
    metadata = dict(bundle.get("metadata", {}))
    counts = dict(metadata.get("counts", {})) if isinstance(metadata.get("counts"), dict) else {}
    counts.update({"nodes": len(node_list), "edges": len(edge_list), "coverage_records": len(bundle["coverage"]), "semantic_routes": len(bundle["semantic_routes"]), "mapping_files": len(files), "mapping_records": mapping_records})
    metadata.update({"contract_version": CONTRACT_VERSION, "schema_version": CONTRACT_VERSION, "mapping_backbone_version": BACKBONE_VERSION, "mapping_backbone_applied_at": now(), "mode": "mapping_backbone_bundle", "counts": counts, "mapping_backbone": {"mappings_dir": str(mappings_dir), "mapping_files": [str(path) for path in files]}})
    bundle["metadata"] = metadata
    target = output_path or bundle_path
    dump(target, bundle)
    if target != bundle_path:
        shutil.copy2(target, bundle_path)
    if ui_public_dir is not None:
        ui_public_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundle_path, ui_public_dir / "knowledge-bundle.json")
    if last_good:
        shutil.copy2(bundle_path, bundle_path.with_name("knowledge-bundle.last-good.json"))
        if ui_public_dir is not None:
            shutil.copy2(bundle_path, ui_public_dir / "knowledge-bundle.last-good.json")
    print(f"Attack2Defend mapping backbone applied: files={len(files)} records={mapping_records} nodes={len(node_list)} edges={len(edge_list)} semantic_routes={len(bundle['semantic_routes'])}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Apply static mapping backbone and curated defense mappings.")
    parser.add_argument("--bundle", type=Path, default=root / "data" / "knowledge-bundle.json")
    parser.add_argument("--mappings-dir", type=Path, default=root / "data" / "mappings")
    parser.add_argument("--ui-public-dir", type=Path, default=root / "app" / "navigator-ui" / "public" / "data")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--no-ui-mirror", action="store_true")
    parser.add_argument("--last-good", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        return apply_mapping_backbone(args.bundle, args.mappings_dir, None if args.no_ui_mirror else args.ui_public_dir, args.output, args.last_good)
    except Exception as exc:
        print(f"ERROR: failed to apply mapping backbone: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
