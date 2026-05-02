#!/usr/bin/env python3
"""Validate an Attack2Defend knowledge bundle.

The validator is intentionally dependency-free so it can run in CI, cron and
minimal Debian deployments. It validates both the original static bundle shape
and the stronger nsfw/CVE2CAPEC parity contract used by the mapping backbone.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_TOP_LEVEL_KEYS = {"metadata", "nodes", "edges", "indexes", "coverage", "routes"}
REQUIRED_SEEDS = {"CVE-2021-44228", "T1567", "CVE-2024-37079", "CWE-79", "D3-MFA"}
VALID_NODE_TYPES = {"cve", "cwe", "capec", "attack", "d3fend", "artifact", "control", "detection", "evidence", "gap", "action"}
SEMANTIC_ROUTE_STATUSES = {"complete", "partial-defense", "catalog-only", "seed-only", "unresolved", "conflict", "partial"}
FRAMEWORK_CHAIN_TYPES = ("cve", "cwe", "capec", "attack", "d3fend")
BIDIRECTIONAL_INDEX_KEYS = (
    "cve_to_cwe",
    "cve_to_cpe",
    "cwe_to_capec",
    "capec_to_attack",
    "attack_to_d3fend",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Bundle must be a JSON object")
    return payload


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _id(value: Any) -> str:
    return str(value or "").strip().upper()


def _type(value: Any) -> str:
    return str(value or "").strip().lower()


def validate_bundle(
    bundle: dict[str, Any],
    *,
    require_public_sources: bool = False,
    require_mapping_backbone: bool = False,
    require_semantic_routes: bool = False,
    require_framework_chain: bool = False,
    require_cpe_index: bool = False,
    require_kev_index: bool = False,
    require_bidirectional_indexes: bool = False,
    require_source_confidence: bool = False,
    require_search_index: bool = False,
    min_nodes: int | None = None,
    min_edges: int | None = None,
    min_mapping_files: int | None = None,
) -> list[str]:
    errors: list[str] = []
    missing_keys = REQUIRED_TOP_LEVEL_KEYS - set(bundle)
    if missing_keys:
        errors.append(f"Missing top-level keys: {', '.join(sorted(missing_keys))}")

    nodes = bundle.get("nodes", [])
    edges = bundle.get("edges", [])
    indexes = bundle.get("indexes", {})
    metadata = bundle.get("metadata", {})
    semantic_routes = bundle.get("semantic_routes", [])

    if not isinstance(nodes, list):
        errors.append("nodes must be a list")
        nodes = []
    if not isinstance(edges, list):
        errors.append("edges must be a list")
        edges = []
    if not isinstance(indexes, dict):
        errors.append("indexes must be an object")
        indexes = {}
    if not isinstance(metadata, dict):
        errors.append("metadata must be an object")
        metadata = {}
    if semantic_routes is None:
        semantic_routes = []
    if not isinstance(semantic_routes, list):
        errors.append("semantic_routes must be a list when present")
        semantic_routes = []

    if min_nodes is not None and len(nodes) < min_nodes:
        errors.append(f"node count {len(nodes)} is below required minimum {min_nodes}")
    if min_edges is not None and len(edges) < min_edges:
        errors.append(f"edge count {len(edges)} is below required minimum {min_edges}")

    node_ids: set[str] = set()
    node_types: set[str] = set()
    cpe_nodes: set[str] = set()
    kev_cves: set[str] = set()
    public_edge_count = 0
    curated_edge_count = 0

    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] is not an object")
            continue
        node_id = _id(node.get("id"))
        node_type = _type(node.get("type"))
        node_name = str(node.get("name", "")).strip()
        node_metadata = _as_dict(node.get("metadata"))
        if not node_id:
            errors.append(f"nodes[{index}] missing id")
            continue
        if node_id in node_ids:
            errors.append(f"duplicate node id: {node_id}")
        node_ids.add(node_id)
        node_types.add(node_type)
        if node_id.startswith("CPE:2.3") or node_metadata.get("framework") == "cpe":
            cpe_nodes.add(node_id)
        if node_type == "cve" and (node_metadata.get("kev") is True or node_metadata.get("kev_status") in {"known_exploited", "kev"}):
            kev_cves.add(node_id)
        if node_type not in VALID_NODE_TYPES:
            errors.append(f"node {node_id} invalid type: {node_type!r}")
        if not node_name:
            errors.append(f"node {node_id} missing name")

    edge_keys: set[tuple[str, str, str]] = set()
    edge_relationships: set[str] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] is not an object")
            continue
        source = _id(edge.get("source"))
        target = _id(edge.get("target"))
        relationship = _type(edge.get("relationship"))
        edge_relationships.add(relationship)
        if not source or not target or not relationship:
            errors.append(f"edges[{index}] missing source/target/relationship")
            continue
        if source not in node_ids:
            errors.append(f"broken edge source: {source} -> {target}")
        if target not in node_ids:
            errors.append(f"broken edge target: {source} -> {target}")
        key = (source, relationship, target)
        if key in edge_keys:
            errors.append(f"duplicate edge: {source} {relationship} {target}")
        edge_keys.add(key)

        source_kind = str(edge.get("source_kind", ""))
        source_ref = str(edge.get("source_ref", ""))
        confidence = str(edge.get("confidence", ""))
        if source_kind.startswith("public") or confidence == "public_source" or source_ref.startswith(("mitre_", "capec_", "nvd_", "d3fend_", "baseline:")):
            public_edge_count += 1
        if source_kind == "curated" or edge.get("curation_status") == "curated":
            curated_edge_count += 1
        if require_mapping_backbone or require_source_confidence:
            if not confidence:
                errors.append(f"edge {source} {relationship} {target} missing confidence")
            if not source_ref:
                errors.append(f"edge {source} {relationship} {target} missing source_ref")

    route_inputs = set(_as_list(indexes.get("route_inputs")))
    metadata_seed_inputs = _as_dict(metadata.get("seed_inputs"))
    metadata_available = set(_as_list(metadata_seed_inputs.get("available")))
    available = route_inputs | metadata_available | {_id(route.get("root")) for route in semantic_routes if isinstance(route, dict)}
    missing_seeds = REQUIRED_SEEDS - {_id(item) for item in available}
    if missing_seeds:
        errors.append(f"missing required seeds: {', '.join(sorted(missing_seeds))}")

    search_index = indexes.get("search", [])
    if isinstance(search_index, list) and len(search_index) < len(nodes):
        errors.append("search index has fewer entries than nodes")
    if require_search_index and (not isinstance(search_index, list) or not search_index):
        errors.append("indexes.search is empty")

    if require_public_sources:
        public_collection = _as_dict(metadata.get("public_collection"))
        successful_collectors = set(_as_list(public_collection.get("successful_collectors")))
        if metadata.get("mode") not in {"public_sources_bundle", "mapping_backbone_bundle"}:
            errors.append("bundle mode is not public_sources_bundle or mapping_backbone_bundle")
        if public_collection.get("enabled") is not True and metadata.get("mode") != "mapping_backbone_bundle":
            errors.append("metadata.public_collection.enabled is not true")
        if not (("attack" in node_types and "cwe" in node_types and "capec" in node_types) or ("attack" in node_types and ("kev" in successful_collectors or "cve" in node_types))):
            errors.append("public/mapping bundle must include ATT&CK + CWE + CAPEC, or ATT&CK + KEV/CVE")
        if public_edge_count == 0:
            errors.append("public/mapping bundle has no public-source or public-compatible edges")

    if require_framework_chain:
        for required_type in FRAMEWORK_CHAIN_TYPES:
            if required_type not in node_types:
                errors.append(f"framework chain missing node type: {required_type}")
        required_relationships = {
            "vulnerability_has_weakness",
            "weakness_enables_attack_pattern",
            "attack_pattern_maps_to_technique",
            "technique_mitigated_by_countermeasure",
        }
        missing_relationships = required_relationships - edge_relationships
        if missing_relationships:
            errors.append(f"framework chain missing relationships: {', '.join(sorted(missing_relationships))}")

    if require_cpe_index:
        cpe_to_cve = _as_dict(indexes.get("cpe_to_cve"))
        cve_to_cpe = _as_dict(_as_dict(indexes.get("forward")).get("cve_to_cpe"))
        if not cpe_nodes:
            errors.append("bundle has no CPE/product nodes")
        if not cpe_to_cve:
            errors.append("indexes.cpe_to_cve is empty")
        if not cve_to_cpe:
            errors.append("indexes.forward.cve_to_cpe is empty")

    if require_kev_index:
        kev_index = _as_dict(indexes.get("kev"))
        if not kev_index:
            errors.append("indexes.kev is empty")
        if not kev_cves and not kev_index:
            errors.append("bundle has no KEV-marked CVEs")

    if require_bidirectional_indexes:
        forward = _as_dict(indexes.get("forward"))
        reverse = _as_dict(indexes.get("reverse"))
        if not forward:
            errors.append("indexes.forward is empty")
        if not reverse:
            errors.append("indexes.reverse is empty")
        for key in BIDIRECTIONAL_INDEX_KEYS:
            if key not in forward:
                errors.append(f"indexes.forward.{key} is missing")
        for key in ("cwe_to_cve", "cpe_to_cve", "capec_to_cwe", "attack_to_capec", "d3fend_to_attack"):
            if key not in reverse:
                errors.append(f"indexes.reverse.{key} is missing")

    if require_mapping_backbone:
        mapping_backbone = _as_dict(metadata.get("mapping_backbone"))
        mapping_files = mapping_backbone.get("mapping_files", [])
        if not mapping_backbone:
            errors.append("metadata.mapping_backbone is missing")
        if not isinstance(mapping_files, list) or not mapping_files:
            errors.append("metadata.mapping_backbone.mapping_files is empty")
        if min_mapping_files is not None and isinstance(mapping_files, list) and len(mapping_files) < min_mapping_files:
            errors.append(f"mapping file count {len(mapping_files)} is below required minimum {min_mapping_files}")
        if curated_edge_count == 0:
            errors.append("mapping backbone has no curated defensive edges")
        for required_type in ("control", "detection", "evidence", "gap", "action"):
            if required_type not in node_types:
                errors.append(f"mapping backbone missing node type: {required_type}")

    if require_semantic_routes:
        if not semantic_routes:
            errors.append("semantic_routes is empty")
        for index, route in enumerate(semantic_routes):
            if not isinstance(route, dict):
                errors.append(f"semantic_routes[{index}] is not an object")
                continue
            root = _id(route.get("root"))
            if not root:
                errors.append(f"semantic_routes[{index}] missing root")
            if root and root not in node_ids:
                errors.append(f"semantic route root does not exist: {root}")
            status = str(route.get("coverage_status", ""))
            if status not in SEMANTIC_ROUTE_STATUSES:
                errors.append(f"semantic route {root or index} invalid coverage_status: {status}")
            if not isinstance(route.get("nodes"), list):
                errors.append(f"semantic route {root or index} nodes must be a list")
            if not isinstance(route.get("edges"), list):
                errors.append(f"semantic route {root or index} edges must be a list")
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate an Attack2Defend knowledge bundle.")
    parser.add_argument("bundle", type=Path, nargs="?", default=Path("data/knowledge-bundle.json"))
    parser.add_argument("--require-public-sources", action="store_true")
    parser.add_argument("--require-mapping-backbone", action="store_true")
    parser.add_argument("--require-semantic-routes", action="store_true")
    parser.add_argument("--require-framework-chain", action="store_true")
    parser.add_argument("--require-cpe-index", action="store_true")
    parser.add_argument("--require-kev-index", action="store_true")
    parser.add_argument("--require-bidirectional-indexes", action="store_true")
    parser.add_argument("--require-source-confidence", action="store_true")
    parser.add_argument("--require-search-index", action="store_true")
    parser.add_argument("--min-nodes", type=int, default=None)
    parser.add_argument("--min-edges", type=int, default=None)
    parser.add_argument("--min-mapping-files", type=int, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        bundle = load_json(args.bundle)
    except Exception as exc:
        print(f"ERROR: failed to load bundle: {exc}", file=sys.stderr)
        return 1
    errors = validate_bundle(
        bundle,
        require_public_sources=args.require_public_sources,
        require_mapping_backbone=args.require_mapping_backbone,
        require_semantic_routes=args.require_semantic_routes,
        require_framework_chain=args.require_framework_chain,
        require_cpe_index=args.require_cpe_index,
        require_kev_index=args.require_kev_index,
        require_bidirectional_indexes=args.require_bidirectional_indexes,
        require_source_confidence=args.require_source_confidence,
        require_search_index=args.require_search_index,
        min_nodes=args.min_nodes,
        min_edges=args.min_edges,
        min_mapping_files=args.min_mapping_files,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Attack2Defend bundle validated: {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
