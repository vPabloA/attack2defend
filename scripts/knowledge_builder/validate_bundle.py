#!/usr/bin/env python3
"""Validate an Attack2Defend knowledge bundle.

This script is intentionally dependency-free so it can run in cron, CI, and
minimal Debian servers without extra packages.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_TOP_LEVEL_KEYS = {"metadata", "nodes", "edges", "indexes", "coverage", "routes"}
REQUIRED_SEEDS = {"CVE-2021-44228", "T1567", "CVE-2024-37079", "CWE-79", "D3-MFA"}
VALID_NODE_TYPES = {"cve", "cwe", "capec", "attack", "d3fend", "artifact", "control", "detection", "evidence", "gap"}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Bundle must be a JSON object")
    return payload


def validate_bundle(bundle: dict[str, Any], *, require_public_sources: bool = False, min_nodes: int | None = None, min_edges: int | None = None) -> list[str]:
    errors: list[str] = []

    missing_keys = REQUIRED_TOP_LEVEL_KEYS - set(bundle)
    if missing_keys:
        errors.append(f"Missing top-level keys: {', '.join(sorted(missing_keys))}")

    nodes = bundle.get("nodes", [])
    edges = bundle.get("edges", [])
    indexes = bundle.get("indexes", {})
    metadata = bundle.get("metadata", {})

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

    if min_nodes is not None and len(nodes) < min_nodes:
        errors.append(f"node count {len(nodes)} is below required minimum {min_nodes}")
    if min_edges is not None and len(edges) < min_edges:
        errors.append(f"edge count {len(edges)} is below required minimum {min_edges}")

    node_ids: set[str] = set()
    node_types: set[str] = set()
    public_node_count = 0
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] is not an object")
            continue
        node_id = str(node.get("id", "")).strip().upper()
        node_type = str(node.get("type", "")).strip().lower()
        node_name = str(node.get("name", "")).strip()
        metadata_obj = node.get("metadata", {}) if isinstance(node.get("metadata", {}), dict) else {}
        if not node_id:
            errors.append(f"nodes[{index}] missing id")
            continue
        if node_id in node_ids:
            errors.append(f"duplicate node id: {node_id}")
        node_ids.add(node_id)
        node_types.add(node_type)
        if str(metadata_obj.get("source", "")).startswith(("mitre_", "cwe_", "capec_", "cisa_", "nvd_", "d3fend_")):
            public_node_count += 1
        if node_type not in VALID_NODE_TYPES:
            errors.append(f"node {node_id} invalid type: {node_type!r}")
        if not node_name:
            errors.append(f"node {node_id} missing name")

    edge_keys: set[tuple[str, str, str]] = set()
    public_edge_count = 0
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] is not an object")
            continue
        source = str(edge.get("source", "")).strip().upper()
        target = str(edge.get("target", "")).strip().upper()
        relationship = str(edge.get("relationship", "")).strip().lower()
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
        if edge.get("confidence") == "public_source" or str(edge.get("source_ref", "")).startswith(("mitre_", "capec_", "nvd_", "d3fend_")):
            public_edge_count += 1

    route_inputs = set(indexes.get("route_inputs", [])) if isinstance(indexes.get("route_inputs", []), list) else set()
    metadata_seed_inputs = metadata.get("seed_inputs", {})
    metadata_available = set(metadata_seed_inputs.get("available", [])) if isinstance(metadata_seed_inputs, dict) else set()
    available = route_inputs | metadata_available
    missing_seeds = REQUIRED_SEEDS - {str(item).upper() for item in available}
    if missing_seeds:
        errors.append(f"missing required seeds: {', '.join(sorted(missing_seeds))}")

    search_index = indexes.get("search", [])
    if isinstance(search_index, list) and len(search_index) < len(nodes):
        errors.append("search index has fewer entries than nodes")

    if require_public_sources:
        public_collection = metadata.get("public_collection", {}) if isinstance(metadata.get("public_collection", {}), dict) else {}
        public_sources = metadata.get("public_sources", [])
        if metadata.get("mode") != "public_sources_bundle":
            errors.append("bundle mode is not public_sources_bundle")
        if public_collection.get("enabled") is not True:
            errors.append("metadata.public_collection.enabled is not true")
        if not isinstance(public_sources, list) or not public_sources:
            errors.append("metadata.public_sources is empty")
        for required_type in ("attack", "cwe", "capec"):
            if required_type not in node_types:
                errors.append(f"public bundle missing node type: {required_type}")
        if public_node_count == 0:
            errors.append("public bundle has no public-source nodes")
        if public_edge_count == 0:
            errors.append("public bundle has no public-source edges")

    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate an Attack2Defend knowledge bundle.")
    parser.add_argument("bundle", type=Path, nargs="?", default=Path("data/knowledge-bundle.json"))
    parser.add_argument("--require-public-sources", action="store_true", help="Require metadata and graph evidence that public collectors were used.")
    parser.add_argument("--min-nodes", type=int, default=None)
    parser.add_argument("--min-edges", type=int, default=None)
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
        min_nodes=args.min_nodes,
        min_edges=args.min_edges,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Attack2Defend bundle validated: {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
