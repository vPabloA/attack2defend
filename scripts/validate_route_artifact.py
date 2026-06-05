#!/usr/bin/env python3
"""Validate a route coherence artifact against schema and provenance rules.

Usage:
  python scripts/validate_route_artifact.py --input CVE-2026-23479
  python scripts/validate_route_artifact.py --artifact artifacts/routes/CVE-2026-23479/route-coherence.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))


def _load_artifact(input_id: str | None, artifact_path: str | None) -> dict:
    if artifact_path:
        path = Path(artifact_path)
    elif input_id:
        path = _REPO_ROOT / "artifacts" / "routes" / input_id.upper() / "route-coherence.json"
    else:
        print("ERROR: provide --input or --artifact", file=sys.stderr)
        sys.exit(1)

    if not path.exists():
        print(f"ERROR: artifact not found: {path}", file=sys.stderr)
        sys.exit(1)

    return json.loads(path.read_text(encoding="utf-8"))


_VALID_STATUS = {"complete", "complete_with_inferred_edges", "partial", "degraded", "failed"}
_VALID_NODE_TYPES = {"cve", "cwe", "capec", "attack", "d3fend"}
_VALID_BASIS = {"official_explicit", "official_related", "analytical_inferred", "conditional", "unverified"}


def _validate_schema(artifact: dict) -> list[str]:
    """Manual structural validation against a2d_route_coherence.schema.json."""
    errors: list[str] = []

    for req in ("artifact_type", "schema_version", "input", "status", "route", "graph", "provenance"):
        if req not in artifact:
            errors.append(f"schema: missing required field '{req}'")

    if artifact.get("artifact_type") != "a2d_route_coherence":
        errors.append(f"schema: artifact_type must be 'a2d_route_coherence', got {artifact.get('artifact_type')!r}")
    if artifact.get("schema_version") != "1.0":
        errors.append(f"schema: schema_version must be '1.0', got {artifact.get('schema_version')!r}")
    if artifact.get("status") not in _VALID_STATUS:
        errors.append(f"schema: invalid status {artifact.get('status')!r}")

    route = artifact.get("route", {})
    if not isinstance(route.get("canonical_chain"), list):
        errors.append("schema: route.canonical_chain must be an array")

    graph = artifact.get("graph", {})
    if "nodes" not in graph:
        errors.append("schema: graph.nodes is required")
    if "edges" not in graph:
        errors.append("schema: graph.edges is required")

    for node in route.get("all_nodes", []):
        if node.get("type") not in _VALID_NODE_TYPES:
            errors.append(f"schema: node {node.get('id')!r} has invalid type {node.get('type')!r}")

    for edge in route.get("all_edges", []):
        basis = edge.get("mapping_basis")
        if basis and basis not in _VALID_BASIS:
            errors.append(f"schema: edge {edge.get('source')}→{edge.get('target')} has invalid mapping_basis {basis!r}")

    for gnode in graph.get("nodes", []):
        if gnode.get("type") not in _VALID_NODE_TYPES:
            errors.append(f"schema: graph node {gnode.get('id')!r} has invalid type {gnode.get('type')!r}")
        xl = gnode.get("xLayer")
        if not isinstance(xl, int) or not (0 <= xl <= 4):
            errors.append(f"schema: graph node {gnode.get('id')!r} has invalid xLayer {xl!r}")

    return errors


def validate_dict(artifact: dict) -> list[str]:
    errors: list[str] = _validate_schema(artifact)

    route = artifact.get("route", {})
    all_nodes = route.get("all_nodes", [])
    all_edges = route.get("all_edges", [])
    graph = artifact.get("graph", {})
    analysis = artifact.get("analysis_es", {})

    if not all_nodes:
        errors.append("route.all_nodes is empty")
    if not graph.get("nodes"):
        errors.append("graph.nodes is empty")
    if not graph.get("edges") and all_edges:
        errors.append("graph.edges is empty but all_edges is not")
    if not analysis.get("technical_narrative"):
        errors.append("analysis_es.technical_narrative is empty")
    if not analysis.get("logical_sequence"):
        errors.append("analysis_es.logical_sequence is empty")

    # Portable no-invention check: node IDs must be a subset of source_known_ids
    # recorded at generation time (baseline + bundle + live resolvers).
    validation_ctx = artifact.get("validation_context", {})
    known_ids: set[str] = set(validation_ctx.get("source_known_ids", []))
    if known_ids:
        for node in all_nodes:
            if node["id"] not in known_ids:
                errors.append(
                    f"Node '{node['id']}' not in validation_context.source_known_ids — possible invented ID"
                )
    else:
        errors.append("validation_context.source_known_ids is missing — offline no-invention check cannot run")

    for edge in all_edges:
        if not edge.get("mapping_basis"):
            errors.append(f"Edge {edge.get('source')}→{edge.get('target')} missing mapping_basis")
        if not edge.get("source_refs"):
            errors.append(f"Edge {edge.get('source')}→{edge.get('target')} has no source_refs")
        if edge.get("mapping_basis") == "official_explicit" and edge.get("score", 100) < 50:
            errors.append(f"Edge {edge.get('source')}→{edge.get('target')} falsely claims official_explicit")

    if not artifact.get("provenance"):
        errors.append("provenance section is missing")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a route coherence artifact")
    parser.add_argument("--input", default=None, help="Input ID (e.g. CVE-2026-23479)")
    parser.add_argument("--artifact", default=None, help="Direct path to route-coherence.json")
    args = parser.parse_args(argv)

    artifact = _load_artifact(args.input, args.artifact)
    errors = validate_dict(artifact)

    if errors:
        print(f"FAILED — {len(errors)} error(s):")
        for e in errors:
            print(f"  ✗ {e}")
        return 1

    print(f"PASSED — artifact for {artifact.get('input', '?')} is valid")
    print(f"  status: {artifact.get('status')}")
    print(f"  nodes: {len(artifact.get('route', {}).get('all_nodes', []))}")
    print(f"  edges: {len(artifact.get('route', {}).get('all_edges', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
