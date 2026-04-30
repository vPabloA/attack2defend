#!/usr/bin/env python3
"""Attack2Defend Threat Knowledge Builder.

This is the scheduled-job entrypoint for the MVP knowledge base.

MVP behavior:
- reads curated route files from data/samples/*.route.json;
- normalizes nodes and edges into the public knowledge bundle;
- validates duplicate IDs and broken edges;
- writes data/nodes.json, data/edges.json, data/indexes.json, data/metadata.json;
- optionally writes a timestamped snapshot under data/snapshots/.

Future behavior:
- fetch NVD/CVE, CWE, CAPEC, ATT&CK STIX, D3FEND and CISA KEV;
- merge those public sources with internal curated mappings;
- preserve internal coverage state independently.

SOC runtime rule:
The navigator consumes the generated local bundle. It must not depend on live
public APIs during analyst runtime.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BUILDER_VERSION = "0.1.0"
CONTRACT_VERSION = "attack2defend.knowledge_bundle.v1"

VALID_NODE_TYPES = {
    "cve",
    "cwe",
    "capec",
    "attack",
    "d3fend",
    "artifact",
    "control",
    "detection",
    "evidence",
    "gap",
}


@dataclass(slots=True)
class BuildIssue:
    severity: str
    message: str
    source: str = ""


@dataclass(slots=True)
class BuildState:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    source_files: list[str] = field(default_factory=list)
    route_inputs: list[str] = field(default_factory=list)
    issues: list[BuildIssue] = field(default_factory=list)

    def warn(self, message: str, source: str = "") -> None:
        self.issues.append(BuildIssue(severity="warning", message=message, source=source))

    def error(self, message: str, source: str = "") -> None:
        self.issues.append(BuildIssue(severity="error", message=message, source=source))

    @property
    def has_errors(self) -> bool:
        return any(issue.severity == "error" for issue in self.issues)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def normalize_id(value: Any) -> str:
    return str(value or "").strip().upper()


def normalize_node(raw: dict[str, Any], source: Path, state: BuildState) -> dict[str, Any] | None:
    node_id = normalize_id(raw.get("id"))
    node_type = str(raw.get("type") or "").strip().lower()
    name = str(raw.get("name") or "").strip()

    if not node_id:
        state.error("Node without id", str(source))
        return None
    if node_type not in VALID_NODE_TYPES:
        state.error(f"Node {node_id} has invalid type: {node_type!r}", str(source))
        return None
    if not name:
        state.error(f"Node {node_id} has empty name", str(source))
        return None

    node = {
        "id": node_id,
        "type": node_type,
        "name": name,
    }
    if raw.get("description"):
        node["description"] = str(raw.get("description"))
    if raw.get("url"):
        node["url"] = str(raw.get("url"))
    if isinstance(raw.get("metadata"), dict):
        node["metadata"] = raw["metadata"]
    return node


def normalize_edge(raw: dict[str, Any], source: Path, state: BuildState) -> dict[str, Any] | None:
    source_id = normalize_id(raw.get("source"))
    target_id = normalize_id(raw.get("target"))
    relationship = str(raw.get("relationship") or "").strip().lower()

    if not source_id or not target_id:
        state.error(f"Edge with missing source/target: {raw}", str(source))
        return None
    if not relationship:
        state.error(f"Edge {source_id}->{target_id} has empty relationship", str(source))
        return None

    edge = {
        "source": source_id,
        "target": target_id,
        "relationship": relationship,
    }
    for optional_key in ("source_framework", "target_framework", "confidence", "source_ref"):
        if raw.get(optional_key):
            edge[optional_key] = str(raw.get(optional_key))
    return edge


def ingest_route_file(path: Path, state: BuildState) -> None:
    payload = load_json(path)
    state.source_files.append(str(path))

    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    route_input = normalize_id(metadata.get("input"))
    if route_input:
        state.route_inputs.append(route_input)

    raw_nodes = payload.get("nodes")
    raw_edges = payload.get("edges")
    if not isinstance(raw_nodes, list):
        state.error("Route file missing nodes[]", str(path))
        return
    if not isinstance(raw_edges, list):
        state.error("Route file missing edges[]", str(path))
        return

    for raw_node in raw_nodes:
        if not isinstance(raw_node, dict):
            state.error(f"Invalid node object: {raw_node!r}", str(path))
            continue
        node = normalize_node(raw_node, path, state)
        if node is None:
            continue
        existing = state.nodes.get(node["id"])
        if existing and existing != node:
            state.warn(f"Duplicate node {node['id']} differs; keeping first occurrence", str(path))
            continue
        state.nodes[node["id"]] = node

    for raw_edge in raw_edges:
        if not isinstance(raw_edge, dict):
            state.error(f"Invalid edge object: {raw_edge!r}", str(path))
            continue
        edge = normalize_edge(raw_edge, path, state)
        if edge is None:
            continue
        key = (edge["source"], edge["target"], edge["relationship"])
        state.edges[key] = edge


def validate_edges(state: BuildState) -> None:
    node_ids = set(state.nodes)
    for edge in state.edges.values():
        if edge["source"] not in node_ids:
            state.error(f"Broken edge source does not exist: {edge['source']} -> {edge['target']}")
        if edge["target"] not in node_ids:
            state.error(f"Broken edge target does not exist: {edge['source']} -> {edge['target']}")


def build_indexes(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], route_inputs: list[str]) -> dict[str, Any]:
    by_type: dict[str, list[str]] = {}
    outgoing: dict[str, list[dict[str, str]]] = {}
    incoming: dict[str, list[dict[str, str]]] = {}
    relationships: dict[str, int] = {}

    for node in nodes:
        by_type.setdefault(node["type"], []).append(node["id"])

    for edge in edges:
        outgoing.setdefault(edge["source"], []).append({
            "target": edge["target"],
            "relationship": edge["relationship"],
        })
        incoming.setdefault(edge["target"], []).append({
            "source": edge["source"],
            "relationship": edge["relationship"],
        })
        relationships[edge["relationship"]] = relationships.get(edge["relationship"], 0) + 1

    return {
        "by_type": {key: sorted(value) for key, value in sorted(by_type.items())},
        "outgoing": {key: value for key, value in sorted(outgoing.items())},
        "incoming": {key: value for key, value in sorted(incoming.items())},
        "relationships": dict(sorted(relationships.items())),
        "route_inputs": sorted(set(route_inputs)),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def build_bundle(source_dir: Path, output_dir: Path, snapshot_dir: Path | None, *, strict: bool) -> int:
    state = BuildState()
    route_files = sorted(source_dir.glob("*.route.json"))
    if not route_files:
        state.error(f"No route files found in {source_dir}")

    for route_file in route_files:
        ingest_route_file(route_file, state)

    validate_edges(state)

    if strict and any(issue.severity == "warning" for issue in state.issues):
        state.error("Strict mode treats warnings as build blockers")

    if state.has_errors:
        print_issues(state)
        return 1

    generated_at = utc_now()
    nodes = sorted(state.nodes.values(), key=lambda node: (node["type"], node["id"]))
    edges = sorted(state.edges.values(), key=lambda edge: (edge["source"], edge["relationship"], edge["target"]))
    indexes = build_indexes(nodes, edges, state.route_inputs)
    metadata = {
        "contract_version": CONTRACT_VERSION,
        "builder_version": BUILDER_VERSION,
        "generated_at": generated_at,
        "source_files": state.source_files,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "route_inputs": len(set(state.route_inputs)),
            "warnings": len([issue for issue in state.issues if issue.severity == "warning"]),
        },
        "warnings": [issue.__dict__ for issue in state.issues if issue.severity == "warning"],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "nodes.json", nodes)
    write_json(output_dir / "edges.json", edges)
    write_json(output_dir / "indexes.json", indexes)
    write_json(output_dir / "metadata.json", metadata)

    if snapshot_dir is not None:
        stamp = generated_at.replace(":", "").replace("-", "")
        target = snapshot_dir / stamp
        target.mkdir(parents=True, exist_ok=True)
        for file_name in ("nodes.json", "edges.json", "indexes.json", "metadata.json"):
            shutil.copy2(output_dir / file_name, target / file_name)

    print(f"Attack2Defend knowledge bundle generated: nodes={len(nodes)} edges={len(edges)} output={output_dir}")
    if state.issues:
        print_issues(state)
    return 0


def print_issues(state: BuildState) -> None:
    for issue in state.issues:
        source = f" [{issue.source}]" if issue.source else ""
        print(f"{issue.severity.upper()}: {issue.message}{source}", file=sys.stderr)


def parse_args(argv: list[str]) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Build the Attack2Defend local knowledge bundle.")
    parser.add_argument("--source-dir", type=Path, default=repo_root / "data" / "samples")
    parser.add_argument("--output-dir", type=Path, default=repo_root / "data")
    parser.add_argument("--snapshot-dir", type=Path, default=repo_root / "data" / "snapshots")
    parser.add_argument("--no-snapshot", action="store_true", help="Skip timestamped snapshot creation.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as build blockers.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    snapshot_dir = None if args.no_snapshot else args.snapshot_dir
    return build_bundle(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        snapshot_dir=snapshot_dir,
        strict=args.strict,
    )


if __name__ == "__main__":
    raise SystemExit(main())
