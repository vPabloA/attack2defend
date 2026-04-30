#!/usr/bin/env python3
"""Attack2Defend Threat Knowledge Builder.

Scheduled-job entrypoint for the local Attack2Defend knowledge base.

The builder can run in two modes:

1. Curated mode (default): reads data/samples/*.route.json and generates a
   deterministic local bundle.
2. Public-source mode (--with-public-sources): extends the curated bundle with
   public ATT&CK, CWE, CAPEC, CISA KEV, optional NVD and best-effort D3FEND data.

SOC runtime rule:
The Navigator UI never calls public APIs directly. Public sources are fetched by
this scheduled builder and published as a local snapshot.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from public_collectors import collect_public_sources
except Exception:  # pragma: no cover - import failure is reported at runtime when requested
    collect_public_sources = None  # type: ignore[assignment]

BUILDER_VERSION = "0.3.0"
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

LIST_COVERAGE_FIELDS = ("controls", "detections", "evidence", "gaps", "owners")
REQUIRED_SEED_INPUTS = {
    "CVE-2021-44228",
    "T1567",
    "CVE-2024-37079",
    "CWE-79",
    "D3-MFA",
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
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    routes: list[dict[str, Any]] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    route_inputs: list[str] = field(default_factory=list)
    public_sources: list[str] = field(default_factory=list)
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


def normalize_node(raw: dict[str, Any], source: Path | str, state: BuildState) -> dict[str, Any] | None:
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

    node: dict[str, Any] = {"id": node_id, "type": node_type, "name": name}
    for optional_key in ("description", "url"):
        if raw.get(optional_key):
            node[optional_key] = str(raw.get(optional_key))
    if isinstance(raw.get("metadata"), dict):
        node["metadata"] = raw["metadata"]
    return node


def merge_node(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if value in ("", None, [], {}):
            continue
        if key == "metadata" and isinstance(value, dict):
            metadata = dict(merged.get("metadata", {}))
            metadata.update(value)
            merged["metadata"] = metadata
        elif key not in merged or merged[key] in ("", None, [], {}):
            merged[key] = value
    return merged


def normalize_edge(raw: dict[str, Any], source: Path | str, state: BuildState) -> dict[str, Any] | None:
    source_id = normalize_id(raw.get("source"))
    target_id = normalize_id(raw.get("target"))
    relationship = str(raw.get("relationship") or "").strip().lower()

    if not source_id or not target_id:
        state.error(f"Edge with missing source/target: {raw}", str(source))
        return None
    if not relationship:
        state.error(f"Edge {source_id}->{target_id} has empty relationship", str(source))
        return None

    edge: dict[str, Any] = {"source": source_id, "target": target_id, "relationship": relationship}
    for optional_key in ("source_framework", "target_framework", "confidence", "source_ref"):
        if raw.get(optional_key):
            edge[optional_key] = str(raw.get(optional_key))
    return edge


def normalize_coverage(raw: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    if raw.get("status"):
        record["status"] = str(raw.get("status")).strip().lower()
    for field_name in LIST_COVERAGE_FIELDS:
        values = raw.get(field_name, [])
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list):
            clean = sorted({str(value).strip() for value in values if str(value).strip()})
            if clean:
                record[field_name] = clean
    return record


def merge_coverage(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    if incoming.get("status"):
        if not merged.get("status"):
            merged["status"] = incoming["status"]
        elif merged.get("status") != incoming.get("status"):
            merged["status"] = "partial"
    for field_name in LIST_COVERAGE_FIELDS:
        merged[field_name] = sorted(set(merged.get(field_name, [])) | set(incoming.get(field_name, [])))
        if not merged[field_name]:
            merged.pop(field_name, None)
    return merged


def upsert_node(state: BuildState, node: dict[str, Any], source: Path | str) -> None:
    normalized = normalize_node(node, source, state)
    if normalized is None:
        return
    existing = state.nodes.get(normalized["id"])
    if existing and existing != normalized:
        state.nodes[normalized["id"]] = merge_node(existing, normalized)
    else:
        state.nodes[normalized["id"]] = normalized


def upsert_edge(state: BuildState, edge: dict[str, Any], source: Path | str) -> None:
    normalized = normalize_edge(edge, source, state)
    if normalized is None:
        return
    key = (normalized["source"], normalized["target"], normalized["relationship"])
    state.edges[key] = normalized


def ingest_route_file(path: Path, state: BuildState) -> None:
    payload = load_json(path)
    state.source_files.append(str(path))

    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    route_input = normalize_id(metadata.get("input"))
    if route_input:
        state.route_inputs.append(route_input)
    state.routes.append({"file": str(path), **metadata})

    raw_nodes = payload.get("nodes")
    raw_edges = payload.get("edges")
    if not isinstance(raw_nodes, list):
        state.error("Route file missing nodes[]", str(path))
        return
    if not isinstance(raw_edges, list):
        state.error("Route file missing edges[]", str(path))
        return

    for raw_node in raw_nodes:
        if isinstance(raw_node, dict):
            upsert_node(state, raw_node, path)
        else:
            state.error(f"Invalid node object: {raw_node!r}", str(path))

    for raw_edge in raw_edges:
        if isinstance(raw_edge, dict):
            upsert_edge(state, raw_edge, path)
        else:
            state.error(f"Invalid edge object: {raw_edge!r}", str(path))

    raw_coverage = payload.get("coverage")
    if isinstance(raw_coverage, dict):
        for target_id_raw, record_raw in raw_coverage.items():
            target_id = normalize_id(target_id_raw)
            if not target_id or not isinstance(record_raw, dict):
                state.warn(f"Ignoring invalid coverage record: {target_id_raw!r}", str(path))
                continue
            record = normalize_coverage(record_raw)
            state.coverage[target_id] = merge_coverage(state.coverage.get(target_id, {}), record)


def ingest_public_result(state: BuildState, result: Any) -> None:
    for node in getattr(result, "nodes", {}).values():
        upsert_node(state, node, "public_collectors")
    for edge in getattr(result, "edges", {}).values():
        upsert_edge(state, edge, "public_collectors")
    for route in getattr(result, "routes", []):
        if isinstance(route, dict):
            route_input = normalize_id(route.get("input"))
            if route_input:
                state.route_inputs.append(route_input)
            state.routes.append(route)
    for route_input in getattr(result, "route_inputs", set()):
        normalized_input = normalize_id(route_input)
        if normalized_input:
            state.route_inputs.append(normalized_input)
    state.public_sources.extend(getattr(result, "sources", []))
    for warning in getattr(result, "warnings", []):
        state.warn(str(warning), "public_collectors")


def validate_edges(state: BuildState) -> None:
    node_ids = set(state.nodes)
    for edge in state.edges.values():
        if edge["source"] not in node_ids:
            state.error(f"Broken edge source does not exist: {edge['source']} -> {edge['target']}")
        if edge["target"] not in node_ids:
            state.error(f"Broken edge target does not exist: {edge['source']} -> {edge['target']}")


def validate_coverage(state: BuildState) -> None:
    node_ids = set(state.nodes)
    for target_id in state.coverage:
        if target_id not in node_ids:
            state.warn(f"Coverage target is not a known node: {target_id}")


def validate_seed_inputs(state: BuildState) -> None:
    available = set(state.route_inputs)
    missing = sorted(REQUIRED_SEED_INPUTS - available)
    if missing:
        state.error(f"Missing required seed inputs: {', '.join(missing)}")


def build_indexes(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], route_inputs: list[str]) -> dict[str, Any]:
    by_type: dict[str, list[str]] = {}
    outgoing: dict[str, list[dict[str, str]]] = {}
    incoming: dict[str, list[dict[str, str]]] = {}
    relationships: dict[str, int] = {}
    search: list[dict[str, str]] = []

    for node in nodes:
        by_type.setdefault(node["type"], []).append(node["id"])
        search.append({"id": node["id"], "type": node["type"], "name": node["name"], "text": f"{node['id']} {node['name']}".lower()})

    for edge in edges:
        outgoing.setdefault(edge["source"], []).append({"target": edge["target"], "relationship": edge["relationship"]})
        incoming.setdefault(edge["target"], []).append({"source": edge["source"], "relationship": edge["relationship"]})
        relationships[edge["relationship"]] = relationships.get(edge["relationship"], 0) + 1

    return {
        "by_type": {key: sorted(value) for key, value in sorted(by_type.items())},
        "outgoing": {key: value for key, value in sorted(outgoing.items())},
        "incoming": {key: value for key, value in sorted(incoming.items())},
        "relationships": dict(sorted(relationships.items())),
        "route_inputs": sorted(set(route_inputs)),
        "search": sorted(search, key=lambda item: (item["type"], item["id"])),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_bundle_files(output_dir: Path, bundle: dict[str, Any]) -> None:
    for file_name in ("nodes", "edges", "indexes", "coverage", "routes", "metadata"):
        write_json(output_dir / f"{file_name}.json", bundle[file_name])
    write_json(output_dir / "knowledge-bundle.json", bundle)


def copy_bundle_files(source_dir: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for file_name in ("nodes.json", "edges.json", "indexes.json", "coverage.json", "routes.json", "metadata.json", "knowledge-bundle.json"):
        shutil.copy2(source_dir / file_name, target_dir / file_name)


def build_bundle(
    source_dir: Path,
    output_dir: Path,
    snapshot_dir: Path | None,
    ui_public_dir: Path | None,
    *,
    strict: bool,
    with_public_sources: bool,
    cache_dir: Path,
    refresh_public_sources: bool,
    public_timeout: int,
    public_fail_on_error: bool,
    public_no_attack: bool,
    public_no_cwe: bool,
    public_no_capec: bool,
    public_no_kev: bool,
    public_no_d3fend: bool,
    with_nvd: bool,
    nvd_cves: list[str],
    nvd_recent_days: int,
    nvd_api_key: str | None,
    max_kev_cves: int | None,
    max_d3fend_attack_ids: int,
) -> int:
    state = BuildState()
    route_files = sorted(source_dir.glob("*.route.json"))
    if not route_files:
        state.error(f"No route files found in {source_dir}")

    for route_file in route_files:
        ingest_route_file(route_file, state)

    if with_public_sources:
        if collect_public_sources is None:
            state.error("public_collectors.py could not be imported")
        else:
            try:
                public_result = collect_public_sources(
                    cache_dir,
                    refresh=refresh_public_sources,
                    timeout=public_timeout,
                    include_attack=not public_no_attack,
                    include_cwe=not public_no_cwe,
                    include_capec=not public_no_capec,
                    include_kev=not public_no_kev,
                    include_d3fend=not public_no_d3fend,
                    include_nvd=with_nvd,
                    nvd_cves=nvd_cves,
                    nvd_recent_days=nvd_recent_days,
                    nvd_api_key=nvd_api_key,
                    max_kev_cves=max_kev_cves,
                    max_d3fend_attack_ids=max_d3fend_attack_ids,
                    fail_on_error=public_fail_on_error,
                )
                ingest_public_result(state, public_result)
            except Exception as exc:  # noqa: BLE001 - top-level builder must report cleanly
                if public_fail_on_error:
                    state.error(f"Public source collection failed: {exc}")
                else:
                    state.warn(f"Public source collection failed: {exc}", "public_collectors")

    validate_edges(state)
    validate_coverage(state)
    validate_seed_inputs(state)

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
        "public_sources": sorted(set(state.public_sources)),
        "mode": "public_sources_bundle" if with_public_sources else "curated_mvp_bundle",
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "coverage_records": len(state.coverage),
            "routes": len(state.routes),
            "route_inputs": len(set(state.route_inputs)),
            "warnings": len([issue for issue in state.issues if issue.severity == "warning"]),
        },
        "seed_inputs": {"required": sorted(REQUIRED_SEED_INPUTS), "available": sorted(set(state.route_inputs))},
        "public_collection": {
            "enabled": with_public_sources,
            "nvd_enabled": with_nvd or bool(nvd_cves) or nvd_recent_days > 0,
            "nvd_recent_days": nvd_recent_days,
            "nvd_cves": sorted({normalize_id(item) for item in nvd_cves}),
            "cache_dir": str(cache_dir),
        },
        "warnings": [asdict(issue) for issue in state.issues if issue.severity == "warning"],
    }
    bundle = {"metadata": metadata, "nodes": nodes, "edges": edges, "indexes": indexes, "coverage": dict(sorted(state.coverage.items())), "routes": state.routes}

    output_dir.mkdir(parents=True, exist_ok=True)
    write_bundle_files(output_dir, bundle)

    if ui_public_dir is not None:
        copy_bundle_files(output_dir, ui_public_dir)

    if snapshot_dir is not None:
        stamp = generated_at.replace(":", "").replace("-", "")
        target = snapshot_dir / stamp
        copy_bundle_files(output_dir, target)

    print("Attack2Defend knowledge bundle generated: " f"nodes={len(nodes)} edges={len(edges)} routes={len(state.routes)} output={output_dir}")
    if with_public_sources:
        print(f"Public source mode enabled: sources={len(set(state.public_sources))} cache={cache_dir}")
    if ui_public_dir is not None:
        print(f"UI public bundle mirrored: {ui_public_dir}")
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
    parser.add_argument("--ui-public-dir", type=Path, default=repo_root / "app" / "navigator-ui" / "public" / "data")
    parser.add_argument("--cache-dir", type=Path, default=repo_root / "data" / "raw")
    parser.add_argument("--no-snapshot", action="store_true", help="Skip timestamped snapshot creation.")
    parser.add_argument("--no-ui-mirror", action="store_true", help="Do not mirror bundle to the Navigator UI public directory.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as build blockers.")
    parser.add_argument("--with-public-sources", action="store_true", help="Hydrate the bundle with public ATT&CK/CWE/CAPEC/KEV/D3FEND sources.")
    parser.add_argument("--refresh-public-sources", action="store_true", help="Ignore cached public files and refetch public sources.")
    parser.add_argument("--public-timeout", type=int, default=45)
    parser.add_argument("--public-fail-on-error", action="store_true", help="Fail the build if any public source collector fails.")
    parser.add_argument("--public-no-attack", action="store_true")
    parser.add_argument("--public-no-cwe", action="store_true")
    parser.add_argument("--public-no-capec", action="store_true")
    parser.add_argument("--public-no-kev", action="store_true")
    parser.add_argument("--public-no-d3fend", action="store_true")
    parser.add_argument("--with-nvd", action="store_true", help="Enable NVD CVE collection. Use with --nvd-cve or --nvd-recent-days.")
    parser.add_argument("--nvd-cve", action="append", default=[], help="Fetch a specific CVE from NVD. May be repeated.")
    parser.add_argument("--nvd-recent-days", type=int, default=0, help="Fetch CVEs modified in the last N days from NVD.")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    parser.add_argument("--max-kev-cves", type=int, default=None)
    parser.add_argument("--max-d3fend-attack-ids", type=int, default=250)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    snapshot_dir = None if args.no_snapshot else args.snapshot_dir
    ui_public_dir = None if args.no_ui_mirror else args.ui_public_dir
    return build_bundle(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        snapshot_dir=snapshot_dir,
        ui_public_dir=ui_public_dir,
        strict=args.strict,
        with_public_sources=args.with_public_sources,
        cache_dir=args.cache_dir,
        refresh_public_sources=args.refresh_public_sources,
        public_timeout=args.public_timeout,
        public_fail_on_error=args.public_fail_on_error,
        public_no_attack=args.public_no_attack,
        public_no_cwe=args.public_no_cwe,
        public_no_capec=args.public_no_capec,
        public_no_kev=args.public_no_kev,
        public_no_d3fend=args.public_no_d3fend,
        with_nvd=args.with_nvd,
        nvd_cves=args.nvd_cve,
        nvd_recent_days=args.nvd_recent_days,
        nvd_api_key=args.nvd_api_key,
        max_kev_cves=args.max_kev_cves,
        max_d3fend_attack_ids=args.max_d3fend_attack_ids,
    )


if __name__ == "__main__":
    raise SystemExit(main())
