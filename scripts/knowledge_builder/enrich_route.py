#!/usr/bin/env python3
"""Incrementally enrich an Attack2Defend route and persist local JSON artifacts.

Examples:
  python scripts/knowledge_builder/enrich_route.py CVE-2026-0013 --mode enrich_missing --write
  python scripts/knowledge_builder/enrich_route.py --input data/cherry_picks.txt --mode enrich_missing --write

This is a builder/enrichment-time CLI. It does not change the browser runtime
contract; the UI must continue reading local JSON only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attack2defend.capability import resolve_defense_route
from attack2defend.enrichment import build_enrichment_result, merge_bundle_with_stats, normalize_route_input, write_knowledge_store
from attack2defend.runtime_bundle import write_runtime_bundle

SOURCE_PRIORITY = {
    "nvd_api": 100,
    "cisa_kev": 95,
    "cwe_xml": 90,
    "capec_xml": 90,
    "mitre_attack_stix": 90,
    "mitre_d3fend_ontology": 90,
    "d3fend_api": 80,
    "galeax_cve2capec_database": 60,
    "galeax_cve2capec_cwe_db": 55,
    "galeax_cve2capec_capec_db": 55,
    "galeax_cve2capec_techniques_db": 55,
    "galeax_cve2capec_defend_db": 55,
}


def source_priority(value: Any) -> int:
    return SOURCE_PRIORITY.get(str(value or ""), 0)


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: dict[str, Any], *, pretty: bool) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None) + "\n", encoding="utf-8")


def read_inputs(args: argparse.Namespace) -> list[str]:
    values: list[str] = []
    if args.route_input:
        values.append(args.route_input)
    if args.input:
        input_path = Path(args.input)
        if input_path.exists():
            values.extend(line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#"))
        else:
            values.append(args.input)
    return values


def edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(edge.get("source") or "").strip().upper(),
        str(edge.get("target") or "").strip().upper(),
        str(edge.get("relationship") or "").strip().lower(),
    )


def merge_patch_node(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    existing_source = merged.get("source_ref") or (merged.get("metadata") or {}).get("source")
    incoming_source = incoming.get("source_ref") or (incoming.get("metadata") or {}).get("source")
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key == "metadata" and isinstance(value, dict):
            metadata = dict(merged.get("metadata") or {})
            for meta_key, meta_value in value.items():
                if meta_value in (None, "", [], {}):
                    continue
                if meta_key == "source" and source_priority(incoming_source) > source_priority(existing_source):
                    metadata[meta_key] = meta_value
                else:
                    metadata.setdefault(meta_key, meta_value)
            merged["metadata"] = metadata
        elif key == "source_ref":
            if source_priority(value) >= source_priority(existing_source):
                merged[key] = value
        elif key not in merged or merged.get(key) in (None, "", [], {}) or merged.get(key) == merged.get("id"):
            merged[key] = value
    return merged


def route_node_ids(capability: dict[str, Any], raw_input: str) -> set[str]:
    ids = {normalize_route_input(raw_input)}
    ids.update(str(node.get("id") or "").upper() for node in capability.get("threat_route_map", {}).get("nodes", []) or [] if node.get("id"))
    return ids


def filter_patch_to_relevant(
    raw_input: str,
    capability: dict[str, Any],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Keep an enrichment patch incremental to the requested route."""

    node_index = {str(node.get("id") or "").upper(): node for node in nodes if node.get("id")}
    outgoing: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        source, target, _ = edge_key(edge)
        outgoing.setdefault(source, []).append(edge)
        if target:
            outgoing.setdefault(target, [])

    relevant = route_node_ids(capability, raw_input)
    queue = list(relevant)
    while queue and len(relevant) < 180:
        current = queue.pop(0)
        for edge in outgoing.get(current, [])[:24]:
            source, target, _ = edge_key(edge)
            for node_id in (source, target):
                if node_id and node_id not in relevant:
                    relevant.add(node_id)
                    queue.append(node_id)

    filtered_nodes = [node for node_id, node in node_index.items() if node_id in relevant]
    filtered_edges = [edge for edge in edges if edge_key(edge)[0] in relevant and edge_key(edge)[1] in relevant]
    return filtered_nodes, filtered_edges


def collector_result_to_bundle_patch(raw_input: str, capability: dict[str, Any], *, cache_dir: Path, mode: str, timeout: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Run existing public collectors only from explicit enrichment mode.

    The implementation intentionally reuses scripts/knowledge_builder/public_collectors.py
    instead of creating a second ingestion stack. If a public source is unavailable,
    the route still falls back to the local bundle and records the warning.
    """

    if mode == "local_only":
        return [], [], []

    try:
        from scripts.knowledge_builder.public_collectors import collect_attack, collect_capec, collect_cve2capec, collect_cwe, collect_d3fend_ontology, collect_nvd
    except Exception as exc:  # pragma: no cover - defensive for direct script use
        return [], [], [f"public_collectors import failed: {exc}"]

    normalized = normalize_route_input(raw_input)
    refresh = mode == "refresh"
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    warnings: list[str] = []

    def absorb(result: Any) -> None:
        for node in getattr(result, "nodes", {}).values():
            identifier = str(node.get("id", "")).upper()
            nodes[identifier] = merge_patch_node(nodes.get(identifier, {}), node)
        for key, edge in getattr(result, "edges", {}).items():
            source = str(edge.get("source", "")).upper()
            target = str(edge.get("target", "")).upper()
            rel = str(edge.get("relationship", "")).lower()
            if source and target and rel:
                edges[(source, target, rel)] = edge
        warnings.extend(getattr(result, "warnings", []) or [])

    try:
        if normalized.startswith("CVE-"):
            absorb(collect_nvd(cache_dir, cves=[normalized], refresh=refresh, timeout=timeout, api_key=os.environ.get("NVD_API_KEY")))
            year = int(normalized.split("-")[1])
            absorb(collect_cve2capec(cache_dir, years=[year], refresh=refresh, timeout=timeout))
        # Framework collectors are broad but cache-backed. They are the official enrichment path
        # for empty CWE/CAPEC/ATT&CK descriptions created by shortcut mapping databases.
        absorb(collect_cwe(cache_dir, refresh=refresh, timeout=timeout))
        absorb(collect_capec(cache_dir, refresh=refresh, timeout=timeout))
        absorb(collect_attack(cache_dir, refresh=refresh, timeout=timeout))
        absorb(collect_d3fend_ontology(cache_dir, refresh=refresh, timeout=timeout))
    except Exception as exc:
        warnings.append(f"official enrichment failed; local bundle used: {exc}")

    filtered_nodes, filtered_edges = filter_patch_to_relevant(raw_input, capability, list(nodes.values()), list(edges.values()))
    return filtered_nodes, filtered_edges, warnings


def run_one(raw_input: str, args: argparse.Namespace) -> dict[str, Any]:
    bundle_path = Path(args.bundle)
    original_bundle = load_json(bundle_path)
    local_capability = resolve_defense_route({"input": raw_input}, bundle_path=bundle_path)
    enrichment_nodes, enrichment_edges, warnings = collector_result_to_bundle_patch(raw_input, local_capability, cache_dir=Path(args.cache_dir), mode=args.mode, timeout=args.timeout)

    effective_bundle_path = bundle_path
    stats = {"nodes_added": 0, "nodes_updated": 0, "edges_added": 0, "edges_updated": 0}
    if enrichment_nodes or enrichment_edges:
        enriched_bundle, stats = merge_bundle_with_stats(original_bundle, enrichment_nodes, enrichment_edges)
        effective_bundle_path = Path(args.temp_bundle)
        write_json(effective_bundle_path, enriched_bundle, pretty=False)
        if args.write or args.write_bundle:
            write_json(bundle_path, enriched_bundle, pretty=True)
            if args.ui_bundle:
                write_runtime_bundle(args.ui_bundle, enriched_bundle, pretty=False)

    capability = resolve_defense_route({"input": raw_input}, bundle_path=effective_bundle_path)
    result = build_enrichment_result(capability, raw_input=raw_input, mode=args.mode)
    result.nodes_added = stats["nodes_added"]
    result.nodes_updated = stats["nodes_updated"]
    result.edges_added = stats["edges_added"]
    if warnings:
        result.validation.setdefault("warnings", []).extend(warnings)

    if args.write:
        write_knowledge_store(args.store_dir, result)
    return result.as_dict()


def main() -> int:
    parser = argparse.ArgumentParser(description="Incrementally enrich a CVE/CWE/CAPEC/ATT&CK/D3FEND route.")
    parser.add_argument("route_input", nargs="?", help="Single ID to enrich, e.g. CVE-2026-0013 or CAPEC-196.")
    parser.add_argument("--input", help="Single ID or newline-delimited file of cherry-picked IDs.")
    parser.add_argument("--bundle", default="data/knowledge-bundle.json", help="Local bundle path.")
    parser.add_argument("--mode", choices=["local_only", "enrich_missing", "refresh"], default="local_only")
    parser.add_argument("--cache-dir", default="data/public-cache", help="Official-source cache directory.")
    parser.add_argument("--store-dir", default="data/knowledge-store", help="Incremental JSONL store directory.")
    parser.add_argument("--temp-bundle", default="data/.tmp-enriched-knowledge-bundle.json", help="Temporary merged bundle path.")
    parser.add_argument("--write", action="store_true", help="Write JSONL knowledge-store artifacts and update the local bundle with route-relevant enrichments.")
    parser.add_argument("--write-bundle", action="store_true", help="Also update data/knowledge-bundle.json with official-source enrichments.")
    parser.add_argument("--ui-bundle", default="app/navigator-ui/public/data/knowledge-bundle.json", help="Mirror updated bundle to the static UI public data path when --write is used.")
    parser.add_argument("--output", help="Write combined enrichment result JSON.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()

    inputs = read_inputs(args)
    if not inputs:
        parser.error("provide route_input or --input")

    results = [run_one(value, args) for value in inputs]
    payload = {"schema_version": "1.0", "count": len(results), "results": results}
    if args.output:
        write_json(args.output, payload, pretty=args.pretty)
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))

    return 0 if all(item.get("validation", {}).get("status") == "pass" for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
