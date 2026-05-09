#!/usr/bin/env python3
"""Stamp mandatory provenance fields on existing Attack2Defend bundle edges."""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        item = value.strip().lower()
        if item in {"true", "1", "yes"}:
            return True
        if item in {"false", "0", "no"}:
            return False
    return default


def feed(edge: dict[str, Any]) -> str:
    for key in ("source_feed", "source_kind", "curation_status", "license"):
        value = str(edge.get(key) or "").strip()
        if value:
            return value
    ref = str(edge.get("source_ref") or edge.get("mapping_file") or "").strip()
    if ref.startswith("data/mappings/"):
        return "attack2defend_mapping_backbone"
    if ref.startswith(("mitre_", "capec_", "nvd_", "d3fend_", "cisa_", "baseline:")):
        return "public_framework_cache"
    return "attack2defend_curated_bundle"


def ref(edge: dict[str, Any]) -> str:
    for key in ("source_ref", "mapping_file", "evidence_url"):
        value = str(edge.get(key) or "").strip()
        if value:
            return value
    source = str(edge.get("source") or "UNKNOWN").strip().upper()
    relationship = str(edge.get("relationship") or "related_to").strip().lower()
    target = str(edge.get("target") or "UNKNOWN").strip().upper()
    return f"generated:edge:{source}:{relationship}:{target}"


def transform(edge: dict[str, Any], metadata: dict[str, Any]) -> str:
    if edge.get("transform_version"):
        return str(edge["transform_version"])
    if edge.get("mapping_file") or str(edge.get("source_ref") or "").startswith("data/mappings/"):
        return f"mapping_backbone:{metadata.get('mapping_backbone_version', 'unknown')}"
    return f"knowledge_builder:{metadata.get('builder_version', 'unknown')}"


def stamp(edge: dict[str, Any], metadata: dict[str, Any], generated_at: str) -> dict[str, Any]:
    out = dict(edge)
    out.setdefault("source_feed", feed(out))
    if not out.get("source_ref") and not out.get("source_url"):
        out["source_ref"] = ref(out)
    out.setdefault("retrieved_at", metadata.get("mapping_backbone_applied_at") or metadata.get("generated_at") or generated_at)
    out.setdefault("transform_version", transform(out, metadata))
    out.setdefault("confidence", "medium")
    out["deterministic"] = as_bool(out.get("deterministic"), True)
    out["inferred"] = as_bool(out.get("inferred"), False)
    return out


def enforce_bundle(bundle: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    metadata = dict(bundle.get("metadata", {})) if isinstance(bundle.get("metadata"), dict) else {}
    generated_at = generated_at or now()
    edges = bundle.get("edges", [])
    if not isinstance(edges, list):
        raise ValueError("bundle.edges must be a list")
    stamped = [stamp(edge, metadata, generated_at) if isinstance(edge, dict) else edge for edge in edges]
    counts = dict(metadata.get("counts", {})) if isinstance(metadata.get("counts"), dict) else {}
    counts["edges_with_provenance"] = sum(1 for edge in stamped if isinstance(edge, dict))
    metadata["counts"] = counts
    metadata["edge_provenance_version"] = VERSION
    metadata["edge_provenance_enforced_at"] = generated_at
    out = dict(bundle)
    out["metadata"] = metadata
    out["edges"] = stamped
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Enforce edge provenance on Attack2Defend bundle.")
    parser.add_argument("--bundle", type=Path, default=root / "data" / "knowledge-bundle.json")
    parser.add_argument("--ui-public-dir", type=Path, default=root / "app" / "navigator-ui" / "public" / "data")
    parser.add_argument("--no-ui-mirror", action="store_true")
    parser.add_argument("--last-good", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    bundle = enforce_bundle(load_json(args.bundle))
    dump_json(args.bundle, bundle)
    dump_json(args.bundle.parent / "edges.json", bundle["edges"])
    dump_json(args.bundle.parent / "metadata.json", bundle["metadata"])
    if not args.no_ui_mirror:
        args.ui_public_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.bundle, args.ui_public_dir / "knowledge-bundle.json")
        dump_json(args.ui_public_dir / "edges.json", bundle["edges"])
        dump_json(args.ui_public_dir / "metadata.json", bundle["metadata"])
    if args.last_good:
        shutil.copy2(args.bundle, args.bundle.with_name("knowledge-bundle.last-good.json"))
    print(f"Attack2Defend edge provenance enforced: edges={len(bundle.get('edges', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
