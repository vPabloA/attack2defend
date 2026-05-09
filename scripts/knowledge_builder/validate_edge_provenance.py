#!/usr/bin/env python3
"""Validate mandatory provenance fields on Attack2Defend bundle edges."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = (
    "source_feed",
    "retrieved_at",
    "transform_version",
    "confidence",
    "deterministic",
    "inferred",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("bundle must be a JSON object")
    return payload


def has_value(value: Any) -> bool:
    return value not in (None, "", [], {})


def edge_label(edge: dict[str, Any], index: int) -> str:
    source = str(edge.get("source") or "?").strip().upper()
    relationship = str(edge.get("relationship") or "?").strip().lower()
    target = str(edge.get("target") or "?").strip().upper()
    return f"edges[{index}] {source} {relationship} {target}"


def validate_edge(edge: dict[str, Any], index: int) -> list[str]:
    label = edge_label(edge, index)
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in edge or not has_value(edge.get(field)):
            errors.append(f"{label} missing provenance field: {field}")
    if not (has_value(edge.get("source_ref")) or has_value(edge.get("source_url"))):
        errors.append(f"{label} missing provenance reference: source_ref or source_url")
    if "deterministic" in edge and not isinstance(edge.get("deterministic"), bool):
        errors.append(f"{label} provenance field deterministic must be boolean")
    if "inferred" in edge and not isinstance(edge.get("inferred"), bool):
        errors.append(f"{label} provenance field inferred must be boolean")
    return errors


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    edges = bundle.get("edges", [])
    if not isinstance(edges, list):
        return ["edges must be a list"]
    errors: list[str] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] is not an object")
            continue
        errors.extend(validate_edge(edge, index))
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Attack2Defend edge provenance contract.")
    parser.add_argument("bundle", type=Path, nargs="?", default=Path("data/knowledge-bundle.json"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        bundle = load_json(args.bundle)
    except Exception as exc:
        print(f"ERROR: failed to load bundle: {exc}", file=sys.stderr)
        return 1
    errors = validate_bundle(bundle)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Attack2Defend edge provenance validated: {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
