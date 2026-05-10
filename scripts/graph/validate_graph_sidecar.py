#!/usr/bin/env python3
"""Validate Attack2Defend graph sidecar artifacts."""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRET_RE = re.compile(r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|Bearer\s+[A-Za-z0-9._-]{12,}|sk-[A-Za-z0-9]{10,}", re.I)
ABS_PATH_RE = re.compile(r"/(home|Users)/[^\s,\"']+")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def scan_text(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if SECRET_RE.search(text):
        errors.append(f"secret_like_value:{path}")
    if ABS_PATH_RE.search(text):
        errors.append(f"absolute_local_path:{path}")


def validate(out_dir: Path) -> list[str]:
    errors: list[str] = []
    required = [
        "nodes.csv",
        "edges.csv",
        "schema.cypher",
        "import.cypher",
        "neo4j_queries.cypher",
        "graph-summary.json",
        "graph-quality-report.json",
    ]
    for name in required:
        path = out_dir / name
        if not path.exists():
            errors.append(f"missing:{name}")
        elif path.stat().st_size == 0:
            errors.append(f"empty:{name}")
        elif path.suffix in {".json", ".csv", ".cypher"}:
            scan_text(path, errors)
    if errors:
        return errors

    nodes = read_csv(out_dir / "nodes.csv")
    edges = read_csv(out_dir / "edges.csv")
    node_ids = [row.get("id", "").strip() for row in nodes]
    node_set = set(node_ids)
    if len(node_ids) != len(node_set):
        errors.append("duplicate_node_ids")
    for idx, node_id in enumerate(node_ids, start=2):
        if not node_id:
            errors.append(f"node_missing_id:row_{idx}")
    for idx, row in enumerate(edges, start=2):
        source = row.get("source", "").strip()
        target = row.get("target", "").strip()
        relationship = row.get("relationship", "").strip()
        rel_type = row.get("relationship_type", "").strip()
        if not source:
            errors.append(f"edge_missing_source:row_{idx}")
        if not target:
            errors.append(f"edge_missing_target:row_{idx}")
        if not relationship:
            errors.append(f"edge_missing_relationship:row_{idx}")
        if not rel_type:
            errors.append(f"edge_missing_relationship_type:row_{idx}")
        if source and source not in node_set:
            errors.append(f"edge_source_not_found:row_{idx}:{source}")
        if target and target not in node_set:
            errors.append(f"edge_target_not_found:row_{idx}:{target}")
    for name in ["graph-summary.json", "graph-quality-report.json"]:
        try:
            json.loads((out_dir / name).read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"invalid_json:{name}:{exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Attack2Defend graph sidecar artifacts")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "data" / "graph")
    args = parser.parse_args(argv)
    errors = validate(args.out_dir)
    if errors:
        print("validate-graph: FAIL")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"validate-graph: OK out={args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
