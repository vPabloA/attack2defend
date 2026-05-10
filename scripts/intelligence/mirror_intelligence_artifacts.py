#!/usr/bin/env python3
"""Mirror Intelligence Factory artifacts into navigator-ui public/data."""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": rel(path), "error": str(exc)}


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def default_factory_report() -> dict[str, Any]:
    return {
        "status": "not_generated",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": "not-generated",
        "promotion_mode": "not_available",
        "candidates_seen": 0,
        "candidates_generated": 0,
        "candidates_validated": 0,
        "candidates_scored": 0,
        "candidates_promoted": 0,
        "candidates_rejected": 0,
        "candidates_queued_for_review": 0,
        "pending_review_count": 0,
        "blocking": False,
        "timeout_waited_for_human": False,
        "top_candidates": [],
        "top_queued_candidates": [],
        "top_rejection_reasons": [],
        "artifact_paths": {},
        "errors": [],
    }


def default_golden_report() -> dict[str, Any]:
    return {
        "status": "not_generated",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": 0,
        "cases_evaluated": 0,
        "cases": [],
    }


def default_graph_quality_report() -> dict[str, Any]:
    return {
        "status": "not_generated",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "node_count": 0,
        "edge_count": 0,
        "orphan_node_count": 0,
        "weak_edge_count": 0,
        "missing_source_ref_count": 0,
        "broken_edge_count": 0,
        "routes_with_defense_path": 0,
        "routes_missing_defense_path": 0,
        "routes_missing_evidence": 0,
        "ai_promoted_edge_count": 0,
        "top_structural_gaps": [],
    }


def mirror_audit_log(src: Path, dst: Path) -> int:
    rows: list[Any] = []
    if src.exists():
        for line in src.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                rows.append({"status": "parse_error", "raw": line[:500]})
    write_json(dst, {"entries": rows, "count": len(rows), "source": rel(src)})
    return len(rows)


def mirror_promoted(src_dir: Path, dst_dir: Path) -> int:
    entries: list[dict[str, Any]] = []
    dst_dir.mkdir(parents=True, exist_ok=True)
    if src_dir.exists():
        for src in sorted(src_dir.glob("*.json")):
            dst = dst_dir / src.name
            shutil.copy2(src, dst)
            payload = read_json(src, {})
            entries.append({
                "file": src.name,
                "path": f"/data/mappings/ai_promoted/{src.name}",
                "run_id": payload.get("run_id") if isinstance(payload, dict) else None,
                "mappings": len(payload.get("mappings", [])) if isinstance(payload, dict) else 0,
                "generated_at": payload.get("generated_at") if isinstance(payload, dict) else None,
            })
    write_json(dst_dir / "index.json", {"entries": entries, "count": len(entries)})
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mirror Intelligence Factory artifacts into static UI public/data")
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--ui-public-data", type=Path, default=ROOT / "app" / "navigator-ui" / "public" / "data")
    args = parser.parse_args(argv)

    data = args.data_dir
    public = args.ui_public_data
    intelligence = public / "intelligence"
    reports = public / "reports"
    candidates = public / "candidates"
    mappings = public / "mappings" / "ai_promoted"
    graph = public / "graph"

    factory = read_json(data / "intelligence" / "intelligence-factory-report.json", default_factory_report())
    policy = read_json(data / "intelligence" / "promotion_policy.json", {"status": "not_generated", "promotion_mode": "not_available"})
    golden = read_json(data / "reports" / "golden-route-evaluation.json", default_golden_report())
    graph_quality = read_json(data / "graph" / "graph-quality-report.json", default_graph_quality_report())

    write_json(intelligence / "intelligence-factory-report.json", factory)
    write_json(intelligence / "promotion_policy.json", policy)
    write_json(reports / "golden-route-evaluation.json", golden)
    write_json(graph / "graph-quality-report.json", graph_quality)
    audit_count = mirror_audit_log(data / "candidates" / "audit_log.jsonl", candidates / "audit_log.json")
    promoted_count = mirror_promoted(data / "mappings" / "ai_promoted", mappings)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": rel(data),
        "target_root": rel(public),
        "artifacts": {
            "factory_report": "/data/intelligence/intelligence-factory-report.json",
            "promotion_policy": "/data/intelligence/promotion_policy.json",
            "golden_report": "/data/reports/golden-route-evaluation.json",
            "graph_quality_report": "/data/graph/graph-quality-report.json",
            "audit_log": "/data/candidates/audit_log.json",
            "promoted_mappings_index": "/data/mappings/ai_promoted/index.json",
        },
        "counts": {"audit_entries": audit_count, "promoted_mapping_files": promoted_count},
    }
    write_json(intelligence / "manifest.json", manifest)
    print(
        f"mirror-intelligence: target={rel(public)} audit_entries={audit_count} "
        f"promoted_files={promoted_count} graph_nodes={graph_quality.get('node_count', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
