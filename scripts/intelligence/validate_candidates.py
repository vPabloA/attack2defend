#!/usr/bin/env python3
"""Validate Intelligence Factory candidate artifacts.

The validator is deterministic and safe for CI/SOAR/MCP automation.
It does not call LLMs and never edits the canonical bundle.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

VALID_STATUSES = {
    "pending", "validated", "scored", "auto_promoted", "queued_for_review",
    "rejected_by_policy", "blocked", "dry_run", "failed", "needs_evidence", "deferred",
    "approved", "rejected",
}
VALID_CONFIDENCE = {"high", "medium", "low", "unknown"}
SECRET_PATTERNS = [
    re.compile(r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY", re.I),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{12,}", re.I),
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(description="Validate Attack2Defend candidate artifacts")
    p.add_argument("path", nargs="?", type=Path, default=root / "data" / "candidates")
    p.add_argument("--json-report", action="store_true")
    return p.parse_args(argv)


def validate_candidate(candidate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("candidate_id", "run_id", "candidate_type", "model", "generated_at"):
        if not str(candidate.get(field) or "").strip():
            errors.append(f"missing_{field}")

    status = str(candidate.get("status") or "pending")
    if status not in VALID_STATUSES:
        errors.append(f"invalid_status:{status}")

    if _contains_secret(candidate):
        errors.append("secret_detected")

    edge = candidate.get("proposed_edge")
    if candidate.get("candidate_type") == "mapping_edge":
        if not isinstance(edge, dict):
            errors.append("missing_proposed_edge")
        else:
            for field in ("source", "target", "relationship"):
                if not str(edge.get(field) or "").strip():
                    errors.append(f"missing_edge_{field}")
            confidence = str(edge.get("confidence") or candidate.get("confidence") or "unknown").lower()
            if confidence not in VALID_CONFIDENCE:
                errors.append(f"invalid_confidence:{confidence}")
            if not any(str(edge.get(k) or "").strip() for k in ("source_ref", "source_url", "evidence_url")):
                errors.append("missing_edge_source_ref_or_url")

    evidence = candidate.get("evidence") or []
    if candidate.get("candidate_type") == "mapping_edge" and not evidence:
        errors.append("missing_evidence")
    if evidence and not isinstance(evidence, list):
        errors.append("evidence_not_list")
    for idx, item in enumerate(evidence if isinstance(evidence, list) else []):
        if not isinstance(item, dict):
            errors.append(f"evidence_{idx}_not_object")
            continue
        if not any(str(item.get(k) or "").strip() for k in ("source_ref", "source_url", "url", "evidence_url")):
            errors.append(f"evidence_{idx}_missing_source_ref_or_url")

    if candidate.get("deterministic") is True:
        errors.append("ai_candidate_must_not_be_deterministic_true")
    if candidate.get("inferred") is False and candidate.get("candidate_type") == "mapping_edge":
        # Old candidates may omit inferred. Only reject explicit false on AI mapping candidates.
        errors.append("ai_mapping_candidate_must_be_inferred_true")

    return errors


def _contains_secret(obj: Any) -> bool:
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return any(p.search(text) for p in SECRET_PATTERNS)


def iter_candidate_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.exists():
        return []
    return [p for p in sorted(path.rglob("*.json")) if not p.name.startswith("_")]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    results: list[dict[str, Any]] = []
    for path in iter_candidate_files(args.path):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            results.append({"path": str(path), "ok": False, "errors": [f"json_parse_error:{exc}"]})
            continue
        if "candidate_id" not in data:
            continue
        errors = validate_candidate(data)
        results.append({"path": str(path), "candidate_id": data.get("candidate_id"), "ok": not errors, "errors": errors})

    ok = all(r["ok"] for r in results)
    report = {"ok": ok, "candidates_checked": len(results), "results": results}
    if args.json_report:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"validate-candidates: {'OK' if ok else 'FAIL'} checked={len(results)}")
        for r in results:
            if not r["ok"]:
                print(f"  {r['path']}: {', '.join(r['errors'])}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
