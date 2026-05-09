#!/usr/bin/env python3
"""Policy-driven, non-blocking candidate promotion.

Designed for CLI, CI, SOAR, MCP and future API use.

Invariants:
- no input()
- no human wait
- no polling
- no direct writes to data/knowledge-bundle.json
- policy decides auto_promoted | queued_for_review | rejected_by_policy | blocked | dry_run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECRET_PATTERNS = [
    re.compile(r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY", re.I),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{12,}", re.I),
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(description="Policy-driven Attack2Defend candidate promotion")
    p.add_argument("--candidates-dir", type=Path, default=root / "data" / "candidates")
    p.add_argument("--output-dir", type=Path, default=root / "data" / "mappings" / "ai_promoted")
    p.add_argument("--policy", type=Path, default=root / "data" / "intelligence" / "promotion_policy.json")
    p.add_argument("--report", type=Path, default=root / "data" / "intelligence" / "intelligence-factory-report.json")
    p.add_argument("--audit-log", type=Path, default=root / "data" / "candidates" / "audit_log.jsonl")
    p.add_argument("--bundle", type=Path, default=root / "data" / "knowledge-bundle.json")
    p.add_argument("--last-good", type=Path, default=root / "data" / "knowledge-bundle.last-good.json")
    p.add_argument("--run-id", default=None)
    p.add_argument("--promotion-mode", choices=["dry_run", "policy_auto", "review_queue", "emergency_block"], default=None)
    p.add_argument("--json-report", action="store_true")
    return p.parse_args(argv)


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_bundle_node_ids(bundle_path: Path) -> set[str]:
    if not bundle_path.exists():
        return set()
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    ids: set[str] = set()
    for node in bundle.get("nodes", []):
        if isinstance(node, dict):
            node_id = str(node.get("id") or "").strip()
            if node_id:
                ids.add(node_id)
    return ids


def iter_candidate_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.exists():
        return []
    return [p for p in sorted(path.rglob("*.json")) if not p.name.startswith("_")]


def contains_secret(obj: Any) -> bool:
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def normalize_evidence_ref(candidate: dict[str, Any]) -> str:
    edge = candidate.get("proposed_edge") or {}
    if isinstance(edge, dict):
        for key in ("source_ref", "source_url", "evidence_url"):
            value = str(edge.get(key) or "").strip()
            if value:
                return value
    for ev in candidate.get("evidence") or []:
        if isinstance(ev, dict):
            for key in ("source_ref", "source_url", "url", "evidence_url"):
                value = str(ev.get(key) or "").strip()
                if value:
                    return value
    return ""


def build_mapping_record(candidate: dict[str, Any], candidate_path: Path) -> dict[str, Any]:
    edge = candidate["proposed_edge"]
    now = datetime.now(timezone.utc).isoformat()
    source_ref = str(candidate_path.as_posix())
    return {
        "source": edge["source"],
        "target": edge["target"],
        "relationship": edge["relationship"],
        "confidence": edge.get("confidence", candidate.get("confidence", "medium")),
        "source_feed": "ai_promoted",
        "source_ref": source_ref,
        "source_url": normalize_evidence_ref(candidate),
        "source_kind": "ai_promoted",
        "retrieved_at": now,
        "transform_version": "intelligence_factory:0.1.0",
        "deterministic": False,
        "inferred": True,
        "candidate_id": candidate.get("candidate_id"),
        "run_id": candidate.get("run_id"),
        "model": candidate.get("model"),
        "provider": candidate.get("provider", candidate.get("llm_provider", "unknown")),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def append_audit(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        from attack2defend.intelligence.promotion_policy import PromotionPolicy, evaluate_candidate_policy
        from attack2defend.intelligence.scoring import score_candidate
        from scripts.intelligence.validate_candidates import validate_candidate  # type: ignore
    except Exception:
        # Running as script: import validator from sibling path without package assumptions.
        from attack2defend.intelligence.promotion_policy import PromotionPolicy, evaluate_candidate_policy
        from attack2defend.intelligence.scoring import score_candidate
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from validate_candidates import validate_candidate  # type: ignore

    policy = PromotionPolicy.from_file(args.policy)
    if args.promotion_mode:
        policy = PromotionPolicy(**{**policy.to_dict(), "promotion_mode": args.promotion_mode})
    if os.getenv("A2D_PROMOTION_MODE"):
        policy = PromotionPolicy(**{**policy.to_dict(), "promotion_mode": os.getenv("A2D_PROMOTION_MODE")})

    run_id = args.run_id or datetime.now(timezone.utc).strftime("run-%Y%m%d-%H%M%S")
    known_node_ids = load_bundle_node_ids(args.bundle)
    pre_hash = sha256_file(args.bundle)
    last_good_hash = sha256_file(args.last_good)

    candidates: list[tuple[Path, dict[str, Any]]] = []
    for path in iter_candidate_files(args.candidates_dir):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if "candidate_id" in data:
            candidates.append((path, data))

    promoted_records: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    for idx, (path, raw_candidate) in enumerate(candidates[: policy.max_candidates_per_run], 1):
        candidate = score_candidate(raw_candidate)
        validation_errors = validate_candidate(candidate)
        secret_detected = contains_secret(candidate)
        if validation_errors:
            decision = {
                "decision": "queued_for_review",
                "policy_version": policy.policy_version,
                "policy_reason": validation_errors,
                "blocking": False,
                "timeout_waited_for_human": False,
                "promotion_mode": policy.promotion_mode,
            }
        else:
            decision = evaluate_candidate_policy(
                candidate,
                policy,
                known_node_ids=known_node_ids or None,
                secret_detected=secret_detected,
            )

        mapping_path = None
        if decision["decision"] == "auto_promoted":
            mapping = build_mapping_record(candidate, path)
            promoted_records.append(mapping)
            mapping_path = args.output_dir / f"{run_id}.json"

        audit_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "candidate_id": candidate.get("candidate_id"),
            "decision": decision["decision"],
            "policy_version": decision.get("policy_version"),
            "policy_reason": decision.get("policy_reason", []),
            "score": candidate.get("score", {}),
            "operator_mode": "policy_engine",
            "automation_context": "cli_soar_mcp_api_safe",
            "source_candidate_path": path.as_posix(),
            "output_mapping_path": mapping_path.as_posix() if mapping_path else "",
            "pre_bundle_hash": pre_hash,
            "last_good_hash": last_good_hash,
            "post_bundle_hash": None,
            "dry_run": policy.promotion_mode == "dry_run",
            "promotion_mode": policy.promotion_mode,
            "blocking": False,
        }
        append_audit(args.audit_log, audit_record)
        decisions.append({**audit_record, "validation_errors": validation_errors})

    output_mapping = None
    if promoted_records:
        payload = {
            "version": "1.0",
            "source": "attack2defend-intelligence-factory",
            "source_feed": "ai_promoted",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "policy_version": policy.policy_version,
            "mappings": promoted_records,
        }
        output_mapping = args.output_dir / f"{run_id}.json"
        write_json(output_mapping, payload)

    post_hash = sha256_file(args.bundle)
    if pre_hash != post_hash:
        blocked = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "candidate_id": "__bundle_guard__",
            "decision": "blocked",
            "policy_version": policy.policy_version,
            "policy_reason": ["bundle_mutation_detected"],
            "pre_bundle_hash": pre_hash,
            "post_bundle_hash": post_hash,
            "promotion_mode": policy.promotion_mode,
            "blocking": False,
        }
        append_audit(args.audit_log, blocked)
        print(json.dumps({"status": "failed", "error": "bundle_mutation_detected"}, indent=2))
        return 1

    counts = {name: sum(1 for d in decisions if d["decision"] == name) for name in [
        "auto_promoted", "queued_for_review", "rejected_by_policy", "blocked", "dry_run"
    ]}
    report = {
        "status": "completed",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "promotion_mode": policy.promotion_mode,
        "policy_summary": policy.to_dict(),
        "candidates_seen": len(candidates),
        "candidates_generated": len(candidates),
        "candidates_validated": sum(1 for d in decisions if not d.get("validation_errors")),
        "candidates_scored": len(decisions),
        "candidates_promoted": counts["auto_promoted"],
        "candidates_rejected": counts["rejected_by_policy"],
        "candidates_queued_for_review": counts["queued_for_review"],
        "needs_evidence_count": sum(1 for d in decisions if "missing_evidence" in d.get("policy_reason", [])),
        "deferred_count": 0,
        "pending_review_count": counts["queued_for_review"],
        "blocking": False,
        "timeout_waited_for_human": False,
        "top_candidates": decisions[:10],
        "top_queued_candidates": [d for d in decisions if d["decision"] == "queued_for_review"][:10],
        "top_rejection_reasons": _top_reasons(decisions),
        "artifact_paths": {
            "report": args.report.as_posix(),
            "promoted_mapping": output_mapping.as_posix() if output_mapping else "",
            "audit_log": args.audit_log.as_posix(),
        },
        "deferred_taxonomy_signals": ["ai_defense", "ui_navigation"],
        "errors": [],
    }
    write_json(args.report, report)

    if args.json_report:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"promotion: completed mode={policy.promotion_mode} seen={len(candidates)} promoted={counts['auto_promoted']} queued={counts['queued_for_review']} rejected={counts['rejected_by_policy']}")
        print(f"report: {args.report}")
    return 0


def _top_reasons(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for decision in decisions:
        for reason in decision.get("policy_reason", []):
            counts[str(reason)] = counts.get(str(reason), 0) + 1
    return [{"reason": reason, "count": count} for reason, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]]


if __name__ == "__main__":
    raise SystemExit(main())
