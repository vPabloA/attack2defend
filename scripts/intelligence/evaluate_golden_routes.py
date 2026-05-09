#!/usr/bin/env python3
"""Evaluate golden route coverage against the local knowledge bundle."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(description="Evaluate Attack2Defend golden routes")
    p.add_argument("--golden", type=Path, default=root / "tests" / "golden" / "golden_cases.json")
    p.add_argument("--bundle", type=Path, default=root / "data" / "knowledge-bundle.json")
    p.add_argument("--out-json", type=Path, default=root / "data" / "reports" / "golden-route-evaluation.json")
    p.add_argument("--out-md", type=Path, default=root / "data" / "reports" / "golden-route-evaluation.md")
    p.add_argument("--strict", action="store_true")
    return p.parse_args(argv)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def case_expected_ids(case: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for key, value in case.items():
        if key.startswith("expected") or key in {"input", "id", "cve", "cwe", "capec", "attack", "d3fend"}:
            _collect_ids(value, ids)
    return ids


def _collect_ids(value: Any, ids: set[str]) -> None:
    if isinstance(value, str):
        if value.strip():
            ids.add(value.strip())
    elif isinstance(value, list):
        for item in value:
            _collect_ids(item, ids)
    elif isinstance(value, dict):
        for item in value.values():
            _collect_ids(item, ids)


def evaluate_case(case: dict[str, Any], node_ids: set[str], edge_pairs: set[tuple[str, str]]) -> dict[str, Any]:
    expected = case_expected_ids(case)
    present = sorted(i for i in expected if i in node_ids)
    missing = sorted(i for i in expected if i not in node_ids)
    possible_links = []
    for source in expected:
        for target in expected:
            if source != target and (source, target) in edge_pairs:
                possible_links.append({"source": source, "target": target})
    node_score = 1.0 if not expected else round(len(present) / len(expected), 3)
    link_bonus = 0.1 if possible_links else 0.0
    score = min(1.0, round(node_score + link_bonus, 3))
    return {
        "case_id": case.get("case_id") or case.get("id") or case.get("input") or "unknown",
        "input": case.get("input") or case.get("cve") or case.get("id") or "",
        "expected_ids": sorted(expected),
        "present_expected_ids": present,
        "missing_expected_ids": missing,
        "observed_expected_links": possible_links,
        "missing_expected_links": [],
        "unexpected_gaps": missing,
        "score": score,
        "status": "pass" if not missing else "partial",
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Golden Route Evaluation",
        "",
        f"Generated: {report['generated_at']}",
        f"Overall score: **{report['overall_score']}**",
        "",
        "| Case | Status | Score | Missing IDs |",
        "|---|---:|---:|---|",
    ]
    for case in report["cases"]:
        lines.append(
            f"| `{case['case_id']}` | {case['status']} | {case['score']} | {', '.join(case['missing_expected_ids']) or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.golden.exists():
        print(f"golden file not found: {args.golden}", file=sys.stderr)
        return 1
    if not args.bundle.exists():
        print(f"bundle file not found: {args.bundle}", file=sys.stderr)
        return 1

    golden = load_json(args.golden)
    bundle = load_json(args.bundle)
    cases = golden.get("cases", golden if isinstance(golden, list) else [])
    node_ids = {str(n.get("id")) for n in bundle.get("nodes", []) if isinstance(n, dict) and n.get("id")}
    edge_pairs = {
        (str(e.get("source")), str(e.get("target")))
        for e in bundle.get("edges", [])
        if isinstance(e, dict) and e.get("source") and e.get("target")
    }
    results = [evaluate_case(c, node_ids, edge_pairs) for c in cases]
    overall = round(sum(c["score"] for c in results) / len(results), 3) if results else 0.0
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bundle": args.bundle.as_posix(),
        "golden": args.golden.as_posix(),
        "overall_score": overall,
        "cases_evaluated": len(results),
        "cases": results,
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    args.out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"evaluate-golden: score={overall} cases={len(results)} report={args.out_json}")
    if args.strict and any(c["status"] != "pass" for c in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
