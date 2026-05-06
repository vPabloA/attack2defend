#!/usr/bin/env python3
"""Defense Intelligence Navigator — offline AI curation runner.

This script is the CLI entry point for the intelligence curation layer.
It is NEVER called by the main bundle build pipeline unless explicitly
invoked with --with-ai-curation or via `make curate`.

Static-first guarantee:
  - This script reads data/knowledge-bundle.json (immutable during run)
  - All LLM output goes to data/candidates/{run_id}/ as JSON files
  - Nothing in this script touches data/mappings/ or knowledge-bundle.json
  - Promotion is a separate, explicit step (promote_candidates.py)

Usage:
  # Full run (requires ANTHROPIC_API_KEY and pip install 'attack2defend[ai]')
  python scripts/intelligence/run_curator.py \\
      --bundle data/knowledge-bundle.json \\
      --cache-dir data/raw \\
      --output-dir data/candidates

  # Gap scan only — no LLM calls, no API key needed
  python scripts/intelligence/run_curator.py \\
      --bundle data/knowledge-bundle.json \\
      --cache-dir data/raw \\
      --output-dir data/candidates \\
      --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(
        description="Attack2Defend Defense Intelligence Curator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--bundle",
        type=Path,
        default=root / "data" / "knowledge-bundle.json",
        help="Path to knowledge-bundle.json (default: data/knowledge-bundle.json)",
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=root / "data" / "raw",
        help="Path to public source cache directory (default: data/raw)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=root / "data" / "candidates",
        help="Directory for candidate output files (default: data/candidates)",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=root / "data" / "intelligence" / "curator_config.yaml",
        help="Curator config file (YAML or JSON, optional)",
    )
    p.add_argument(
        "--model",
        default=None,
        help="Claude model ID override (default: from config or claude-sonnet-4-6)",
    )
    p.add_argument(
        "--max-gaps",
        type=int,
        default=None,
        help="Maximum gaps to scan per run (default: from config or 50)",
    )
    p.add_argument(
        "--gap-types",
        nargs="+",
        choices=[
            "missing_d3fend",
            "missing_capec",
            "missing_attack",
            "partial_coverage",
            "coverage_gap",
        ],
        default=None,
        help="Gap types to scan (default: all)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan gaps only — skip LLM calls, no API key required",
    )
    p.add_argument(
        "--run-id",
        default=None,
        help="Explicit run ID (default: auto-generated from timestamp)",
    )
    p.add_argument(
        "--json-report",
        action="store_true",
        help="Print final run report as JSON to stdout",
    )
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def _print_run_report(final_state: dict, elapsed: float, dry_run: bool) -> None:
    gaps = final_state.get("gaps", [])
    candidates = final_state.get("candidates", [])
    errors = final_state.get("errors", [])
    stats = final_state.get("stats", {})
    run_id = final_state.get("run_id", "unknown")
    output_dir = stats.get("output_dir", "")

    print()
    print("=" * 66)
    print("  Attack2Defend Defense Intelligence Navigator — Run Report")
    print("=" * 66)
    print(f"  Run ID   : {run_id}")
    print(f"  Mode     : {'DRY-RUN (gap scan only)' if dry_run else 'FULL (LLM curation)'}")
    print(f"  Duration : {elapsed:.1f}s")
    print(f"  Bundle   : {stats.get('bundle_nodes', 0)} nodes, {stats.get('bundle_edges', 0)} edges")
    print()

    # Gap summary
    gaps_by_type = stats.get("gaps_by_type", {})
    print(f"  Gaps found: {len(gaps)}")
    for gap_type, count in sorted(gaps_by_type.items()):
        print(f"    • {gap_type}: {count}")

    if not dry_run:
        print()
        mapping_cands = [c for c in candidates if c.get("candidate_type") == "mapping_edge"]
        backlog_cands = [c for c in candidates if c.get("candidate_type") == "backlog_item"]
        print(f"  Candidates generated: {len(candidates)}")
        print(f"    • mapping_edge:  {len(mapping_cands)}")
        print(f"    • backlog_item:  {len(backlog_cands)}")

        # Break down by status
        by_status: dict[str, int] = {}
        for c in candidates:
            s = c.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1
        for status, count in sorted(by_status.items()):
            print(f"    → {status}: {count}")

    if output_dir:
        print()
        print(f"  Output   : {output_dir}")
        print(f"  Next step: python scripts/intelligence/promote_candidates.py \\")
        print(f"               --candidates-dir {output_dir} \\")
        print(f"               --output-dir data/mappings/ai_promoted")

    if errors:
        print()
        print(f"  ERRORS ({len(errors)}):")
        for err in errors:
            print(f"    ✗ {err}")

    print("=" * 66)
    print()


def _print_gap_table(gaps: list[dict]) -> None:
    if not gaps:
        print("  (no gaps found)")
        return
    print(f"  {'TYPE':<20} {'SOURCE':<20} {'PRIORITY':<10} {'ROUTE STATUS'}")
    print(f"  {'-'*20} {'-'*20} {'-'*10} {'-'*15}")
    for g in gaps:
        print(
            f"  {g.get('gap_type', ''):<20} "
            f"{g.get('source_id', ''):<20} "
            f"{g.get('priority', ''):<10} "
            f"{g.get('route_status', '')}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # --- Load config --------------------------------------------------------
    try:
        from attack2defend.intelligence.config import CuratorConfig
    except ImportError as exc:
        print(f"ERROR: Cannot import intelligence layer: {exc}", file=sys.stderr)
        print(
            "Make sure the package is installed: pip install -e '.[ai]'",
            file=sys.stderr,
        )
        return 1

    cfg = CuratorConfig.from_file(args.config)

    # CLI overrides take precedence over config file
    model = args.model or cfg.model
    max_gaps = args.max_gaps or cfg.max_gaps_per_run
    gap_types = args.gap_types or cfg.gap_types
    dry_run = args.dry_run

    # --- Validate inputs ----------------------------------------------------
    if not args.bundle.exists():
        print(f"ERROR: bundle not found: {args.bundle}", file=sys.stderr)
        print("Run `make build-bundle` first to generate the knowledge bundle.", file=sys.stderr)
        return 1

    if not dry_run and not args.cache_dir.exists():
        print(
            f"WARNING: cache-dir not found: {args.cache_dir}. "
            "Evidence fetching will be limited.",
            file=sys.stderr,
        )

    # --- Build graph --------------------------------------------------------
    try:
        from attack2defend.intelligence.graph import build_curator_graph, make_initial_state
    except ImportError as exc:
        print(f"ERROR: LangGraph not available: {exc}", file=sys.stderr)
        print(
            "Install AI dependencies: pip install 'attack2defend[ai]'",
            file=sys.stderr,
        )
        return 1

    initial_state = make_initial_state(
        bundle_path=str(args.bundle),
        cache_dir=str(args.cache_dir),
        output_dir=str(args.output_dir),
        model=model,
        max_gaps=max_gaps,
        gap_types=list(gap_types),
        dry_run=dry_run,
        run_id=args.run_id,
    )

    print(
        f"\nAttack2Defend Defense Intelligence Navigator\n"
        f"  bundle   : {args.bundle}\n"
        f"  cache    : {args.cache_dir}\n"
        f"  output   : {args.output_dir}\n"
        f"  model    : {model}\n"
        f"  max_gaps : {max_gaps}\n"
        f"  dry_run  : {dry_run}\n"
        f"  run_id   : {initial_state['run_id']}\n"
    )

    # --- Run graph ----------------------------------------------------------
    try:
        graph = build_curator_graph()
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    start = time.monotonic()

    try:
        final_state = graph.invoke(initial_state)
    except Exception as exc:
        print(f"ERROR: curator graph failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    elapsed = time.monotonic() - start

    # --- Report -------------------------------------------------------------
    if args.json_report:
        report = {
            "run_id": final_state.get("run_id"),
            "elapsed_seconds": round(elapsed, 2),
            "dry_run": dry_run,
            "stats": final_state.get("stats", {}),
            "gaps_found": len(final_state.get("gaps", [])),
            "candidates_generated": len(final_state.get("candidates", [])),
            "errors": final_state.get("errors", []),
        }
        print(json.dumps(report, indent=2))
    else:
        # Print gap table in dry-run mode
        if dry_run and final_state.get("gaps"):
            print("\n  Detected gaps:")
            _print_gap_table(final_state.get("gaps", []))
        _print_run_report(final_state, elapsed, dry_run)

    return 1 if final_state.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
