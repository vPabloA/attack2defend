#!/usr/bin/env python3
"""Promote reviewed AI candidates to the mapping backbone.

Workflow:
  1. Reads all pending/approved candidates from data/candidates/
  2. Shows each promotable candidate for human review
  3. On explicit approval, writes a backbone-compatible mapping file
     to data/mappings/ai_promoted/{candidate_id}.json
  4. Marks the candidate as promoted in its source file

The mapping files written here are automatically picked up by
`apply_mapping_backbone.py` on the next `make build-backbone` run.

Invariants:
  - A candidate with no source_ref is NEVER promoted (no source = no edge)
  - A candidate with no evidence is NEVER promoted (no evidence = no promotion)
  - Promotion is always explicit: --auto flag must be used consciously
  - Every promoted file is fully auditable (candidate_id, run_id, model, evidence)

Usage:
  # Interactive review (default)
  python scripts/intelligence/promote_candidates.py \\
      --candidates-dir data/candidates \\
      --output-dir data/mappings/ai_promoted

  # List candidates without promoting
  python scripts/intelligence/promote_candidates.py \\
      --candidates-dir data/candidates \\
      --list-only

  # Auto-promote all currently approved candidates (CI-safe)
  python scripts/intelligence/promote_candidates.py \\
      --candidates-dir data/candidates \\
      --output-dir data/mappings/ai_promoted \\
      --auto-approve-status approved
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(
        description="Promote AI candidates to the Attack2Defend mapping backbone",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--candidates-dir",
        type=Path,
        default=root / "data" / "candidates",
        help="Directory containing candidate JSON files (default: data/candidates)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=root / "data" / "mappings" / "ai_promoted",
        help="Output directory for promoted mapping files (default: data/mappings/ai_promoted)",
    )
    p.add_argument(
        "--list-only",
        action="store_true",
        help="List candidates without interactive review or promotion",
    )
    p.add_argument(
        "--status-filter",
        choices=["pending", "approved", "rejected", "needs_evidence", "all"],
        default="pending",
        help="Which candidate status to show/process (default: pending)",
    )
    p.add_argument(
        "--auto-approve-status",
        choices=["approved"],
        default=None,
        help="Auto-promote candidates with this status (no interactive prompt)",
    )
    p.add_argument(
        "--promoted-by",
        default="operator",
        help="Identifier for the promoter (recorded in mapping metadata)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be promoted without writing files",
    )
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Mapping file writer
# ---------------------------------------------------------------------------

def _write_promoted_mapping(
    candidate_dict: dict,
    output_dir: Path,
    promoted_by: str,
    dry_run: bool,
) -> Path | None:
    """Write a backbone-compatible mapping JSON for an approved candidate.

    Returns the path written, or None on failure / dry-run.
    """
    from attack2defend.intelligence.candidates import CandidateProposal

    candidate = CandidateProposal.from_dict(candidate_dict)
    errors = candidate.promotion_errors()
    if errors:
        print(f"  ✗ Cannot promote {candidate.candidate_id}: {'; '.join(errors)}")
        return None

    assert candidate.proposed_edge is not None  # guaranteed by promotion_errors check
    now = datetime.now(timezone.utc).isoformat()

    mapping_payload = {
        "version": "1.0",
        "description": (
            f"AI-promoted mapping — reviewed and approved by {promoted_by}. "
            f"Source candidate: {candidate.candidate_id}"
        ),
        "source": "attack2defend-intelligence-curator",
        "license": "attack2defend-ai-promoted",
        "generated_at": now,
        "promoted_by": promoted_by,
        "promoted_at": now,
        "candidate_id": candidate.candidate_id,
        "run_id": candidate.run_id,
        "model": candidate.model,
        "gap_explanation": candidate.gap_explanation,
        "justification": candidate.justification,
        "evidence": [e.to_dict() for e in candidate.evidence],
        "mappings": [candidate.proposed_edge.to_mapping_record()],
    }

    if dry_run:
        print(f"  [DRY-RUN] would write: {output_dir / candidate.candidate_id}.json")
        print(f"    edge: {candidate.proposed_edge.source} → {candidate.proposed_edge.target}")
        print(f"    rel:  {candidate.proposed_edge.relationship}")
        print(f"    conf: {candidate.proposed_edge.confidence}")
        print(f"    ref:  {candidate.proposed_edge.source_ref}")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{candidate.candidate_id}.json"
    out_path.write_text(
        json.dumps(mapping_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


def _mark_candidate_promoted(
    candidate_path: Path,
    candidate_dict: dict,
    promoted_by: str,
    promotion_notes: str = "",
) -> None:
    """Update the candidate file to reflect promotion."""
    now = datetime.now(timezone.utc).isoformat()
    candidate_dict["status"] = "approved"
    candidate_dict["promoted_by"] = promoted_by
    candidate_dict["promoted_at"] = now
    if promotion_notes:
        candidate_dict["promotion_notes"] = promotion_notes
    candidate_path.write_text(
        json.dumps(candidate_dict, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _mark_candidate_rejected(
    candidate_path: Path,
    candidate_dict: dict,
    reason: str = "",
) -> None:
    candidate_dict["status"] = "rejected"
    if reason:
        candidate_dict["promotion_notes"] = reason
    candidate_path.write_text(
        json.dumps(candidate_dict, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_candidate_summary(c: dict, index: int, total: int) -> None:
    cid = c.get("candidate_id", "?")
    ctype = c.get("candidate_type", "?")
    status = c.get("status", "?")
    input_id = c.get("input_id", "?")
    model = c.get("model", "?")
    generated_at = c.get("generated_at", "?")[:19]

    print(f"\n{'─'*66}")
    print(f"  Candidate {index}/{total}: {cid}")
    print(f"  Type    : {ctype}  |  Status : {status}")
    print(f"  Input   : {input_id}  |  Model  : {model}")
    print(f"  Created : {generated_at}")
    print()

    edge = c.get("proposed_edge")
    if edge:
        print(f"  Proposed edge:")
        print(f"    {edge.get('source','?')} ──[{edge.get('relationship','?')}]──▶ {edge.get('target','?')}")
        print(f"    confidence : {edge.get('confidence','?')}")
        print(f"    source_ref : {edge.get('source_ref','(MISSING)')}")
        print()

    evidence = c.get("evidence", [])
    if evidence:
        print(f"  Evidence ({len(evidence)} item(s)):")
        for ev in evidence[:3]:
            print(f"    • {ev.get('url', 'no-url')}")
            excerpt = ev.get("excerpt", "")
            if excerpt:
                print(f"      \"{excerpt[:120]}{'…' if len(excerpt)>120 else ''}\"")

    gap_expl = c.get("gap_explanation", "")
    if gap_expl:
        print(f"\n  Gap:  {gap_expl[:200]}")
    justif = c.get("justification", "")
    if justif:
        print(f"  Why:  {justif[:200]}")

    backlog = c.get("backlog_items", [])
    if backlog:
        print(f"\n  Backlog items ({len(backlog)}):")
        for item in backlog[:2]:
            print(f"    [{item.get('priority','?').upper()}][{item.get('owner','?')}] {item.get('title','')}")

    # Show promotion errors if any
    from attack2defend.intelligence.candidates import CandidateProposal
    try:
        obj = CandidateProposal.from_dict(c)
        errors = obj.promotion_errors()
        if errors:
            print(f"\n  ⚠ Promotion blockers: {'; '.join(errors)}")
    except Exception:
        pass


def _list_candidates(candidates: list[tuple[Path, dict]]) -> None:
    print(f"\n{'═'*66}")
    print(f"  Candidates  ({len(candidates)} total)")
    print(f"{'─'*66}")
    print(f"  {'ID':<30} {'TYPE':<16} {'STATUS':<16} {'INPUT'}")
    print(f"  {'-'*30} {'-'*16} {'-'*16} {'-'*15}")
    for _, c in candidates:
        print(
            f"  {c.get('candidate_id','?'):<30} "
            f"{c.get('candidate_type','?'):<16} "
            f"{c.get('status','?'):<16} "
            f"{c.get('input_id','?')}"
        )
    print(f"{'═'*66}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # --- Load intelligence package ------------------------------------------
    try:
        from attack2defend.intelligence.candidates import (
            CandidateProposal,
            CandidateStatus,
            load_candidates_from_dir,
        )
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Install with: pip install -e '.'", file=sys.stderr)
        return 1

    # --- Load candidates from disk ------------------------------------------
    if not args.candidates_dir.exists():
        print(f"No candidates directory found: {args.candidates_dir}")
        print("Run `make curate` first to generate candidates.")
        return 0

    # Load with file paths for in-place updates
    all_pairs: list[tuple[Path, dict]] = []
    for f in sorted(args.candidates_dir.rglob("*.json")):
        if f.name.startswith("_"):
            continue  # skip manifests
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if "candidate_id" in data:
                all_pairs.append((f, data))
        except Exception:
            pass

    if not all_pairs:
        print("No candidate files found in", args.candidates_dir)
        return 0

    # --- Filter by status ---------------------------------------------------
    if args.status_filter == "all":
        pairs = all_pairs
    else:
        pairs = [(p, c) for p, c in all_pairs if c.get("status") == args.status_filter]

    # Only promote mapping_edge candidates (backlog items don't need promotion)
    promotable_pairs = [
        (p, c) for p, c in pairs
        if c.get("candidate_type") == "mapping_edge"
    ]

    print(f"\nAttack2Defend — Candidate Promotion Tool")
    print(f"  candidates dir : {args.candidates_dir}")
    print(f"  output dir     : {args.output_dir}")
    print(f"  total loaded   : {len(all_pairs)}")
    print(f"  status filter  : {args.status_filter}")
    print(f"  promotable     : {len(promotable_pairs)}")

    if args.list_only:
        _list_candidates(promotable_pairs)
        return 0

    if not promotable_pairs:
        print(f"\nNo '{args.status_filter}' mapping_edge candidates to process.")
        print("Use --status-filter all to see all candidates.")
        return 0

    # --- Auto-approve mode --------------------------------------------------
    if args.auto_approve_status:
        auto_pairs = [
            (p, c) for p, c in promotable_pairs
            if c.get("status") == args.auto_approve_status
        ]
        promoted = 0
        skipped = 0
        for path, candidate in auto_pairs:
            out = _write_promoted_mapping(candidate, args.output_dir, args.promoted_by, args.dry_run)
            if out or args.dry_run:
                if not args.dry_run:
                    _mark_candidate_promoted(path, candidate, args.promoted_by)
                    print(f"  ✓ Promoted: {candidate.get('candidate_id')} → {out}")
                promoted += 1
            else:
                skipped += 1
        print(f"\nAuto-promotion complete: {promoted} promoted, {skipped} skipped.")
        return 0

    # --- Interactive review mode --------------------------------------------
    print(f"\nInteractive review — {len(promotable_pairs)} candidate(s)\n")
    print("  Commands:  [a]pprove  [r]eject  [s]kip  [q]uit")

    promoted_count = 0
    rejected_count = 0
    skipped_count = 0

    for i, (path, candidate) in enumerate(promotable_pairs, 1):
        _print_candidate_summary(candidate, i, len(promotable_pairs))

        # Check if promotable
        try:
            obj = CandidateProposal.from_dict(candidate)
            blocking = obj.promotion_errors()
        except Exception as exc:
            print(f"  ✗ Cannot parse candidate: {exc}")
            skipped_count += 1
            continue

        if blocking:
            print(f"\n  This candidate cannot be promoted: {'; '.join(blocking)}")
            print("  [s]kip  [r]eject  [q]uit  > ", end="", flush=True)
            prompt_choices = {"s", "r", "q"}
        else:
            print("\n  [a]pprove  [r]eject  [s]kip  [q]uit  > ", end="", flush=True)
            prompt_choices = {"a", "r", "s", "q"}

        try:
            choice = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nInterrupted.")
            break

        if choice not in prompt_choices:
            choice = "s"

        if choice == "q":
            print("Exiting review.")
            break
        elif choice == "a" and "a" in prompt_choices:
            print("  Notes (optional, press Enter to skip): ", end="", flush=True)
            try:
                notes = input().strip()
            except (EOFError, KeyboardInterrupt):
                notes = ""
            out = _write_promoted_mapping(candidate, args.output_dir, args.promoted_by, args.dry_run)
            if out:
                _mark_candidate_promoted(path, candidate, args.promoted_by, notes)
                print(f"  ✓ Promoted to: {out}")
                promoted_count += 1
            elif args.dry_run:
                promoted_count += 1
            else:
                print(f"  ✗ Promotion failed — check errors above.")
                skipped_count += 1
        elif choice == "r":
            print("  Reason (optional): ", end="", flush=True)
            try:
                reason = input().strip()
            except (EOFError, KeyboardInterrupt):
                reason = ""
            if not args.dry_run:
                _mark_candidate_rejected(path, candidate, reason)
            print(f"  ✗ Rejected: {candidate.get('candidate_id')}")
            rejected_count += 1
        else:
            print(f"  → Skipped")
            skipped_count += 1

    print(f"\n{'─'*66}")
    print(f"  Review complete:")
    print(f"    ✓ Promoted : {promoted_count}")
    print(f"    ✗ Rejected : {rejected_count}")
    print(f"    → Skipped  : {skipped_count}")
    if promoted_count and not args.dry_run:
        print(f"\n  Next step: run `make build-backbone` to merge promoted mappings.")
    print(f"{'─'*66}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
