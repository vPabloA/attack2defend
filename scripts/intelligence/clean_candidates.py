#!/usr/bin/env python3
"""Archive old candidate artifacts without deleting audit history."""

from __future__ import annotations

import argparse
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_args(argv=None):
    root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(description="Archive old Attack2Defend candidate files")
    p.add_argument("--candidates-dir", type=Path, default=root / "data" / "candidates")
    p.add_argument("--archive-dir", type=Path, default=root / "data" / "candidates" / "archive")
    p.add_argument("--days", type=int, default=int(os.getenv("A2D_CANDIDATE_ARCHIVE_DAYS", "30")))
    p.add_argument("--execute", action="store_true", help="Actually move files. Default is dry-run.")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    files = []
    if args.candidates_dir.exists():
        for path in args.candidates_dir.rglob("*.json"):
            if "archive" in path.parts or path.name.startswith("_") or path.name == "audit_log.jsonl":
                continue
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                files.append(path)
    print(f"clean-candidates: candidates_to_archive={len(files)} days={args.days} execute={args.execute}")
    if not args.execute:
        for path in files[:20]:
            print(f"  [DRY-RUN] {path}")
        return 0
    args.archive_dir.mkdir(parents=True, exist_ok=True)
    for path in files:
        rel = path.relative_to(args.candidates_dir)
        dest = args.archive_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dest))
        print(f"  archived {path} -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
