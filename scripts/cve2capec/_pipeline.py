"""Shared helper for the CVE2CAPEC-style pipeline scripts."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPORTER_DIR = REPO_ROOT / "scripts" / "canonical_exports"

if str(EXPORTER_DIR) not in sys.path:
    sys.path.insert(0, str(EXPORTER_DIR))

from build_canonical import build_canonical, parse_args  # noqa: E402  (import after path setup)


def run_pipeline_step(step: str, argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])
    ui_nsfw_dir = None if args.no_ui_mirror else args.ui_nsfw_dir
    ui_cve2capec_dir = None if args.no_ui_mirror else args.ui_cve2capec_dir
    try:
        summary = build_canonical(
            bundle_path=args.bundle,
            nsfw_dir=args.nsfw_dir,
            cve2capec_dir=args.cve2capec_dir,
            ui_nsfw_dir=ui_nsfw_dir,
            ui_cve2capec_dir=ui_cve2capec_dir,
            summary_path=args.summary_path,
        )
    except Exception as exc:  # noqa: BLE001 - top-level CLI error reporter
        print(f"ERROR: cve2capec step {step} failed: {exc}", file=sys.stderr)
        return 1
    counts = summary.get("counts", {})
    print(f"cve2capec[{step}] exported: counts={counts}")
    return 0
