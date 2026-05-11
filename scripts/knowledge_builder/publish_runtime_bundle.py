#!/usr/bin/env python3
"""Publish a compact static runtime bundle for the Navigator UI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from attack2defend.runtime_bundle import STREAM_THRESHOLD_BYTES, publish_runtime_bundle


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Strip builder-only fields from a knowledge bundle for browser runtime use.")
    parser.add_argument("--source", type=Path, default=ROOT / "data" / "knowledge-bundle.json")
    parser.add_argument("--output", type=Path, default=ROOT / "app" / "navigator-ui" / "public" / "data" / "knowledge-bundle.json")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the runtime bundle.")
    parser.add_argument("--stream-threshold-bytes", type=int, default=STREAM_THRESHOLD_BYTES)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = publish_runtime_bundle(
        args.source,
        args.output,
        pretty=args.pretty,
        stream_threshold_bytes=args.stream_threshold_bytes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
