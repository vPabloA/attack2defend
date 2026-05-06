#!/usr/bin/env python3
"""Export an Attack2Defend capability response as JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from attack2defend.capability import resolve_defense_route


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Attack2Defend capability JSON.")
    parser.add_argument("--bundle", default="data/knowledge-bundle.json", help="Local knowledge bundle path.")
    parser.add_argument("--input", required=True, help="CVE, CWE, CAPEC, ATT&CK, D3FEND, or defense ID.")
    parser.add_argument("--output", help="Optional output file path.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    args = parser.parse_args()

    response = resolve_defense_route({"input": args.input}, bundle_path=args.bundle)
    indent = 2 if args.pretty else None
    payload = json.dumps(response, ensure_ascii=False, indent=indent)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
