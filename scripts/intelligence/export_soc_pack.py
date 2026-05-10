#!/usr/bin/env python3
"""Export a SOC-actionable Attack2Defend package for one input ID."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from attack2defend.automation.service import AutomationService


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export SOC-actionable Attack2Defend package")
    parser.add_argument("--input", required=True, help="CVE/CWE/CAPEC/ATT&CK/D3FEND/control/detection ID")
    parser.add_argument("--bundle", type=Path, default=Path("data/knowledge-bundle.json"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)

    service = AutomationService(bundle_path=args.bundle)
    payload = service.build_soc_action_pack(args.input)
    text = json.dumps(payload, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
