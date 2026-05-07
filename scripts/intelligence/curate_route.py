#!/usr/bin/env python3
"""Export an official-RAG grounded curated route candidate.

This CLI is offline and bundle-first. It resolves a capability response from the
local bundle, builds an official context pack from deterministic graph evidence,
then emits a schema-shaped curated route candidate. It does not call public APIs,
does not call an LLM unless --llm is explicitly passed, and does not edit the
bundle. Even with --llm, validators always win.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from attack2defend.capability import resolve_defense_route
from attack2defend.intelligence import (
    AiCherryPickerConfig,
    build_curated_route,
    build_official_context_pack,
    cherry_pick_route,
)


def write_json(path: str | None, payload: dict, *, pretty: bool) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None)
    if path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an official-RAG grounded curated route candidate.")
    parser.add_argument("--bundle", default="data/knowledge-bundle.json", help="Local knowledge bundle path.")
    parser.add_argument("--input", required=True, help="CVE, CWE, CAPEC, ATT&CK, D3FEND, or defense ID.")
    parser.add_argument("--output", help="Optional curated route output path.")
    parser.add_argument("--context-output", help="Optional official context pack output path.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--llm", action="store_true", help="Attempt validator-gated LLM mode. Falls back deterministically if no provider client is configured.")
    args = parser.parse_args()

    capability = resolve_defense_route({"input": args.input}, bundle_path=args.bundle)
    context_pack = build_official_context_pack(capability)
    if args.llm:
        os.environ["A2D_CHERRY_PICKER_MODE"] = "llm"
        curated_route = cherry_pick_route(capability, context_pack, config=AiCherryPickerConfig.from_env())
    else:
        curated_route = build_curated_route(capability, context_pack)

    if args.context_output:
        write_json(args.context_output, context_pack, pretty=args.pretty)
    write_json(args.output, curated_route, pretty=args.pretty)

    return 0 if curated_route.get("validation", {}).get("status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
