#!/usr/bin/env python3
"""Export an official-RAG grounded curated route candidate.

This CLI is offline and bundle-first. It resolves a capability response from the
local bundle, builds an official context pack from deterministic graph evidence,
then emits a schema-shaped curated route candidate. It does not call public APIs,
does not call an LLM unless --llm is explicitly passed, and does not edit the
bundle. Even with --llm, validators always win.

Artifact output (--artifact-output):
  Writes a JSON file containing the route result plus diagnostic metadata:
    ai_status : llm_validated | fallback_deterministic | provider_failed | validation_failed
    generated_at : ISO-8601 timestamp
    provider / model : as reported by llm_adapter
    provider_errors : list of sanitized provider error dicts (no secrets)
  The artifact never contains API keys or secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
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
from attack2defend.intelligence.route_narrative import apply_route_narrative, build_route_narrative


def write_json(path: str | None, payload: dict, *, pretty: bool) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None)
    if path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _ai_status(route: dict) -> str:
    adapter = route.get("llm_adapter", {})
    if adapter.get("used"):
        return "llm_validated"
    reason = adapter.get("fallback_reason", "")
    if "provider_error" in reason:
        return "provider_failed"
    if reason == "validation_failed":
        return "validation_failed"
    return "fallback_deterministic"


def build_artifact(route: dict, *, input_id: str) -> dict:
    """Build a portable, secret-free artifact for auditing and CI gating."""
    adapter = route.get("llm_adapter", {})
    return {
        "artifact_type": "a2d_curated_route_artifact",
        "schema_version": "1.0",
        "input_id": input_id,
        "ai_status": _ai_status(route),
        "selection_method": route.get("selection_method", "deterministic"),
        "provider": adapter.get("provider", ""),
        "model": adapter.get("model", ""),
        "validation_status": route.get("validation", {}).get("status", "unknown"),
        "llm_used": adapter.get("used", False),
        "fallback_reason": adapter.get("fallback_reason", "") if not adapter.get("used") else "",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_ai_artifact(route: dict, *, input_id: str, capability: dict, context_pack: dict, config: AiCherryPickerConfig) -> dict:
    """Build AI-curated route artifact for UI consumption."""
    adapter = route.get("llm_adapter", {})
    narrative = build_route_narrative(capability, context_pack, route, config=config)
    polished_route = apply_route_narrative(route, narrative)
    return {
        "ai_status": _ai_status(route),
        "selection_method": route.get("selection_method", "deterministic"),
        "input": input_id,
        "normalized_input": capability.get("normalized_input", input_id),
        "input_type": capability.get("input_type", route.get("input_type", "")),
        "narrative_status": narrative.get("status", "deterministic_fallback"),
        "llm_adapter": {
            "used": adapter.get("used", False),
            "reason": adapter.get("fallback_reason", "") if not adapter.get("used") else "",
        },
        "provider": adapter.get("provider", ""),
        "model": adapter.get("model", ""),
        "validator_status": route.get("validation", {}).get("status", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "narrative": narrative,
        "curated_route": polished_route,
    }


def print_debug(route: dict, *, file=sys.stderr) -> None:
    adapter = route.get("llm_adapter", {})
    print("=== LLM provider diagnostics ===", file=file)
    print(f"  ai_status        : {_ai_status(route)}", file=file)
    print(f"  provider         : {adapter.get('provider', 'n/a')}", file=file)
    print(f"  model            : {adapter.get('model', 'n/a')}", file=file)
    print(f"  providers_tried  : {adapter.get('providers_attempted', [])}", file=file)
    print(f"  fallback_reason  : {adapter.get('fallback_reason', '')}", file=file)
    print(f"  llm_used         : {adapter.get('used', False)}", file=file)
    print(f"  validation       : {route.get('validation', {}).get('status', 'n/a')}", file=file)
    errors = adapter.get("provider_errors", [])
    if errors:
        print(f"  provider_errors  ({len(errors)}):", file=file)
        for err in errors:
            print(f"    [{err.get('error_type')}] {err.get('provider')}/{err.get('model')}", file=file)
            if err.get("http_status"):
                print(f"      http_status : {err['http_status']}", file=file)
            print(f"      message     : {err.get('message', '')}", file=file)
            print(f"      endpoint    : {err.get('endpoint_sanitized', '')}", file=file)
            if err.get("response_body_sanitized"):
                print(f"      body        : {err['response_body_sanitized']}", file=file)
    print("================================", file=file)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an official-RAG grounded curated route candidate.")
    parser.add_argument("--bundle", default="data/knowledge-bundle.json", help="Local knowledge bundle path.")
    parser.add_argument("--input", required=True, help="CVE, CWE, CAPEC, ATT&CK, D3FEND, or defense ID.")
    parser.add_argument("--output", help="Optional curated route output path.")
    parser.add_argument("--context-output", help="Optional official context pack output path.")
    parser.add_argument("--artifact-output", help="Write a portable AI artifact JSON to this path.")
    parser.add_argument("--ai-artifact-output", help="Write AI-curated route JSON for UI to this path.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--llm", action="store_true", help="Attempt validator-gated LLM mode. Falls back deterministically if no provider is configured.")
    parser.add_argument("--debug-provider", action="store_true", help="Print provider diagnostics to stderr.")
    parser.add_argument("--provider-order", help="Comma-separated provider order for auto mode, e.g. openai,gemini,anthropic.")
    parser.add_argument("--fail-on-provider-error", action="store_true", help="Exit with code 3 when LLM was requested but all providers failed (vs. falling back silently).")
    args = parser.parse_args()

    if args.provider_order:
        os.environ["A2D_PROVIDER_ORDER"] = args.provider_order

    capability = resolve_defense_route({"input": args.input}, bundle_path=args.bundle)
    context_pack = build_official_context_pack(capability)
    config = AiCherryPickerConfig.from_env()

    if args.llm:
        os.environ["A2D_CHERRY_PICKER_MODE"] = "llm"
        config = AiCherryPickerConfig.from_env()
        curated_route = cherry_pick_route(capability, context_pack, config=config)
    else:
        curated_route = build_curated_route(capability, context_pack)

    if args.debug_provider:
        print_debug(curated_route)

    if args.context_output:
        write_json(args.context_output, context_pack, pretty=args.pretty)

    write_json(args.output, curated_route, pretty=args.pretty)

    if args.artifact_output:
        artifact = build_artifact(curated_route, input_id=args.input)
        write_json(args.artifact_output, artifact, pretty=args.pretty)

    if args.ai_artifact_output:
        ai_artifact = build_ai_artifact(curated_route, input_id=args.input, capability=capability, context_pack=context_pack, config=config)
        write_json(args.ai_artifact_output, ai_artifact, pretty=args.pretty)

    # Exit code logic
    validation_ok = curated_route.get("validation", {}).get("status") == "pass"
    if not validation_ok:
        return 2

    if args.fail_on_provider_error and args.llm:
        status = _ai_status(curated_route)
        if status == "provider_failed":
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
