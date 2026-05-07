import json
import subprocess
import sys
from pathlib import Path

import jsonschema

from attack2defend.capability import resolve_defense_route
from attack2defend.intelligence import (
    CURATED_ROUTE_LIMITS,
    build_curated_route,
    build_official_context_pack,
    validate_curated_route,
)


BUNDLE = "data/knowledge-bundle.json"
CONTEXT_SCHEMA = Path("schemas/a2d_official_context_pack.schema.json")
CURATED_SCHEMA = Path("schemas/a2d_curated_route.schema.json")


def _schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_official_context_pack_validates_against_schema():
    capability = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    context_pack = build_official_context_pack(capability)

    jsonschema.validate(context_pack, _schema(CONTEXT_SCHEMA))
    assert context_pack["source_policy"]["runtime_public_api_calls"] is False
    assert context_pack["source_policy"]["llm_may_use_external_knowledge"] is False
    assert context_pack["source_policy"]["validator_wins"] is True


def test_curated_route_validates_against_schema_and_limits():
    capability = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    context_pack = build_official_context_pack(capability)
    curated_route = build_curated_route(capability, context_pack)

    jsonschema.validate(curated_route, _schema(CURATED_SCHEMA))
    assert curated_route["validation"]["status"] == "pass"
    for stage in curated_route["stages"]:
        assert len(stage["selected"]) <= CURATED_ROUTE_LIMITS[stage["type"]]
        for selected in stage["selected"]:
            assert selected["reason_es"]
            assert selected["id"] in {entry["id"] for entry in context_pack["entries"]}


def test_curated_route_validator_blocks_invented_ids():
    capability = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    context_pack = build_official_context_pack(capability)
    curated_route = build_curated_route(capability, context_pack)
    curated_route["stages"][0]["selected"] = [
        {
            "id": "CVE-2999-DOES-NOT-EXIST",
            "type": "cve",
            "name": "Invented CVE",
            "official_link": "",
            "source_ref": "missing_source_ref",
            "rank": 1,
            "score": 999,
            "reason_es": "Invented node should be rejected.",
        }
    ]

    errors = validate_curated_route(curated_route, context_pack)

    assert any("invented id" in error for error in errors)


def test_curate_route_cli_outputs_valid_json():
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/intelligence/curate_route.py",
            "--bundle",
            BUNDLE,
            "--input",
            "CVE-2024-37079",
            "--pretty",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    jsonschema.validate(payload, _schema(CURATED_SCHEMA))
    assert payload["mode"] == "official_rag_grounded"
    assert payload["runtime_public_api_calls"] is False
    assert payload["validation"]["status"] == "pass"
