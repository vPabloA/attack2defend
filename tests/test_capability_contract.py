import json
import subprocess
import sys
from pathlib import Path

import jsonschema

from attack2defend.capability import resolve_defense_route


SCHEMA_PATH = Path("schemas/a2d_capability_response.schema.json")
EXAMPLE_PATH = Path("examples/mcp_security/resolve_defense_route.json")
BUNDLE = "data/knowledge-bundle.json"


def _schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_capability_output_validates_against_schema():
    result = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)

    jsonschema.validate(result, _schema())


def test_mcp_security_example_validates_against_schema():
    example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))

    jsonschema.validate(example, _schema())
    assert example["integration_context"]["mcp_security_ready"] is True
    assert example["executive_summary_es"]
    assert example["recommended_actions"][0]["description_es"]


def test_unresolved_output_validates_against_schema():
    result = resolve_defense_route({"input": "CVE-2099-0000"}, bundle_path=BUNDLE)

    jsonschema.validate(result, _schema())
    assert result["coverage_status"] == "unresolved"


def test_export_capability_pack_pretty_outputs_valid_json():
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/intelligence/export_capability_pack.py",
            "--bundle",
            BUNDLE,
            "--input",
            "T1190",
            "--pretty",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    jsonschema.validate(payload, _schema())
    assert payload["capability"] == "attack2defend.resolve_defense_route"
