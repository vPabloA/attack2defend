import json
from pathlib import Path
from typing import Any

import jsonschema

from attack2defend.capability import resolve_defense_route


BUNDLE = "data/knowledge-bundle.json"
SCHEMA_PATH = Path("schemas/a2d_capability_response.schema.json")
EXAMPLE_PATH = Path("examples/mcp_security/resolve_defense_route.json")
ABSOLUTE_PATH_MARKERS = (
    "/home/",
    "/Users/",
    "/private/",
    "/var/folders/",
    "C:\\",
    "D:\\",
    "\\Users\\",
)


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    if isinstance(value, str):
        return [value]
    return []


def _assert_no_absolute_paths(payload: Any) -> None:
    leaked = [
        text
        for text in _strings(payload)
        if any(marker in text for marker in ABSOLUTE_PATH_MARKERS)
    ]
    assert leaked == []


def _metadata_source_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if isinstance(metadata, dict):
            for key in ("source_ref", "mapping_file", "source"):
                item = metadata.get(key)
                if isinstance(item, str):
                    refs.append(item)
        for child in value.values():
            refs.extend(_metadata_source_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_metadata_source_refs(child))
    return refs


def test_capability_output_has_only_portable_source_refs() -> None:
    result = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)

    jsonschema.validate(result, _schema())
    _assert_no_absolute_paths(result)
    assert "data/mappings/backbone_core.json" in result["source_refs"]
    assert all(not ref.startswith(("/home/", "/Users/", "/private/", "/var/folders/")) for ref in result["source_refs"])


def test_metadata_source_refs_are_sanitized_recursively() -> None:
    result = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    metadata_refs = _metadata_source_refs(result)

    assert metadata_refs
    assert "data/mappings/backbone_core.json" in metadata_refs
    _assert_no_absolute_paths(metadata_refs)


def test_mcp_security_example_has_no_absolute_paths_and_validates_schema() -> None:
    example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))

    jsonschema.validate(example, _schema())
    _assert_no_absolute_paths(example)
    assert example["source_refs"]
    assert "data/mappings/backbone_core.json" in example["source_refs"]
