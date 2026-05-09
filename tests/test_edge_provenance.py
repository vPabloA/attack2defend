from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = REPO_ROOT / "scripts" / "knowledge_builder" / "validate_edge_provenance.py"
ENFORCER_PATH = REPO_ROOT / "scripts" / "knowledge_builder" / "enforce_edge_provenance.py"

VALIDATOR_SPEC = spec_from_file_location("validate_edge_provenance", VALIDATOR_PATH)
assert VALIDATOR_SPEC and VALIDATOR_SPEC.loader
VALIDATOR = module_from_spec(VALIDATOR_SPEC)
sys.modules[VALIDATOR_SPEC.name] = VALIDATOR
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)

ENFORCER_SPEC = spec_from_file_location("enforce_edge_provenance", ENFORCER_PATH)
assert ENFORCER_SPEC and ENFORCER_SPEC.loader
ENFORCER = module_from_spec(ENFORCER_SPEC)
sys.modules[ENFORCER_SPEC.name] = ENFORCER
ENFORCER_SPEC.loader.exec_module(ENFORCER)


def minimal_bundle(edge):
    return {
        "metadata": {
            "builder_version": "test",
            "generated_at": "2026-05-08T00:00:00Z",
        },
        "nodes": [
            {"id": "CVE-2021-44228", "type": "cve", "name": "Log4Shell"},
            {"id": "CWE-502", "type": "cwe", "name": "Deserialization of Untrusted Data"},
        ],
        "edges": [edge],
        "indexes": {},
        "coverage": {},
        "routes": [],
    }


def test_validator_rejects_edges_without_mandatory_provenance():
    bundle = minimal_bundle({"source": "CVE-2021-44228", "target": "CWE-502", "relationship": "vulnerability_has_weakness"})
    errors = VALIDATOR.validate_bundle(bundle)
    assert any("missing provenance field: source_feed" in error for error in errors)
    assert any("missing provenance reference" in error for error in errors)


def test_provenance_enforcer_stamps_existing_edges_without_changing_topology():
    bundle = minimal_bundle(
        {
            "source": "CVE-2021-44228",
            "target": "CWE-502",
            "relationship": "vulnerability_has_weakness",
            "source_ref": "test:fixture",
        }
    )
    hardened = ENFORCER.enforce_bundle(bundle, generated_at="2026-05-08T00:00:00Z")
    edge = hardened["edges"][0]
    assert edge["source"] == "CVE-2021-44228"
    assert edge["target"] == "CWE-502"
    assert edge["relationship"] == "vulnerability_has_weakness"
    assert edge["source_feed"]
    assert edge["source_ref"] == "test:fixture"
    assert edge["retrieved_at"] == "2026-05-08T00:00:00Z"
    assert edge["transform_version"] == "knowledge_builder:test"
    assert edge["confidence"] == "medium"
    assert edge["deterministic"] is True
    assert edge["inferred"] is False
    assert hardened["metadata"]["counts"]["edges_with_provenance"] == 1
    assert VALIDATOR.validate_bundle(hardened) == []
