from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json
import shutil
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "knowledge_builder" / "build_knowledge_base.py"
VALIDATOR_PATH = REPO_ROOT / "scripts" / "knowledge_builder" / "validate_bundle.py"

SPEC = spec_from_file_location("build_knowledge_base", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VALIDATOR_SPEC = spec_from_file_location("validate_bundle", VALIDATOR_PATH)
assert VALIDATOR_SPEC and VALIDATOR_SPEC.loader
VALIDATOR = module_from_spec(VALIDATOR_SPEC)
sys.modules[VALIDATOR_SPEC.name] = VALIDATOR
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)

BuildState = MODULE.BuildState
REQUIRED_SEED_INPUTS = MODULE.REQUIRED_SEED_INPUTS
validate_seed_inputs = MODULE.validate_seed_inputs


def build_bundle_for_test(**overrides):
    defaults = {
        "strict": False,
        "with_public_sources": False,
        "cache_dir": Path("unused-cache"),
        "refresh_public_sources": False,
        "public_timeout": 10,
        "public_fail_on_error": False,
        "public_no_attack": False,
        "public_no_cwe": False,
        "public_no_capec": False,
        "public_no_kev": False,
        "public_no_d3fend": False,
        "with_nvd": False,
        "nvd_cves": [],
        "nvd_recent_days": 0,
        "nvd_api_key": None,
        "max_kev_cves": None,
        "max_d3fend_attack_ids": 5,
    }
    defaults.update(overrides)
    return MODULE.build_bundle(**defaults)


def test_validate_seed_inputs_passes_when_all_required_are_present():
    state = BuildState(route_inputs=sorted(REQUIRED_SEED_INPUTS))
    validate_seed_inputs(state)
    assert state.has_errors is False


def test_validate_seed_inputs_fails_when_required_seed_is_missing():
    missing_seed = "D3-MFA"
    state = BuildState(route_inputs=sorted(REQUIRED_SEED_INPUTS - {missing_seed}))
    validate_seed_inputs(state)
    assert state.has_errors is True
    assert any(missing_seed in issue.message for issue in state.issues)


def test_build_bundle_generates_expected_files_and_valid_bundle(tmp_path):
    source_dir = tmp_path / "samples"
    output_dir = tmp_path / "data"
    snapshot_dir = tmp_path / "snapshots"
    ui_public_dir = tmp_path / "ui-public" / "data"
    shutil.copytree(REPO_ROOT / "data" / "samples", source_dir)

    exit_code = build_bundle_for_test(
        source_dir=source_dir,
        output_dir=output_dir,
        snapshot_dir=snapshot_dir,
        ui_public_dir=ui_public_dir,
        cache_dir=tmp_path / "raw",
    )

    assert exit_code == 0
    expected_files = {
        "nodes.json",
        "edges.json",
        "indexes.json",
        "coverage.json",
        "routes.json",
        "metadata.json",
        "knowledge-bundle.json",
    }
    for file_name in expected_files:
        assert (output_dir / file_name).exists(), file_name
        assert (ui_public_dir / file_name).exists(), file_name

    bundle = json.loads((output_dir / "knowledge-bundle.json").read_text(encoding="utf-8"))
    assert VALIDATOR.validate_bundle(bundle) == []

    metadata = bundle["metadata"]
    assert set(metadata["seed_inputs"]["required"]) == REQUIRED_SEED_INPUTS
    assert REQUIRED_SEED_INPUTS.issubset(set(metadata["seed_inputs"]["available"]))
    assert metadata["public_collection"]["enabled"] is False
    assert bundle["nodes"]
    assert bundle["edges"]
    assert bundle["coverage"]
    assert bundle["routes"]
    assert any(snapshot_dir.iterdir())


def test_bundle_validator_detects_broken_edge():
    bundle = {
        "metadata": {"seed_inputs": {"available": sorted(REQUIRED_SEED_INPUTS)}},
        "nodes": [{"id": "CVE-2021-44228", "type": "cve", "name": "Log4Shell"}],
        "edges": [{"source": "CVE-2021-44228", "target": "MISSING", "relationship": "broken"}],
        "indexes": {"route_inputs": sorted(REQUIRED_SEED_INPUTS), "search": [{"id": "CVE-2021-44228"}]},
        "coverage": {},
        "routes": [],
    }

    errors = VALIDATOR.validate_bundle(bundle)
    assert any("broken edge target" in error for error in errors)


def test_public_source_validator_requires_public_metadata():
    bundle = {
        "metadata": {
            "mode": "curated_mvp_bundle",
            "seed_inputs": {"available": sorted(REQUIRED_SEED_INPUTS)},
            "public_collection": {"enabled": False},
            "public_sources": [],
        },
        "nodes": [{"id": "T1190", "type": "attack", "name": "Exploit Public-Facing Application"}],
        "edges": [],
        "indexes": {"route_inputs": sorted(REQUIRED_SEED_INPUTS), "search": [{"id": "T1190"}]},
        "coverage": {},
        "routes": [],
    }

    errors = VALIDATOR.validate_bundle(bundle, require_public_sources=True, min_nodes=1)
    assert any("public_sources_bundle" in error for error in errors)
    assert any("metadata.public_collection.enabled" in error for error in errors)
