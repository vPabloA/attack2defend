from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "knowledge_builder" / "build_knowledge_base.py"
SPEC = spec_from_file_location("build_knowledge_base", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

BuildState = MODULE.BuildState
REQUIRED_SEED_INPUTS = MODULE.REQUIRED_SEED_INPUTS
validate_seed_inputs = MODULE.validate_seed_inputs


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
