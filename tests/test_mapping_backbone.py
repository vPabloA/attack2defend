import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "mapping_builder"))
sys.path.insert(0, str(ROOT / "scripts" / "knowledge_builder"))

from apply_mapping_backbone import apply_mapping_backbone  # noqa: E402
from validate_bundle import validate_bundle  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_mapping_backbone_creates_defensive_semantic_route(tmp_path: Path) -> None:
    bundle = {
        "metadata": {"contract_version": "attack2defend.knowledge_bundle.v1", "mode": "curated_mvp_bundle", "counts": {}},
        "nodes": [],
        "edges": [],
        "indexes": {"route_inputs": ["CVE-2021-44228"], "search": []},
        "coverage": {},
        "routes": [{"input": "CVE-2021-44228", "name": "Log4Shell"}],
    }
    bundle_path = tmp_path / "knowledge-bundle.json"
    write_json(bundle_path, bundle)

    assert apply_mapping_backbone(bundle_path, ROOT / "data" / "mappings", None, None, False) == 0
    result = json.loads(bundle_path.read_text(encoding="utf-8"))

    errors = validate_bundle(result, require_mapping_backbone=True, require_semantic_routes=True, min_mapping_files=1)
    assert errors == []
    route = next(route for route in result["semantic_routes"] if route["root"] == "CVE-2021-44228")
    assert "CWE-20" in route["nodes"]
    assert "T1190" in route["nodes"]
    assert any(node.startswith("DET-") for node in route["nodes"])
    assert any(node.startswith("ACT-") for node in route["nodes"])
    assert route["coverage_status"] in {"complete", "partial-defense", "partial"}


def test_unknown_route_is_not_invented(tmp_path: Path) -> None:
    bundle = {
        "metadata": {"contract_version": "attack2defend.knowledge_bundle.v1", "mode": "curated_mvp_bundle", "counts": {}},
        "nodes": [{"id": "CVE-2099-0001", "type": "cve", "name": "Unknown future CVE"}],
        "edges": [],
        "indexes": {"route_inputs": ["CVE-2099-0001"], "search": []},
        "coverage": {},
        "routes": [{"input": "CVE-2099-0001", "name": "Unknown"}],
    }
    bundle_path = tmp_path / "knowledge-bundle.json"
    write_json(bundle_path, bundle)

    assert apply_mapping_backbone(bundle_path, ROOT / "data" / "mappings", None, None, False) == 0
    result = json.loads(bundle_path.read_text(encoding="utf-8"))
    route = next(route for route in result["semantic_routes"] if route["root"] == "CVE-2099-0001")
    assert route["coverage_status"] == "unresolved"
    assert route["nodes"] == ["CVE-2099-0001"]
