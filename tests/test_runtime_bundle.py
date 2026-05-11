import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "mapping_builder"))

from apply_mapping_backbone import apply_mapping_backbone  # noqa: E402
from attack2defend.runtime_bundle import publish_runtime_bundle  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_publish_runtime_bundle_strips_builder_only_semantic_routes(tmp_path: Path) -> None:
    source = tmp_path / "knowledge-bundle.json"
    output = tmp_path / "public" / "knowledge-bundle.json"
    bundle = {
        "metadata": {"counts": {"semantic_routes": 1}},
        "nodes": [{"id": "CVE-2026-0013", "type": "cve", "name": "CVE-2026-0013"}],
        "edges": [],
        "indexes": {"route_inputs": ["CVE-2026-0013"], "search": []},
        "coverage": {},
        "routes": [{"input": "CVE-2026-0013", "name": "Synthetic route"}],
        "semantic_routes": [{"root": "CVE-2026-0013", "nodes": ["CVE-2026-0013"], "edges": []}],
    }
    write_json(source, bundle)

    result = publish_runtime_bundle(source, output, stream_threshold_bytes=1)
    runtime = json.loads(output.read_text(encoding="utf-8"))

    assert result["omitted_top_level_fields"] == ["semantic_routes"]
    assert "semantic_routes" not in runtime
    assert runtime["nodes"][0]["id"] == "CVE-2026-0013"
    assert runtime["metadata"]["runtime_bundle"]["strategy"] == "static_runtime_compact"


def test_mapping_backbone_mirrors_compact_runtime_bundle_to_ui(tmp_path: Path) -> None:
    bundle = {
        "metadata": {"contract_version": "attack2defend.knowledge_bundle.v1", "mode": "curated_mvp_bundle", "counts": {}},
        "nodes": [],
        "edges": [],
        "indexes": {"route_inputs": ["CVE-2021-44228"], "search": []},
        "coverage": {},
        "routes": [{"input": "CVE-2021-44228", "name": "Log4Shell"}],
    }
    bundle_path = tmp_path / "knowledge-bundle.json"
    ui_public_dir = tmp_path / "ui-public"
    write_json(bundle_path, bundle)

    assert apply_mapping_backbone(bundle_path, ROOT / "data" / "mappings", ui_public_dir, None, True) == 0

    canonical = json.loads(bundle_path.read_text(encoding="utf-8"))
    runtime = json.loads((ui_public_dir / "knowledge-bundle.json").read_text(encoding="utf-8"))
    last_good = json.loads((ui_public_dir / "knowledge-bundle.last-good.json").read_text(encoding="utf-8"))

    assert canonical["semantic_routes"]
    assert "semantic_routes" not in runtime
    assert "semantic_routes" not in last_good
    assert runtime["nodes"]
    assert runtime["edges"]
    assert runtime["indexes"]["route_inputs"]
