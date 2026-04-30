import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_build_knowledge_base_outputs_and_edges():
    subprocess.run([sys.executable, "scripts/knowledge_builder/build_knowledge_base.py"], cwd=REPO_ROOT, check=True)

    expected_files = [
        "data/nodes.json",
        "data/edges.json",
        "data/indexes.json",
        "data/coverage.json",
        "data/routes.json",
        "data/metadata.json",
        "data/knowledge-bundle.json",
        "app/navigator-ui/public/data/knowledge-bundle.json",
    ]
    for rel_path in expected_files:
        assert (REPO_ROOT / rel_path).exists(), f"missing output file: {rel_path}"

    nodes = json.loads((REPO_ROOT / "data/nodes.json").read_text(encoding="utf-8"))
    edges = json.loads((REPO_ROOT / "data/edges.json").read_text(encoding="utf-8"))
    routes = json.loads((REPO_ROOT / "data/routes.json").read_text(encoding="utf-8"))

    node_ids = {node["id"].upper() for node in nodes}
    broken_edges = [e for e in edges if e["source"].upper() not in node_ids or e["target"].upper() not in node_ids]
    assert broken_edges == []

    for seed in ["CVE-2021-44228", "T1567", "CVE-2024-37079", "CWE-79", "D3-MFA"]:
        assert seed in routes
        assert routes[seed]["found"] is True
