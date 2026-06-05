"""Golden test for CVE-2026-23479 (Redis UAF) coherence route.

Verifies that the coherence engine produces the canonical 17-node chain
with full provenance — no invented IDs, no false official_explicit claims,
non-empty narrative and graph — using only offline data (curated fixture
+ built-in baselines, no live API calls).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from attack2defend.coherence import engine as _engine
from attack2defend.coherence import narrative as _narrative
from attack2defend.graph import projection as _projection

REQUIRED_IDS = [
    "CVE-2026-23479",
    "CWE-416",
    "CAPEC-129",
    "CAPEC-124",
    "CAPEC-26",
    "T1190",
    "T1210",
    "T1059.004",
    "D3-SWI",
    "D3-AVE",
    "D3-NI",
    "D3-NTF",
    "D3-NTA",
    "D3-SCH",
    "D3-RN",
    "D3-PSEP",
    "D3-EI",
]

_REPO_ROOT = Path(__file__).parents[1]
_CURATED_FILE = _REPO_ROOT / "data" / "mappings" / "curated" / "cve_2026_23479_redis_uaf.json"


def _load_curated_bundle() -> tuple[list[dict], list[dict]]:
    """Convert the curated mapping fixture into bundle nodes/edges format."""
    if not _CURATED_FILE.exists():
        return [], []
    data = json.loads(_CURATED_FILE.read_text(encoding="utf-8"))
    mappings = data.get("mappings", [])

    node_map: dict[str, dict] = {}
    for m in mappings:
        if m["from"] not in node_map:
            node_map[m["from"]] = {
                "id": m["from"], "type": m["from_type"], "name": m.get("from_name", m["from"]),
            }
        if m["to"] not in node_map:
            node_map[m["to"]] = {
                "id": m["to"], "type": m["to_type"], "name": m.get("to_name", m["to"]),
            }

    edges = [
        {
            "source": m["from"],
            "target": m["to"],
            "relationship": m.get("relationship", "mapped_to"),
            "confidence": m.get("confidence", "medium"),
            "source_ref": m.get("source_ref", "curated"),
            "source_kind": m.get("source_kind", "curated"),
        }
        for m in mappings
    ]
    return list(node_map.values()), edges


@pytest.fixture(scope="module")
def artifact():
    bundle_nodes, bundle_edges = _load_curated_bundle()
    return _engine.analyze(
        input_id="CVE-2026-23479",
        bundle_nodes=bundle_nodes,
        bundle_edges=bundle_edges,
        live=False,
        cache_dir=None,
    )


def test_all_required_ids_present(artifact):
    node_ids = {n.id for n in artifact.all_nodes}
    missing = [req for req in REQUIRED_IDS if req not in node_ids]
    assert not missing, f"Required IDs missing from artifact: {missing}"


def test_node_count_at_least_required(artifact):
    assert len(artifact.all_nodes) >= len(REQUIRED_IDS), (
        f"Expected at least {len(REQUIRED_IDS)} nodes, got {len(artifact.all_nodes)}"
    )


def test_all_edges_have_mapping_basis(artifact):
    bad = [
        f"{e.source}→{e.target}"
        for e in artifact.all_edges
        if not e.mapping_basis
    ]
    assert not bad, f"Edges missing mapping_basis: {bad}"


def test_all_edges_have_source_refs(artifact):
    bad = [
        f"{e.source}→{e.target}"
        for e in artifact.all_edges
        if not e.source_refs
    ]
    assert not bad, f"Edges missing source_refs: {bad}"


def test_no_false_official_explicit(artifact):
    """Edges with mapping_basis='official_explicit' must have score >= 50."""
    bad = [
        f"{e.source}→{e.target} (score={e.score})"
        for e in artifact.all_edges
        if e.mapping_basis == "official_explicit" and e.score < 50
    ]
    assert not bad, f"Edges falsely claiming official_explicit: {bad}"


def test_status_not_failed(artifact):
    assert artifact.status != "failed", f"Artifact status is 'failed': {artifact.status}"


def test_narrative_not_empty(artifact):
    analysis = _narrative.generate(artifact, use_llm=False)
    assert analysis.technical_narrative.strip(), "technical_narrative is empty"
    assert analysis.logical_sequence, "logical_sequence is empty"
    assert analysis.conclusion.strip(), "conclusion is empty"


def test_narrative_no_invented_ids(artifact):
    """Narrative must not invent new IDs that aren't in the artifact nodes."""
    analysis = _narrative.generate(artifact, use_llm=False)
    known_ids = {n.id for n in artifact.all_nodes}
    text = f"{analysis.technical_narrative} {analysis.conclusion} {analysis.ascii_route}"
    # Check that all IDs mentioned in narrative (matching known patterns) exist in artifact
    import re
    mentioned = set(re.findall(
        r'\b(?:CVE-\d{4}-\d+|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d+)?|D3-[A-Z]+)\b',
        text,
    ))
    invented = mentioned - known_ids
    assert not invented, f"Narrative mentions IDs not in artifact: {invented}"


def test_graph_nodes_not_empty(artifact):
    graph = _projection.build_graph_json(artifact)
    assert graph["nodes"], "graph.nodes is empty"


def test_graph_edges_not_empty(artifact):
    graph = _projection.build_graph_json(artifact)
    assert graph["edges"], "graph.edges is empty"


def test_graph_nodes_have_positions(artifact):
    graph = _projection.build_graph_json(artifact)
    missing_pos = [n["id"] for n in graph["nodes"] if "x" not in n or "y" not in n]
    assert not missing_pos, f"Graph nodes missing x/y positions: {missing_pos}"


def test_graph_node_ids_subset_of_artifact(artifact):
    artifact_ids = {n.id for n in artifact.all_nodes}
    graph = _projection.build_graph_json(artifact)
    graph_ids = {n["id"] for n in graph["nodes"]}
    extra = graph_ids - artifact_ids
    assert not extra, f"Graph contains node IDs not in artifact: {extra}"


def test_provenance_section_present(artifact):
    d = artifact.to_dict()
    prov = d.get("provenance", {})
    assert prov, "provenance section is missing"
    # At least one non-empty list
    any_prov = any(prov.get(k) for k in ("official_explicit", "official_related", "analytical_inferred"))
    assert any_prov, "provenance has no official or analytical entries"


def test_canonical_chain_covers_layers(artifact):
    """Canonical chain must cover at least 3 framework layers."""
    chain = artifact.canonical_chain
    types = {n.type for n in artifact.all_nodes if n.id in chain}
    assert len(types) >= 3, f"Canonical chain covers only {len(types)} framework types: {types}"


def test_validate_script_passes(artifact):
    """The validate_dict script must return no errors for the complete artifact."""
    import importlib.util
    script = Path(__file__).parents[1] / "scripts" / "validate_route_artifact.py"
    spec = importlib.util.spec_from_file_location("validate_route_artifact", script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    # The CLI always generates narrative before saving. Replicate that here.
    import copy
    full = copy.deepcopy(artifact)
    full.analysis_es = _narrative.generate(full, use_llm=False)
    errors = mod.validate_dict(full.to_dict())
    assert not errors, f"validate_dict returned errors: {errors}"
