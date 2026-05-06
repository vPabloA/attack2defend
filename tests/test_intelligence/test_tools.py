"""Unit tests for the intelligence tools layer.

These tests use a minimal synthetic bundle and never hit the network.
They verify:
  - gap scanning logic (correct detection by type)
  - priority heuristics (KEV and route status boosting)
  - evidence parsing from cached sources (XML, JSON)
  - edge cases (empty bundle, missing cache)
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

import pytest

from attack2defend.intelligence.tools import (
    _infer_type,
    _make_gap,
    fetch_evidence_for_gaps,
    scan_bundle_gaps,
)


# ------------------------------------------------------------------ #
# Minimal synthetic bundle fixture                                     #
# ------------------------------------------------------------------ #


def _make_bundle(
    *,
    attack_nodes: list[str] | None = None,
    cwe_nodes: list[str] | None = None,
    capec_nodes: list[str] | None = None,
    cve_nodes: list[str] | None = None,
    d3fend_nodes: list[str] | None = None,
    attack_to_d3fend: dict | None = None,
    cwe_to_capec: dict | None = None,
    capec_to_attack: dict | None = None,
    kev: dict | None = None,
    semantic_routes: list | None = None,
    coverage: dict | None = None,
) -> dict:
    nodes = []
    for nid in (attack_nodes or []):
        nodes.append({"id": nid, "type": "attack", "name": f"Technique {nid}"})
    for nid in (cwe_nodes or []):
        nodes.append({"id": nid, "type": "cwe", "name": f"Weakness {nid}"})
    for nid in (capec_nodes or []):
        nodes.append({"id": nid, "type": "capec", "name": f"Pattern {nid}"})
    for nid in (cve_nodes or []):
        nodes.append({"id": nid, "type": "cve", "name": f"Vuln {nid}"})
    for nid in (d3fend_nodes or []):
        nodes.append({"id": nid, "type": "d3fend", "name": f"Defense {nid}"})

    return {
        "nodes": nodes,
        "edges": [],
        "indexes": {
            "forward": {
                "attack_to_d3fend": attack_to_d3fend or {},
                "cwe_to_capec": cwe_to_capec or {},
                "capec_to_attack": capec_to_attack or {},
            },
            "kev": kev or {},
        },
        "semantic_routes": semantic_routes or [],
        "coverage": coverage or {},
    }


# ------------------------------------------------------------------ #
# _infer_type                                                          #
# ------------------------------------------------------------------ #


@pytest.mark.parametrize("node_id,expected", [
    ("CVE-2021-44228", "cve"),
    ("CWE-79", "cwe"),
    ("CAPEC-63", "capec"),
    ("T1190", "attack"),
    ("T1567.002", "attack"),
    ("D3-AH", "d3fend"),
    ("D3-MFA", "d3fend"),
    ("CTRL-001", "artifact"),  # unknown → artifact
])
def test_infer_type(node_id, expected):
    assert _infer_type(node_id) == expected


# ------------------------------------------------------------------ #
# scan_bundle_gaps — missing_d3fend                                    #
# ------------------------------------------------------------------ #


def test_scan_detects_attack_without_d3fend():
    bundle = _make_bundle(
        attack_nodes=["T1190", "T1059"],
        attack_to_d3fend={"T1059": ["D3-AH"]},  # T1190 has no D3FEND
    )
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=10)
    gap_sources = {g["source_id"] for g in gaps}
    assert "T1190" in gap_sources
    assert "T1059" not in gap_sources


def test_scan_skips_attack_with_d3fend():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        attack_to_d3fend={"T1190": ["D3-AH", "D3-MFA"]},
    )
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=10)
    assert len(gaps) == 0


def test_scan_gap_type_field_is_correct():
    bundle = _make_bundle(attack_nodes=["T1190"])
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=10)
    assert all(g["gap_type"] == "missing_d3fend" for g in gaps)


def test_scan_gap_has_required_fields():
    bundle = _make_bundle(attack_nodes=["T1190"])
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=10)
    assert len(gaps) == 1
    g = gaps[0]
    for field in ("gap_id", "gap_type", "source_id", "source_type", "target_type",
                  "node_name", "description", "priority", "route_status"):
        assert field in g, f"missing field: {field}"


def test_scan_gap_id_is_unique_per_node():
    bundle = _make_bundle(attack_nodes=["T1190", "T1059"])
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=10)
    gap_ids = [g["gap_id"] for g in gaps]
    assert len(gap_ids) == len(set(gap_ids))


# ------------------------------------------------------------------ #
# scan_bundle_gaps — missing_capec                                     #
# ------------------------------------------------------------------ #


def test_scan_detects_cwe_without_capec():
    bundle = _make_bundle(
        cwe_nodes=["CWE-79", "CWE-89"],
        cwe_to_capec={"CWE-89": ["CAPEC-66"]},  # CWE-79 missing CAPEC
    )
    gaps = scan_bundle_gaps(bundle, ["missing_capec"], max_gaps=10)
    gap_sources = {g["source_id"] for g in gaps}
    assert "CWE-79" in gap_sources
    assert "CWE-89" not in gap_sources


# ------------------------------------------------------------------ #
# scan_bundle_gaps — missing_attack                                    #
# ------------------------------------------------------------------ #


def test_scan_detects_capec_without_attack():
    bundle = _make_bundle(
        capec_nodes=["CAPEC-63", "CAPEC-66"],
        capec_to_attack={"CAPEC-66": ["T1059"]},
    )
    gaps = scan_bundle_gaps(bundle, ["missing_attack"], max_gaps=10)
    gap_sources = {g["source_id"] for g in gaps}
    assert "CAPEC-63" in gap_sources
    assert "CAPEC-66" not in gap_sources


# ------------------------------------------------------------------ #
# scan_bundle_gaps — partial_coverage                                  #
# ------------------------------------------------------------------ #


def test_scan_detects_partial_semantic_route():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        semantic_routes=[{
            "root": "T1190",
            "coverage_status": "catalog-only",
            "nodes": ["T1190"],
            "missing_segments": ["d3fend", "control"],
        }],
    )
    gaps = scan_bundle_gaps(bundle, ["partial_coverage"], max_gaps=10)
    assert len(gaps) == 1
    assert gaps[0]["source_id"] == "T1190"
    assert gaps[0]["priority"] == "high"  # catalog-only → high


def test_scan_ignores_complete_semantic_route():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        semantic_routes=[{
            "root": "T1190",
            "coverage_status": "complete",
            "nodes": ["T1190"],
            "missing_segments": [],
        }],
    )
    gaps = scan_bundle_gaps(bundle, ["partial_coverage"], max_gaps=10)
    assert len(gaps) == 0


# ------------------------------------------------------------------ #
# scan_bundle_gaps — coverage_gap                                      #
# ------------------------------------------------------------------ #


def test_scan_detects_coverage_gap():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        coverage={
            "T1190": {
                "status": "partial",
                "gaps": ["Missing SIEM detection rule", "No EDR telemetry"],
            }
        },
    )
    gaps = scan_bundle_gaps(bundle, ["coverage_gap"], max_gaps=10)
    assert len(gaps) == 1
    assert gaps[0]["source_id"] == "T1190"


def test_scan_ignores_coverage_with_empty_gaps():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        coverage={"T1190": {"status": "covered", "gaps": []}},
    )
    gaps = scan_bundle_gaps(bundle, ["coverage_gap"], max_gaps=10)
    assert len(gaps) == 0


# ------------------------------------------------------------------ #
# max_gaps limit                                                       #
# ------------------------------------------------------------------ #


def test_scan_respects_max_gaps():
    # Create 20 unmapped ATT&CK techniques
    techniques = [f"T{1000 + i}" for i in range(20)]
    bundle = _make_bundle(attack_nodes=techniques)
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=5)
    assert len(gaps) <= 5


# ------------------------------------------------------------------ #
# Priority heuristics                                                  #
# ------------------------------------------------------------------ #


def test_catalog_only_route_yields_high_priority():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        semantic_routes=[{
            "root": "T1190",
            "coverage_status": "catalog-only",
            "nodes": ["T1190"],
            "missing_segments": ["d3fend"],
        }],
    )
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend"], max_gaps=10)
    assert len(gaps) == 1
    assert gaps[0]["priority"] in {"high", "critical"}


# ------------------------------------------------------------------ #
# fetch_evidence_for_gaps                                              #
# ------------------------------------------------------------------ #


def test_fetch_evidence_returns_empty_for_missing_cache():
    gaps = [{
        "gap_id": "gap-missing_d3fend-T1190",
        "gap_type": "missing_d3fend",
        "source_id": "T1190",
    }]
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp) / "empty_cache"
        cache_dir.mkdir()
        result = fetch_evidence_for_gaps(gaps, cache_dir)
    assert "gap-missing_d3fend-T1190" in result
    assert result["gap-missing_d3fend-T1190"] == []


def test_fetch_evidence_d3fend_from_cache():
    d3fend_data = {
        "defensive-technique": [
            {
                "@id": "d3f:ApplicationHardening",
                "rdfs:label": "Application Hardening",
                "d3f:definition": "Harden the application against exploitation",
            }
        ]
    }
    gaps = [{
        "gap_id": "gap-missing_d3fend-T1190",
        "gap_type": "missing_d3fend",
        "source_id": "T1190",
    }]
    with tempfile.TemporaryDirectory() as tmp:
        d3fend_dir = Path(tmp) / "d3fend"
        d3fend_dir.mkdir()
        (d3fend_dir / "T1190.json").write_text(
            json.dumps(d3fend_data), encoding="utf-8"
        )
        result = fetch_evidence_for_gaps(gaps, Path(tmp))

    items = result.get("gap-missing_d3fend-T1190", [])
    assert len(items) >= 1
    assert items[0]["source"] == "d3fend"
    assert "http" in items[0]["url"]
    assert items[0]["confidence"] == "medium"


def test_fetch_evidence_capec_from_zip_cache():
    # Minimal CAPEC XML with CWE-79 relationship
    capec_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="86" Name="XSS via HTTP Request Headers">
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="79"/>
      </Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>"""

    gaps = [{
        "gap_id": "gap-missing_capec-CWE-79",
        "gap_type": "missing_capec",
        "source_id": "CWE-79",
    }]

    with tempfile.TemporaryDirectory() as tmp:
        capec_dir = Path(tmp) / "capec"
        capec_dir.mkdir()
        zip_path = capec_dir / "capec_latest.xml.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("capec_latest.xml", capec_xml)

        result = fetch_evidence_for_gaps(gaps, Path(tmp))

    items = result.get("gap-missing_capec-CWE-79", [])
    assert len(items) >= 1
    assert items[0]["source"] == "capec"
    assert "CAPEC-86" in items[0]["capec_id"]
    assert items[0]["confidence"] == "high"


# ------------------------------------------------------------------ #
# Empty bundle edge cases                                              #
# ------------------------------------------------------------------ #


def test_scan_empty_bundle_returns_no_gaps():
    bundle = _make_bundle()
    gaps = scan_bundle_gaps(bundle, ["missing_d3fend", "missing_capec"], max_gaps=50)
    assert gaps == []


def test_scan_all_gap_types_on_minimal_bundle():
    bundle = _make_bundle(
        attack_nodes=["T1190"],
        cwe_nodes=["CWE-79"],
        capec_nodes=["CAPEC-63"],
    )
    gap_types = ["missing_d3fend", "missing_capec", "missing_attack",
                 "partial_coverage", "coverage_gap"]
    gaps = scan_bundle_gaps(bundle, gap_types, max_gaps=100)
    found_types = {g["gap_type"] for g in gaps}
    assert "missing_d3fend" in found_types
    assert "missing_capec" in found_types
    assert "missing_attack" in found_types
