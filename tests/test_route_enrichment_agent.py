import json
import re
import zipfile
from io import BytesIO
from pathlib import Path

from attack2defend.enrichment import build_enrichment_result, normalize_route_input, validate_synthesis, write_knowledge_store
from scripts.knowledge_builder import public_collectors


def capability_fixture():
    nodes = [
        {"id": "CVE-2026-0013", "type": "cve", "name": "CVE-2026-0013", "description": "Synthetic vulnerable service condition.", "official_link": "https://nvd.nist.gov/vuln/detail/CVE-2026-0013", "source_ref": "nvd_api", "metadata": {"source": "nvd_api"}},
        {"id": "CWE-664", "type": "cwe", "name": "Improper Control of a Resource Through its Lifetime", "description": "The product does not maintain or incorrectly maintains control over a resource.", "official_link": "https://cwe.mitre.org/data/definitions/664.html", "source_ref": "cwe_xml", "metadata": {"source": "cwe_xml"}},
        {"id": "CAPEC-196", "type": "capec", "name": "Session Credential Falsification through Forging", "description": "An attacker creates a false but functional session credential.", "official_link": "https://capec.mitre.org/data/definitions/196.html", "source_ref": "capec_xml", "metadata": {"source": "capec_xml"}},
        {"id": "T1606", "type": "attack", "name": "Forge Web Credentials", "description": "Adversaries may forge credential materials used to access web applications or Internet services.", "official_link": "https://attack.mitre.org/techniques/T1606/", "source_ref": "mitre_attack_stix", "metadata": {"source": "mitre_attack_stix", "x_mitre_data_sources": ["Logon Session", "Application Log"], "x_mitre_platforms": ["SaaS", "Identity Provider"]}},
        {"id": "D3-TB", "type": "d3fend", "name": "Token Binding", "description": "Bind tokens to expected context.", "official_link": "https://d3fend.mitre.org/technique/D3-TB/", "source_ref": "galeax_cve2capec_defend_db", "metadata": {"source": "galeax_cve2capec_defend_db", "artifact": "Access Token", "d3fend_tactic": "Harden"}},
    ]
    edges = [
        {"source": "CVE-2026-0013", "target": "CWE-664", "relationship": "has_weakness", "confidence": "public_source", "source_ref": "nvd_api"},
        {"source": "CWE-664", "target": "CAPEC-196", "relationship": "may_enable_attack_pattern", "confidence": "public_source", "source_ref": "capec_xml"},
        {"source": "CAPEC-196", "target": "T1606", "relationship": "may_map_to_attack_technique", "confidence": "public_source", "source_ref": "capec_xml"},
        {"source": "T1606", "target": "D3-TB", "relationship": "may_be_defended_by", "confidence": "public_source", "source_ref": "galeax_cve2capec_defend_db"},
    ]
    return {
        "capability": "attack2defend.resolve_defense_route",
        "input": "CVE-2026-0013",
        "normalized_input": "CVE-2026-0013",
        "input_type": "cve",
        "coverage_status": "partial-defense",
        "confidence": "high",
        "priority": {"final_priority": "medium"},
        "source_refs": ["nvd_api", "cwe_xml", "capec_xml", "mitre_attack_stix", "galeax_cve2capec_defend_db"],
        "threat_route_map": {"status": "complete", "nodes": nodes, "edges": edges, "missing_segments": []},
    }


def test_normalize_route_input():
    assert normalize_route_input("2026-0013") == "CVE-2026-0013"
    assert normalize_route_input("cwe 664") == "CWE-664"
    assert normalize_route_input("capec 196") == "CAPEC-196"
    assert normalize_route_input("1606") == "T1606"
    assert normalize_route_input("d3_tb") == "D3-TB"


def test_grounded_synthesis_is_specific_and_validated():
    result = build_enrichment_result(capability_fixture(), raw_input="CVE-2026-0013", mode="local_only")
    payload = result.as_dict()
    synthesis_text = json.dumps(payload["synthesis"], ensure_ascii=False)
    assert "CAPEC-196" in synthesis_text
    assert "T1606" in synthesis_text
    assert "Forge Web Credentials" in synthesis_text
    assert "Token Binding" in synthesis_text
    assert "La cadena técnica queda así" in payload["synthesis"]["technical_route_explanation_es"]
    assert "web credentials" in payload["synthesis"]["why_this_matters_es"].lower()
    assert any(item["control_type"] == "preventive" for item in payload["synthesis"]["defensive_controls_d3fend"])
    assert payload["evidence"]["nodes"]
    assert payload["route"]["threat_route_map"]["status"] == "complete"
    assert payload["validation"]["status"] == "pass"
    assert payload["validation"]["invented_ids"] == []


def test_capec_description_is_enriched_from_official_xml(monkeypatch, tmp_path: Path):
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Attack_Pattern_Catalog>
      <Attack_Patterns>
        <Attack_Pattern ID="196" Name="Session Credential Falsification through Forging" Status="Draft" Abstraction="Standard">
          <Description>An attacker creates a false but functional session credential.</Description>
          <Likelihood_Of_Attack>Medium</Likelihood_Of_Attack>
          <Typical_Severity>Medium</Typical_Severity>
        </Attack_Pattern>
      </Attack_Patterns>
    </Attack_Pattern_Catalog>
    """
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("2000.xml", xml)

    monkeypatch.setattr(public_collectors, "fetch_bytes", lambda *args, **kwargs: buffer.getvalue())

    result = public_collectors.collect_capec(tmp_path)
    node = result.nodes["CAPEC-196"]
    assert node["name"] == "Session Credential Falsification through Forging"
    assert node["description"] == "An attacker creates a false but functional session credential."
    assert node["source_ref"] == "capec_xml"


def test_validation_blocks_invented_ids():
    capability = capability_fixture()
    result = build_enrichment_result(capability, raw_input="CVE-2026-0013", mode="local_only")
    bad_synthesis = dict(result.synthesis)
    bad_synthesis["technical_route_explanation_es"] = "El LLM sugirió T9999, que no existe en la ruta."

    validation = validate_synthesis(capability, bad_synthesis)
    assert validation["status"] == "fail"
    assert validation["invented_ids"] == ["T9999"]


def test_synthesis_claims_are_sourced_or_marked_as_inference():
    result = build_enrichment_result(capability_fixture(), raw_input="CVE-2026-0013", mode="local_only")
    important_sections = (
        "telemetry_required",
        "detection_hypotheses",
        "defensive_controls_d3fend",
        "expected_evidence",
        "owner_actions",
        "closure_criteria",
        "claims",
    )
    for section in important_sections:
        for item in result.synthesis[section]:
            assert item.get("source_ref") or (item.get("evidence_basis") == "inference" and item.get("requires_validation") is True), (section, item)


def test_ui_fetches_only_local_static_data():
    source = Path("app/navigator-ui/src/main.tsx").read_text(encoding="utf-8")
    fetch_targets = re.findall(r"fetch\(['\"]([^'\"]+)['\"]", source)
    assert fetch_targets
    assert all(target.startswith("/data/") for target in fetch_targets)


def test_write_knowledge_store(tmp_path: Path):
    result = build_enrichment_result(capability_fixture(), raw_input="CVE-2026-0013", mode="local_only")
    write_knowledge_store(tmp_path, result)
    assert (tmp_path / "nodes.jsonl").exists()
    assert (tmp_path / "edges.jsonl").exists()
    assert (tmp_path / "routes.jsonl").exists()
    assert (tmp_path / "CVE-2026-0013.enrichment.json").exists()
    route_text = (tmp_path / "routes.jsonl").read_text(encoding="utf-8")
    assert "CVE-2026-0013" in route_text
    assert "detection_hypotheses" in route_text
    export_payload = json.loads((tmp_path / "CVE-2026-0013.enrichment.json").read_text(encoding="utf-8"))
    assert {"route", "evidence", "synthesis", "validation"} <= set(export_payload)
