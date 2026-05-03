"""Tests for the NSFW + CVE2CAPEC canonical exporter."""
from __future__ import annotations

import json
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPORT_PATH = REPO_ROOT / "scripts" / "canonical_exports" / "build_canonical.py"
VALIDATOR_PATH = REPO_ROOT / "scripts" / "canonical_exports" / "validate_canonical.py"


def _load_module(path: Path, name: str):
    spec = spec_from_file_location(name, path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EXPORT = _load_module(EXPORT_PATH, "build_canonical_test")
VALIDATOR = _load_module(VALIDATOR_PATH, "validate_canonical_test")


def write_bundle(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def sample_bundle() -> dict:
    return {
        "metadata": {"contract_version": "attack2defend.knowledge_bundle.v2"},
        "nodes": [
            {
                "id": "CVE-2021-44228",
                "type": "cve",
                "name": "Log4Shell",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "metadata": {
                    "kev": True,
                    "kev_status": "known_exploited",
                    "vendor": "Apache",
                    "product": "Log4j",
                    "kev_date_added": "2021-12-10",
                    "cvss_v3_base_score": "10.0",
                    "cvss_v3_severity": "CRITICAL",
                },
            },
            {"id": "CWE-20", "type": "cwe", "name": "Improper Input Validation"},
            {"id": "CAPEC-100", "type": "capec", "name": "Overflow Buffers"},
            {
                "id": "T1190",
                "type": "attack",
                "name": "Exploit Public-Facing Application",
                "metadata": {"kill_chain_phases": [{"phase_name": "initial-access"}]},
            },
            {
                "id": "D3-WAF",
                "type": "d3fend",
                "name": "Web Application Firewall",
                "metadata": {"d3fend_tactic": "harden"},
            },
            {
                "id": "CPE:2.3:A:APACHE:LOG4J:*:*:*:*:*:*:*:*",
                "type": "artifact",
                "name": "Apache Log4j",
                "metadata": {"framework": "cpe", "vendor": "apache", "product": "log4j"},
            },
        ],
        "edges": [
            {"source": "CVE-2021-44228", "target": "CWE-20", "relationship": "vulnerability_has_weakness"},
            {"source": "CWE-20", "target": "CAPEC-100", "relationship": "weakness_enables_attack_pattern"},
            {"source": "CAPEC-100", "target": "T1190", "relationship": "attack_pattern_maps_to_technique"},
            {"source": "T1190", "target": "D3-WAF", "relationship": "technique_mitigated_by_countermeasure"},
            {
                "source": "CVE-2021-44228",
                "target": "CPE:2.3:A:APACHE:LOG4J:*:*:*:*:*:*:*:*",
                "relationship": "affects_product_or_platform",
            },
        ],
        "indexes": {"kev": {"CVE-2021-44228": {"vendor": "Apache", "product": "Log4j"}}},
        "coverage": {},
        "routes": [],
    }


def test_canonical_export_writes_nsfw_and_cve2capec(tmp_path: Path) -> None:
    bundle_path = tmp_path / "knowledge-bundle.json"
    write_bundle(bundle_path, sample_bundle())

    nsfw_dir = tmp_path / "nsfw"
    cve2capec_dir = tmp_path / "cve2capec"
    summary_path = tmp_path / "summary.json"

    summary = EXPORT.build_canonical(
        bundle_path=bundle_path,
        nsfw_dir=nsfw_dir,
        cve2capec_dir=cve2capec_dir,
        ui_nsfw_dir=None,
        ui_cve2capec_dir=None,
        summary_path=summary_path,
    )

    cve_cwe = json.loads((nsfw_dir / "cve_cwe.json").read_text(encoding="utf-8"))
    assert cve_cwe == {"CVE-2021-44228": ["CWE-20"]}

    cwe_capec = json.loads((nsfw_dir / "cwe_capec.json").read_text(encoding="utf-8"))
    assert cwe_capec == {"CWE-20": ["CAPEC-100"]}

    capec_attack = json.loads((nsfw_dir / "capec_attack.json").read_text(encoding="utf-8"))
    assert capec_attack == {"CAPEC-100": ["T1190"]}

    attack_defend = json.loads((nsfw_dir / "attack_defend.json").read_text(encoding="utf-8"))
    assert attack_defend == {"T1190": ["D3-WAF"]}

    cve_cpe = json.loads((nsfw_dir / "cve_cpe.json").read_text(encoding="utf-8"))
    assert cve_cpe == {"CVE-2021-44228": ["CPE:2.3:A:APACHE:LOG4J:*:*:*:*:*:*:*:*"]}

    cve_cvss = json.loads((nsfw_dir / "cve_cvss.json").read_text(encoding="utf-8"))
    assert cve_cvss["CVE-2021-44228"]["cvss_v3_base_score"] == "10.0"

    tactics_techniques = json.loads((nsfw_dir / "tactics_techniques.json").read_text(encoding="utf-8"))
    assert tactics_techniques.get("initial-access") == ["T1190"]

    d3fend_tactics = json.loads((nsfw_dir / "d3fend_tactics.json").read_text(encoding="utf-8"))
    assert d3fend_tactics.get("harden") == ["D3-WAF"]

    kevs_text = (nsfw_dir / "kevs.txt").read_text(encoding="utf-8").strip().splitlines()
    assert "CVE-2021-44228" in kevs_text

    cve_2021 = (cve2capec_dir / "database" / "CVE-2021.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(cve_2021) == 1
    record = json.loads(cve_2021[0])
    assert record["id"] == "CVE-2021-44228"
    assert record["cwe"] == ["CWE-20"]
    assert record["capec"] == ["CAPEC-100"]
    assert record["technique"] == ["T1190"]
    assert record["d3fend"] == ["D3-WAF"]
    assert record["kev"] is True

    cwe_db = json.loads((cve2capec_dir / "resources" / "cwe_db.json").read_text(encoding="utf-8"))
    assert "CWE-20" in cwe_db
    capec_db = json.loads((cve2capec_dir / "resources" / "capec_db.json").read_text(encoding="utf-8"))
    assert "CAPEC-100" in capec_db
    techniques_db = json.loads((cve2capec_dir / "resources" / "techniques_db.json").read_text(encoding="utf-8"))
    assert "T1190" in techniques_db
    techniques_assoc = json.loads((cve2capec_dir / "resources" / "techniques_association.json").read_text(encoding="utf-8"))
    assert techniques_assoc["T1190"]["capec"] == ["CAPEC-100"]
    assert techniques_assoc["T1190"]["d3fend"] == ["D3-WAF"]
    defend_lines = (cve2capec_dir / "resources" / "defend_db.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert any("D3-WAF" in line for line in defend_lines)

    assert (cve2capec_dir / "results" / "new_cves.jsonl").exists()
    assert (cve2capec_dir / "lastUpdate.txt").exists()
    assert summary_path.exists()
    assert summary["counts"]["cve_cwe"] == 1
    assert summary["cve2capec"]["totals"]["cves"] == 1


def test_validate_canonical_passes_for_real_export(tmp_path: Path) -> None:
    bundle_path = tmp_path / "knowledge-bundle.json"
    write_bundle(bundle_path, sample_bundle())
    nsfw_dir = tmp_path / "nsfw"
    cve2capec_dir = tmp_path / "cve2capec"

    EXPORT.build_canonical(
        bundle_path=bundle_path,
        nsfw_dir=nsfw_dir,
        cve2capec_dir=cve2capec_dir,
        ui_nsfw_dir=None,
        ui_cve2capec_dir=None,
        summary_path=None,
    )

    exit_code = VALIDATOR.main(["--nsfw-dir", str(nsfw_dir), "--cve2capec-dir", str(cve2capec_dir)])
    assert exit_code == 0


def test_validate_canonical_detects_missing_files(tmp_path: Path) -> None:
    nsfw_dir = tmp_path / "nsfw"
    cve2capec_dir = tmp_path / "cve2capec"
    nsfw_dir.mkdir()
    cve2capec_dir.mkdir()
    (cve2capec_dir / "database").mkdir()
    (cve2capec_dir / "resources").mkdir()
    (cve2capec_dir / "results").mkdir()

    exit_code = VALIDATOR.main(["--nsfw-dir", str(nsfw_dir), "--cve2capec-dir", str(cve2capec_dir)])
    assert exit_code == 1
