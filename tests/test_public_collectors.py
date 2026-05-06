from __future__ import annotations

import json
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "knowledge_builder" / "public_collectors.py"

SPEC = spec_from_file_location("public_collectors_test", MODULE_PATH)
assert SPEC and SPEC.loader
PUBLIC = module_from_spec(SPEC)
sys.modules[SPEC.name] = PUBLIC
SPEC.loader.exec_module(PUBLIC)


def test_framework_id_normalizers_accept_public_numeric_ids() -> None:
    assert PUBLIC.cwe_id("664") == "CWE-664"
    assert PUBLIC.capec_id("196") == "CAPEC-196"
    assert PUBLIC.attack_id("1134.002") == "T1134.002"


def test_collect_cve2capec_ingests_current_year_database(monkeypatch, tmp_path: Path) -> None:
    payloads = {
        PUBLIC.CVE2CAPEC_LAST_UPDATE_URL: b"2026-05-04T04:11:10.563914+00:00\n",
        PUBLIC.CVE2CAPEC_CWE_DB_URL: json.dumps({
            "664": {"ChildOf": [], "RelatedAttackPatterns": ["196"]},
            "669": {"ChildOf": ["664"], "RelatedAttackPatterns": []},
        }).encode("utf-8"),
        PUBLIC.CVE2CAPEC_CAPEC_DB_URL: json.dumps({
            "196": {
                "name": "Session Credential Falsification through Forging",
                "techniques": "TAXONOMY NAME:ATTACK:ENTRY ID:1134.002:ENTRY NAME:Access Token Manipulation: Create Process with Token::",
            },
        }).encode("utf-8"),
        PUBLIC.CVE2CAPEC_TECHNIQUES_DB_URL: json.dumps({"T1134.002": ["Privilege Escalation"]}).encode("utf-8"),
        PUBLIC.CVE2CAPEC_DEFEND_DB_URL: (
            json.dumps({
                "T1134.002": [
                    {
                        "id": "D3-CCSA",
                        "tactic": "Detect",
                        "technique": "Credential Compromise Scope Analysis",
                        "artifact": "Credential",
                    }
                ]
            })
            + "\n"
        ).encode("utf-8"),
        PUBLIC.CVE2CAPEC_DATABASE_URL.format(year=2026): (
            json.dumps({
                "CVE-2026-31431": {
                    "CWE": ["664", "669"],
                    "CAPEC": ["196"],
                    "TECHNIQUES": ["1134.002"],
                    "DEFEND": [
                        {
                            "id": "D3-CCSA",
                            "tactic": "Detect",
                            "technique": "Credential Compromise Scope Analysis",
                            "artifact": "Credential",
                        }
                    ],
                }
            })
            + "\n"
        ).encode("utf-8"),
    }

    def fake_fetch_bytes(url, cache_path, *, timeout=45, refresh=False, headers=None):
        return payloads[url]

    monkeypatch.setattr(PUBLIC, "fetch_bytes", fake_fetch_bytes)

    result = PUBLIC.collect_cve2capec(tmp_path, years=[2026])

    assert "CVE-2026-31431" in result.nodes
    assert "CWE-664" in result.nodes
    assert "CAPEC-196" in result.nodes
    assert "T1134.002" in result.nodes
    assert "D3-CCSA" in result.nodes
    assert "CVE-2026-31431" in result.route_inputs
    assert ("CVE-2026-31431", "CWE-664", "has_weakness") in result.edges
    assert ("CVE-2026-31431", "CWE-669", "has_weakness") in result.edges
    assert ("CWE-664", "CAPEC-196", "may_enable_attack_pattern") in result.edges
    assert ("CWE-669", "CWE-664", "child_of") in result.edges
    assert ("CAPEC-196", "T1134.002", "may_map_to_attack_technique") in result.edges
    assert ("T1134.002", "D3-CCSA", "may_be_defended_by") in result.edges
