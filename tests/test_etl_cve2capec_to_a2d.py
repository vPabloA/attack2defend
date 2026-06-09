from __future__ import annotations

import gzip
import json
import sys
from argparse import Namespace
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "etl_cve2capec_to_a2d.py"

SPEC = spec_from_file_location("etl_cve2capec_to_a2d_test", MODULE_PATH)
assert SPEC and SPEC.loader
ETL = module_from_spec(SPEC)
sys.modules[SPEC.name] = ETL
SPEC.loader.exec_module(ETL)


def fake_sources() -> tuple[dict[str, object], dict[str, object], dict[str, object], list[dict[str, object]], dict[str, object], dict[int, list[dict[str, object]]], list[str]]:
    cwe_db = {
        "CWE-94": {
            "id": "CWE-94",
            "name": "Improper Control of Generation of Code",
            "description": "Synthetic CWE record for route testing.",
            "url": "https://cwe.mitre.org/data/definitions/94.html",
            "RelatedAttackPatterns": ["CAPEC-242"],
        }
    }
    capec_db = {
        "CAPEC-242": {
            "id": "CAPEC-242",
            "name": "Code Injection",
            "description": "Synthetic CAPEC record for route testing.",
            "url": "https://capec.mitre.org/data/definitions/242.html",
            "techniques": "TAXONOMY NAME:ATTACK:ENTRY ID:1021:ENTRY NAME:Remote Services::",
        }
    }
    atlas_db = {
        "T1059": {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Synthetic ATT&CK technique.",
            "url": "https://attack.mitre.org/techniques/T1059/",
        },
        "T1021": {
            "id": "T1021",
            "name": "Remote Services",
            "description": "Synthetic ATT&CK technique.",
            "url": "https://attack.mitre.org/techniques/T1021/",
        },
    }
    defend_rows = [
        {
            "T1059": [
                {
                    "id": "D3-PSEP",
                    "name": "Process Sandboxing",
                    "technique": "Process Sandboxing",
                    "artifact": "Process",
                    "tactic": "Contain",
                    "url": "https://d3fend.mitre.org/technique/d3f:ProcessSandboxing/",
                }
            ]
        }
    ]
    techniques_association = {
        "T1059": {"capec": [], "d3fend": ["D3-PSEP"]},
        "T1021": {"capec": ["CAPEC-242"], "d3fend": []},
    }
    year_rows = {
        2026: [
            {
                "id": "CVE-2021-44228",
                "name": "Apache Log4j2 JNDI RCE / Log4Shell",
                "description": "Synthetic smoke CVE.",
                "cwe": ["CWE-94"],
                "capec": ["CAPEC-242"],
                "technique": ["T1059"],
                "d3fend": ["D3-PSEP"],
                "kev": True,
                "kev_date_added": "2021-12-10",
                "product": "Log4j",
                "vendor": "Apache",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "published": "2021-12-10T00:00:00Z",
            },
            {
                "id": "CVE-2022-0001",
                "name": "Synthetic candidate route",
                "description": "Synthetic candidate CVE.",
                "cwe": ["CWE-94"],
                "technique": ["T1021"],
                "kev": False,
                "product": "Synthetic",
                "vendor": "ExampleCorp",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0001",
                "published": "2022-01-01T00:00:00Z",
            },
        ]
    }
    source_urls = [
        "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/techniques_association.json",
        "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/atlas_db.json",
        "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/defend_db.jsonl",
        "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/capec_db.json",
        "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/resources/cwe_db.json",
        "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main/database/CVE-2026.jsonl.gz",
    ]
    return cwe_db, capec_db, atlas_db, defend_rows, techniques_association, year_rows, source_urls


def test_load_sources_parses_jsonl_gz_and_lookup_maps(monkeypatch, tmp_path: Path) -> None:
    cwe_db, capec_db, atlas_db, defend_rows, techniques_association, year_rows, source_urls = fake_sources()
    payloads = {
        ETL.URLS["last_update"]: b"2026-06-08T00:00:00Z\n",
        ETL.URLS["techniques_association"]: techniques_association,
        ETL.URLS["atlas_db"]: atlas_db,
        ETL.URLS["cwe_db"]: cwe_db,
        ETL.URLS["capec_db"]: capec_db,
        ETL.URLS["defend_db"]: (json.dumps(defend_rows[0]) + "\n").encode("utf-8"),
        ETL.URLS["year"].format(year=2026): gzip.compress(
            ("\n".join(json.dumps(row) for row in year_rows[2026]) + "\n").encode("utf-8")
        ),
    }

    def fake_fetch_bytes(url, cache_path, *, timeout=45, refresh=False, headers=None):
        value = payloads.get(url)
        assert value is not None, url
        if isinstance(value, bytes):
            return value
        return json.dumps(value).encode("utf-8")

    def fake_fetch_json(url, cache_path, *, timeout=45, refresh=False, headers=None):
        value = payloads.get(url)
        assert value is not None, url
        assert isinstance(value, dict), url
        return value

    monkeypatch.setattr(ETL, "fetch_bytes", fake_fetch_bytes)
    monkeypatch.setattr(ETL, "fetch_json", fake_fetch_json)

    spinner = type("Spinner", (), {"step": lambda self, message: None, "done": lambda self, message: None})()
    loaded = ETL.load_sources(tmp_path / "cache", [2026], False, spinner)
    loaded_cwe_db, loaded_capec_db, loaded_atlas_db, loaded_defend_rows, loaded_assoc, loaded_year_rows, loaded_urls = loaded

    assert loaded_cwe_db["CWE-94"]["name"] == "Improper Control of Generation of Code"
    assert loaded_capec_db["CAPEC-242"]["name"] == "Code Injection"
    assert loaded_atlas_db["T1059"]["name"] == "Command and Scripting Interpreter"
    assert loaded_defend_rows[0]["T1059"][0]["id"] == "D3-PSEP"
    assert loaded_assoc["T1059"]["d3fend"] == ["D3-PSEP"]
    assert loaded_year_rows[2026][0]["id"] == "CVE-2021-44228"
    assert ETL.URLS["year"].format(year=2026) in loaded_urls

    maps = ETL.build_lookup_maps(cwe_db, capec_db, atlas_db, defend_rows, techniques_association)
    assert maps["cwe_to_capec"]["CWE-94"] == ["CAPEC-242"]
    assert maps["capec_to_attack"]["CAPEC-242"] == ["T1021"]
    assert maps["attack_to_d3fend"]["T1059"] == ["D3-PSEP"]


def test_build_bundle_generates_soc_ready_routes(monkeypatch, tmp_path: Path) -> None:
    cwe_db, capec_db, atlas_db, defend_rows, techniques_association, year_rows, source_urls = fake_sources()

    def fake_load_sources(cache_dir, years, refresh, spinner):
        return cwe_db, capec_db, atlas_db, defend_rows, techniques_association, year_rows, source_urls

    monkeypatch.setattr(ETL, "load_sources", fake_load_sources)
    monkeypatch.setattr(ETL, "ThinkerSpinner", lambda: type("Spinner", (), {"step": lambda self, message: None, "done": lambda self, message: None})())

    args = Namespace(
        cache_dir=tmp_path / "cache",
        bundle=tmp_path / "knowledge-bundle.json",
        public_bundle=tmp_path / "public" / "data" / "knowledge-bundle.json",
        last_good=tmp_path / "knowledge-bundle.last-good.json",
        public_last_good=tmp_path / "public" / "data" / "knowledge-bundle.last-good.json",
        start_year=2026,
        end_year=2026,
        years=[2026],
        refresh=False,
        validate_only=False,
    )

    bundle = ETL.build_bundle(args)

    assert bundle["bundle_version"].startswith("v")
    assert bundle["nodes"]
    assert bundle["edges"]
    assert bundle["canonical_chain"]
    assert bundle["reverse_index"]
    assert bundle["stats"]["total_cves_processed"] == 2
    assert bundle["cves"]["CVE-2021-44228"]["review_status"] == "approved"
    assert bundle["cves"]["CVE-2021-44228"]["tier1_readout"]["copy_paste_10_lines"][0] == "CVE: CVE-2021-44228"
    assert bundle["cves"]["CVE-2021-44228"]["soc_action_pack"]["d3fend_controls"]
    edge = next(
        item
        for item in bundle["edges"]
        if item["source"] == "CVE-2021-44228" and item["relationship"] == "vulnerability_has_weakness"
    )
    assert edge["source_feed"] == "canonical_cve2capec"
    assert edge["retrieved_at"] == bundle["generated_at"]
    assert edge["transform_version"].startswith("knowledge_builder:")
    assert edge["deterministic"] is True
    assert edge["inferred"] is False
    assert bundle["reverse_index"]["by_attack"]["T1059"] == ["CVE-2021-44228"]
    assert "CVE-2022-0001" in bundle["reverse_index"]["by_attack"]["T1021"]
    assert any(item["id"] == "CVE-2022-0001" for item in bundle["review_queue"])
    assert ETL.validate_bundle(bundle) == []


def test_build_bundle_accepts_raw_cve2capec_year_rows(monkeypatch, tmp_path: Path) -> None:
    cwe_db, capec_db, atlas_db, defend_rows, techniques_association, _, source_urls = fake_sources()
    raw_year_rows = {
        2026: [
            {
                "CVE-2026-77777": {
                    "CWE": ["CWE-94"],
                    "CAPEC": ["CAPEC-242"],
                    "TECHNIQUES": ["T1059"],
                    "DEFEND": [
                        {
                            "id": "D3-PSEP",
                            "name": "Process Sandboxing",
                            "technique": "Process Sandboxing",
                            "artifact": "Process",
                            "tactic": "Contain",
                            "url": "https://d3fend.mitre.org/technique/d3f:ProcessSandboxing/",
                        }
                    ],
                }
            }
        ]
    }

    def fake_load_sources(cache_dir, years, refresh, spinner):
        return cwe_db, capec_db, atlas_db, defend_rows, techniques_association, raw_year_rows, source_urls

    monkeypatch.setattr(ETL, "load_sources", fake_load_sources)
    monkeypatch.setattr(ETL, "ThinkerSpinner", lambda: type("Spinner", (), {"step": lambda self, message: None, "done": lambda self, message: None})())

    args = Namespace(
        cache_dir=tmp_path / "cache",
        bundle=tmp_path / "knowledge-bundle.json",
        public_bundle=tmp_path / "public" / "data" / "knowledge-bundle.json",
        last_good=tmp_path / "knowledge-bundle.last-good.json",
        public_last_good=tmp_path / "public" / "data" / "knowledge-bundle.last-good.json",
        start_year=2026,
        end_year=2026,
        years=[2026],
        refresh=False,
        validate_only=False,
    )

    bundle = ETL.build_bundle(args)

    assert bundle["stats"]["total_cves_processed"] == 1
    assert "CVE-2026-77777" in bundle["cves"]
    assert bundle["cves"]["CVE-2026-77777"]["canonical_chain"]
    assert bundle["cves"]["CVE-2026-77777"]["review_status"] == "approved"
    assert bundle["reverse_index"]["by_attack"]["T1059"] == ["CVE-2026-77777"]
