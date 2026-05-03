#!/usr/bin/env python3
"""Build NSFW + CVE2CAPEC canonical mapping files from the knowledge bundle.

The Attack2Defend knowledge bundle is the single source of truth. This script
reshapes its nodes/edges into the public file layouts expected by:

* https://github.com/frncscrlnd/nsfw         (data/*.json, kevs.txt)
* https://github.com/Galeax/CVE2CAPEC        (database/CVE-YYYY.jsonl,
                                              resources/*.json[l],
                                              results/new_cves.jsonl,
                                              lastUpdate.txt)

The same data is mirrored into the Navigator UI public folder so the static
NSFW-compatible page can fetch it without backend services.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BUNDLE = REPO_ROOT / "data" / "knowledge-bundle.json"
DEFAULT_NSFW_DIR = REPO_ROOT / "data" / "canonical" / "nsfw"
DEFAULT_CVE2CAPEC_DIR = REPO_ROOT / "data" / "canonical" / "cve2capec"
DEFAULT_UI_NSFW_DIR = REPO_ROOT / "app" / "navigator-ui" / "public" / "nsfw" / "data"
DEFAULT_UI_CVE2CAPEC_DIR = REPO_ROOT / "app" / "navigator-ui" / "public" / "cve2capec"

CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)
CAPEC_RE = re.compile(r"^CAPEC-(\d+)$", re.IGNORECASE)
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
D3FEND_RE = re.compile(r"^D3-[A-Z0-9-]+$", re.IGNORECASE)
CPE_RE = re.compile(r"^CPE:?2\.3", re.IGNORECASE)

EXPORTER_VERSION = "0.1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_bundle(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    if not isinstance(bundle, dict):
        raise ValueError(f"Bundle must be a JSON object: {path}")
    return bundle


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


def write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


def is_kind(node: dict[str, Any], kinds: set[str]) -> bool:
    return str(node.get("type") or "").lower() in kinds


def edge_kind(edge: dict[str, Any], rels: set[str]) -> bool:
    return str(edge.get("relationship") or "").lower() in rels


def cve_year(cve: str) -> str:
    match = CVE_RE.match(cve.strip())
    return match.group(1) if match else "unknown"


def collect_nsfw_mappings(bundle: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Return ID-keyed mapping objects matching the NSFW data file format."""
    cve_cwe: dict[str, set[str]] = defaultdict(set)
    cwe_capec: dict[str, set[str]] = defaultdict(set)
    capec_attack: dict[str, set[str]] = defaultdict(set)
    attack_defend: dict[str, set[str]] = defaultdict(set)
    cve_cpe: dict[str, set[str]] = defaultdict(set)
    tactics_techniques: dict[str, set[str]] = defaultdict(set)
    d3fend_tactics: dict[str, set[str]] = defaultdict(set)

    nodes = {str(n.get("id", "")).upper(): n for n in bundle.get("nodes", []) if isinstance(n, dict)}

    for edge in bundle.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "").upper()
        target = str(edge.get("target") or "").upper()
        rel = str(edge.get("relationship") or "").lower()

        if rel in {"vulnerability_has_weakness", "has_weakness", "has_related_weakness"}:
            if CVE_RE.match(source) and CWE_RE.match(target):
                cve_cwe[source].add(target)
        elif rel in {"weakness_enables_attack_pattern", "may_enable_attack_pattern"}:
            if CWE_RE.match(source) and CAPEC_RE.match(target):
                cwe_capec[source].add(target)
        elif rel in {"attack_pattern_maps_to_technique", "may_map_to_attack_technique"}:
            if CAPEC_RE.match(source) and ATTACK_RE.match(target):
                capec_attack[source].add(target)
        elif rel in {"technique_mitigated_by_countermeasure", "may_be_defended_by"}:
            if ATTACK_RE.match(source) and D3FEND_RE.match(target):
                attack_defend[source].add(target)
        elif rel in {"affects_product_or_platform", "affects_artifact"}:
            target_node = nodes.get(target, {})
            metadata = target_node.get("metadata") if isinstance(target_node.get("metadata"), dict) else {}
            framework = str(metadata.get("framework") or "").lower()
            if CVE_RE.match(source) and (framework == "cpe" or CPE_RE.match(target)):
                cve_cpe[source].add(target)

    # tactics_techniques and d3fend_tactics derived from node metadata.
    for node_id, node in nodes.items():
        node_type = str(node.get("type") or "").lower()
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        if node_type == "attack":
            for phase in metadata.get("kill_chain_phases", []) or []:
                if isinstance(phase, dict):
                    name = str(phase.get("phase_name") or "").strip()
                    if name:
                        tactics_techniques[name].add(node_id)
        if node_type == "d3fend":
            tactic = str(metadata.get("d3fend_tactic") or metadata.get("tactic") or "").strip()
            if tactic:
                d3fend_tactics[tactic].add(node_id)

    def freeze(mapping: dict[str, set[str]]) -> dict[str, list[str]]:
        return {key: sorted(value) for key, value in sorted(mapping.items())}

    return {
        "cve_cwe": freeze(cve_cwe),
        "cwe_capec": freeze(cwe_capec),
        "capec_attack": freeze(capec_attack),
        "attack_defend": freeze(attack_defend),
        "cve_cpe": freeze(cve_cpe),
        "tactics_techniques": freeze(tactics_techniques),
        "d3fend_tactics": freeze(d3fend_tactics),
    }


def collect_kev_list(bundle: dict[str, Any]) -> list[str]:
    indexes = bundle.get("indexes") if isinstance(bundle.get("indexes"), dict) else {}
    kev_index = indexes.get("kev") if isinstance(indexes, dict) else {}
    if isinstance(kev_index, dict) and kev_index:
        return sorted(kev_index.keys())
    kev: set[str] = set()
    for node in bundle.get("nodes", []):
        if not isinstance(node, dict):
            continue
        if str(node.get("type") or "").lower() != "cve":
            continue
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        if metadata.get("kev") is True or metadata.get("kev_status") in {"kev", "known_exploited"}:
            kev.add(str(node.get("id") or "").upper())
    return sorted(item for item in kev if item)


def collect_cve_cvss(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cvss: dict[str, dict[str, Any]] = {}
    for node in bundle.get("nodes", []):
        if not isinstance(node, dict):
            continue
        if str(node.get("type") or "").lower() != "cve":
            continue
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        record: dict[str, Any] = {}
        for key in (
            "cvss_v3",
            "cvss_v3_base_score",
            "cvss_v3_severity",
            "cvss_v2",
            "cvss_v2_base_score",
            "cvss_v2_severity",
        ):
            if metadata.get(key) is not None:
                record[key] = metadata[key]
        if record:
            cvss[str(node.get("id") or "").upper()] = record
    return dict(sorted(cvss.items()))


def write_nsfw_files(target_dir: Path, mappings: dict[str, dict[str, list[str]]], kevs: list[str], cvss: dict[str, dict[str, Any]]) -> list[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    files = {
        "cve_cwe.json": mappings["cve_cwe"],
        "cwe_capec.json": mappings["cwe_capec"],
        "capec_attack.json": mappings["capec_attack"],
        "attack_defend.json": mappings["attack_defend"],
        "cve_cpe.json": mappings["cve_cpe"],
        "cve_cvss.json": cvss,
        "tactics_techniques.json": mappings["tactics_techniques"],
        "d3fend_tactics.json": mappings["d3fend_tactics"],
    }
    for filename, payload in files.items():
        path = target_dir / filename
        write_json(path, payload)
        written.append(path)

    kev_path = target_dir / "kevs.txt"
    write_text(kev_path, "\n".join(kevs) + ("\n" if kevs else ""))
    written.append(kev_path)
    return written


def collect_resource_dbs(bundle: dict[str, Any]) -> dict[str, Any]:
    cwe_db: dict[str, dict[str, Any]] = {}
    capec_db: dict[str, dict[str, Any]] = {}
    techniques_db: dict[str, dict[str, Any]] = {}
    defend_db: list[dict[str, Any]] = []
    techniques_association: dict[str, dict[str, list[str]]] = {}

    for node in bundle.get("nodes", []):
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or "").upper()
        node_type = str(node.get("type") or "").lower()
        if not node_id:
            continue
        record = {
            "id": node_id,
            "name": node.get("name") or node_id,
            "url": node.get("url") or "",
            "description": node.get("description") or "",
        }
        if node_type == "cwe":
            cwe_db[node_id] = record
        elif node_type == "capec":
            capec_db[node_id] = record
        elif node_type == "attack":
            techniques_db[node_id] = record
        elif node_type == "d3fend":
            defend_db.append(record)

    for technique_id, record in techniques_db.items():
        techniques_association.setdefault(technique_id, {"capec": [], "d3fend": []})

    for edge in bundle.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "").upper()
        target = str(edge.get("target") or "").upper()
        rel = str(edge.get("relationship") or "").lower()
        if rel in {"attack_pattern_maps_to_technique", "may_map_to_attack_technique"}:
            if CAPEC_RE.match(source) and ATTACK_RE.match(target):
                techniques_association.setdefault(target, {"capec": [], "d3fend": []})["capec"].append(source)
        elif rel in {"technique_mitigated_by_countermeasure", "may_be_defended_by"}:
            if ATTACK_RE.match(source) and D3FEND_RE.match(target):
                techniques_association.setdefault(source, {"capec": [], "d3fend": []})["d3fend"].append(target)

    for value in techniques_association.values():
        value["capec"] = sorted(set(value.get("capec", [])))
        value["d3fend"] = sorted(set(value.get("d3fend", [])))

    return {
        "cwe_db": dict(sorted(cwe_db.items())),
        "capec_db": dict(sorted(capec_db.items())),
        "techniques_db": dict(sorted(techniques_db.items())),
        "defend_db": sorted(defend_db, key=lambda item: item["id"]),
        "techniques_association": dict(sorted(techniques_association.items())),
    }


def build_cve_records(bundle: dict[str, Any], mappings: dict[str, dict[str, list[str]]]) -> dict[str, list[dict[str, Any]]]:
    records_by_year: dict[str, list[dict[str, Any]]] = defaultdict(list)
    nodes = {str(n.get("id", "")).upper(): n for n in bundle.get("nodes", []) if isinstance(n, dict)}
    cve_cwe = mappings["cve_cwe"]
    cwe_capec = mappings["cwe_capec"]
    capec_attack = mappings["capec_attack"]
    attack_defend = mappings["attack_defend"]
    cve_cpe = mappings["cve_cpe"]

    for cve_id, node in nodes.items():
        if not CVE_RE.match(cve_id):
            continue
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        cwes = cve_cwe.get(cve_id, [])
        capecs = sorted({c for cwe in cwes for c in cwe_capec.get(cwe, [])})
        techniques = sorted({t for capec in capecs for t in capec_attack.get(capec, [])})
        defenses = sorted({d for tech in techniques for d in attack_defend.get(tech, [])})
        record = {
            "id": cve_id,
            "year": cve_year(cve_id),
            "name": node.get("name") or cve_id,
            "description": node.get("description") or "",
            "url": node.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cwe": cwes,
            "capec": capecs,
            "technique": techniques,
            "d3fend": defenses,
            "cpe": cve_cpe.get(cve_id, []),
            "kev": bool(metadata.get("kev")) or metadata.get("kev_status") in {"kev", "known_exploited"},
            "vendor": metadata.get("vendor"),
            "product": metadata.get("product"),
            "kev_date_added": metadata.get("kev_date_added"),
        }
        records_by_year[record["year"]].append(record)

    for year in records_by_year:
        records_by_year[year].sort(key=lambda item: item["id"])
    return dict(sorted(records_by_year.items()))


def write_cve2capec_layout(
    target_dir: Path,
    bundle: dict[str, Any],
    mappings: dict[str, dict[str, list[str]]],
    resources: dict[str, Any],
) -> dict[str, Any]:
    target_dir.mkdir(parents=True, exist_ok=True)
    database_dir = target_dir / "database"
    resources_dir = target_dir / "resources"
    results_dir = target_dir / "results"
    database_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    by_year = build_cve_records(bundle, mappings)
    summary: dict[str, Any] = {"years": {}, "totals": {"cves": 0}}
    for year, records in by_year.items():
        path = database_dir / f"CVE-{year}.jsonl"
        count = write_jsonl(path, records)
        summary["years"][year] = count
        summary["totals"]["cves"] += count

    results_path = results_dir / "new_cves.jsonl"
    new_cves: list[dict[str, Any]] = []
    for records in by_year.values():
        new_cves.extend(records)
    new_cves.sort(key=lambda item: item["id"], reverse=True)
    write_jsonl(results_path, new_cves[:200])

    write_json(resources_dir / "cwe_db.json", resources["cwe_db"])
    write_json(resources_dir / "capec_db.json", resources["capec_db"])
    write_json(resources_dir / "techniques_db.json", resources["techniques_db"])
    write_jsonl(resources_dir / "defend_db.jsonl", resources["defend_db"])
    write_json(resources_dir / "techniques_association.json", resources["techniques_association"])

    last_update_path = target_dir / "lastUpdate.txt"
    write_text(last_update_path, utc_now() + "\n")

    summary["totals"]["new_cves"] = min(len(new_cves), 200)
    summary["resources"] = {key: len(value) for key, value in resources.items()}
    summary["last_update"] = utc_now()
    return summary


def mirror_directory(source_dir: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for source_path in source_dir.rglob("*"):
        if not source_path.is_file():
            continue
        relative = source_path.relative_to(source_dir)
        destination = target_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source_path.read_bytes())


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build NSFW + CVE2CAPEC canonical mapping outputs from the knowledge bundle.")
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--nsfw-dir", type=Path, default=DEFAULT_NSFW_DIR)
    parser.add_argument("--cve2capec-dir", type=Path, default=DEFAULT_CVE2CAPEC_DIR)
    parser.add_argument("--ui-nsfw-dir", type=Path, default=DEFAULT_UI_NSFW_DIR)
    parser.add_argument("--ui-cve2capec-dir", type=Path, default=DEFAULT_UI_CVE2CAPEC_DIR)
    parser.add_argument("--no-ui-mirror", action="store_true")
    parser.add_argument("--summary-path", type=Path, default=None)
    return parser.parse_args(argv)


def build_canonical(
    bundle_path: Path,
    nsfw_dir: Path,
    cve2capec_dir: Path,
    ui_nsfw_dir: Path | None,
    ui_cve2capec_dir: Path | None,
    summary_path: Path | None,
) -> dict[str, Any]:
    bundle = load_bundle(bundle_path)
    mappings = collect_nsfw_mappings(bundle)
    kevs = collect_kev_list(bundle)
    cvss = collect_cve_cvss(bundle)
    resources = collect_resource_dbs(bundle)

    write_nsfw_files(nsfw_dir, mappings, kevs, cvss)
    cve2capec_summary = write_cve2capec_layout(cve2capec_dir, bundle, mappings, resources)

    if ui_nsfw_dir is not None:
        mirror_directory(nsfw_dir, ui_nsfw_dir)
    if ui_cve2capec_dir is not None:
        mirror_directory(cve2capec_dir, ui_cve2capec_dir)

    summary = {
        "exporter_version": EXPORTER_VERSION,
        "generated_at": utc_now(),
        "bundle": str(bundle_path),
        "nsfw_dir": str(nsfw_dir),
        "cve2capec_dir": str(cve2capec_dir),
        "ui_nsfw_dir": str(ui_nsfw_dir) if ui_nsfw_dir else None,
        "ui_cve2capec_dir": str(ui_cve2capec_dir) if ui_cve2capec_dir else None,
        "counts": {
            "cve_cwe": len(mappings["cve_cwe"]),
            "cwe_capec": len(mappings["cwe_capec"]),
            "capec_attack": len(mappings["capec_attack"]),
            "attack_defend": len(mappings["attack_defend"]),
            "cve_cpe": len(mappings["cve_cpe"]),
            "tactics_techniques": len(mappings["tactics_techniques"]),
            "d3fend_tactics": len(mappings["d3fend_tactics"]),
            "kevs": len(kevs),
            "cvss": len(cvss),
        },
        "cve2capec": cve2capec_summary,
    }

    if summary_path is not None:
        write_json(summary_path, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    ui_nsfw_dir = None if args.no_ui_mirror else args.ui_nsfw_dir
    ui_cve2capec_dir = None if args.no_ui_mirror else args.ui_cve2capec_dir
    try:
        summary = build_canonical(
            bundle_path=args.bundle,
            nsfw_dir=args.nsfw_dir,
            cve2capec_dir=args.cve2capec_dir,
            ui_nsfw_dir=ui_nsfw_dir,
            ui_cve2capec_dir=ui_cve2capec_dir,
            summary_path=args.summary_path,
        )
    except Exception as exc:  # noqa: BLE001 - top-level CLI error reporter
        print(f"ERROR: canonical export failed: {exc}", file=sys.stderr)
        return 1
    print(
        "Attack2Defend canonical exports written: "
        f"nsfw={args.nsfw_dir} cve2capec={args.cve2capec_dir} "
        f"counts={summary['counts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
