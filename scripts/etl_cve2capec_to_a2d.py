#!/usr/bin/env python3
"""Build the Attack2Defend SOC-ready bundle from Galeax CVE2CAPEC sources."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import cycle
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from scripts.mapping_builder.apply_mapping_backbone import apply_mapping_backbone as merge_mapping_backbone
from scripts.knowledge_builder.public_collectors import attack_id, capec_id, cwe_id, d3fend_id, fetch_bytes, fetch_json, normalize_id
from attack2defend.runtime_bundle import write_runtime_bundle

BASE_URL = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main"
URLS = {
    "last_update": f"{BASE_URL}/lastUpdate.txt",
    "techniques_association": f"{BASE_URL}/resources/techniques_association.json",
    "atlas_db": f"{BASE_URL}/resources/atlas_db.json",
    "defend_db": f"{BASE_URL}/resources/defend_db.jsonl",
    "capec_db": f"{BASE_URL}/resources/capec_db.json",
    "cwe_db": f"{BASE_URL}/resources/cwe_db.json",
    "year": f"{BASE_URL}/database/CVE-{{year}}.jsonl.gz",
}

SMOKE_CVES = [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2017-0144",
    "CVE-2019-19781",
    "CVE-2023-34362",
    "CVE-2023-3519",
    "CVE-2024-3094",
    "CVE-2023-4966",
    "CVE-2020-1472",
    "CVE-2021-34527",
]

DEFAULT_START_YEAR = 2021
MAX_CHAIN_PER_CVE = 8
MAX_STAGE_VALUES = 4
MAX_TEXT = 180
MAX_BUNDLE_BYTES = 50 * 1024 * 1024
CONTRACT_VERSION = "attack2defend.knowledge_bundle.v2"
BUILDER_VERSION = "etl_cve2capec_to_a2d.1"


@dataclass
class ThinkerSpinner:
    enabled: bool = sys.stdout.isatty()
    frames: tuple[str, ...] = ("◐", "◓", "◑", "◒")
    index: int = 0

    def step(self, message: str) -> None:
        frame = self.frames[self.index % len(self.frames)]
        self.index += 1
        line = f"{frame} Thinker Spinner · {message}"
        if self.enabled:
            sys.stdout.write("\r" + line[:120].ljust(120))
            sys.stdout.flush()
        else:
            print(line)

    def done(self, message: str) -> None:
        if self.enabled:
            sys.stdout.write("\r" + (" " * 120) + "\r")
            sys.stdout.flush()
        print(f"✓ Thinker Spinner · {message}")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shorten(value: Any, limit: int = MAX_TEXT) -> str:
    text = " ".join(str(value or "").split()).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def uniq(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = normalize_id(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def to_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def parse_jsonl_bytes(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def year_range(start_year: int, end_year: int) -> list[int]:
    return [year for year in range(start_year, end_year + 1) if year > 0]


def normalize_cve2capec_year_row(row: dict[str, Any], *, source_year: int, source_file: str) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None

    normalized_id = normalize_id(row.get("id"))
    if normalized_id.startswith("CVE-"):
        normalized = dict(row)
        normalized["id"] = normalized_id
        normalized["source_year"] = source_year
        normalized["source_file"] = source_file
        return normalized

    cve_keys = [normalize_id(key) for key, value in row.items() if isinstance(key, str) and normalize_id(key).startswith("CVE-") and isinstance(value, dict)]
    if len(cve_keys) != 1:
        return None

    cve_id = cve_keys[0]
    record = dict(row.get(cve_id, {}))
    if not record:
        return None
    record["id"] = cve_id
    record["source_year"] = source_year
    record["source_file"] = source_file
    return record


def node_type_from_id(node_id: str) -> str:
    text = normalize_id(node_id)
    if text.startswith("CVE-"):
        return "cve"
    if text.startswith("CWE-"):
        return "cwe"
    if text.startswith("CAPEC-"):
        return "capec"
    if text.startswith("T") and len(text) >= 5 and text[1:5].isdigit():
        return "attack"
    if text.startswith("D3-"):
        return "d3fend"
    if text.startswith("CTRL-"):
        return "control"
    if text.startswith("DET-"):
        return "detection"
    if text.startswith("EV-"):
        return "evidence"
    if text.startswith("GAP-"):
        return "gap"
    if text.startswith("ACT-"):
        return "action"
    return "artifact"


def first_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item
    return ""


def extract_attack_ids(raw_value: Any) -> list[str]:
    text = str(raw_value or "")
    tokens: list[str] = []
    marker = "ENTRY ID:"
    cursor = 0
    while True:
        index = text.find(marker, cursor)
        if index < 0:
            break
        start = index + len(marker)
        end = start
        while end < len(text) and (text[end].isalnum() or text[end] in {".", "_"}):
            end += 1
        candidate = attack_id(text[start:end])
        if candidate:
            tokens.append(candidate)
        cursor = end
    if not tokens and text.strip():
        candidate = attack_id(text.strip())
        if candidate:
            tokens.append(candidate)
    return uniq(tokens)


def extract_d3fend_ids(raw_value: Any) -> list[str]:
    tokens: list[str] = []
    for item in to_list(raw_value):
        if isinstance(item, dict):
            candidate = d3fend_id(item.get("id") or item.get("d3fend_id") or item.get("technique_id") or item.get("external_id"))
            if candidate:
                tokens.append(candidate)
            continue
        candidate = d3fend_id(item)
        if candidate:
            tokens.append(candidate)
    return uniq(tokens)


def flatten_atlas_entries(payload: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        return {}
    result: dict[str, list[dict[str, Any]]] = {}
    for raw_id, entries in payload.items():
        attack = attack_id(raw_id)
        if not attack:
            continue
        normalized: list[dict[str, Any]] = []
        raw_entries = entries if isinstance(entries, list) else [entries]
        for entry in raw_entries:
            if not isinstance(entry, dict):
                if isinstance(entry, str) and entry.strip():
                    normalized.append(
                        {
                            "id": attack,
                            "name": shorten(entry, 120),
                            "url": f"https://attack.mitre.org/techniques/{attack.replace('.', '/')}/",
                            "tactics": [],
                        }
                    )
                continue
            normalized.append(
                {
                    "id": attack_id(entry.get("id")) or attack,
                    "name": shorten(entry.get("name") or attack),
                    "url": str(entry.get("url") or ""),
                    "tactics": [str(item) for item in entry.get("tactics", []) if str(item).strip()] if isinstance(entry.get("tactics"), list) else [],
                }
            )
        if normalized:
            result[attack] = normalized
    return result


def flatten_attack_controls(payload: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        return {}
    result: dict[str, list[dict[str, Any]]] = {}
    for raw_attack, entries in payload.items():
        attack = attack_id(raw_attack)
        if not attack or not isinstance(entries, list):
            continue
        normalized: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            did = d3fend_id(entry.get("id"))
            if not did:
                continue
            normalized.append(
                {
                    "id": did,
                    "name": shorten(entry.get("technique") or entry.get("name") or did),
                    "tactic": shorten(entry.get("tactic") or ""),
                    "artifact": shorten(entry.get("artifact") or ""),
                }
            )
        if normalized:
            result[attack] = normalized
    return result


class BundleBuilder:
    def __init__(self, *, generated_at: str) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.cves: dict[str, dict[str, Any]] = {}
        self.routes: list[dict[str, Any]] = []
        self.review_queue: list[dict[str, Any]] = []
        self.canonical_chain: list[dict[str, Any]] = []
        self.coverage: dict[str, dict[str, Any]] = {}
        self.reverse_index: dict[str, dict[str, set[str]]] = {
            "by_cwe": defaultdict(set),
            "by_capec": defaultdict(set),
            "by_attack": defaultdict(set),
            "by_d3fend": defaultdict(set),
        }
        self.indexes: dict[str, Any] = {
            "by_type": defaultdict(list),
            "outgoing": defaultdict(list),
            "incoming": defaultdict(list),
            "search": [],
            "forward": {
                "cve_to_cwe": defaultdict(list),
                "cve_to_cpe": defaultdict(list),
                "cwe_to_capec": defaultdict(list),
                "capec_to_attack": defaultdict(list),
                "attack_to_d3fend": defaultdict(list),
            },
            "reverse": {
                "cwe_to_cve": defaultdict(list),
                "cpe_to_cve": defaultdict(list),
                "capec_to_cwe": defaultdict(list),
                "attack_to_capec": defaultdict(list),
                "d3fend_to_attack": defaultdict(list),
            },
            "cpe_to_cve": defaultdict(list),
            "kev": {},
            "route_inputs": [],
            "relationships": defaultdict(int),
        }
        self.metadata_sources: list[str] = []
        self.source_files: list[str] = []
        self.warnings: list[str] = []
        self.smoke_hits: set[str] = set()
        self.generated_at = generated_at

    def add_node(self, node_id: str, node_type: str, name: str, description: str = "", url: str = "", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        node_id = normalize_id(node_id)
        node_type = str(node_type).lower().strip() or node_type_from_id(node_id)
        existing = self.nodes.get(node_id, {})
        merged = dict(existing)
        merged.update({"id": node_id, "type": node_type, "name": shorten(name or node_id, 120)})
        if description:
            merged["description"] = shorten(description, 220)
        if url:
            merged["url"] = str(url)
        current_metadata = dict(existing.get("metadata", {})) if isinstance(existing.get("metadata"), dict) else {}
        if metadata:
            current_metadata.update({k: v for k, v in metadata.items() if v not in (None, "", [], {})})
        if current_metadata:
            merged["metadata"] = current_metadata
        self.nodes[node_id] = merged
        return merged

    def add_edge(self, source: str, target: str, relationship: str, *, confidence: str = "high", provenance: str = "canonical", review_status: str = "approved", source_ref: str = "canonical:cve2capec", source_kind: str = "canonical") -> dict[str, Any]:
        source = normalize_id(source)
        target = normalize_id(target)
        relationship = str(relationship).strip().lower()
        if not source or not target or not relationship:
            raise ValueError("Broken edge")
        canonical_provenance = str(provenance or "").strip().lower() == "canonical"
        inferred = review_status != "approved" or not canonical_provenance
        edge = {
            "source": source,
            "target": target,
            "relationship": relationship,
            "confidence": confidence,
            "provenance": provenance,
            "review_status": review_status,
            "source_ref": source_ref,
            "source_kind": source_kind,
            "source_feed": "canonical_cve2capec",
            "retrieved_at": self.generated_at,
            "transform_version": f"knowledge_builder:{BUILDER_VERSION}",
            "deterministic": True,
            "inferred": inferred,
        }
        key = (source, target, relationship)
        self.edges[key] = edge
        self.indexes["outgoing"][source].append({"target": target, "relationship": relationship})
        self.indexes["incoming"][target].append({"source": source, "relationship": relationship})
        self.indexes["relationships"][relationship] += 1
        return edge

    def add_reverse(self, cve_id: str, chain: dict[str, Any]) -> None:
        cve_id = normalize_id(cve_id)
        for key in ("cwe", "capec", "attack", "d3fend"):
            value = chain.get(key)
            if not value:
                continue
            self.reverse_index[f"by_{key}"][normalize_id(value)].add(cve_id)

    def add_search_entry(self, node_id: str, node_type: str, name: str, text: str) -> None:
        self.indexes["search"].append({"id": node_id, "type": node_type, "name": name, "text": text})

    def route_counts(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "cves": len(self.cves),
            "routes": len(self.routes),
            "canonical_chains": len(self.canonical_chain),
            "review_queue": len(self.review_queue),
        }

    def stage_candidates(self, direct: list[str], derived: list[str]) -> list[str]:
        return uniq(direct + derived)[:MAX_STAGE_VALUES] or []

    def build_chains(
        self,
        cve_id: str,
        cwe_values: list[str],
        capec_values: list[str],
        attack_values: list[str],
        d3fend_values: list[str],
        cwe_to_capec: dict[str, list[str]],
        capec_to_attack: dict[str, list[str]],
        attack_to_d3fend: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        cwe_candidates = self.stage_candidates(cwe_values, [])
        if not cwe_candidates:
            cwe_candidates = [""]
        chains: dict[tuple[str, str, str, str], dict[str, Any]] = {}

        for cwe in cwe_candidates:
            capec_candidates = self.stage_candidates(capec_values, cwe_to_capec.get(cwe, []))
            if not capec_candidates:
                capec_candidates = [""]
            for capec in capec_candidates:
                attack_candidates = self.stage_candidates(attack_values, capec_to_attack.get(capec, []))
                if not attack_candidates:
                    attack_candidates = [""]
                for attack in attack_candidates:
                    d3_candidates = self.stage_candidates(d3fend_values, attack_to_d3fend.get(attack, []))
                    if not d3_candidates:
                        d3_candidates = [""]
                    for d3 in d3_candidates:
                        key = (normalize_id(cwe), normalize_id(capec), normalize_id(attack), normalize_id(d3))
                        score = 0
                        if cwe:
                            score += 10
                        if capec:
                            score += 20
                        if attack:
                            score += 30
                        if d3:
                            score += 40
                        if cwe and cwe in cwe_values:
                            score += 4
                        if capec and capec in capec_values:
                            score += 4
                        if attack and attack in attack_values:
                            score += 4
                        if d3 and d3 in d3fend_values:
                            score += 4
                        complete = bool(cwe and capec and attack and d3)
                        if complete:
                            score += 100
                        if not any(key):
                            continue
                        current = chains.get(key)
                        if current and current["score"] >= score:
                            continue
                        chains[key] = {
                            "cve": cve_id,
                            "cwe": normalize_id(cwe) or None,
                            "capec": normalize_id(capec) or None,
                            "attack": normalize_id(attack) or None,
                            "d3fend": normalize_id(d3) or None,
                            "provenance": "canonical",
                            "confidence": "high" if complete else "medium" if score >= 40 else "low",
                            "review_status": "approved" if complete else "candidate",
                            "score": score,
                        }
        chains_list = sorted(chains.values(), key=lambda item: (-int(item["score"]), item.get("cwe") or "", item.get("capec") or "", item.get("attack") or "", item.get("d3fend") or ""))
        return [{k: v for k, v in chain.items() if k != "score"} for chain in chains_list[:MAX_CHAIN_PER_CVE]]

    def route_nodes_for_chain(self, chain: dict[str, Any]) -> list[str]:
        ids = [chain.get("cve"), chain.get("cwe"), chain.get("capec"), chain.get("attack"), chain.get("d3fend")]
        return [normalize_id(item) for item in ids if normalize_id(item)]

    def build_soc_action_pack(self, record: dict[str, Any], chains: list[dict[str, Any]], node_maps: dict[str, dict[str, Any]]) -> dict[str, Any]:
        cve_id = normalize_id(record["id"])
        attack_ids = uniq(
            [chain.get("attack") for chain in chains if chain.get("attack")]
            + to_list(record.get("technique"))
            + to_list(record.get("TECHNIQUES"))
            + to_list(record.get("techniques"))
            + to_list(record.get("ATTACK"))
            + to_list(record.get("attack"))
        )
        d3_ids = uniq(
            [chain.get("d3fend") for chain in chains if chain.get("d3fend")]
            + extract_d3fend_ids(record.get("d3fend"))
            + extract_d3fend_ids(record.get("DEFEND"))
        )
        capec_ids = uniq([chain.get("capec") for chain in chains if chain.get("capec")] + to_list(record.get("capec")) + to_list(record.get("CAPEC")))
        cwe_ids = uniq([chain.get("cwe") for chain in chains if chain.get("cwe")] + to_list(record.get("cwe")) + to_list(record.get("CWE")) + to_list(record.get("weakness")))

        attack_techniques: list[dict[str, Any]] = []
        for attack in attack_ids[:4]:
            attack_techniques.append(
                {
                    "id": attack,
                    "name": node_maps["attack"].get(attack, {}).get("name", attack),
                    "justification": f"Canonical mapping from {cve_id} to ATT&CK technique {attack}.",
                    "provenance": "canonical",
                    "confidence": "high" if attack in record.get("technique", []) else "medium",
                    "review_status": "approved" if attack in record.get("technique", []) else "candidate",
                }
            )

        d3fend_controls: list[dict[str, Any]] = []
        for attack in attack_ids[:3]:
            controls = node_maps["attack_to_d3fend"].get(attack, [])[:3]
            for d3 in controls:
                d3fend_controls.append(
                    {
                        "id": d3,
                        "name": node_maps["d3fend"].get(d3, {}).get("name", d3),
                        "justification": f"{attack} is mitigated by {node_maps['d3fend'].get(d3, {}).get('name', d3)}.",
                        "provenance": "canonical",
                        "confidence": "high",
                        "review_status": "approved",
                    }
                )
        if not d3fend_controls:
            d3fend_controls = [
                {
                    "id": "D3-AI",
                    "name": "Asset Inventory",
                    "justification": "Generic control when no direct D3FEND mapping is available.",
                    "provenance": "inferred",
                    "confidence": "medium",
                    "review_status": "candidate",
                },
                {
                    "id": "D3-NTF",
                    "name": "Network Traffic Filtering",
                    "justification": "Generic control when no direct D3FEND mapping is available.",
                    "provenance": "inferred",
                    "confidence": "medium",
                    "review_status": "candidate",
                },
                {
                    "id": "D3-SU",
                    "name": "Software Update",
                    "justification": "Generic control when no direct D3FEND mapping is available.",
                    "provenance": "inferred",
                    "confidence": "medium",
                    "review_status": "candidate",
                },
            ]

        compensating_controls = [
            ("patch/upgrade", "Apply vendor updates or upgrade the exposed product."),
            ("virtual patching/WAF", "Use filtering or virtual patching on exposed surfaces."),
            ("hardening", "Remove or disable unused surface area and reduce privilege."),
            ("exposure reduction", "Reduce public exposure to the affected service or component."),
            ("segmentation", "Limit lateral reach and isolate the affected asset."),
            ("monitoring", "Increase visibility for the affected service path."),
            ("logging", "Preserve and centralize event and access records."),
            ("exploit pattern detection", "Track request or process patterns aligned with the mapped ATT&CK technique."),
        ]
        compact_controls = [
            {
                "id": f"COMP-{cve_id}-{index + 1}",
                "label": label,
                "text": text,
                "provenance": "inferred",
                "confidence": "medium",
                "review_status": "candidate",
            }
            for index, (label, text) in enumerate(compensating_controls[:5])
        ]

        evidence_to_review = evidence_templates_for_record(record, attack_ids, capec_ids, cwe_ids)
        detection_rules = detection_templates_for_record(record, attack_ids, capec_ids)
        gaps = gap_templates_for_record(record, attack_ids, d3fend_controls, detection_rules, evidence_to_review)
        ioc_candidates = ioc_templates_for_record(record, attack_ids, capec_ids, cwe_ids)
        risk_acceptance_matrix = [
            {
                "id": f"RISK-{cve_id}-PATCH",
                "label": "Patch/upgrade minimum",
                "minimum_controls": ["Patch/upgrade", "Monitoring", "Logging"],
                "rationale": "Keep the product updated and visible while the route remains active.",
                "provenance": "inferred",
                "confidence": "medium",
                "review_status": "candidate",
            },
            {
                "id": f"RISK-{cve_id}-EDGE",
                "label": "Edge protection minimum",
                "minimum_controls": ["Virtual patching/WAF", "Exposure reduction", "Segmentation"],
                "rationale": "Use edge protection and reduce direct exposure if patching is delayed.",
                "provenance": "inferred",
                "confidence": "medium",
                "review_status": "candidate",
            },
        ]
        if not any(chain.get("review_status") == "approved" for chain in chains):
            gaps.insert(
                0,
                {
                    "id": f"GAP-{cve_id}-ROUTE",
                    "label": "Route gap",
                    "text": "No complete canonical route was produced for this CVE.",
                    "provenance": "canonical",
                    "confidence": "high",
                    "review_status": "candidate",
                },
            )

        return {
            "attack_techniques": attack_techniques,
            "d3fend_controls": d3fend_controls[:3],
            "compensating_controls": compact_controls,
            "detection_rules": detection_rules,
            "evidence_to_review": evidence_to_review,
            "ioc_candidates": ioc_candidates,
            "gaps": gaps,
            "risk_acceptance_matrix": risk_acceptance_matrix,
        }

    def build_tier1_readout(self, record: dict[str, Any], pack: dict[str, Any], associated_cves: list[str], chains: list[dict[str, Any]]) -> dict[str, Any]:
        cve_id = normalize_id(record["id"])
        top_attack = pack["attack_techniques"][0]["id"] if pack["attack_techniques"] else "n/a"
        top_attack_name = pack["attack_techniques"][0]["name"] if pack["attack_techniques"] else "n/a"
        d3_names = ", ".join(item["name"] for item in pack["d3fend_controls"][:3]) or "n/a"
        evidence = ", ".join(item["text"] for item in pack["evidence_to_review"][:2]) or "n/a"
        controls = ", ".join(item["text"] for item in pack["compensating_controls"][:2]) or "n/a"
        detection = ", ".join(item["text"] for item in pack["detection_rules"][:2]) or "n/a"
        gaps = ", ".join(item["text"] for item in pack["gaps"][:2]) or "No explicit gaps."
        risk = pack["risk_acceptance_matrix"][0]["rationale"] if pack["risk_acceptance_matrix"] else "n/a"
        severity = derive_severity(record, chains)
        copy_block = [
            f"CVE: {cve_id}",
            f"Severity: {severity}",
            f"Likely ATT&CK: {top_attack} - {top_attack_name}",
            f"Defensive mapping: {d3_names}",
            f"Evidence to review: {evidence}",
            f"Compensating controls: {controls}",
            f"Detection guidance: {detection}",
            f"Known gaps: {gaps}",
            f"Escalate if: {gaps}",
            f"Risk acceptance: {risk}",
        ]
        return {
            "title": f"Tier 1 Analyst Readout · {cve_id}",
            "summary": f"{record.get('name') or cve_id}: {top_attack_name} with {len(pack['d3fend_controls'])} D3FEND controls.",
            "bullets": [
                shorten(record.get("description") or record.get("name") or cve_id, 200),
                f"Route status: {chains[0]['review_status'] if chains else 'candidate'}",
                f"Associated CVEs: {', '.join(associated_cves[:5]) if associated_cves else 'none'}",
            ],
            "severity": severity,
            "cvss": record.get("cvss"),
            "vector": extract_vector(record.get("cvss")),
            "confidence": chains[0].get("confidence") if chains else "unknown",
            "provenance": "canonical",
            "review_status": "approved" if any(chain.get("review_status") == "approved" for chain in chains) else "candidate",
            "mode": "cve",
            "associated_cves": associated_cves[:5],
            "attack_techniques": pack["attack_techniques"],
            "d3fend_controls": pack["d3fend_controls"],
            "compensating_controls": pack["compensating_controls"],
            "detection_guidance": pack["detection_rules"],
            "evidence_to_review": pack["evidence_to_review"],
            "gaps": pack["gaps"],
            "risk_acceptance_matrix": pack["risk_acceptance_matrix"],
            "copy_paste_10_lines": copy_block[:10],
            "checklist": checklist_for_record(record, associated_cves, pack, severity),
            "escalation_criteria": escalation_for_record(record, pack),
            "source_ref": record.get("source_file") or "canonical:cve2capec",
        }

    def record_cve(
        self,
        record: dict[str, Any],
        *,
        source_year: int,
        source_file: str,
        cwe_to_capec: dict[str, list[str]],
        capec_to_attack: dict[str, list[str]],
        attack_to_d3fend: dict[str, list[str]],
        node_maps: dict[str, dict[str, Any]],
    ) -> None:
        cve_id = normalize_id(record.get("id"))
        if not cve_id:
            return
        name = shorten(record.get("name") or cve_id, 120)
        description = shorten(record.get("description") or name, 220)
        severity = derive_severity(record, [])
        cwe_values = uniq(to_list(record.get("cwe")) + to_list(record.get("CWE")) + to_list(record.get("weakness")))
        capec_values = uniq(to_list(record.get("capec")) + to_list(record.get("CAPEC")))
        attack_values = uniq(
            to_list(record.get("technique"))
            + to_list(record.get("TECHNIQUES"))
            + to_list(record.get("techniques"))
            + to_list(record.get("ATTACK"))
            + to_list(record.get("attack"))
        )
        d3fend_values = uniq(extract_d3fend_ids(record.get("d3fend")) + extract_d3fend_ids(record.get("DEFEND")))

        self.add_node(
            cve_id,
            "cve",
            name,
            description,
            record.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            {
                "year": source_year,
                "vendor": record.get("vendor"),
                "product": record.get("product"),
                "kev": bool(record.get("kev")),
                "kev_date_added": record.get("kev_date_added"),
                "route_count": 0,
                "source_ref": source_file,
            },
        )

        chains = self.build_chains(cve_id, cwe_values, capec_values, attack_values, d3fend_values, cwe_to_capec, capec_to_attack, attack_to_d3fend)
        if not chains:
            chains = [
                {
                    "cve": cve_id,
                    "cwe": cwe_values[0] if cwe_values else None,
                    "capec": capec_values[0] if capec_values else None,
                    "attack": attack_values[0] if attack_values else None,
                    "d3fend": d3fend_values[0] if d3fend_values else None,
                    "provenance": "canonical",
                    "confidence": "low",
                    "review_status": "candidate",
                }
            ]

        for chain in chains:
            self.canonical_chain.append(chain)
            self.add_reverse(cve_id, chain)
            self.add_search_entry(cve_id, "cve", name, f"{name} {description}")
            if chain.get("cwe"):
                self.add_node(chain["cwe"], "cwe", node_maps["cwe"].get(chain["cwe"], {}).get("name", chain["cwe"]), node_maps["cwe"].get(chain["cwe"], {}).get("description", ""), node_maps["cwe"].get(chain["cwe"], {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
                self.add_edge(cve_id, chain["cwe"], "vulnerability_has_weakness", confidence=chain["confidence"], provenance=chain["provenance"], review_status=chain["review_status"], source_ref=source_file)
                self.indexes["forward"]["cve_to_cwe"][cve_id].append(chain["cwe"])
                self.indexes["reverse"]["cwe_to_cve"][chain["cwe"]].append(cve_id)
            if chain.get("capec"):
                self.add_node(chain["capec"], "capec", node_maps["capec"].get(chain["capec"], {}).get("name", chain["capec"]), node_maps["capec"].get(chain["capec"], {}).get("description", ""), node_maps["capec"].get(chain["capec"], {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
                source = chain.get("cwe") or cve_id
                self.add_edge(source, chain["capec"], "weakness_enables_attack_pattern" if chain.get("cwe") else "may_enable_attack_pattern", confidence=chain["confidence"], provenance=chain["provenance"], review_status=chain["review_status"], source_ref=source_file)
                if chain.get("cwe"):
                    self.indexes["forward"]["cwe_to_capec"][chain["cwe"]].append(chain["capec"])
                    self.indexes["reverse"]["capec_to_cwe"][chain["capec"]].append(chain["cwe"])
            if chain.get("attack"):
                self.add_node(chain["attack"], "attack", node_maps["attack"].get(chain["attack"], {}).get("name", chain["attack"]), node_maps["attack"].get(chain["attack"], {}).get("description", ""), node_maps["attack"].get(chain["attack"], {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
                source = chain.get("capec") or cve_id
                self.add_edge(source, chain["attack"], "attack_pattern_maps_to_technique" if chain.get("capec") else "may_map_to_attack_technique", confidence=chain["confidence"], provenance=chain["provenance"], review_status=chain["review_status"], source_ref=source_file)
                if chain.get("capec"):
                    self.indexes["forward"]["capec_to_attack"][chain["capec"]].append(chain["attack"])
                    self.indexes["reverse"]["attack_to_capec"][chain["attack"]].append(chain["capec"])
            if chain.get("d3fend"):
                self.add_node(chain["d3fend"], "d3fend", node_maps["d3fend"].get(chain["d3fend"], {}).get("name", chain["d3fend"]), node_maps["d3fend"].get(chain["d3fend"], {}).get("description", ""), node_maps["d3fend"].get(chain["d3fend"], {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
                source = chain.get("attack") or cve_id
                self.add_edge(source, chain["d3fend"], "technique_mitigated_by_countermeasure" if chain.get("attack") else "may_be_defended_by", confidence=chain["confidence"], provenance=chain["provenance"], review_status=chain["review_status"], source_ref=source_file)
                if chain.get("attack"):
                    self.indexes["forward"]["attack_to_d3fend"][chain["attack"]].append(chain["d3fend"])
                    self.indexes["reverse"]["d3fend_to_attack"][chain["d3fend"]].append(chain["attack"])

        pack = self.build_soc_action_pack(record, chains, node_maps)
        associated_cves = []
        top_chain = chains[0]
        for bucket_key, value in (
            ("by_cwe", top_chain.get("cwe")),
            ("by_capec", top_chain.get("capec")),
            ("by_attack", top_chain.get("attack")),
            ("by_d3fend", top_chain.get("d3fend")),
        ):
            if value:
                associated_cves.extend(sorted(self.reverse_index[bucket_key][normalize_id(value)] - {cve_id}))
        associated_cves = uniq(associated_cves)
        readout = self.build_tier1_readout(record, pack, associated_cves[:5], chains)

        cve_record = {
            "id": cve_id,
            "type": "cve",
            "label": cve_id,
            "description": description,
            "severity": severity,
            "cvss": record.get("cvss"),
            "published": record.get("published"),
            "provenance": "canonical",
            "confidence": "high" if any(chain.get("review_status") == "approved" for chain in chains) else "medium",
            "review_status": "approved" if any(chain.get("review_status") == "approved" for chain in chains) else "candidate",
            "canonical_chain": chains,
            "soc_action_pack": pack,
            "tier1_readout": readout,
            "source_year": source_year,
            "route_count": len(chains),
            "vendor": record.get("vendor"),
            "product": record.get("product"),
            "kev": bool(record.get("kev")),
        }
        self.cves[cve_id] = cve_record
        self.nodes[cve_id]["metadata"]["route_count"] = len(chains)
        self.routes.append(
            {
                "id": f"route-{cve_id.lower()}",
                "input": cve_id,
                "name": record.get("name") or cve_id,
                "curation_status": cve_record["review_status"],
                "notes": readout["summary"],
                "file": source_file,
            }
        )
        self.coverage[cve_id] = {
            "status": "covered" if cve_record["review_status"] == "approved" else "partial" if chains else "missing",
            "controls": [item["id"] for item in pack["d3fend_controls"][:3]],
            "detections": [item["id"] for item in pack["detection_rules"][:3]],
            "evidence": [item["id"] for item in pack["evidence_to_review"][:3]],
            "gaps": [item["id"] for item in pack["gaps"][:3]],
            "owners": ["Vulnerability Management", "SOC", "Detection Engineering"],
        }
        if cve_id in SMOKE_CVES:
            self.smoke_hits.add(cve_id)
        if cve_record["review_status"] != "approved":
            self.review_queue.append(
                {
                    "id": cve_id,
                    "label": record.get("name") or cve_id,
                    "review_status": cve_record["review_status"],
                    "provenance": "canonical" if chains else "inferred",
                    "confidence": cve_record["confidence"],
                    "reason": readout["summary"],
                    "cve_count": 1,
                    "route_count": len(chains),
                    "focus": cve_id,
                }
            )

        self.indexes["route_inputs"].append(cve_id)
        self.indexes["kev"][cve_id] = {
            "vendor": record.get("vendor"),
            "product": record.get("product"),
            "date_added": record.get("kev_date_added"),
            "required_action": record.get("required_action"),
        } if record.get("kev") else {}
        self.add_search_entry(cve_id, "cve", record.get("name") or cve_id, f"{record.get('name') or cve_id} {description}")

        for cwe in cwe_values:
            self.add_node(cwe, "cwe", node_maps["cwe"].get(cwe, {}).get("name", cwe), node_maps["cwe"].get(cwe, {}).get("description", ""), node_maps["cwe"].get(cwe, {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
        for capec in capec_values:
            self.add_node(capec, "capec", node_maps["capec"].get(capec, {}).get("name", capec), node_maps["capec"].get(capec, {}).get("description", ""), node_maps["capec"].get(capec, {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
        for attack in attack_values:
            self.add_node(attack, "attack", node_maps["attack"].get(attack, {}).get("name", attack), node_maps["attack"].get(attack, {}).get("description", ""), node_maps["attack"].get(attack, {}).get("url", ""), {"source_ref": "canonical:cve2capec"})
        for d3 in d3fend_values:
            self.add_node(d3, "d3fend", node_maps["d3fend"].get(d3, {}).get("name", d3), node_maps["d3fend"].get(d3, {}).get("description", ""), node_maps["d3fend"].get(d3, {}).get("url", ""), {"source_ref": "canonical:cve2capec"})

    def finalize(self, *, source_urls: list[str], generated_at: str, source_years: list[int], warnings: list[str]) -> dict[str, Any]:
        node_list = sorted(self.nodes.values(), key=lambda item: (item["type"], item["id"]))
        edge_list = sorted(self.edges.values(), key=lambda item: (item["source"], item["relationship"], item["target"]))
        reverse_index = {key: {inner_key: sorted(values) for inner_key, values in sorted(bucket.items())} for key, bucket in self.reverse_index.items()}
        by_type = {node_type: sorted(node_id for node_id, node in self.nodes.items() if node.get("type") == node_type) for node_type in sorted({node.get("type", "") for node in node_list})}
        search_entries = sorted(self.indexes["search"], key=lambda item: (item["type"], item["id"]))
        forward = {key: {inner: sorted(values) for inner, values in sorted(bucket.items())} for key, bucket in self.indexes["forward"].items()}
        reverse = {key: {inner: sorted(values) for inner, values in sorted(bucket.items())} for key, bucket in self.indexes["reverse"].items()}
        cpe_to_cve = {key: sorted(values) for key, values in sorted(self.indexes["cpe_to_cve"].items())}
        kev = {key: value for key, value in sorted(self.indexes["kev"].items()) if value}
        indexes = {
            "by_type": by_type,
            "outgoing": {key: value for key, value in sorted(self.indexes["outgoing"].items())},
            "incoming": {key: value for key, value in sorted(self.indexes["incoming"].items())},
            "search": search_entries,
            "forward": forward,
            "reverse": reverse,
            "route_inputs": sorted(set(self.indexes["route_inputs"])),
            "cpe_to_cve": cpe_to_cve,
            "kev": kev,
            "relationships": {key: self.indexes["relationships"][key] for key in sorted(self.indexes["relationships"])},
        }
        stats = {
            "total_cves_processed": len(self.cves),
            "total_nodes": len(node_list),
            "total_edges": len(edge_list),
            "total_canonical_chains": len(self.canonical_chain),
            "cves_with_complete_route": sum(1 for cve in self.cves.values() if cve["review_status"] == "approved"),
            "cves_without_route": sum(1 for cve in self.cves.values() if not cve["canonical_chain"]),
            "cves_with_candidate_route": sum(1 for cve in self.cves.values() if cve["review_status"] != "approved"),
            "review_queue_size": len(self.review_queue),
            "smoke_test_hits": len(self.smoke_hits),
            "smoke_test_warnings": len([item for item in warnings if "smoke" in item.lower()]),
            "source_years": source_years,
        }
        metadata = {
            "contract_version": CONTRACT_VERSION,
            "builder_version": BUILDER_VERSION,
            "generated_at": generated_at,
            "mode": "cve2capec_soc_ready",
            "counts": {
                "nodes": len(node_list),
                "edges": len(edge_list),
                "cves": len(self.cves),
                "routes": len(self.routes),
                "canonical_chains": len(self.canonical_chain),
                "review_queue": len(self.review_queue),
            },
            "public_sources": source_urls,
            "source_files": self.source_files,
            "seed_inputs": {"required": list(SMOKE_CVES), "available": sorted(self.smoke_hits)},
            "warnings": warnings,
            "public_collection": {"enabled": True, "source": "CVE2CAPEC"},
        }
        bundle = {
            "bundle_version": f"v{generated_at[:10]}",
            "generated_at": generated_at,
            "source": "CVE2CAPEC",
            "provenance": "canonical",
            "metadata": metadata,
            "nodes": node_list,
            "edges": edge_list,
            "canonical_chain": self.canonical_chain,
            "cves": {key: value for key, value in sorted(self.cves.items())},
            "reverse_index": reverse_index,
            "review_queue": sorted(self.review_queue, key=lambda item: (item["review_status"], item["id"])),
            "stats": stats,
            "indexes": indexes,
            "coverage": {key: value for key, value in sorted(self.coverage.items())},
            "routes": sorted(self.routes, key=lambda item: item["input"]),
        }
        return bundle


def derive_severity(record: dict[str, Any], chains: list[dict[str, Any]]) -> str:
    if record.get("kev"):
        return "critical"
    if any(chain.get("review_status") == "approved" for chain in chains):
        return "high"
    if chains and len(chains[0]) >= 4:
        return "medium"
    return "unknown"


def extract_vector(cvss: Any) -> str | None:
    if isinstance(cvss, dict):
        for key in ("vector", "vectorString", "vector_string"):
            value = cvss.get(key)
            if isinstance(value, str) and value.strip():
                return value
    if isinstance(cvss, str) and cvss.strip().startswith("CVSS"):
        return cvss
    return None


def evidence_templates_for_record(record: dict[str, Any], attack_ids: list[str], capec_ids: list[str], cwe_ids: list[str]) -> list[dict[str, Any]]:
    name = shorten(record.get("name") or record.get("id") or "CVE", 120)
    attack_name = attack_ids[0] if attack_ids else "unknown"
    templates = [
        ("logs", f"Application, access and request logs for {name}."),
        ("events", f"Endpoint or process events linked to {attack_name}."),
        ("telemetry", f"Network telemetry for the exposed surface of {record.get('product') or name}."),
    ]
    if cwe_ids:
        templates.append(("vuln", f"Vulnerability or exposure evidence for {cwe_ids[0]} ."))
    if capec_ids:
        templates.append(("pattern", f"Attack pattern evidence aligned to {capec_ids[0]}."))
    return [
        {
            "id": f"EVID-{normalize_id(record['id'])}-{index + 1}",
            "label": label,
            "text": text,
            "provenance": "inferred",
            "confidence": "medium",
            "review_status": "candidate",
        }
        for index, (label, text) in enumerate(templates[:4])
    ]


def detection_templates_for_record(record: dict[str, Any], attack_ids: list[str], capec_ids: list[str]) -> list[dict[str, Any]]:
    attack = attack_ids[0] if attack_ids else "unknown"
    templates = [
        ("monitoring", f"Search for activity consistent with {attack}."),
        ("request", f"Look for exploitation patterns targeting {record.get('name') or record.get('id')}."),
    ]
    if capec_ids:
        templates.append(("pattern", f"Track behavior aligned to {capec_ids[0]}."))
    return [
        {
            "id": f"DETECT-{normalize_id(record['id'])}-{index + 1}",
            "label": label,
            "text": text,
            "provenance": "inferred",
            "confidence": "medium",
            "review_status": "candidate",
        }
        for index, (label, text) in enumerate(templates[:3])
    ]


def gap_templates_for_record(record: dict[str, Any], attack_ids: list[str], d3fend_controls: list[dict[str, Any]], detection_rules: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if not d3fend_controls:
        gaps.append(("d3fend", "No direct D3FEND control was selected."))
    if not detection_rules:
        gaps.append(("detection", "No detection guidance was selected."))
    if not evidence:
        gaps.append(("evidence", "No evidence items were selected."))
    if not attack_ids:
        gaps.append(("attack", "No ATT&CK technique was selected."))
    if not gaps:
        gaps.append(("route", "Canonical route is present but still requires environment validation."))
    return [
        {
            "id": f"GAP-{normalize_id(record['id'])}-{index + 1}",
            "label": label,
            "text": text,
            "provenance": "canonical" if "route" in label else "inferred",
            "confidence": "high" if "route" in label else "medium",
            "review_status": "candidate",
        }
        for index, (label, text) in enumerate(gaps[:4])
    ]


def ioc_templates_for_record(record: dict[str, Any], attack_ids: list[str], capec_ids: list[str], cwe_ids: list[str]) -> list[dict[str, Any]]:
    values = [
        record.get("vendor"),
        record.get("product"),
        record.get("name"),
        attack_ids[0] if attack_ids else None,
        capec_ids[0] if capec_ids else None,
        cwe_ids[0] if cwe_ids else None,
    ]
    tokens = [shorten(item, 60) for item in values if item and shorten(item, 60)]
    if not tokens:
        tokens = [normalize_id(record["id"])]
    return [
        {
            "id": f"IOC-{normalize_id(record['id'])}-{index + 1}",
            "label": "IOC candidate",
            "text": token,
            "provenance": "inferred",
            "confidence": "low",
            "review_status": "candidate",
        }
        for index, token in enumerate(tokens[:4])
    ]


def checklist_for_record(record: dict[str, Any], associated_cves: list[str], pack: dict[str, Any], severity: str) -> list[str]:
    return [
        f"Confirm asset exposure for {record.get('id')}.",
        f"Confirm severity {severity} and route completeness.",
        f"Check associated CVEs: {', '.join(associated_cves[:3]) if associated_cves else 'none'}.",
        f"Validate D3FEND controls: {', '.join(item['id'] for item in pack['d3fend_controls'][:3])}.",
    ]


def escalation_for_record(record: dict[str, Any], pack: dict[str, Any]) -> list[str]:
    return [
        f"No evidence is available for {record.get('id')}.",
        "The route remains incomplete or candidate if the bundle lacks a direct mapping.",
        f"Detection guidance is still provisional: {pack['detection_rules'][0]['text'] if pack['detection_rules'] else 'n/a'}.",
    ]


def build_lookup_maps(cwe_db: dict[str, Any], capec_db: dict[str, Any], atlas_db: dict[str, Any], defend_rows: list[dict[str, Any]], techniques_association: dict[str, Any]) -> dict[str, Any]:
    cwe_to_capec: dict[str, list[str]] = defaultdict(list)
    capec_to_attack: dict[str, list[str]] = defaultdict(list)
    attack_to_d3fend: dict[str, list[str]] = defaultdict(list)
    attack_aliases: dict[str, list[dict[str, Any]]] = flatten_atlas_entries(atlas_db)
    defend_index: dict[str, list[dict[str, Any]]] = flatten_attack_controls(techniques_association)

    for raw_cwe, entry in cwe_db.items():
        cwe = cwe_id(raw_cwe)
        if not cwe or not isinstance(entry, dict):
            continue
        for raw_capec in entry.get("RelatedAttackPatterns", []) or []:
            capec = capec_id(raw_capec)
            if capec:
                cwe_to_capec[cwe].append(capec)
        for raw_parent in entry.get("ChildOf", []) or []:
            cwe_id(raw_parent)

    for raw_capec, entry in capec_db.items():
        capec = capec_id(raw_capec)
        if not capec or not isinstance(entry, dict):
            continue
        for attack in extract_attack_ids(entry.get("techniques")):
            capec_to_attack[capec].append(attack)

    for row in defend_rows:
        for raw_attack, entries in row.items():
            attack = attack_id(raw_attack)
            if not attack or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                did = d3fend_id(entry.get("id"))
                if did:
                    attack_to_d3fend[attack].append(did)

    for attack, entries in techniques_association.items():
        if not isinstance(entries, dict):
            continue
        for capec in entries.get("capec", []) or []:
            capec = capec_id(capec)
            if capec:
                capec_to_attack[capec].append(attack)
        for d3 in entries.get("d3fend", []) or []:
            d3 = d3fend_id(d3)
            if d3:
                attack_to_d3fend[attack].append(d3)

    for attack in defend_index:
        for entry in defend_index[attack]:
            did = d3fend_id(entry["id"])
            if did:
                attack_to_d3fend[attack].append(did)

    return {
        "cwe_to_capec": {key: uniq(values) for key, values in cwe_to_capec.items()},
        "capec_to_attack": {key: uniq(values) for key, values in capec_to_attack.items()},
        "attack_to_d3fend": {key: uniq(values) for key, values in attack_to_d3fend.items()},
        "attack_aliases": attack_aliases,
        "defend_index": defend_index,
    }


def build_node_maps(cwe_db: dict[str, Any], capec_db: dict[str, Any], atlas_db: dict[str, Any], defend_rows: list[dict[str, Any]], attack_aliases: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    node_maps = {
        "cwe": {},
        "capec": {},
        "attack": {},
        "d3fend": {},
        "attack_to_d3fend": defaultdict(list),
    }
    for raw_cwe, entry in cwe_db.items():
        cwe = cwe_id(raw_cwe)
        if not cwe or not isinstance(entry, dict):
            continue
        node_maps["cwe"][cwe] = {
            "name": shorten(entry.get("name") or cwe, 120),
            "description": shorten(entry.get("description") or "", 160),
            "url": str(entry.get("url") or f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"),
        }
    for raw_capec, entry in capec_db.items():
        capec = capec_id(raw_capec)
        if not capec or not isinstance(entry, dict):
            continue
        node_maps["capec"][capec] = {
            "name": shorten(entry.get("name") or capec, 120),
            "description": shorten(entry.get("description") or "", 160),
            "url": str(entry.get("url") or f"https://capec.mitre.org/data/definitions/{capec.split('-')[1]}.html"),
        }
    for attack, entries in attack_aliases.items():
        names = [shorten(entry.get("name") or attack, 120) for entry in entries[:3]]
        node_maps["attack"][attack] = {
            "name": names[0] if names else attack,
            "description": shorten(", ".join(sorted({name for name in names if name})) or "", 160),
            "url": entries[0].get("url") if entries and entries[0].get("url") else f"https://attack.mitre.org/techniques/{attack.replace('.', '/')}/",
            "aliases": entries[:3],
        }
    for row in defend_rows:
        for raw_attack, entries in row.items():
            attack = attack_id(raw_attack)
            if not attack or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                did = d3fend_id(entry.get("id"))
                if not did:
                    continue
                node_maps["d3fend"][did] = {
                    "name": shorten(entry.get("name") or entry.get("technique") or did, 120),
                    "description": shorten(entry.get("artifact") or entry.get("tactic") or "", 160),
                    "url": str(entry.get("url") or f"https://d3fend.mitre.org/technique/d3f:{did[3:].replace('-', '')}/"),
                }
                node_maps["attack_to_d3fend"][attack].append(did)
    return node_maps


def load_sources(cache_dir: Path, years: list[int], refresh: bool, spinner: ThinkerSpinner) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[int, list[dict[str, Any]]], list[str]]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    source_urls = [URLS["last_update"], URLS["techniques_association"], URLS["atlas_db"], URLS["defend_db"], URLS["capec_db"], URLS["cwe_db"]]
    spinner.step("Loading canonical lookup sources")
    last_update_path = cache_dir / "lastUpdate.txt"
    try:
        fetch_bytes(URLS["last_update"], last_update_path, refresh=refresh)
    except Exception as exc:
        if not last_update_path.exists():
            raise RuntimeError(f"Unable to load lastUpdate.txt: {exc}") from exc
    techniques_association = fetch_json(URLS["techniques_association"], cache_dir / "resources" / "techniques_association.json", refresh=refresh)
    atlas_local = cache_dir / "resources" / "techniques_db.json"
    if atlas_local.exists() and not refresh:
        atlas_db = read_json(atlas_local)
    else:
        try:
            atlas_db = fetch_json(URLS["atlas_db"], cache_dir / "resources" / "atlas_db.json", refresh=refresh)
        except Exception:
            atlas_db = read_json(atlas_local)
            if not atlas_db:
                raise
    cwe_db = fetch_json(URLS["cwe_db"], cache_dir / "resources" / "cwe_db.json", refresh=refresh)
    capec_db = fetch_json(URLS["capec_db"], cache_dir / "resources" / "capec_db.json", refresh=refresh)
    defend_bytes = fetch_bytes(URLS["defend_db"], cache_dir / "resources" / "defend_db.jsonl", refresh=refresh)
    defend_rows = parse_jsonl_bytes(defend_bytes)
    year_rows: dict[int, list[dict[str, Any]]] = {}
    for year in years:
        spinner.step(f"Fetching CVE-{year}.jsonl.gz")
        url = URLS["year"].format(year=year)
        cache_path = cache_dir / "database" / f"CVE-{year}.jsonl.gz"
        fallback_path = cache_dir / "database" / f"CVE-{year}.jsonl"
        if fallback_path.exists() and not refresh:
            data = fallback_path.read_bytes()
        else:
            try:
                data = fetch_bytes(url, cache_path, refresh=refresh)
            except Exception as exc:
                if fallback_path.exists():
                    data = fallback_path.read_bytes()
                else:
                    print(f"WARNING: skipping CVE database for {year}: {exc}")
                    continue
        if data.startswith(b"\x1f\x8b"):
            import gzip

            data = gzip.decompress(data)
        rows = parse_jsonl_bytes(data)
        year_rows[year] = rows
        source_urls.append(url)
    spinner.done("Canonical sources loaded")
    return cwe_db, capec_db, atlas_db, defend_rows, techniques_association, year_rows, source_urls


def build_bundle(args: argparse.Namespace) -> dict[str, Any]:
    spinner = ThinkerSpinner()
    years = args.years if args.years else year_range(args.start_year, args.end_year)
    cwe_db, capec_db, atlas_db, defend_rows, techniques_association, year_rows, source_urls = load_sources(args.cache_dir, years, args.refresh, spinner)
    maps = build_lookup_maps(cwe_db, capec_db, atlas_db, defend_rows, techniques_association)
    node_maps = build_node_maps(cwe_db, capec_db, atlas_db, defend_rows, maps["attack_aliases"])
    generated_at = now_iso()
    builder = BundleBuilder(generated_at=generated_at)
    builder.source_files.extend([str(args.cache_dir / "resources" / "techniques_association.json"), str(args.cache_dir / "resources" / "atlas_db.json"), str(args.cache_dir / "resources" / "defend_db.jsonl"), str(args.cache_dir / "resources" / "capec_db.json"), str(args.cache_dir / "resources" / "cwe_db.json")])

    for year, rows in sorted(year_rows.items()):
        source_file = f"database/CVE-{year}.jsonl.gz"
        for row in rows:
            normalized_row = normalize_cve2capec_year_row(row, source_year=year, source_file=source_file)
            if normalized_row is None:
                continue
            builder.record_cve(
                normalized_row,
                source_year=year,
                source_file=source_file,
                cwe_to_capec=maps["cwe_to_capec"],
                capec_to_attack=maps["capec_to_attack"],
                attack_to_d3fend=maps["attack_to_d3fend"],
                node_maps=node_maps,
            )

    bundle = builder.finalize(source_urls=source_urls, generated_at=generated_at, source_years=sorted(year_rows), warnings=builder.warnings)
    bundle = update_associated_cves(bundle)
    return bundle


def update_associated_cves(bundle: dict[str, Any]) -> dict[str, Any]:
    reverse_index = bundle.get("reverse_index", {})
    cves = bundle.get("cves", {})
    for cve_id, record in cves.items():
        if not isinstance(record, dict):
            continue
        chains = record.get("canonical_chain", [])
        associated: list[str] = []
        for chain in chains[:1]:
            for key in ("cwe", "capec", "attack", "d3fend"):
                value = chain.get(key)
                if not value:
                    continue
                associated.extend([item for item in reverse_index.get(f"by_{key}", {}).get(normalize_id(value), []) if item != cve_id])
        associated = uniq(associated)
        readout = record.get("tier1_readout", {})
        readout["associated_cves"] = associated[:5]
        readout["copy_paste_10_lines"] = list(readout.get("copy_paste_10_lines", []))[:10]
        record["tier1_readout"] = readout
    bundle["cves"] = cves
    return bundle


def compact_bundle(bundle: dict[str, Any], *, aggressive: bool = False) -> dict[str, Any]:
    compact = deepcopy(bundle)
    compact.pop("semantic_routes", None)
    for node in compact.get("nodes", []):
        if isinstance(node, dict):
            if node.get("description"):
                node["description"] = shorten(node["description"], 100 if aggressive else 160)
            metadata = node.get("metadata")
            if isinstance(metadata, dict):
                for key, value in list(metadata.items()):
                    if isinstance(value, str):
                        metadata[key] = shorten(value, 80 if aggressive else 120)
    for record in compact.get("cves", {}).values():
        if not isinstance(record, dict):
            continue
        if record.get("description"):
            record["description"] = shorten(record["description"], 100 if aggressive else 160)
        if aggressive:
            record.pop("soc_action_pack", None)
            record.pop("tier1_readout", None)
            if isinstance(record.get("canonical_chain"), list) and record["canonical_chain"]:
                record["canonical_chain"] = record["canonical_chain"][:1]
        readout = record.get("tier1_readout")
        if isinstance(readout, dict):
            if readout.get("summary"):
                readout["summary"] = shorten(readout["summary"], 120 if aggressive else 180)
            readout["bullets"] = list(readout.get("bullets", []))[:3 if aggressive else 5]
            readout["copy_paste_10_lines"] = [shorten(line, 120 if aggressive else 180) for line in list(readout.get("copy_paste_10_lines", []))[:10]]
            for key in ("checklist", "escalation_criteria"):
                readout[key] = [shorten(item, 120 if aggressive else 180) for item in list(readout.get(key, []))[:4]]
        pack = record.get("soc_action_pack")
        if isinstance(pack, dict):
            for key in ("attack_techniques", "d3fend_controls", "compensating_controls", "detection_rules", "evidence_to_review", "ioc_candidates", "gaps"):
                pack[key] = list(pack.get(key, []))[:2 if aggressive else 3]
            pack["risk_acceptance_matrix"] = list(pack.get("risk_acceptance_matrix", []))[:2]
    if aggressive:
        compact.pop("coverage", None)
        compact.pop("indexes", None)
        compact["review_queue"] = list(compact.get("review_queue", []))[: max(1, min(1000, len(compact.get("review_queue", []))))]
    return compact


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return ["Bundle is not a JSON object."]
    for key in ("nodes", "edges", "canonical_chain", "reverse_index", "cves", "stats"):
        value = bundle.get(key)
        if value in (None, [], {}):
            errors.append(f"Missing or empty top-level field: {key}")
    if not isinstance(bundle.get("nodes"), list) or not bundle["nodes"]:
        errors.append("nodes must be a non-empty list")
    if not isinstance(bundle.get("edges"), list) or not bundle["edges"]:
        errors.append("edges must be a non-empty list")
    if not isinstance(bundle.get("canonical_chain"), list) or not bundle["canonical_chain"]:
        errors.append("canonical_chain must be a non-empty list")
    if not isinstance(bundle.get("reverse_index"), dict) or not bundle["reverse_index"]:
        errors.append("reverse_index must be a non-empty object")
    if not isinstance(bundle.get("stats"), dict) or not bundle["stats"]:
        errors.append("stats must be a non-empty object")
    cves = bundle.get("cves", {})
    if not isinstance(cves, dict) or not cves:
        errors.append("cves must be a non-empty object")
    smoke_hits = 0
    smoke_present = 0
    for cve in SMOKE_CVES:
        if cve in cves:
            smoke_present += 1
            record = cves[cve]
            if isinstance(record, dict) and record.get("canonical_chain"):
                smoke_hits += 1
    if smoke_present and smoke_hits == 0:
        errors.append("None of the smoke test CVEs produced a route.")
    return errors


def print_stats(bundle: dict[str, Any]) -> None:
    stats = bundle.get("stats", {})
    print(f"total CVEs processed: {stats.get('total_cves_processed', 0)}")
    print(f"total nodes: {stats.get('total_nodes', 0)}")
    print(f"total edges: {stats.get('total_edges', 0)}")
    print(f"total canonical chains: {stats.get('total_canonical_chains', 0)}")
    print(f"CVEs with complete route: {stats.get('cves_with_complete_route', 0)}")
    print(f"CVEs without route: {stats.get('cves_without_route', 0)}")
    cves = bundle.get("cves", {}) if isinstance(bundle.get("cves", {}), dict) else {}
    present_smoke = [cve for cve in SMOKE_CVES if cve in cves]
    routed_smoke = [cve for cve in present_smoke if isinstance(cves.get(cve), dict) and cves[cve].get("canonical_chain")]
    missing_smoke = [cve for cve in SMOKE_CVES if cve not in present_smoke]
    print(f"smoke test CVEs present: {len(present_smoke)}")
    print(f"smoke test CVEs with route: {len(routed_smoke)}")
    if missing_smoke:
        print(f"WARNING: smoke test CVEs not present in loaded dataset: {', '.join(missing_smoke)}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build attack2defend knowledge bundle from CVE2CAPEC.")
    parser.add_argument("--cache-dir", type=Path, default=REPO_ROOT / "data" / "raw" / "cve2capec")
    parser.add_argument("--mappings-dir", type=Path, default=REPO_ROOT / "data" / "mappings")
    parser.add_argument("--bundle", type=Path, default=REPO_ROOT / "data" / "knowledge-bundle.json")
    parser.add_argument("--public-bundle", type=Path, default=REPO_ROOT / "app" / "navigator-ui" / "public" / "data" / "knowledge-bundle.json")
    parser.add_argument("--last-good", type=Path, default=REPO_ROOT / "data" / "knowledge-bundle.last-good.json")
    parser.add_argument("--public-last-good", type=Path, default=REPO_ROOT / "app" / "navigator-ui" / "public" / "data" / "knowledge-bundle.last-good.json")
    parser.add_argument("--start-year", type=int, default=DEFAULT_START_YEAR)
    parser.add_argument("--end-year", type=int, default=datetime.now(timezone.utc).year)
    parser.add_argument("--years", type=int, nargs="*")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--with-backbone", action="store_true", help="Merge mapping backbone into the canonical bundle after ETL.")
    parser.add_argument("--validate-only", action="store_true")
    return parser.parse_args(argv)


def publish(bundle: dict[str, Any], args: argparse.Namespace) -> None:
    write_json(args.bundle, bundle)
    write_runtime_bundle(args.public_bundle, bundle, pretty=False)
    write_json(args.last_good, bundle)
    write_runtime_bundle(args.public_last_good, bundle, pretty=False)


def bundle_size_bytes(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.validate_only:
        bundle = read_json(args.bundle)
        errors = validate_bundle(bundle)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print_stats(bundle)
        print("Validation only: OK")
        return 0

    spinner = ThinkerSpinner()
    spinner.step("Starting ETL")
    years = args.years if args.years else year_range(args.start_year, args.end_year)
    bundle = build_bundle(args)
    spinner.step("Validating generated bundle")
    errors = validate_bundle(bundle)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    publish(bundle, args)
    merged_bundle = read_json(args.bundle)
    size = bundle_size_bytes(args.bundle)
    if args.with_backbone:
        spinner.step("Applying mapping backbone compatibility layer")
        merge_mapping_backbone(args.bundle, args.mappings_dir, args.public_bundle.parent, None, False)
        merged_bundle = read_json(args.bundle)
        size = bundle_size_bytes(args.bundle)
    if size > MAX_BUNDLE_BYTES:
        spinner.step("Bundle exceeded size limit, compacting")
        compacted = compact_bundle(merged_bundle, aggressive=False)
        write_json(args.bundle, compacted)
        if bundle_size_bytes(args.bundle) > MAX_BUNDLE_BYTES:
            compacted = compact_bundle(compacted, aggressive=True)
            write_json(args.bundle, compacted)
        write_runtime_bundle(args.public_bundle, compacted, pretty=False)
        write_json(args.last_good, compact_bundle(read_json(args.bundle), aggressive=False))
        write_runtime_bundle(args.public_last_good, read_json(args.last_good), pretty=False)
        size = bundle_size_bytes(args.bundle)
    else:
        write_json(args.last_good, merged_bundle)
        write_runtime_bundle(args.public_last_good, merged_bundle, pretty=False)
    spinner.done(f"Bundle ready ({size} bytes)")
    print_stats(bundle)
    print(f"Bundle written to {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
