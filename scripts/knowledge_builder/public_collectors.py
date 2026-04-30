#!/usr/bin/env python3
"""Public-source collectors for Attack2Defend.

These collectors run only in the scheduled knowledge-builder path. They are not
used by the Navigator UI at SOC runtime.

The module is dependency-free on purpose so it can run in CI, cron and minimal
Debian servers.
"""

from __future__ import annotations

import gzip
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

ATTACK_ENTERPRISE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CWE_LATEST_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_LATEST_XML_ZIP_URL = "https://capec.mitre.org/data/xml/capec_latest.xml.zip"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
D3FEND_ATTACK_API_URL = "https://d3fend.mitre.org/api/offensive-technique/attack/{attack_id}.json"

CWE_ID_RE = re.compile(r"^CWE-?([0-9]+)$", re.IGNORECASE)
CAPEC_ID_RE = re.compile(r"^CAPEC-?([0-9]+)$", re.IGNORECASE)
ATTACK_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$", re.IGNORECASE)
CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
D3FEND_ID_RE = re.compile(r"^D3-[A-Z0-9-]+$", re.IGNORECASE)


@dataclass(slots=True)
class CollectorResult:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    routes: list[dict[str, Any]] = field(default_factory=list)
    route_inputs: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_node(self, node: dict[str, Any]) -> None:
        node_id = normalize_id(node.get("id"))
        if not node_id:
            return
        node = {**node, "id": node_id, "type": str(node.get("type", "")).lower()}
        existing = self.nodes.get(node_id)
        if existing:
            self.nodes[node_id] = merge_node(existing, node)
        else:
            self.nodes[node_id] = node

    def add_edge(self, source: str, target: str, relationship: str, **extra: Any) -> None:
        source_id = normalize_id(source)
        target_id = normalize_id(target)
        rel = str(relationship).strip().lower()
        if not source_id or not target_id or not rel:
            return
        edge = {"source": source_id, "target": target_id, "relationship": rel}
        edge.update({key: value for key, value in extra.items() if value not in (None, "", [], {})})
        self.edges[(source_id, target_id, rel)] = edge

    def extend(self, other: "CollectorResult") -> None:
        for node in other.nodes.values():
            self.add_node(node)
        self.edges.update(other.edges)
        self.routes.extend(other.routes)
        self.route_inputs.update(other.route_inputs)
        self.sources.extend(other.sources)
        self.warnings.extend(other.warnings)


def normalize_id(value: Any) -> str:
    return str(value or "").strip().upper()


def cwe_id(value: Any) -> str | None:
    match = CWE_ID_RE.match(str(value or "").strip())
    return f"CWE-{match.group(1)}" if match else None


def capec_id(value: Any) -> str | None:
    match = CAPEC_ID_RE.match(str(value or "").strip())
    return f"CAPEC-{match.group(1)}" if match else None


def attack_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if ATTACK_ID_RE.match(text) else None


def cve_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if CVE_ID_RE.match(text) else None


def d3fend_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if D3FEND_ID_RE.match(text) else None


def merge_node(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key == "metadata" and isinstance(value, dict):
            metadata = dict(merged.get("metadata", {}))
            metadata.update(value)
            merged["metadata"] = metadata
        elif key not in merged or merged[key] in ("", None, [], {}):
            merged[key] = value
    return merged


def fetch_bytes(url: str, cache_path: Path, *, timeout: int = 45, refresh: bool = False, headers: dict[str, str] | None = None) -> bytes:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists() and not refresh:
        return cache_path.read_bytes()

    request = urllib.request.Request(url, headers={"User-Agent": "attack2defend-knowledge-builder/0.1", **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()
    cache_path.write_bytes(data)
    return data


def fetch_json(url: str, cache_path: Path, *, timeout: int = 45, refresh: bool = False, headers: dict[str, str] | None = None) -> dict[str, Any]:
    data = fetch_bytes(url, cache_path, timeout=timeout, refresh=refresh, headers=headers)
    if data.startswith(b"\x1f\x8b"):
        data = gzip.decompress(data)
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object from {url}")
    return payload


def read_first_xml_from_zip(data: bytes) -> ET.Element:
    with zipfile.ZipFile(BytesIO(data)) as archive:
        xml_names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if not xml_names:
            raise ValueError("ZIP archive does not contain XML files")
        with archive.open(xml_names[0]) as handle:
            return ET.parse(handle).getroot()


def strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def children_by_local_name(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if strip_namespace(child.tag) == name]


def first_text(element: ET.Element, child_name: str) -> str:
    for child in children_by_local_name(element, child_name):
        return " ".join("".join(child.itertext()).split())
    return ""


def collect_attack(cache_dir: Path, *, refresh: bool = False, timeout: int = 45) -> CollectorResult:
    result = CollectorResult(sources=[ATTACK_ENTERPRISE_STIX_URL])
    payload = fetch_json(ATTACK_ENTERPRISE_STIX_URL, cache_dir / "attack" / "enterprise-attack.json", refresh=refresh, timeout=timeout)
    objects = payload.get("objects", [])
    stix_to_attack: dict[str, str] = {}

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = None
        for ref in obj.get("external_references", []) or []:
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                external_id = attack_id(ref.get("external_id"))
                break
        if not external_id:
            continue
        stix_to_attack[str(obj.get("id"))] = external_id
        result.add_node({
            "id": external_id,
            "type": "attack",
            "name": obj.get("name") or external_id,
            "description": obj.get("description") or "",
            "url": f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/",
            "metadata": {
                "source": "mitre_attack_stix",
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "x_mitre_platforms": obj.get("x_mitre_platforms", []),
                "x_mitre_data_sources": obj.get("x_mitre_data_sources", []),
            },
        })

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "subtechnique-of":
            continue
        source = stix_to_attack.get(str(obj.get("source_ref")))
        target = stix_to_attack.get(str(obj.get("target_ref")))
        if source and target:
            result.add_edge(source, target, "subtechnique_of", confidence="public_source", source_ref="mitre_attack_stix")

    return result


def collect_cwe(cache_dir: Path, *, refresh: bool = False, timeout: int = 45) -> CollectorResult:
    result = CollectorResult(sources=[CWE_LATEST_XML_ZIP_URL])
    root = read_first_xml_from_zip(fetch_bytes(CWE_LATEST_XML_ZIP_URL, cache_dir / "cwe" / "cwec_latest.xml.zip", refresh=refresh, timeout=timeout))

    for weakness in root.iter():
        if strip_namespace(weakness.tag) != "Weakness":
            continue
        weakness_id = cwe_id(weakness.get("ID"))
        if not weakness_id:
            continue
        result.add_node({
            "id": weakness_id,
            "type": "cwe",
            "name": weakness.get("Name") or weakness_id,
            "description": first_text(weakness, "Description"),
            "url": f"https://cwe.mitre.org/data/definitions/{weakness_id.split('-')[1]}.html",
            "metadata": {"source": "cwe_xml", "abstraction": weakness.get("Abstraction"), "status": weakness.get("Status")},
        })

    return result


def collect_capec(cache_dir: Path, *, refresh: bool = False, timeout: int = 45) -> CollectorResult:
    result = CollectorResult(sources=[CAPEC_LATEST_XML_ZIP_URL])
    root = read_first_xml_from_zip(fetch_bytes(CAPEC_LATEST_XML_ZIP_URL, cache_dir / "capec" / "capec_latest.xml.zip", refresh=refresh, timeout=timeout))

    for attack_pattern in root.iter():
        if strip_namespace(attack_pattern.tag) != "Attack_Pattern":
            continue
        pattern_id = capec_id(attack_pattern.get("ID"))
        if not pattern_id:
            continue
        result.add_node({
            "id": pattern_id,
            "type": "capec",
            "name": attack_pattern.get("Name") or pattern_id,
            "description": first_text(attack_pattern, "Description"),
            "url": f"https://capec.mitre.org/data/definitions/{pattern_id.split('-')[1]}.html",
            "metadata": {"source": "capec_xml", "status": attack_pattern.get("Status")},
        })

        for related_weaknesses in children_by_local_name(attack_pattern, "Related_Weaknesses"):
            for related in children_by_local_name(related_weaknesses, "Related_Weakness"):
                weakness_id = cwe_id(related.get("CWE_ID"))
                if weakness_id:
                    result.add_node({"id": weakness_id, "type": "cwe", "name": weakness_id, "url": f"https://cwe.mitre.org/data/definitions/{weakness_id.split('-')[1]}.html", "metadata": {"source": "capec_related_weakness"}})
                    result.add_edge(weakness_id, pattern_id, "may_enable_attack_pattern", confidence="public_source", source_ref="capec_xml")

        for taxonomy_mappings in children_by_local_name(attack_pattern, "Taxonomy_Mappings"):
            for mapping in children_by_local_name(taxonomy_mappings, "Taxonomy_Mapping"):
                taxonomy_name = str(mapping.get("Taxonomy_Name") or "").lower()
                if "attack" not in taxonomy_name:
                    continue
                entry_id = attack_id(mapping.get("Entry_ID") or first_text(mapping, "Entry_ID"))
                if entry_id:
                    result.add_node({"id": entry_id, "type": "attack", "name": entry_id, "url": f"https://attack.mitre.org/techniques/{entry_id.replace('.', '/')}/", "metadata": {"source": "capec_attack_mapping"}})
                    result.add_edge(pattern_id, entry_id, "may_map_to_attack_technique", confidence="public_source", source_ref="capec_xml")

    return result


def collect_kev(cache_dir: Path, *, refresh: bool = False, timeout: int = 45, max_cves: int | None = None) -> CollectorResult:
    result = CollectorResult(sources=[CISA_KEV_URL])
    payload = fetch_json(CISA_KEV_URL, cache_dir / "kev" / "known_exploited_vulnerabilities.json", refresh=refresh, timeout=timeout)
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return result

    for item in vulnerabilities[:max_cves] if max_cves else vulnerabilities:
        if not isinstance(item, dict):
            continue
        vid = cve_id(item.get("cveID"))
        if not vid:
            continue
        result.add_node({
            "id": vid,
            "type": "cve",
            "name": item.get("vulnerabilityName") or vid,
            "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
            "metadata": {
                "source": "cisa_kev",
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                "required_action": item.get("requiredAction"),
            },
        })
        result.route_inputs.add(vid)
        result.routes.append({"id": f"route-kev-{vid.lower()}", "input": vid, "name": item.get("vulnerabilityName") or vid, "curation_status": "public_kev", "source": "cisa_kev"})

    return result


def collect_nvd(
    cache_dir: Path,
    *,
    cves: list[str] | None = None,
    recent_days: int = 0,
    api_key: str | None = None,
    refresh: bool = False,
    timeout: int = 45,
    max_results: int = 2000,
) -> CollectorResult:
    result = CollectorResult(sources=[NVD_CVE_API_URL])
    headers = {"apiKey": api_key} if api_key else None
    requested_urls: list[tuple[str, Path]] = []

    for raw_cve in cves or []:
        vid = cve_id(raw_cve)
        if not vid:
            result.warnings.append(f"Ignoring invalid CVE id for NVD fetch: {raw_cve}")
            continue
        query = urllib.parse.urlencode({"cveId": vid})
        requested_urls.append((f"{NVD_CVE_API_URL}?{query}", cache_dir / "nvd" / f"{vid}.json"))

    if recent_days > 0:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=recent_days)
        query = urllib.parse.urlencode({
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": str(min(max_results, 2000)),
        })
        requested_urls.append((f"{NVD_CVE_API_URL}?{query}", cache_dir / "nvd" / f"recent-{recent_days}d.json"))

    for index, (url, cache_path) in enumerate(requested_urls):
        if index and api_key is None and refresh:
            time.sleep(6)
        payload = fetch_json(url, cache_path, refresh=refresh, timeout=timeout, headers=headers)
        ingest_nvd_payload(payload, result)

    return result


def ingest_nvd_payload(payload: dict[str, Any], result: CollectorResult) -> None:
    for item in payload.get("vulnerabilities", []) or []:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            continue
        cve = item["cve"]
        vid = cve_id(cve.get("id"))
        if not vid:
            continue
        descriptions = cve.get("descriptions", []) or []
        description = ""
        for desc in descriptions:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                description = desc.get("value") or ""
                break
        result.add_node({
            "id": vid,
            "type": "cve",
            "name": vid,
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
            "metadata": {"source": "nvd_api", "published": cve.get("published"), "last_modified": cve.get("lastModified")},
        })
        result.route_inputs.add(vid)
        result.routes.append({"id": f"route-nvd-{vid.lower()}", "input": vid, "name": vid, "curation_status": "public_nvd", "source": "nvd_api"})
        for weakness in cve.get("weaknesses", []) or []:
            for desc in weakness.get("description", []) if isinstance(weakness, dict) else []:
                weakness_id = cwe_id(desc.get("value") if isinstance(desc, dict) else "")
                if weakness_id:
                    result.add_node({"id": weakness_id, "type": "cwe", "name": weakness_id, "url": f"https://cwe.mitre.org/data/definitions/{weakness_id.split('-')[1]}.html", "metadata": {"source": "nvd_weakness"}})
                    result.add_edge(vid, weakness_id, "has_weakness", confidence="public_source", source_ref="nvd_api")


def collect_d3fend_for_attack_ids(
    attack_ids: list[str],
    cache_dir: Path,
    *,
    refresh: bool = False,
    timeout: int = 45,
    max_attack_ids: int = 250,
) -> CollectorResult:
    result = CollectorResult()
    for attack in sorted({value for value in (attack_id(item) for item in attack_ids) if value})[:max_attack_ids]:
        url = D3FEND_ATTACK_API_URL.format(attack_id=attack)
        result.sources.append(url)
        cache_name = attack.replace(".", "_") + ".json"
        try:
            payload = fetch_json(url, cache_dir / "d3fend" / cache_name, refresh=refresh, timeout=timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            result.warnings.append(f"D3FEND fetch failed for {attack}: {exc}")
            continue
        for item in extract_d3fend_records(payload):
            did = d3fend_id(item.get("id"))
            if not did:
                continue
            result.add_node({
                "id": did,
                "type": "d3fend",
                "name": item.get("name") or did,
                "url": item.get("url") or f"https://d3fend.mitre.org/technique/{did}/",
                "metadata": {"source": "d3fend_api"},
            })
            result.add_edge(attack, did, "may_be_defended_by", confidence="public_source", source_ref="d3fend_api")
    return result


def extract_d3fend_records(payload: Any) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            candidate_id = d3fend_id(value.get("id") or value.get("d3fend_id") or value.get("external_id") or value.get("technique_id"))
            if candidate_id:
                records.append({
                    "id": candidate_id,
                    "name": str(value.get("name") or value.get("label") or value.get("title") or candidate_id),
                    "url": str(value.get("url") or ""),
                })
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    return records


def collect_public_sources(
    cache_dir: Path,
    *,
    refresh: bool = False,
    timeout: int = 45,
    include_attack: bool = True,
    include_cwe: bool = True,
    include_capec: bool = True,
    include_kev: bool = True,
    include_d3fend: bool = True,
    include_nvd: bool = False,
    nvd_cves: list[str] | None = None,
    nvd_recent_days: int = 0,
    nvd_api_key: str | None = None,
    max_kev_cves: int | None = None,
    max_d3fend_attack_ids: int = 250,
    fail_on_error: bool = False,
) -> CollectorResult:
    aggregate = CollectorResult()

    def run(name: str, func: Any) -> None:
        try:
            aggregate.extend(func())
        except Exception as exc:  # noqa: BLE001 - collectors should isolate source failures
            message = f"Public collector {name} failed: {exc}"
            if fail_on_error:
                raise RuntimeError(message) from exc
            aggregate.warnings.append(message)

    if include_attack:
        run("attack", lambda: collect_attack(cache_dir, refresh=refresh, timeout=timeout))
    if include_cwe:
        run("cwe", lambda: collect_cwe(cache_dir, refresh=refresh, timeout=timeout))
    if include_capec:
        run("capec", lambda: collect_capec(cache_dir, refresh=refresh, timeout=timeout))
    if include_kev:
        run("kev", lambda: collect_kev(cache_dir, refresh=refresh, timeout=timeout, max_cves=max_kev_cves))
    if include_nvd or nvd_cves or nvd_recent_days > 0:
        run("nvd", lambda: collect_nvd(cache_dir, cves=nvd_cves or [], recent_days=nvd_recent_days, api_key=nvd_api_key, refresh=refresh, timeout=timeout))
    if include_d3fend:
        attack_ids = [node_id for node_id, node in aggregate.nodes.items() if node.get("type") == "attack"]
        run("d3fend", lambda: collect_d3fend_for_attack_ids(attack_ids, cache_dir, refresh=refresh, timeout=timeout, max_attack_ids=max_d3fend_attack_ids))

    return aggregate
