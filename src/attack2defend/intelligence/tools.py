"""Read-only intelligence tools for the curator graph.

These functions are the only points of contact between the curator and
external data (bundle, raw cache). They are deliberately side-effect-free:
they read; they never write.

Design:
  - No LangChain imports (usable without AI extras installed)
  - All inputs/outputs are plain dicts/lists/strings
  - Each function is independently testable with mock data
"""

from __future__ import annotations

import gzip
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ------------------------------------------------------------------ #
# Gap scanning                                                         #
# ------------------------------------------------------------------ #

_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_CAPEC_RE = re.compile(r"^CAPEC-\d+$")
_D3_RE = re.compile(r"^D3-")


def scan_bundle_gaps(
    bundle: dict,
    gap_types: list[str],
    max_gaps: int = 50,
) -> list[dict]:
    """Scan a knowledge bundle and return gap records.

    Returns a list of gap dicts, each with:
      gap_id, gap_type, source_id, source_type, target_type,
      description, node_name, node_url, priority, route_status
    """
    nodes: dict[str, dict] = {
        n["id"].upper(): n
        for n in bundle.get("nodes", [])
        if isinstance(n, dict) and n.get("id")
    }
    edges_raw: list[dict] = [
        e for e in bundle.get("edges", []) if isinstance(e, dict)
    ]
    fwd_index = bundle.get("indexes", {}).get("forward", {})
    kev_index: set[str] = set(bundle.get("indexes", {}).get("kev", {}).keys())
    semantic_routes: list[dict] = bundle.get("semantic_routes", [])
    coverage: dict[str, dict] = bundle.get("coverage", {})

    # Build quick edge lookup: (source, target_type) → list of target ids
    outgoing_by_type: dict[tuple[str, str], list[str]] = {}
    for e in edges_raw:
        src = str(e.get("source", "")).upper()
        tgt = str(e.get("target", "")).upper()
        tgt_node = nodes.get(tgt, {})
        tgt_type = str(tgt_node.get("type", _infer_type(tgt)))
        outgoing_by_type.setdefault((src, tgt_type), []).append(tgt)

    # Build route status map: node_id → worst route status
    node_route_status: dict[str, str] = {}
    for route in semantic_routes:
        status = route.get("coverage_status", "unknown")
        for nid in route.get("nodes", []):
            nid_upper = nid.upper()
            existing = node_route_status.get(nid_upper, "unknown")
            node_route_status[nid_upper] = _worst_status(existing, status)

    # Build KEV-touching attack techniques (for priority boosting)
    kev_attack_techniques: set[str] = set()
    if kev_index:
        cve_to_attack = _build_cve_attack_index(edges_raw, nodes)
        for cve_id in kev_index:
            kev_attack_techniques.update(cve_to_attack.get(cve_id.upper(), []))

    gaps: list[dict] = []

    def _add(gap: dict) -> bool:
        if len(gaps) >= max_gaps:
            return False
        gaps.append(gap)
        return True

    # --- missing_d3fend: ATT&CK techniques with no D3FEND edges ----------
    if "missing_d3fend" in gap_types:
        attack_to_d3fend = fwd_index.get("attack_to_d3fend", {})
        for nid, node in sorted(nodes.items()):
            if node.get("type") != "attack":
                continue
            if not _ATTACK_RE.match(nid):
                continue
            if attack_to_d3fend.get(nid):
                continue
            route_st = node_route_status.get(nid, "unknown")
            priority = _gap_priority(nid, route_st, kev_attack_techniques)
            if not _add(_make_gap(
                gap_type="missing_d3fend",
                source_id=nid,
                source_type="attack",
                target_type="d3fend",
                node=node,
                description=(
                    f"ATT&CK technique {nid} ({node.get('name', nid)}) "
                    "has no D3FEND countermeasures mapped in the bundle"
                ),
                priority=priority,
                route_status=route_st,
            )):
                break

    # --- missing_capec: CWE nodes with no CAPEC edges --------------------
    if "missing_capec" in gap_types:
        cwe_to_capec = fwd_index.get("cwe_to_capec", {})
        for nid, node in sorted(nodes.items()):
            if node.get("type") != "cwe":
                continue
            if cwe_to_capec.get(nid):
                continue
            route_st = node_route_status.get(nid, "unknown")
            priority = _gap_priority(nid, route_st, set())
            if not _add(_make_gap(
                gap_type="missing_capec",
                source_id=nid,
                source_type="cwe",
                target_type="capec",
                node=node,
                description=(
                    f"CWE {nid} ({node.get('name', nid)}) "
                    "has no CAPEC attack pattern mappings in the bundle"
                ),
                priority=priority,
                route_status=route_st,
            )):
                break

    # --- missing_attack: CAPEC nodes with no ATT&CK edges ----------------
    if "missing_attack" in gap_types:
        capec_to_attack = fwd_index.get("capec_to_attack", {})
        for nid, node in sorted(nodes.items()):
            if node.get("type") != "capec":
                continue
            if capec_to_attack.get(nid):
                continue
            route_st = node_route_status.get(nid, "unknown")
            priority = _gap_priority(nid, route_st, set())
            if not _add(_make_gap(
                gap_type="missing_attack",
                source_id=nid,
                source_type="capec",
                target_type="attack",
                node=node,
                description=(
                    f"CAPEC {nid} ({node.get('name', nid)}) "
                    "has no ATT&CK technique mappings in the bundle"
                ),
                priority=priority,
                route_status=route_st,
            )):
                break

    # --- partial_coverage: semantic routes with degraded status ----------
    if "partial_coverage" in gap_types:
        seen_roots: set[str] = set()
        for route in sorted(semantic_routes, key=lambda r: r.get("root", "")):
            status = route.get("coverage_status", "unknown")
            if status not in {"partial", "catalog-only", "partial-defense"}:
                continue
            root = str(route.get("root", "")).upper()
            if root in seen_roots:
                continue
            seen_roots.add(root)
            root_node = nodes.get(root, {})
            missing = route.get("missing_segments", [])
            priority = "high" if status == "catalog-only" else "medium"
            if not _add(_make_gap(
                gap_type="partial_coverage",
                source_id=root,
                source_type=root_node.get("type", _infer_type(root)),
                target_type="chain",
                node=root_node,
                description=(
                    f"Semantic route for {root} has status '{status}'. "
                    f"Missing framework segments: {', '.join(missing) or 'none listed'}"
                ),
                priority=priority,
                route_status=status,
                extra={"missing_segments": missing},
            )):
                break

    # --- coverage_gap: coverage records with non-empty gaps[] ------------
    if "coverage_gap" in gap_types:
        for raw_id, rec in sorted(coverage.items()):
            if not isinstance(rec, dict):
                continue
            cov_gaps = rec.get("gaps", [])
            if not cov_gaps:
                continue
            nid = raw_id.upper()
            node = nodes.get(nid, {"id": nid, "name": nid, "type": _infer_type(nid)})
            route_st = node_route_status.get(nid, "unknown")
            priority = _gap_priority(nid, route_st, kev_attack_techniques)
            if not _add(_make_gap(
                gap_type="coverage_gap",
                source_id=nid,
                source_type=node.get("type", _infer_type(nid)),
                target_type="evidence",
                node=node,
                description=(
                    f"Coverage record for {nid} declares {len(cov_gaps)} gap(s): "
                    + "; ".join(str(g) for g in cov_gaps[:3])
                ),
                priority=priority,
                route_status=route_st,
                extra={"declared_gaps": cov_gaps},
            )):
                break

    return gaps


# ------------------------------------------------------------------ #
# Evidence fetching from local cache                                   #
# ------------------------------------------------------------------ #


def fetch_evidence_for_gaps(
    gaps: list[dict],
    cache_dir: Path,
) -> dict[str, list[dict]]:
    """Fetch evidence for each gap from local public source cache.

    Returns: gap_id → list of evidence items
    Each evidence item: {url, excerpt, confidence, source, retrieved_at}
    """
    result: dict[str, list[dict]] = {}
    now = datetime.now(timezone.utc).isoformat()

    d3fend_dir = cache_dir / "d3fend"
    attack_index: dict[str, dict] | None = None

    for gap in gaps:
        gap_id = gap["gap_id"]
        gap_type = gap["gap_type"]
        source_id = gap["source_id"]
        items: list[dict] = []

        if gap_type == "missing_d3fend":
            # Look for cached D3FEND API response for this ATT&CK technique
            technique_clean = source_id.upper().replace(".", "_")
            cache_file = d3fend_dir / f"{technique_clean}.json"
            if cache_file.exists():
                try:
                    d3data = json.loads(cache_file.read_text(encoding="utf-8"))
                    items.extend(_parse_d3fend_evidence(source_id, d3data, now))
                except Exception:
                    pass

        elif gap_type == "missing_capec":
            # Parse CAPEC XML cache for CWE → CAPEC relationships
            capec_file = cache_dir / "capec" / "capec_latest.xml"
            if not capec_file.exists():
                capec_gz = cache_dir / "capec" / "capec_latest.xml.zip"
                if capec_gz.exists():
                    capec_file = capec_gz  # handled below
            items.extend(_parse_capec_evidence_for_cwe(source_id, cache_dir, now))

        elif gap_type == "missing_attack":
            # Look for CAPEC → ATT&CK mapping in ATT&CK STIX cache
            if attack_index is None:
                attack_index = _load_attack_index(cache_dir)
            items.extend(_parse_attack_evidence_for_capec(source_id, attack_index, now))

        elif gap_type in {"partial_coverage", "coverage_gap"}:
            # Use ATT&CK technique context from STIX if it's an ATT&CK node
            if _ATTACK_RE.match(source_id):
                if attack_index is None:
                    attack_index = _load_attack_index(cache_dir)
                items.extend(_parse_attack_technique_context(source_id, attack_index, now))

        result[gap_id] = items

    return result


# ------------------------------------------------------------------ #
# Evidence parsers                                                     #
# ------------------------------------------------------------------ #


def _parse_d3fend_evidence(attack_id: str, d3data: Any, now: str) -> list[dict]:
    """Extract D3FEND countermeasures from cached API response."""
    items: list[dict] = []
    if not isinstance(d3data, dict):
        return items

    # Handle two common D3FEND API response shapes
    # Shape 1: {"@graph": [...]} (bulk export)
    # Shape 2: {"offensive-technique": {...}, "defensive-technique": [...]}
    defensive = d3data.get("defensive-technique") or []
    if not defensive:
        graph = d3data.get("@graph") or []
        defensive = [
            n for n in graph
            if isinstance(n, dict) and n.get("@type", "") == "d3f:DefensiveTechnique"
        ]

    for dt in defensive:
        if not isinstance(dt, dict):
            continue
        dt_id = dt.get("@id", "") or dt.get("d3f:d3fend-id", "")
        dt_name = dt.get("rdfs:label", "") or dt.get("d3f:definition", "")[:60]
        d3_url = f"https://d3fend.mitre.org/technique/{dt_id.replace('d3f:', 'd3f:')}"
        excerpt = (
            f"{dt_id} ({dt_name}) is listed as a D3FEND countermeasure "
            f"for ATT&CK technique {attack_id} in the D3FEND knowledge graph."
        )
        items.append({
            "url": d3_url,
            "excerpt": excerpt,
            "confidence": "medium",
            "source": "d3fend",
            "d3fend_id": dt_id,
            "retrieved_at": now,
        })
    return items


def _parse_capec_evidence_for_cwe(cwe_id: str, cache_dir: Path, now: str) -> list[dict]:
    """Extract CAPEC patterns related to a CWE from the CAPEC XML cache."""
    items: list[dict] = []
    cwe_num = cwe_id.replace("CWE-", "").strip()

    # Try unzipped first, then zipped
    capec_xml = cache_dir / "capec" / "capec_latest.xml"
    capec_zip = cache_dir / "capec" / "capec_latest.xml.zip"

    xml_bytes: bytes | None = None
    if capec_xml.exists():
        xml_bytes = capec_xml.read_bytes()
    elif capec_zip.exists():
        try:
            import zipfile
            with zipfile.ZipFile(capec_zip) as zf:
                names = [n for n in zf.namelist() if n.endswith(".xml")]
                if names:
                    xml_bytes = zf.read(names[0])
        except Exception:
            pass

    if not xml_bytes:
        return items

    try:
        root = ET.fromstring(xml_bytes)
        ns = {"capec": "http://capec.mitre.org/capec-3"}
        for pattern in root.iter("{http://capec.mitre.org/capec-3}Attack_Pattern"):
            pattern_id = pattern.get("ID", "")
            name = pattern.get("Name", "")
            # Check Related_Weaknesses
            for rw in pattern.iter("{http://capec.mitre.org/capec-3}Related_Weakness"):
                if rw.get("CWE_ID") == cwe_num:
                    capec_url = f"https://capec.mitre.org/data/definitions/{pattern_id}.html"
                    items.append({
                        "url": capec_url,
                        "excerpt": (
                            f"CAPEC-{pattern_id} ({name}) lists CWE-{cwe_num} "
                            "as a related weakness in the CAPEC taxonomy."
                        ),
                        "confidence": "high",
                        "source": "capec",
                        "capec_id": f"CAPEC-{pattern_id}",
                        "retrieved_at": now,
                    })
                    break  # one evidence item per pattern is enough
    except ET.ParseError:
        pass
    return items[:10]  # cap at 10


def _load_attack_index(cache_dir: Path) -> dict[str, dict]:
    """Load ATT&CK STIX bundle from cache as {technique_id: stix_object}."""
    attack_file = cache_dir / "attack" / "enterprise-attack.json"
    if not attack_file.exists():
        return {}
    try:
        stix = json.loads(attack_file.read_text(encoding="utf-8"))
        index: dict[str, dict] = {}
        for obj in stix.get("objects", []):
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    tid = ref["external_id"].upper()
                    index[tid] = obj
                    break
        return index
    except Exception:
        return {}


def _parse_attack_evidence_for_capec(
    capec_id: str,
    attack_index: dict[str, dict],
    now: str,
) -> list[dict]:
    """Find ATT&CK techniques referencing a CAPEC ID."""
    items: list[dict] = []
    capec_num = capec_id.replace("CAPEC-", "").strip()
    for tid, obj in sorted(attack_index.items()):
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "capec" and ref.get("external_id") == f"CAPEC-{capec_num}":
                name = obj.get("name", tid)
                url = next(
                    (r["url"] for r in obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack" and r.get("url")),
                    f"https://attack.mitre.org/techniques/{tid}/",
                )
                items.append({
                    "url": url,
                    "excerpt": (
                        f"ATT&CK technique {tid} ({name}) references "
                        f"CAPEC-{capec_num} in its external_references."
                    ),
                    "confidence": "high",
                    "source": "attack",
                    "attack_id": tid,
                    "retrieved_at": now,
                })
    return items[:5]


def _parse_attack_technique_context(
    attack_id: str,
    attack_index: dict[str, dict],
    now: str,
) -> list[dict]:
    """Return technique context from ATT&CK cache as evidence for partial coverage."""
    obj = attack_index.get(attack_id.upper())
    if not obj:
        return []
    name = obj.get("name", attack_id)
    desc = (obj.get("description") or "")[:300]
    url = next(
        (r["url"] for r in obj.get("external_references", [])
         if r.get("source_name") == "mitre-attack" and r.get("url")),
        f"https://attack.mitre.org/techniques/{attack_id}/",
    )
    return [{
        "url": url,
        "excerpt": f"{attack_id} ({name}): {desc}",
        "confidence": "medium",
        "source": "attack",
        "attack_id": attack_id,
        "retrieved_at": now,
    }]


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #


def _make_gap(
    *,
    gap_type: str,
    source_id: str,
    source_type: str,
    target_type: str,
    node: dict,
    description: str,
    priority: str,
    route_status: str,
    extra: dict | None = None,
) -> dict:
    gap: dict = {
        "gap_id": f"gap-{gap_type}-{source_id}",
        "gap_type": gap_type,
        "source_id": source_id,
        "source_type": source_type,
        "target_type": target_type,
        "node_name": node.get("name", source_id),
        "node_url": node.get("url", ""),
        "description": description,
        "priority": priority,
        "route_status": route_status,
    }
    if extra:
        gap.update(extra)
    return gap


def _infer_type(node_id: str) -> str:
    nid = node_id.upper()
    if nid.startswith("CVE-"):
        return "cve"
    if nid.startswith("CWE-"):
        return "cwe"
    if nid.startswith("CAPEC-"):
        return "capec"
    if _ATTACK_RE.match(nid):
        return "attack"
    if _D3_RE.match(nid):
        return "d3fend"
    return "artifact"


_STATUS_ORDER = {
    # Higher index = more concerning for security gap prioritisation.
    # "unknown" sits at 0 so any real route status overrides it.
    "unknown": 0,
    "complete": 1,
    "partial-defense": 2,
    "partial": 3,
    "seed-only": 4,
    "catalog-only": 5,
    "unresolved": 6,
}


def _worst_status(a: str, b: str) -> str:
    """Return the more security-concerning of two route status strings."""
    return a if _STATUS_ORDER.get(a, 0) >= _STATUS_ORDER.get(b, 0) else b


def _gap_priority(
    source_id: str,
    route_status: str,
    kev_attack_techniques: set[str],
) -> str:
    if source_id in kev_attack_techniques:
        return "critical"
    if route_status in {"catalog-only", "unresolved"}:
        return "high"
    if route_status in {"partial", "partial-defense"}:
        return "medium"
    return "low"


def _build_cve_attack_index(
    edges: list[dict],
    nodes: dict[str, dict],
) -> dict[str, list[str]]:
    """Build {cve_id → [attack_technique_ids]} from edge list."""
    index: dict[str, list[str]] = {}
    # Direct CVE → ATT&CK edges (rare but possible)
    for e in edges:
        src = str(e.get("source", "")).upper()
        tgt = str(e.get("target", "")).upper()
        if nodes.get(src, {}).get("type") == "cve" and nodes.get(tgt, {}).get("type") == "attack":
            index.setdefault(src, []).append(tgt)
    return index
