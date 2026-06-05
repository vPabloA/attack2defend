"""Route Coherence Engine.

Orchestrates the full CVE→CWE→CAPEC→ATT&CK→D3FEND chain assembly:
  1. Identify input type
  2. Resolve source data (live APIs with cache, or bundle-only)
  3. Walk the chain layer by layer
  4. Classify each edge with mapping_basis + score
  5. Return a RouteCoherenceArtifact

Bundle fallback: if source resolvers return nothing, falls back to the
local knowledge bundle graph (BFS via RouteResolver).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..coherence.edge_classifier import categorize_edges, classify
from ..coherence.schema import (
    CoherenceEdge,
    CoherenceNode,
    GraphEdge,
    GraphNode,
    ProvenanceIndex,
    RouteCoherenceArtifact,
)

# Well-known CVE CWE→CAPEC baseline used when live sources return nothing.
# This covers common weakness patterns so the engine degrades gracefully.
_BASELINE_CWE_CAPEC: dict[str, list[str]] = {
    "CWE-416": ["CAPEC-129", "CAPEC-124", "CAPEC-26"],
    "CWE-787": ["CAPEC-100", "CAPEC-129"],
    "CWE-89":  ["CAPEC-66"],
    "CWE-79":  ["CAPEC-86", "CAPEC-198"],
    "CWE-20":  ["CAPEC-100", "CAPEC-248"],
    "CWE-22":  ["CAPEC-126"],
    "CWE-94":  ["CAPEC-242"],
    "CWE-918": ["CAPEC-664"],
    "CWE-502": ["CAPEC-586"],
    "CWE-917": ["CAPEC-136"],
    "CWE-122": ["CAPEC-100"],
}

# CAPEC→ATT&CK baseline
_BASELINE_CAPEC_ATTACK: dict[str, list[str]] = {
    "CAPEC-129": ["T1190", "T1210", "T1059.004"],
    "CAPEC-124": ["T1190", "T1210"],
    "CAPEC-26":  ["T1499", "T1210"],
    "CAPEC-100": ["T1190", "T1210"],
    "CAPEC-66":  ["T1190"],
    "CAPEC-86":  ["T1189"],
    "CAPEC-136": ["T1190"],
    "CAPEC-248": ["T1059"],
    "CAPEC-242": ["T1059"],
    "CAPEC-664": ["T1190"],
    "CAPEC-126": ["T1190"],
    "CAPEC-586": ["T1059"],
}

# ATT&CK→D3FEND baseline
_BASELINE_ATTACK_D3FEND: dict[str, list[str]] = {
    "T1190": ["D3-SWI", "D3-AVE", "D3-NI", "D3-NTF", "D3-NTA"],
    "T1210": ["D3-SWI", "D3-AVE", "D3-NI", "D3-NTF", "D3-NTA"],
    "T1059": ["D3-PA", "D3-PSA", "D3-PSEP"],
    "T1059.004": ["D3-SCH", "D3-RN", "D3-PSEP", "D3-EI"],
    "T1189": ["D3-WAF", "D3-NTF"],
    "T1499": ["D3-NTF", "D3-NTA"],
    "T1499.002": ["D3-NTF", "D3-NTA"],
}

# Node metadata stubs for IDs not in bundle
_NODE_STUBS: dict[str, dict[str, str]] = {
    "CWE-416": {"name": "Use After Free", "url": "https://cwe.mitre.org/data/definitions/416.html"},
    "CAPEC-129": {"name": "Pointer Manipulation", "url": "https://capec.mitre.org/data/definitions/129.html"},
    "CAPEC-124": {"name": "Shared Resource Manipulation", "url": "https://capec.mitre.org/data/definitions/124.html"},
    "CAPEC-26":  {"name": "Leveraging Race Conditions", "url": "https://capec.mitre.org/data/definitions/26.html"},
    "T1190": {"name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1210": {"name": "Exploitation of Remote Services", "url": "https://attack.mitre.org/techniques/T1210/"},
    "T1059.004": {"name": "Unix Shell", "url": "https://attack.mitre.org/techniques/T1059/004/"},
    "T1059": {"name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1499": {"name": "Endpoint Denial of Service", "url": "https://attack.mitre.org/techniques/T1499/"},
    "T1189": {"name": "Drive-by Compromise", "url": "https://attack.mitre.org/techniques/T1189/"},
    "D3-SWI": {"name": "Software Inventory", "url": "https://d3fend.mitre.org/technique/D3-SWI/"},
    "D3-AVE": {"name": "Asset Vulnerability Enumeration", "url": "https://d3fend.mitre.org/technique/D3-AVE/"},
    "D3-NI":  {"name": "Network Isolation", "url": "https://d3fend.mitre.org/technique/D3-NI/"},
    "D3-NTF": {"name": "Network Traffic Filtering", "url": "https://d3fend.mitre.org/technique/D3-NTF/"},
    "D3-NTA": {"name": "Network Traffic Analysis", "url": "https://d3fend.mitre.org/technique/D3-NTA/"},
    "D3-PA":  {"name": "Process Analysis", "url": "https://d3fend.mitre.org/technique/D3-PA/"},
    "D3-PSA": {"name": "Process Spawn Analysis", "url": "https://d3fend.mitre.org/technique/D3-PSA/"},
    "D3-PSEP": {"name": "Process Spawn Event Prevention", "url": "https://d3fend.mitre.org/technique/D3-PSEP/"},
    "D3-SCH": {"name": "Source Code Hardening", "url": "https://d3fend.mitre.org/technique/D3-SCH/"},
    "D3-RN":  {"name": "Reference Nullification", "url": "https://d3fend.mitre.org/technique/D3-RN/"},
    "D3-EI":  {"name": "Execution Isolation", "url": "https://d3fend.mitre.org/technique/D3-EI/"},
    "D3-WAF": {"name": "Web Application Firewall", "url": "https://d3fend.mitre.org/technique/D3-WAF/"},
}

_LAYER_INDEX = {"cve": 0, "cwe": 1, "capec": 2, "attack": 3, "d3fend": 4}


def _build_baseline_known_ids() -> frozenset[str]:
    ids: set[str] = set(_NODE_STUBS.keys())
    for mapping in (_BASELINE_CWE_CAPEC, _BASELINE_CAPEC_ATTACK, _BASELINE_ATTACK_D3FEND):
        for k, vs in mapping.items():
            ids.add(k)
            ids.update(vs)
    return frozenset(ids)


BASELINE_KNOWN_IDS: frozenset[str] = _build_baseline_known_ids()


def analyze(
    input_id: str,
    bundle_nodes: list[dict[str, Any]] | None = None,
    bundle_edges: list[dict[str, Any]] | None = None,
    live: bool = False,
    cache_dir: Path | None = None,
) -> RouteCoherenceArtifact:
    """Build a RouteCoherenceArtifact from any input identifier."""
    input_upper = input_id.upper().strip()
    input_type = _infer_type(input_upper)

    artifact = RouteCoherenceArtifact(input=input_upper, input_type=input_type)
    source_summary: dict[str, bool] = {
        "bundle_local": bool(bundle_nodes),
        "nvd": False,
        "cwe_mitre": False,
        "capec_mitre": False,
        "attack_stix": False,
        "d3fend_api": False,
        "vendor_advisory": False,
        "cache_hit": False,
    }

    # --- Step 1: Build node map from bundle ---
    bundle_node_map: dict[str, dict[str, Any]] = {}
    if bundle_nodes:
        for n in bundle_nodes:
            bundle_node_map[n["id"].upper()] = n

    # IDs provably known from external sources (baselines + bundle input).
    # The validator uses this to enforce no-invention without being tautological.
    source_known_ids: set[str] = set(BASELINE_KNOWN_IDS)
    source_known_ids.add(input_upper)
    source_known_ids.update(bundle_node_map.keys())

    # --- Step 2: Walk chain starting from input_type ---
    all_nodes: list[CoherenceNode] = []
    all_edges: list[CoherenceEdge] = []

    if input_type == "cve":
        nvd_data: dict[str, Any] = {}
        if live:
            from ..source_resolvers import nvd as _nvd
            nvd_data = _nvd.resolve(input_upper, cache_dir=cache_dir)
            source_summary["nvd"] = bool(nvd_data)
            if nvd_data.get("_cache_hit"):
                source_summary["cache_hit"] = True

        cve_node = _make_node(input_upper, "cve", nvd_data.get("description", ""), role="root",
                              confidence="official" if nvd_data else "inferred",
                              source_refs=["nvd_api"] if nvd_data else ["bundle_local"],
                              bundle_map=bundle_node_map)
        all_nodes.append(cve_node)

        # Get CWE IDs
        cwe_ids: list[str] = nvd_data.get("cwe_ids", [])
        if not cwe_ids:
            # Fall back to bundle
            cwe_ids = _bundle_targets(input_upper, "cwe", bundle_edges)
        # If still nothing, mark as gap
        if not cwe_ids:
            artifact.gaps.append({"segment": "cve→cwe", "description": f"No CWE found for {input_upper}", "requires_curation": True})

        cwe_nodes, cwe_edges = _resolve_cwe_layer(cwe_ids, input_upper, nvd_data, live, cache_dir, bundle_node_map, bundle_edges)
        all_nodes.extend(cwe_nodes)
        all_edges.extend(cwe_edges)
        if cwe_nodes:
            source_summary["cwe_mitre"] = live

    elif input_type == "cwe":
        cwe_node = _make_node(input_upper, "cwe", role="root", confidence="official",
                              source_refs=["bundle_local"], bundle_map=bundle_node_map)
        all_nodes.append(cwe_node)
        cwe_ids = [input_upper]
        cwe_nodes, cwe_edges = [], []

    elif input_type == "capec":
        capec_node = _make_node(input_upper, "capec", role="root", confidence="official",
                                source_refs=["bundle_local"], bundle_map=bundle_node_map)
        all_nodes.append(capec_node)
        cwe_ids = []
        cwe_nodes, cwe_edges = [], []

    else:
        # ATT&CK or D3FEND as input — partial chain
        node = _make_node(input_upper, input_type, role="root", confidence="official",
                          source_refs=["bundle_local"], bundle_map=bundle_node_map)
        all_nodes.append(node)
        cwe_ids = []
        cwe_nodes, cwe_edges = [], []

    # --- Step 3: CAPEC layer ---
    if input_type in ("cve", "cwe"):
        current_cwes = [n.id for n in all_nodes if n.type == "cwe"]
        capec_nodes, capec_edges = _resolve_capec_layer(current_cwes, live, cache_dir, bundle_node_map, bundle_edges)
        all_nodes.extend(capec_nodes)
        all_edges.extend(capec_edges)
        if capec_nodes:
            source_summary["capec_mitre"] = live
    elif input_type == "capec":
        capec_nodes = [n for n in all_nodes if n.type == "capec"]
        capec_edges = []
    else:
        capec_nodes = []

    # --- Step 4: ATT&CK layer ---
    if input_type in ("cve", "cwe", "capec"):
        current_capecs = [n.id for n in all_nodes if n.type == "capec"]
        attack_nodes, attack_edges = _resolve_attack_layer(current_capecs, live, cache_dir, bundle_node_map, bundle_edges)
        all_nodes.extend(attack_nodes)
        all_edges.extend(attack_edges)
        if attack_nodes:
            source_summary["attack_stix"] = live
    elif input_type == "attack":
        attack_nodes = [n for n in all_nodes if n.type == "attack"]
    else:
        attack_nodes = []

    # --- Step 5: D3FEND layer ---
    if input_type in ("cve", "cwe", "capec", "attack"):
        current_attacks = [n.id for n in all_nodes if n.type == "attack"]
        current_cwes_for_d3 = [n.id for n in all_nodes if n.type == "cwe"]
        d3_nodes, d3_edges = _resolve_d3fend_layer(current_attacks, current_cwes_for_d3, live, cache_dir, bundle_node_map, bundle_edges)
        all_nodes.extend(d3_nodes)
        all_edges.extend(d3_edges)
        if d3_nodes:
            source_summary["d3fend_api"] = live

    # --- Deduplicate ---
    all_nodes = _dedup_nodes(all_nodes)
    all_edges = _dedup_edges(all_edges)

    # --- Assign artifact fields ---
    artifact.all_nodes = all_nodes
    artifact.all_edges = all_edges
    artifact.primary_nodes = [n for n in all_nodes if n.role in ("root", "primary")]
    artifact.secondary_nodes = [n for n in all_nodes if n.role == "secondary"]
    artifact.conditional_nodes = [n for n in all_nodes if n.role == "conditional"]
    artifact.defensive_nodes = [n for n in all_nodes if n.type == "d3fend"]
    artifact.source_summary = source_summary

    # --- Build provenance index ---
    cat = categorize_edges(all_edges)
    artifact.provenance = ProvenanceIndex(
        official_explicit=cat.get("official_explicit", []),
        official_related=cat.get("official_related", []),
        analytical_inferred=cat.get("analytical_inferred", []),
        conditional=cat.get("conditional", []),
        unverified=cat.get("unverified", []),
    )

    # --- Build graph ---
    artifact.graph_nodes = _build_graph_nodes(all_nodes)
    artifact.graph_edges = _build_graph_edges(all_edges)

    # --- Determine status ---
    artifact.status = _determine_status(artifact)

    # Expose the externally-derived known IDs so the validator can do a
    # non-tautological node check (not against artifact.all_node_ids()).
    artifact.source_known_ids = frozenset(source_known_ids)

    return artifact


# ─── Layer builders ─────────────────────────────────────────────────────────


def _resolve_cwe_layer(
    cwe_ids: list[str],
    cve_id: str,
    nvd_data: dict[str, Any],
    live: bool,
    cache_dir: Path | None,
    bundle_map: dict[str, dict[str, Any]],
    bundle_edges: list[dict[str, Any]] | None,
) -> tuple[list[CoherenceNode], list[CoherenceEdge]]:
    nodes: list[CoherenceNode] = []
    edges: list[CoherenceEdge] = []

    for cwe_id in cwe_ids[:3]:  # cap at 3 CWEs
        cwe_upper = cwe_id.upper()
        cwe_data: dict[str, Any] = {}
        if live:
            from ..source_resolvers import cwe as _cwe
            cwe_data = _cwe.resolve(cwe_upper, cache_dir=cache_dir)

        basis = "official_explicit" if nvd_data.get("cwe_ids") and cwe_upper in nvd_data["cwe_ids"] else "analytical_inferred"
        source_refs_list = [nvd_data.get("source", "nvd_api")] if nvd_data else ["bundle_local"]

        node = _make_node(cwe_upper, "cwe",
                          description=cwe_data.get("description", ""),
                          url=cwe_data.get("url", f"https://cwe.mitre.org/data/definitions/{cwe_upper.replace('CWE-', '')}.html"),
                          role="primary",
                          confidence="official" if basis == "official_explicit" else "inferred",
                          source_refs=source_refs_list,
                          bundle_map=bundle_map)
        nodes.append(node)

        edge = classify(
            source=cve_id, target=cwe_upper,
            relationship="vulnerability_has_weakness",
            basis_hint=basis,
            source_refs=source_refs_list,
        )
        edges.append(edge)

    return nodes, edges


def _resolve_capec_layer(
    cwe_ids: list[str],
    live: bool,
    cache_dir: Path | None,
    bundle_map: dict[str, dict[str, Any]],
    bundle_edges: list[dict[str, Any]] | None,
) -> tuple[list[CoherenceNode], list[CoherenceEdge]]:
    nodes: list[CoherenceNode] = []
    edges: list[CoherenceEdge] = []
    seen: set[str] = set()

    for cwe_id in cwe_ids:
        cwe_upper = cwe_id.upper()
        capec_ids: list[str] = []
        capec_ids_from_live = False

        if live:
            from ..source_resolvers import cwe as _cwe
            cwe_data = _cwe.resolve(cwe_upper, cache_dir=cache_dir)
            capec_ids = cwe_data.get("related_capec_ids", [])
            capec_ids_from_live = bool(capec_ids)

        if not capec_ids:
            capec_ids = _BASELINE_CWE_CAPEC.get(cwe_upper, [])

        if not capec_ids:
            capec_ids = _bundle_targets(cwe_upper, "capec", bundle_edges)

        for i, capec_id in enumerate(capec_ids[:4]):
            capec_upper = capec_id.upper()
            if capec_upper in seen:
                continue
            seen.add(capec_upper)

            # Primary/secondary/conditional roles
            role: str
            notes = ""
            if i == 0:
                role = "primary"
            elif "26" in capec_upper:
                role = "conditional"
                notes = "conditional: applies only if race condition in exploitation"
            else:
                role = "secondary"

            capec_data: dict[str, Any] = {}
            if live:
                from ..source_resolvers import capec as _capec
                capec_data = _capec.resolve(capec_upper, cache_dir=cache_dir)

            # Only claim official_related when IDs actually came from the live MITRE resolver.
            # If the live call returned nothing and we fell back to baseline/bundle, the provenance
            # is analytical_inferred regardless of whether --live was passed.
            basis = "official_related" if capec_ids_from_live else "analytical_inferred"
            src_refs = ["cwe_mitre"] if capec_ids_from_live else ["baseline:cwe_capec"]

            node = _make_node(capec_upper, "capec",
                              description=capec_data.get("description", ""),
                              url=capec_data.get("url", f"https://capec.mitre.org/data/definitions/{capec_upper.replace('CAPEC-', '')}.html"),
                              role=role,
                              confidence="related" if basis == "official_related" else "inferred",
                              source_refs=src_refs,
                              bundle_map=bundle_map)
            nodes.append(node)

            edge = classify(
                source=cwe_upper, target=capec_upper,
                relationship="weakness_enables_attack_pattern",
                basis_hint=basis,
                source_refs=src_refs,
                notes=notes,
            )
            edges.append(edge)

    return nodes, edges


def _resolve_attack_layer(
    capec_ids: list[str],
    live: bool,
    cache_dir: Path | None,
    bundle_map: dict[str, dict[str, Any]],
    bundle_edges: list[dict[str, Any]] | None,
) -> tuple[list[CoherenceNode], list[CoherenceEdge]]:
    nodes: list[CoherenceNode] = []
    edges: list[CoherenceEdge] = []
    seen: set[str] = set()

    for capec_id in capec_ids:
        capec_upper = capec_id.upper()
        attack_ids: list[str] = []
        attack_ids_from_live = False

        if live:
            from ..source_resolvers import capec as _capec
            capec_data = _capec.resolve(capec_upper, cache_dir=cache_dir)
            attack_ids = capec_data.get("attack_technique_ids", [])
            attack_ids_from_live = bool(attack_ids)

        if not attack_ids:
            attack_ids = _BASELINE_CAPEC_ATTACK.get(capec_upper, [])

        if not attack_ids:
            attack_ids = _bundle_targets(capec_upper, "attack", bundle_edges)

        for attack_id in attack_ids[:4]:
            a_upper = attack_id.upper()
            if a_upper in seen:
                continue
            seen.add(a_upper)

            # Only claim official_related when IDs actually came from the live CAPEC resolver.
            basis = "official_related" if attack_ids_from_live else "analytical_inferred"
            src_refs = ["capec_mitre"] if attack_ids_from_live else ["baseline:capec_attack"]

            attack_data: dict[str, Any] = {}
            if live:
                from ..source_resolvers import attack as _attack
                attack_data = _attack.resolve(a_upper, cache_dir=cache_dir)

            node = _make_node(a_upper, "attack",
                              description=attack_data.get("description", ""),
                              url=attack_data.get("url", f"https://attack.mitre.org/techniques/{a_upper.replace('.', '/')}/"),
                              role="primary",
                              confidence="related" if basis == "official_related" else "inferred",
                              source_refs=src_refs,
                              bundle_map=bundle_map)
            nodes.append(node)

            edge = classify(
                source=capec_upper, target=a_upper,
                relationship="attack_pattern_maps_to_technique",
                basis_hint=basis,
                source_refs=src_refs,
            )
            edges.append(edge)

    # Add post-exploitation T1059/T1059.004 if T1190 or T1210 present
    primary_attacks = {n.id for n in nodes}
    post_ex_sources: list[str] = [a for a in primary_attacks if "T1190" in a or "T1210" in a]
    post_ex_targets = ["T1059.004"] if any("T1059.004" in a or "T1059" in a for a in _BASELINE_CAPEC_ATTACK.values()) else []

    for src_attack in post_ex_sources:
        for post_id in ["T1059.004"]:
            if post_id.upper() not in seen:
                seen.add(post_id.upper())
                post_node = _make_node(post_id.upper(), "attack",
                                       role="primary",
                                       confidence="inferred",
                                       source_refs=["baseline:attack_postex"],
                                       bundle_map=bundle_map)
                nodes.append(post_node)
                post_edge = classify(
                    source=src_attack, target=post_id.upper(),
                    relationship="may_lead_to_post_exploitation",
                    basis_hint="analytical_inferred",
                    source_refs=["baseline:attack_postex"],
                )
                edges.append(post_edge)
                break

    return nodes, edges


def _resolve_d3fend_layer(
    attack_ids: list[str],
    cwe_ids: list[str],
    live: bool,
    cache_dir: Path | None,
    bundle_map: dict[str, dict[str, Any]],
    bundle_edges: list[dict[str, Any]] | None,
) -> tuple[list[CoherenceNode], list[CoherenceEdge]]:
    nodes: list[CoherenceNode] = []
    edges: list[CoherenceEdge] = []
    seen: set[str] = set()

    for attack_id in attack_ids:
        a_upper = attack_id.upper()
        d3_items: list[dict[str, Any]] = []

        if live:
            from ..source_resolvers import d3fend as _d3fend
            d3_items = _d3fend.resolve_for_attack(a_upper, cache_dir=cache_dir)

        d3_ids_from_api = [item["id"] for item in d3_items]

        if not d3_ids_from_api:
            d3_ids_from_api = _BASELINE_ATTACK_D3FEND.get(a_upper, [])

        if not d3_ids_from_api:
            d3_ids_from_api = _bundle_targets(a_upper, "d3fend", bundle_edges)

        for d3_id in d3_ids_from_api[:6]:
            d3_upper = d3_id.upper()
            if d3_upper in seen:
                continue
            seen.add(d3_upper)

            basis = "official_related" if live and d3_items else "analytical_inferred"
            src_refs = ["d3fend_api"] if live and d3_items else ["baseline:attack_d3fend"]

            # Find name from API items or stubs
            d3_name = next((item["name"] for item in d3_items if item["id"].upper() == d3_upper), None)
            if not d3_name:
                d3_name = _NODE_STUBS.get(d3_upper, {}).get("name", d3_upper)

            node = _make_node(d3_upper, "d3fend",
                              description="",
                              url=_NODE_STUBS.get(d3_upper, {}).get("url", f"https://d3fend.mitre.org/technique/{d3_upper}/"),
                              role="defensive",
                              confidence="related" if basis == "official_related" else "inferred",
                              source_refs=src_refs,
                              bundle_map=bundle_map)
            if d3_name:
                node.name = d3_name
            nodes.append(node)

            rel = "technique_mitigated_by_countermeasure"
            if any(k in d3_upper for k in ("NTA", "PA", "PSA")):
                rel = "technique_may_be_detected_by"

            edge = classify(
                source=a_upper, target=d3_upper,
                relationship=rel,
                basis_hint=basis,
                source_refs=src_refs,
            )
            edges.append(edge)

    return nodes, edges


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _infer_type(identifier: str) -> str:
    if re.match(r"^CVE-\d{4}-\d{4,}$", identifier):
        return "cve"
    if re.match(r"^CWE-\d+$", identifier):
        return "cwe"
    if re.match(r"^CAPEC-\d+$", identifier):
        return "capec"
    if re.match(r"^T\d{4}(\.\d{3})?$", identifier):
        return "attack"
    if re.match(r"^D3-[A-Z0-9-]+$", identifier):
        return "d3fend"
    return "unknown"


def _make_node(
    node_id: str,
    node_type: str,
    description: str = "",
    url: str = "",
    role: str = "primary",
    confidence: str = "inferred",
    source_refs: list[str] | None = None,
    bundle_map: dict[str, dict[str, Any]] | None = None,
) -> CoherenceNode:
    stub = _NODE_STUBS.get(node_id, {})
    bundle_entry = (bundle_map or {}).get(node_id, {})

    name = bundle_entry.get("name") or stub.get("name") or node_id
    final_url = url or bundle_entry.get("url") or stub.get("url") or ""
    final_desc = description or bundle_entry.get("description") or ""

    return CoherenceNode(
        id=node_id,
        type=node_type,
        name=name,
        role=role,
        confidence=confidence,
        description=final_desc,
        url=final_url,
        source_refs=source_refs or [],
    )


def _bundle_targets(
    source_id: str,
    target_type: str,
    bundle_edges: list[dict[str, Any]] | None,
) -> list[str]:
    if not bundle_edges:
        return []
    return [
        e["target"]
        for e in bundle_edges
        if e.get("source", "").upper() == source_id.upper()
        and _infer_type(e.get("target", "").upper()) == target_type
    ]


def _dedup_nodes(nodes: list[CoherenceNode]) -> list[CoherenceNode]:
    seen: set[str] = set()
    result: list[CoherenceNode] = []
    for node in nodes:
        if node.id not in seen:
            seen.add(node.id)
            result.append(node)
    return result


def _dedup_edges(edges: list[CoherenceEdge]) -> list[CoherenceEdge]:
    seen: set[str] = set()
    result: list[CoherenceEdge] = []
    for edge in edges:
        key = f"{edge.source}→{edge.target}"
        if key not in seen:
            seen.add(key)
            result.append(edge)
    return result


def _build_graph_nodes(nodes: list[CoherenceNode]) -> list[GraphNode]:
    return [
        GraphNode(
            id=node.id,
            type=node.type,
            label=node.id,
            title=node.name,
            subtitle=node.description[:60] if node.description else "",
            role=node.role,
            confidence=node.confidence,
            source_refs=node.source_refs,
            x_layer=_LAYER_INDEX.get(node.type, 0),
        )
        for node in nodes
    ]


def _build_graph_edges(edges: list[CoherenceEdge]) -> list[GraphEdge]:
    return [
        GraphEdge(
            source=edge.source,
            target=edge.target,
            mapping_basis=edge.mapping_basis,
            label=edge.relationship,
            rationale_es=edge.rationale_es,
            source_refs=edge.source_refs,
        )
        for edge in edges
    ]


def _determine_status(artifact: RouteCoherenceArtifact) -> str:
    if not artifact.all_nodes:
        return "failed"
    types_present = {n.type for n in artifact.all_nodes}
    required = {"cve", "cwe", "capec", "attack", "d3fend"}
    if required.issubset(types_present):
        has_inferred = any(e.mapping_basis in ("analytical_inferred", "conditional") for e in artifact.all_edges)
        return "complete_with_inferred_edges" if has_inferred else "complete"
    if "d3fend" in types_present:
        return "partial"
    return "degraded"
