"""Incremental threat route enrichment for Attack2Defend.

This module preserves the product's static-first contract: public sources may be
used only from explicit builder/enrichment invocations, while the Navigator UI
continues to consume local JSON artifacts. The LLM is intentionally not required
here; the writer produces a grounded, auditable synthesis from graph evidence and
leaves a stable schema for a future validator-gated LLM pass.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

Mode = Literal["local_only", "enrich_missing", "refresh"]
CAPABILITY_NAME = "attack2defend.enrich_threat_route"

THREAT_CHAIN = ("cve", "cwe", "capec", "attack", "d3fend")
NODE_KEY_FIELDS = ("name", "description", "url", "official_link", "source_ref")
CVSS_PRIORITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
OFFICIAL_SOURCE_PRIORITY = {
    "nvd_api": 100,
    "cisa_kev": 95,
    "cwe_xml": 90,
    "capec_xml": 90,
    "mitre_attack_stix": 90,
    "mitre_d3fend_ontology": 90,
    "mitre_d3fend_full_mappings": 90,
    "d3fend_api": 80,
    "galeax_cve2capec_database": 60,
    "galeax_cve2capec_cwe_db": 55,
    "galeax_cve2capec_capec_db": 55,
    "galeax_cve2capec_techniques_db": 55,
    "galeax_cve2capec_defend_db": 55,
    "bundle_derived": 10,
    "missing_source_ref": 0,
}

DEFENSE_CONTROL_TYPE = {
    "detect": "detective",
    "model": "preventive",
    "harden": "preventive",
    "isolate": "containment",
    "evict": "containment",
    "restore": "corrective",
    "deceive": "detective",
}

TECHNIQUE_TELEMETRY_HINTS: dict[str, list[str]] = {
    "T1606": [
        "Identity provider sign-in logs and token issuance events",
        "SAML/OIDC assertion validation failures",
        "Federation metadata, signing certificate and key rollover history",
        "OAuth application credential and service principal changes",
        "Resource access events using newly issued web credentials",
    ],
    "T1528": [
        "OAuth consent and application authorization logs",
        "Cloud API token creation and refresh events",
        "Service principal credential changes",
        "Mailbox, SaaS and cloud resource access logs",
    ],
    "T1539": [
        "Web session creation, reuse and invalidation logs",
        "Cookie/session binding attributes when available",
        "User-agent, source IP and geolocation drift across active sessions",
    ],
    "T1550.004": [
        "Session replay indicators across SaaS and identity provider logs",
        "MFA bypass or token reuse events",
        "Concurrent session activity from incompatible client context",
    ],
    "T1134": [
        "Token privilege assignment and impersonation events",
        "Process creation with explicit token context",
        "Authentication package and logon session telemetry",
    ],
    "T1134.001": [
        "Token duplication or impersonation audit events",
        "Privileged process creation tied to unexpected logon sessions",
    ],
    "T1134.002": [
        "CreateProcessWithToken-style process creation events",
        "Parent/child process lineage with explicit alternate token use",
    ],
    "T1134.003": [
        "Named pipe/RPC or service behavior using newly impersonated tokens",
        "Privilege escalation attempts tied to impersonation APIs",
    ],
    "T1090": [
        "Proxy connection logs",
        "Network session metadata with source/destination drift",
        "DNS and TLS metadata for relay infrastructure",
    ],
    "T1090.001": [
        "Internal proxy connection logs",
        "East-west network sessions through unexpected intermediaries",
        "Proxy authentication and relay service logs",
    ],
}

CVE_RE = re.compile(r"^(?:CVE[-_ ]?)?(20\d{2})[-_ ]?([0-9]{4,})$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE[-_ ]?([0-9]+)$", re.IGNORECASE)
CAPEC_RE = re.compile(r"^CAPEC[-_ ]?([0-9]+)$", re.IGNORECASE)
ATTACK_RE = re.compile(r"^T?[0-9]{4}(?:\.[0-9]{3})?$", re.IGNORECASE)
D3FEND_RE = re.compile(r"^D3[-_][A-Z0-9-]+$", re.IGNORECASE)

RELATIONSHIP_ES = {
    "has_weakness": "presenta o referencia la debilidad",
    "has_related_weakness": "se relaciona con la debilidad",
    "vulnerability_has_weakness": "presenta la debilidad",
    "child_of": "hereda o especializa",
    "may_enable_attack_pattern": "puede habilitar el patrón de ataque",
    "weakness_enables_attack_pattern": "habilita el patrón de ataque",
    "may_map_to_attack_technique": "se expresa operacionalmente como la técnica",
    "attack_pattern_maps_to_technique": "mapea al comportamiento ATT&CK",
    "may_be_defended_by": "puede reducirse, observarse o contenerse mediante",
    "may_be_detected_by": "puede detectarse con",
    "subtechnique_of": "es subtécnica de",
}

OWNER_BY_STAGE = {
    "cve": "Vulnerability Manager / Asset Owner",
    "cwe": "AppSec / Product Security",
    "capec": "Threat Hunter / Detection Engineering",
    "attack": "SOC / Detection Engineering",
    "d3fend": "Security Architecture / SOC Engineering",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_route_input(value: str) -> str:
    """Normalize user input into a canonical CVE/CWE/CAPEC/ATT&CK/D3FEND id."""

    text = str(value or "").strip().upper().replace("_", "-")
    text = re.sub(r"\s+", " ", text)
    cve = CVE_RE.match(text)
    if cve:
        return f"CVE-{cve.group(1)}-{cve.group(2)}"
    cwe = CWE_RE.match(text)
    if cwe:
        return f"CWE-{cwe.group(1)}"
    capec = CAPEC_RE.match(text)
    if capec:
        return f"CAPEC-{capec.group(1)}"
    if ATTACK_RE.match(text):
        return text if text.startswith("T") else f"T{text}"
    if D3FEND_RE.match(text):
        return text.replace("D3_", "D3-")
    return text.replace(" ", "-")


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: dict[str, Any], *, pretty: bool = True) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None) + "\n", encoding="utf-8")


def node_id(node: dict[str, Any]) -> str:
    return str(node.get("id") or "").strip().upper()


def edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(edge.get("source") or "").strip().upper(),
        str(edge.get("target") or "").strip().upper(),
        str(edge.get("relationship") or "").strip().lower(),
    )


def edge_id(edge: dict[str, Any]) -> str:
    source, target, relationship = edge_key(edge)
    return f"{source}|{relationship}|{target}"


def source_ref_for_node(node: dict[str, Any]) -> str:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    return str(node.get("source_ref") or metadata.get("source_ref") or metadata.get("mapping_file") or metadata.get("source") or "missing_source_ref")


def source_priority(source_ref: Any) -> int:
    text = str(source_ref or "").strip()
    if text in OFFICIAL_SOURCE_PRIORITY:
        return OFFICIAL_SOURCE_PRIORITY[text]
    for prefix, priority in OFFICIAL_SOURCE_PRIORITY.items():
        if text.startswith(prefix):
            return priority
    if text.startswith("inference:"):
        return 5
    return 20 if text else 0


def has_claim_support(item: dict[str, Any]) -> bool:
    if item.get("source_ref"):
        return True
    return bool(item.get("evidence_basis") == "inference" and item.get("requires_validation") is True)


def non_empty(value: Any) -> bool:
    return value not in (None, "", [], {})


def merge_node(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Prefer non-empty official/enriched values without destroying metadata."""

    merged = dict(existing)
    existing_source = source_ref_for_node(existing)
    incoming_source = source_ref_for_node(incoming)
    for key, value in incoming.items():
        if not non_empty(value):
            continue
        if key == "metadata" and isinstance(value, dict):
            metadata = dict(merged.get("metadata") or {})
            source_refs = set(metadata.get("source_refs", []) if isinstance(metadata.get("source_refs"), list) else [])
            if existing_source and existing_source != "missing_source_ref":
                source_refs.add(existing_source)
            if incoming_source and incoming_source != "missing_source_ref":
                source_refs.add(incoming_source)
            for meta_key, meta_value in value.items():
                if not non_empty(meta_value):
                    continue
                if meta_key == "source" and source_priority(incoming_source) > source_priority(existing_source):
                    metadata[meta_key] = meta_value
                elif meta_key not in metadata or metadata.get(meta_key) in (None, "", [], {}):
                    metadata[meta_key] = meta_value
                elif isinstance(metadata.get(meta_key), list) and isinstance(meta_value, list):
                    combined: dict[str, Any] = {}
                    for item in [*metadata[meta_key], *meta_value]:
                        combined[json.dumps(item, sort_keys=True, ensure_ascii=False)] = item
                    metadata[meta_key] = [combined[key] for key in sorted(combined)]
                elif meta_key in {"cvss_base_score", "cvss_base_severity", "cvss_vector", "cvss_version"} and source_priority(incoming_source) >= source_priority(existing_source):
                    metadata[meta_key] = meta_value
            if source_refs:
                metadata["source_refs"] = sorted(source_refs)
            merged["metadata"] = metadata
        elif key == "source_ref":
            if source_priority(value) >= source_priority(source_ref_for_node(merged)):
                merged[key] = value
        elif key not in merged or merged.get(key) in (None, "", [], {}) or merged.get(key) == merged.get("id"):
            merged[key] = value
    return merged


def merge_bundle(base_bundle: dict[str, Any], incoming_nodes: Iterable[dict[str, Any]], incoming_edges: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Return a bundle copy with nodes/edges upserted by canonical IDs."""

    bundle = dict(base_bundle)
    nodes = {node_id(item): dict(item) for item in base_bundle.get("nodes", []) if node_id(item)}
    for item in incoming_nodes:
        identifier = node_id(item)
        if not identifier:
            continue
        nodes[identifier] = merge_node(nodes.get(identifier, {}), {**item, "id": identifier})

    edges = {edge_key(item): dict(item) for item in base_bundle.get("edges", []) if all(edge_key(item))}
    for item in incoming_edges:
        key = edge_key(item)
        if not all(key):
            continue
        edges[key] = {**edges.get(key, {}), **item, "source": key[0], "target": key[1], "relationship": key[2]}

    bundle["nodes"] = sorted(nodes.values(), key=lambda item: (str(item.get("type", "")), str(item.get("id", ""))))
    bundle["edges"] = sorted(edges.values(), key=lambda item: edge_key(item))
    metadata = dict(bundle.get("metadata") or {})
    metadata["last_incremental_enrichment_at"] = now_iso()
    metadata["incremental_enrichment_version"] = "1.0"
    bundle["metadata"] = metadata
    return bundle


def merge_bundle_with_stats(
    base_bundle: dict[str, Any],
    incoming_nodes: Iterable[dict[str, Any]],
    incoming_edges: Iterable[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, int]]:
    nodes = {node_id(item): dict(item) for item in base_bundle.get("nodes", []) if node_id(item)}
    edges = {edge_key(item): dict(item) for item in base_bundle.get("edges", []) if all(edge_key(item))}
    stats = {"nodes_added": 0, "nodes_updated": 0, "edges_added": 0, "edges_updated": 0}

    for item in incoming_nodes:
        identifier = node_id(item)
        if not identifier:
            continue
        if identifier not in nodes:
            stats["nodes_added"] += 1
        else:
            merged = merge_node(nodes[identifier], {**item, "id": identifier})
            if json.dumps(merged, sort_keys=True, ensure_ascii=False) != json.dumps(nodes[identifier], sort_keys=True, ensure_ascii=False):
                stats["nodes_updated"] += 1
        nodes[identifier] = merge_node(nodes.get(identifier, {}), {**item, "id": identifier})

    for item in incoming_edges:
        key = edge_key(item)
        if not all(key):
            continue
        normalized = {**edges.get(key, {}), **item, "source": key[0], "target": key[1], "relationship": key[2]}
        if key not in edges:
            stats["edges_added"] += 1
        elif json.dumps(normalized, sort_keys=True, ensure_ascii=False) != json.dumps(edges[key], sort_keys=True, ensure_ascii=False):
            stats["edges_updated"] += 1
        edges[key] = normalized

    return merge_bundle(base_bundle, nodes.values(), edges.values()), stats


def stage_nodes(capability: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    stages = {stage: [] for stage in THREAT_CHAIN}
    for node in capability.get("threat_route_map", {}).get("nodes", []) or []:
        node_type = str(node.get("type") or "").lower()
        if node_type in stages:
            stages[node_type].append(node)
    return stages


def missing_fields_for_node(node: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    identifier = node_id(node)
    if not node.get("name") or node.get("name") == identifier:
        missing.append("name")
    if not node.get("description"):
        missing.append("description")
    if not (node.get("official_link") or node.get("url")):
        missing.append("official_link")
    source_ref = source_ref_for_node(node)
    if not source_ref or source_ref == "missing_source_ref":
        missing.append("source_ref")
    if not isinstance(node.get("metadata"), dict) or not node.get("metadata"):
        missing.append("metadata")
    return missing


def coverage_gap_report(capability: dict[str, Any]) -> dict[str, Any]:
    gaps = []
    incident_counts: dict[str, int] = {}
    for edge in capability.get("threat_route_map", {}).get("edges", []) or []:
        incident_counts[str(edge.get("source") or "").upper()] = incident_counts.get(str(edge.get("source") or "").upper(), 0) + 1
        incident_counts[str(edge.get("target") or "").upper()] = incident_counts.get(str(edge.get("target") or "").upper(), 0) + 1
    for node in capability.get("threat_route_map", {}).get("nodes", []) or []:
        missing = missing_fields_for_node(node)
        if incident_counts.get(node_id(node), 0) == 0:
            missing.append("relationships")
        if missing:
            gaps.append({"id": node.get("id"), "type": node.get("type"), "missing_fields": missing})
    if not capability.get("threat_route_map", {}).get("nodes") or not capability.get("threat_route_map", {}).get("edges"):
        gaps.append({"id": capability.get("normalized_input") or capability.get("input"), "type": capability.get("input_type"), "missing_fields": ["relationships"]})
    return {
        "status": "complete" if not gaps else "partial",
        "missing_node_fields": gaps,
        "missing_segments": capability.get("threat_route_map", {}).get("missing_segments", []),
    }


def _node_label(node: dict[str, Any]) -> str:
    name = node.get("name") or node.get("id") or "unknown"
    identifier = node.get("id") or name
    if name == identifier:
        return str(identifier)
    return f"{identifier} ({name})"


def _describe_edge(edge: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> str:
    source = nodes.get(str(edge.get("source") or "").upper(), {"id": edge.get("source")})
    target = nodes.get(str(edge.get("target") or "").upper(), {"id": edge.get("target")})
    relationship = str(edge.get("relationship") or "relates_to")
    verb = RELATIONSHIP_ES.get(relationship, relationship.replace("_", " "))
    return f"{_node_label(source)} {verb} {_node_label(target)}"


def build_technical_route_explanation(capability: dict[str, Any]) -> str:
    nodes = {node_id(node): node for node in capability.get("threat_route_map", {}).get("nodes", []) or []}
    edges = capability.get("threat_route_map", {}).get("edges", []) or []
    if not edges:
        return "No hay edges suficientes para construir una cadena técnica completa; la ruta queda como catálogo local y requiere enriquecimiento oficial."
    selected = [_describe_edge(edge, nodes) for edge in edges[:12]]
    return "La cadena técnica queda así: " + "; ".join(selected) + "."


def infer_priority(capability: dict[str, Any], gaps: dict[str, Any]) -> str:
    route_priority = build_route_prioritization(capability, gaps)
    final = str(route_priority.get("final_priority") or "").lower()
    if final and final != "unknown":
        return final
    priority = capability.get("priority", {}) or {}
    final = str(priority.get("final_priority") or "").lower()
    if final and final != "unknown":
        return final
    if capability.get("threat_route_map", {}).get("status") == "complete" and gaps.get("status") == "complete":
        return "medium"
    if capability.get("threat_route_map", {}).get("status") in {"partial", "complete"}:
        return "high" if gaps.get("missing_node_fields") else "medium"
    return "unknown"


def build_route_prioritization(capability: dict[str, Any], gaps: dict[str, Any]) -> dict[str, Any]:
    cve_nodes = [node for node in capability.get("threat_route_map", {}).get("nodes", []) or [] if node.get("type") == "cve"]
    metadata = {}
    for node in cve_nodes:
        metadata.update(node.get("metadata") or {})
    cvss_score = metadata.get("cvss_base_score")
    try:
        cvss_numeric = float(cvss_score) if cvss_score not in (None, "") else None
    except (TypeError, ValueError):
        cvss_numeric = None
    cvss_severity = str(metadata.get("cvss_base_severity") or "").upper()
    kev = bool(metadata.get("kev") or metadata.get("date_added") or metadata.get("known_ransomware_campaign_use"))
    route_complete = capability.get("threat_route_map", {}).get("status") == "complete"
    evidence_complete = gaps.get("status") == "complete"
    d3fend_count = len([node for node in capability.get("threat_route_map", {}).get("nodes", []) or [] if node.get("type") == "d3fend"])
    attack_count = len([node for node in capability.get("threat_route_map", {}).get("nodes", []) or [] if node.get("type") == "attack"])

    if kev or (cvss_numeric is not None and cvss_numeric >= 9):
        final = "critical"
    elif cvss_numeric is not None and cvss_numeric >= 7:
        final = "high"
    elif route_complete and attack_count and d3fend_count:
        final = "medium" if evidence_complete else "high"
    elif route_complete:
        final = "medium"
    else:
        final = "unknown"

    return {
        "final_priority": final,
        "cvss": {"score": cvss_numeric, "severity": cvss_severity or None, "vector": metadata.get("cvss_vector"), "source_ref": "nvd_api" if cvss_numeric is not None else ""},
        "epss": {"score": metadata.get("epss"), "source_ref": metadata.get("epss_source_ref", ""), "requires_validation": metadata.get("epss") in (None, "")},
        "cisa_kev": {"known_exploited": kev, "source_ref": "cisa_kev" if kev else ""},
        "asset_exposure": {"status": "not_provided", "evidence_basis": "inference", "requires_validation": True},
        "attack_technique_count": attack_count,
        "d3fend_coverage_count": d3fend_count,
        "evidence_completeness": "complete" if evidence_complete else "partial",
        "route_complete": route_complete,
    }


def build_evidence_pack(capability: dict[str, Any]) -> dict[str, Any]:
    nodes = capability.get("threat_route_map", {}).get("nodes", []) or []
    edges = capability.get("threat_route_map", {}).get("edges", []) or []
    node_map = {node_id(node): node for node in nodes}
    evidence_nodes = [
        {
            "node_id": node.get("id"),
            "node_type": node.get("type"),
            "name": node.get("name") or node.get("id"),
            "description_present": bool(node.get("description")),
            "source_ref": source_ref_for_node(node),
            "url": node.get("official_link") or node.get("url") or "",
            "confidence": "official" if source_priority(source_ref_for_node(node)) >= 80 else "public_source",
        }
        for node in nodes
    ]
    evidence_edges = [
        {
            "edge_id": edge_id(edge),
            "source": edge.get("source"),
            "target": edge.get("target"),
            "relationship": edge.get("relationship"),
            "source_ref": edge.get("source_ref") or "bundle_edge",
            "confidence": edge.get("confidence") or "unknown",
        }
        for edge in edges
    ]
    route_claims = []
    for edge in edges:
        source = node_map.get(str(edge.get("source") or "").upper(), {"id": edge.get("source")})
        target = node_map.get(str(edge.get("target") or "").upper(), {"id": edge.get("target")})
        route_claims.append(
            {
                "claim_type": "route_relationship",
                "claim_es": _describe_edge(edge, node_map),
                "node_id": target.get("id"),
                "edge_id": edge_id(edge),
                "source_ref": edge.get("source_ref") or "bundle_edge",
                "confidence": edge.get("confidence") or "unknown",
                "related_node_ids": [source.get("id"), target.get("id")],
            }
        )
    return {
        "nodes": evidence_nodes,
        "edges": evidence_edges,
        "claims": route_claims,
        "missing_evidence": coverage_gap_report(capability).get("missing_node_fields", []),
    }


def build_telemetry_map(stages: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    telemetry: list[dict[str, Any]] = []
    for attack in stages.get("attack", []):
        metadata = attack.get("metadata") or {}
        data_sources = metadata.get("x_mitre_data_sources") or metadata.get("data_sources") or []
        platforms = metadata.get("x_mitre_platforms") or []
        hints = TECHNIQUE_TELEMETRY_HINTS.get(str(attack.get("id") or "").upper(), [])
        if not data_sources:
            data_sources = hints or ["Authentication logs", "Application logs", "Process events", "Network sessions"]
            evidence_basis = "inference"
            source_ref = f"inference:telemetry:{attack.get('id')}"
            requires_validation = True
        else:
            evidence_basis = "source"
            source_ref = attack.get("source_ref") or (attack.get("metadata") or {}).get("source") or "bundle_derived"
            requires_validation = False
        telemetry.append(
            {
                "technique_id": attack.get("id"),
                "technique_name": attack.get("name") or attack.get("id"),
                "required_telemetry": data_sources,
                "platforms": platforms,
                "evidence_goal_es": f"Confirmar o descartar comportamiento compatible con {attack.get('name') or attack.get('id')} sin declarar incidente hasta correlacionar activo, identidad, ventana temporal y plataforma.",
                "source_ref": source_ref,
                "evidence_basis": evidence_basis,
                "requires_validation": requires_validation,
                "related_node_id": attack.get("id"),
            }
        )
    for defense in stages.get("d3fend", []):
        metadata = defense.get("metadata") or {}
        artifact = metadata.get("artifact") or "Security telemetry"
        tactic = metadata.get("d3fend_tactic") or metadata.get("tactic") or "Detect/Protect"
        telemetry.append(
            {
                "d3fend_id": defense.get("id"),
                "d3fend_name": defense.get("name") or defense.get("id"),
                "required_telemetry": [artifact],
                "defensive_intent": tactic,
                "control_type": DEFENSE_CONTROL_TYPE.get(str(tactic).lower(), "detective"),
                "evidence_goal_es": f"Probar que {defense.get('name') or defense.get('id')} opera sobre {artifact} y deja evidencia suficiente para reducir, detectar, contener o cerrar la ruta ofensiva.",
                "source_ref": defense.get("source_ref") or metadata.get("source") or "bundle_derived",
                "related_node_id": defense.get("id"),
            }
        )
    return telemetry


def build_detection_hypotheses(stages: dict[str, list[dict[str, Any]]]) -> list[dict[str, str]]:
    hypotheses: list[dict[str, str]] = []
    attacks = stages.get("attack", [])
    capecs = stages.get("capec", [])
    d3fends = stages.get("d3fend", [])
    for attack in attacks[:8]:
        attack_name = attack.get("name") or attack.get("id")
        related_capec = capecs[0].get("id") if capecs else "CAPEC context"
        hypotheses.append(
            {
                "id": f"HYP-{attack.get('id', 'ATTACK')}",
                "title": f"Validar comportamiento {attack.get('id')} - {attack_name}",
                "hypothesis_es": f"Si la ruta {related_capec} se materializa como {attack_name}, deberían verse eventos coherentes con el material de credencial, token, sesión, proceso o proxy que usa la técnica; la hipótesis se cierra solo al correlacionar fuente, identidad, activo y ventana temporal.",
                "telemetry_required_es": "; ".join(TECHNIQUE_TELEMETRY_HINTS.get(str(attack.get("id") or "").upper(), [])) or "Logs de autenticación, aplicación, sesiones, procesos y red según la técnica y el activo expuesto.",
                "source_ref": f"inference:hypothesis:{attack.get('id')}",
                "evidence_basis": "inference",
                "requires_validation": True,
                "node_id": attack.get("id"),
            }
        )
    for defense in d3fends[:6]:
        metadata = defense.get("metadata") or {}
        artifact = metadata.get("artifact") or "artefacto defensivo"
        hypotheses.append(
            {
                "id": f"DEF-{defense.get('id', 'D3FEND')}",
                "title": f"Validar control defensivo {defense.get('id')} - {defense.get('name') or defense.get('id')}",
                "hypothesis_es": f"La defensa {defense.get('name') or defense.get('id')} debe producir evidencia sobre {artifact}; si no existe recolección, cobertura o prueba de efectividad, la ruta queda abierta aunque el mapping D3FEND exista.",
                "telemetry_required_es": str(artifact),
                "source_ref": defense.get("source_ref") or metadata.get("source") or "bundle_derived",
                "node_id": defense.get("id"),
                "confidence": "public_source",
            }
        )
    return hypotheses


def build_owner_actions(stages: dict[str, list[dict[str, Any]]], gaps: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for stage, nodes in stages.items():
        if not nodes:
            continue
        actions.append(
            {
                "owner": OWNER_BY_STAGE.get(stage, "SOC"),
                "scope": stage,
                "action_es": f"Validar los {len(nodes)} nodo(s) {stage.upper()} de la ruta priorizada y adjuntar evidencia de afectación, observabilidad o descarte antes de declarar cobertura.",
                "evidence_expected": ["source_ref", "consulta o export", "resultado: hallazgo/descarte", "criterio de cierre"],
                "related_ids": [node.get("id") for node in nodes[:10]],
                "source_ref": source_ref_for_node(nodes[0]) if nodes else "bundle_derived",
                "confidence": "public_source",
            }
        )
    if gaps.get("missing_node_fields"):
        actions.append(
            {
                "owner": "Knowledge Graph Owner",
                "scope": "enrichment",
                "action_es": "Completar campos faltantes de nodos críticos antes de usar la síntesis como briefing ejecutivo.",
                "evidence_expected": ["nodo actualizado", "fuente oficial", "source_ref", "fecha de refresh"],
                "related_ids": [item.get("id") for item in gaps["missing_node_fields"][:10]],
                "evidence_basis": "inference",
                "requires_validation": True,
            }
        )
    return actions


def first_node_description(stages: dict[str, list[dict[str, Any]]], stage: str) -> str:
    for node in stages.get(stage, []):
        description = str(node.get("description") or "").strip()
        if description:
            return description
    return ""


def defensive_intent_es(defense: dict[str, Any]) -> str:
    metadata = defense.get("metadata") or {}
    tactic = str(metadata.get("d3fend_tactic") or metadata.get("tactic") or "Detect").strip()
    artifact = metadata.get("artifact") or "artefacto defensivo"
    name = defense.get("name") or defense.get("id")
    control_type = DEFENSE_CONTROL_TYPE.get(tactic.lower(), "detective")
    if control_type == "preventive":
        verb = "reduce la probabilidad de abuso antes de que el comportamiento ofensivo prospere"
    elif control_type == "detective":
        verb = "aumenta la observabilidad para detectar o confirmar el comportamiento ofensivo"
    elif control_type == "containment":
        verb = "limita, invalida o aísla el material usado por la ruta ofensiva"
    elif control_type == "corrective":
        verb = "restaura el estado esperado después de contención o remediación"
    else:
        verb = "aporta defensa verificable"
    return f"{name} ({tactic}) {verb} sobre {artifact}."


def build_defensive_controls(stages: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    controls = []
    for node in stages.get("d3fend", []):
        metadata = node.get("metadata") or {}
        tactic = metadata.get("d3fend_tactic") or metadata.get("tactic") or "Detect/Protect"
        controls.append(
            {
                "id": node.get("id"),
                "name": node.get("name") or node.get("id"),
                "intent": tactic,
                "intent_es": defensive_intent_es(node),
                "control_type": DEFENSE_CONTROL_TYPE.get(str(tactic).lower(), "detective"),
                "artifact": metadata.get("artifact") or "unknown",
                "source_ref": node.get("source_ref") or metadata.get("source") or "bundle_derived",
                "confidence": "official" if source_priority(node.get("source_ref") or metadata.get("source")) >= 80 else "public_source",
            }
        )
    return controls


def build_expected_evidence(stages: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for cve in stages.get("cve", [])[:3]:
        metadata = cve.get("metadata") or {}
        evidence.append(
            {
                "node_id": cve.get("id"),
                "evidence_es": "Confirmar si el activo inventariado ejecuta el producto/componente afectado y si la versión corresponde a la ventana vulnerable.",
                "source_ref": cve.get("source_ref") or metadata.get("source") or "bundle_derived",
                "confidence": "public_source",
            }
        )
    for attack in stages.get("attack", [])[:8]:
        evidence.append(
            {
                "node_id": attack.get("id"),
                "evidence_es": f"Adjuntar eventos que confirmen o descarten {attack.get('name') or attack.get('id')} en la ventana de exposición: identidad, activo, origen, destino, token/sesión/proceso y resultado.",
                "source_ref": f"inference:evidence:{attack.get('id')}",
                "evidence_basis": "inference",
                "requires_validation": True,
                "confidence": "inferred",
            }
        )
    for defense in stages.get("d3fend", [])[:8]:
        metadata = defense.get("metadata") or {}
        artifact = metadata.get("artifact") or "artefacto defensivo"
        evidence.append(
            {
                "node_id": defense.get("id"),
                "evidence_es": f"Probar que {defense.get('name') or defense.get('id')} existe, cubre {artifact}, genera evidencia y tiene owner de operación.",
                "source_ref": defense.get("source_ref") or metadata.get("source") or "bundle_derived",
                "confidence": "public_source",
            }
        )
    return evidence


def build_synthesis_claims(capability: dict[str, Any], priority: str) -> list[dict[str, Any]]:
    evidence = build_evidence_pack(capability)
    claims = evidence["claims"][:20]
    claims.append(
        {
            "claim_type": "priority",
            "claim_es": f"La prioridad operativa inicial queda en {priority} según CVSS/KEV disponibles, completitud de ruta, cobertura D3FEND y evidencia local.",
            "source_ref": "bundle_derived",
            "confidence": "derived_from_bundle",
        }
    )
    return claims


def build_closure_criteria() -> list[dict[str, Any]]:
    return [
        {
            "criterion_es": "La ruta CVE→CWE→CAPEC→ATT&CK→D3FEND queda completa o con missing_segments documentados.",
            "source_ref": "bundle_derived",
            "confidence": "derived_from_bundle",
        },
        {
            "criterion_es": "Los nodos críticos tienen name, description, url/source_ref y metadata mínima desde fuente oficial o pública cacheada.",
            "source_ref": "bundle_derived",
            "confidence": "derived_from_bundle",
        },
        {
            "criterion_es": "Las hipótesis de detección se ejecutan con ventana temporal, fuente de log, activo, identidad y resultado: hallazgo o descarte.",
            "evidence_basis": "inference",
            "requires_validation": True,
            "confidence": "inferred",
        },
        {
            "criterion_es": "Cada control D3FEND declarado tiene evidencia de existencia, cobertura, owner y criterio de operación o queda registrado como gap.",
            "source_ref": "bundle_derived",
            "confidence": "derived_from_bundle",
        },
    ]


def build_grounded_synthesis(capability: dict[str, Any]) -> dict[str, Any]:
    stages = stage_nodes(capability)
    gaps = coverage_gap_report(capability)
    priority = infer_priority(capability, gaps)
    route_prioritization = build_route_prioritization(capability, gaps)
    normalized = capability.get("normalized_input") or capability.get("input")
    route_status = capability.get("threat_route_map", {}).get("status", "unknown")
    attack_names = [node.get("name") or node.get("id") for node in stages.get("attack", [])[:5]]
    d3fend_names = [node.get("name") or node.get("id") for node in stages.get("d3fend", [])[:5]]
    capec_names = [node.get("name") or node.get("id") for node in stages.get("capec", [])[:5]]
    cve_description = first_node_description(stages, "cve")
    weakness_description = first_node_description(stages, "cwe")
    capec_description = first_node_description(stages, "capec")
    top_attack = stages.get("attack", [{}])[0] if stages.get("attack") else {}
    t1606 = next((node for node in stages.get("attack", []) if node.get("id") == "T1606"), None)
    focus_attack = t1606 or top_attack
    focus_attack_name = focus_attack.get("name") or focus_attack.get("id") or "técnica ATT&CK pendiente"
    focus_defense = stages.get("d3fend", [{}])[0] if stages.get("d3fend") else {}
    focus_defense_text = defensive_intent_es(focus_defense) if focus_defense else "No hay D3FEND suficiente para declarar reducción defensiva."

    return {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "executive_summary_es": (
            f"{normalized} se interpreta como una ruta defensiva auditable, no como un listado de IDs. "
            f"{cve_description or 'El bundle local aún no contiene una descripción oficial del CVE.'} "
            f"Estado de ruta: {route_status}; prioridad operativa inicial: {priority}."
        ),
        "technical_route_explanation_es": build_technical_route_explanation(capability),
        "why_this_matters_es": (
            f"La debilidad relevante indica que {weakness_description or 'hay una condición técnica pendiente de describir'} "
            f"y el patrón CAPEC aporta el cómo ofensivo: {capec_description or ', '.join(capec_names) or 'pendiente de CAPEC enriquecido'}. "
            f"En ATT&CK, {focus_attack.get('id') or ''} {focus_attack_name} representa el comportamiento observable que debe validarse; "
            f"en D3FEND, {focus_defense_text}"
        ),
        "threat_scenario_es": (
            f"Escenario plausible: {', '.join(capec_names) or 'patrón CAPEC pendiente'} deriva en "
            f"{', '.join(attack_names) or 'técnicas ATT&CK pendientes'}; la reducción o validación defensiva se apoya en "
            f"{', '.join(d3fend_names) or 'D3FEND pendiente'}. Toda conclusión queda limitada al bundle/local store salvo que se adjunte evidencia del entorno."
        ),
        "adversary_story_es": (
            f"Un adversario que aprovecha esta ruta intentaría convertir la debilidad en capacidad operativa: manipular el flujo de recursos, "
            f"credenciales, tokens, sesiones o proxy descrito por CAPEC y luego producir comportamiento compatible con {focus_attack_name}. "
            "Esto es una hipótesis defensiva, no una afirmación de explotación, hasta que exista telemetría del activo."
        ),
        "plausible_kill_chain": [
            {
                "stage": "exposure",
                "description_es": "Identificar activo/componente vulnerable y confirmar si el CVE aplica.",
                "source_ref": source_ref_for_node(stages.get("cve", [{}])[0]) if stages.get("cve") else "bundle_derived",
                "confidence": "public_source",
            },
            {
                "stage": "abuse_pattern",
                "description_es": f"Usar la debilidad para materializar {', '.join(capec_names[:3]) or 'un patrón CAPEC pendiente'}.",
                "source_ref": source_ref_for_node(stages.get("capec", [{}])[0]) if stages.get("capec") else "bundle_derived",
                "confidence": "public_source",
            },
            {
                "stage": "observable_behavior",
                "description_es": f"Buscar señales de {focus_attack_name} en las fuentes de identidad, aplicación, proceso o red aplicables.",
                "source_ref": source_ref_for_node(focus_attack) if focus_attack else "bundle_derived",
                "confidence": "public_source",
            },
        ],
        "exposed_assets": [
            {
                "asset_scope_es": "No aportado por el usuario; debe cruzarse con inventario, producto, versión, plataforma e identidad afectada.",
                "evidence_basis": "inference",
                "requires_validation": True,
                "confidence": "inferred",
            }
        ],
        "telemetry_required": build_telemetry_map(stages),
        "detection_hypotheses": build_detection_hypotheses(stages),
        "defensive_controls_d3fend": build_defensive_controls(stages),
        "expected_evidence": build_expected_evidence(stages),
        "gaps": gaps,
        "owner_actions": build_owner_actions(stages, gaps),
        "closure_criteria": build_closure_criteria(),
        "route_prioritization": route_prioritization,
        "claims": build_synthesis_claims(capability, priority),
        "confidence_rationale": {
            "route_confidence": capability.get("confidence", "unknown"),
            "source_policy": "source-grounded; unsupported claims must remain inference/requires_validation",
            "missing_fields_count": len(gaps.get("missing_node_fields", [])),
            "priority_inputs": route_prioritization,
        },
    }


def validate_synthesis(capability: dict[str, Any], synthesis: dict[str, Any]) -> dict[str, Any]:
    allowed_ids = {node_id(node) for node in capability.get("threat_route_map", {}).get("nodes", []) or []}
    allowed_ids.update({node_id(node) for values in stage_nodes(capability).values() for node in values})
    text = json.dumps(synthesis, ensure_ascii=False)
    referenced = sorted({match.group(0).upper() for match in re.finditer(r"(?:CVE-20\d{2}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?|D3-[A-Z0-9-]+)", text, re.IGNORECASE)})
    invented = [identifier for identifier in referenced if identifier not in allowed_ids and not identifier.startswith("HYP-T") and not identifier.startswith("DEF-D3-")]
    missing_source_refs = []
    for section in ("telemetry_required", "detection_hypotheses", "defensive_controls_d3fend", "owner_actions", "expected_evidence", "closure_criteria", "claims", "plausible_kill_chain", "exposed_assets"):
        for index, item in enumerate(synthesis.get(section, []) or []):
            if isinstance(item, dict) and not has_claim_support(item):
                missing_source_refs.append(f"{section}[{index}]")
    unsupported_claims = []
    for index, claim in enumerate(synthesis.get("claims", []) or []):
        if isinstance(claim, dict) and not (claim.get("claim_es") or claim.get("claim")):
            unsupported_claims.append(f"claims[{index}].claim_es")
    return {
        "status": "pass" if not invented and not missing_source_refs and not unsupported_claims else "fail",
        "referenced_ids": referenced,
        "invented_ids": invented,
        "missing_source_refs": missing_source_refs,
        "unsupported_claims": unsupported_claims,
    }


def upsert_jsonl(path: str | Path, records: Iterable[dict[str, Any]], *, key: str = "id") -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, dict[str, Any]] = {}
    if output.exists():
        for line in output.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            record_key = str(payload.get(key) or payload.get("id") or "")
            if record_key:
                existing[record_key] = payload
    for record in records:
        record_key = str(record.get(key) or record.get("id") or "")
        if record_key:
            existing[record_key] = record
    output.write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in existing.values()), encoding="utf-8")


@dataclass
class EnrichmentResult:
    input: str
    normalized_input: str
    mode: Mode
    route_status: str
    enrichment_status: str
    nodes_added: int = 0
    nodes_updated: int = 0
    edges_added: int = 0
    route_ids: list[str] = field(default_factory=list)
    source_refs_used: list[str] = field(default_factory=list)
    missing_fields_after_enrichment: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    final_route_export: dict[str, Any] = field(default_factory=dict)
    synthesis: dict[str, Any] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": CAPABILITY_NAME,
            "input": self.input,
            "normalized_input": self.normalized_input,
            "mode": self.mode,
            "route_status": self.route_status,
            "enrichment_status": self.enrichment_status,
            "nodes_added": self.nodes_added,
            "nodes_updated": self.nodes_updated,
            "edges_added": self.edges_added,
            "route_ids": self.route_ids,
            "source_refs_used": self.source_refs_used,
            "missing_fields_after_enrichment": self.missing_fields_after_enrichment,
            "route": self.final_route_export,
            "evidence": self.evidence,
            "final_route_export": self.final_route_export,
            "synthesis": self.synthesis,
            "validation": self.validation,
        }


def write_knowledge_store(store_dir: str | Path, result: EnrichmentResult) -> None:
    root = Path(store_dir)
    route = result.final_route_export
    nodes = route.get("threat_route_map", {}).get("nodes", []) or []
    edges = route.get("threat_route_map", {}).get("edges", []) or []
    upsert_jsonl(root / "nodes.jsonl", nodes, key="id")
    upsert_jsonl(root / "edges.jsonl", [{**edge, "id": "|".join(edge_key(edge))} for edge in edges], key="id")
    upsert_jsonl(root / "routes.jsonl", [{"id": result.normalized_input, **route, "evidence": result.evidence, "synthesis": result.synthesis, "validation": result.validation}], key="id")
    upsert_jsonl(root / "ai_synthesis_cache.jsonl", [{"id": result.normalized_input, "input": result.input, "synthesis": result.synthesis, "validation": result.validation, "generated_at": now_iso()}], key="id")
    upsert_jsonl(root / "enrichment_runs.jsonl", [{"id": f"{result.normalized_input}:{now_iso()}", **result.as_dict()}], key="id")
    write_json(root / f"{result.normalized_input}.enrichment.json", result.as_dict())


def build_enrichment_result(capability: dict[str, Any], *, raw_input: str, mode: Mode) -> EnrichmentResult:
    normalized = capability.get("normalized_input") or normalize_route_input(raw_input)
    gaps = coverage_gap_report(capability)
    synthesis = build_grounded_synthesis(capability)
    validation = validate_synthesis(capability, synthesis)
    evidence = build_evidence_pack(capability)
    route_ids = [node.get("id") for node in capability.get("threat_route_map", {}).get("nodes", []) or [] if node.get("id")]
    return EnrichmentResult(
        input=raw_input,
        normalized_input=normalized,
        mode=mode,
        route_status=capability.get("threat_route_map", {}).get("status", "unknown"),
        enrichment_status="complete" if gaps.get("status") == "complete" and validation.get("status") == "pass" else "partial",
        route_ids=route_ids,
        source_refs_used=capability.get("source_refs", []) or capability.get("threat_route_map", {}).get("source_refs", []),
        missing_fields_after_enrichment=gaps.get("missing_node_fields", []),
        evidence=evidence,
        final_route_export=capability,
        synthesis=synthesis,
        validation=validation,
    )
