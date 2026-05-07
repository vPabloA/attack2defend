"""Official-RAG grounded curated route selection.

This module is intentionally offline and bundle-first. It does not call public
APIs, does not call an LLM, and does not mutate the knowledge bundle. It builds
an official context pack from the capability response and produces a validated
curated route candidate that a future LLM can replace only if it passes the same
validators.

North Star:
  Full graph is deterministic.
  Curated route is AI-assisted.
  Context is official-RAG grounded.
  Final output is schema-validated.
  Validator wins.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


THREAT_CHAIN = ("cve", "cwe", "capec", "attack", "d3fend")
CURATED_ROUTE_LIMITS: dict[str, int] = {
    "cve": 1,
    "cwe": 3,
    "capec": 6,
    "attack": 8,
    "d3fend": 6,
}
GENERIC_NODE_HINTS = (
    "improper access control",
    "access control",
    "content filtering",
    "content modification",
    "content quarantine",
    "decoy",
)
SPECIFIC_NODE_HINTS = (
    "authentication",
    "bypass",
    "session",
    "public-facing",
    "exploit",
    "software update",
    "inventory",
    "vulnerability",
    "network traffic",
    "administrative",
    "file analysis",
)


@dataclass(frozen=True)
class SelectionCandidate:
    id: str
    type: str
    name: str
    description: str
    official_link: str
    source_ref: str
    rank_score: int
    reason_es: str


def build_official_context_pack(capability_response: dict[str, Any]) -> dict[str, Any]:
    """Build an offline official context pack from a capability response.

    The pack is RAG-ready: entries are restricted to the IDs present in the
    deterministic threat graph and include only bundle-provided official links,
    source refs, names and descriptions. Future collectors can replace/extend
    the `facts` field with NVD/MITRE/vendor excerpts without changing the
    curated route validator contract.
    """

    normalized_input = capability_response.get("normalized_input", "")
    nodes = capability_response.get("threat_route_map", {}).get("nodes", [])
    entries = []
    for node in nodes:
        node_type = node.get("type", "")
        if node_type not in THREAT_CHAIN:
            continue
        official_link = node.get("official_link") or node.get("url") or ""
        source_ref = node.get("source_ref") or "missing_source_ref"
        description = node.get("description") or ""
        name = node.get("name") or node.get("id", "")
        entries.append(
            {
                "id": node.get("id", ""),
                "type": node_type,
                "name": name,
                "description": description,
                "official_url": official_link,
                "source_ref": source_ref,
                "source_type": infer_official_source_type(node),
                "facts": compact_facts(name=name, description=description),
                "official_context_available": bool(official_link or source_ref != "missing_source_ref"),
            }
        )

    return {
        "schema_version": "1.0",
        "input": capability_response.get("input", ""),
        "normalized_input": normalized_input,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "source_policy": {
            "allowed_sources": [
                "nvd",
                "cve_org",
                "vendor_advisory",
                "cisa_kev",
                "mitre_cwe",
                "mitre_capec",
                "mitre_attack",
                "mitre_d3fend",
                "bundle_official_link",
            ],
            "runtime_public_api_calls": False,
            "llm_may_use_external_knowledge": False,
            "validator_wins": True,
        },
        "entries": entries,
        "full_traceability_counts": count_entries(entries),
    }


def build_curated_route(
    capability_response: dict[str, Any],
    official_context_pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a curated route candidate from deterministic graph candidates.

    This is the non-LLM baseline for Sprint 2. A future LLM can perform the same
    cherry-picking, but its output must use the exact same allowed IDs and pass
    `validate_curated_route` before any UI/export consumption.
    """

    context_pack = official_context_pack or build_official_context_pack(capability_response)
    selected_ids: set[str] = set()
    stages = []
    for node_type in THREAT_CHAIN:
        candidates = [entry for entry in context_pack["entries"] if entry["type"] == node_type]
        ranked = rank_candidates(candidates, selected_ids, capability_response)
        limit = CURATED_ROUTE_LIMITS[node_type]
        selected = ranked[:limit]
        selected_ids.update(entry.id for entry in selected)
        stages.append(
            {
                "type": node_type,
                "label": node_type.upper() if node_type != "attack" else "ATT&CK",
                "available_count": len(candidates),
                "selected": [candidate_to_record(entry, index + 1) for index, entry in enumerate(selected)],
            }
        )

    route = {
        "schema_version": "1.0",
        "input": capability_response.get("input", ""),
        "normalized_input": capability_response.get("normalized_input", ""),
        "mode": "official_rag_grounded",
        "selection_method": "deterministic_prefilter",
        "ai_ready": True,
        "runtime_public_api_calls": False,
        "limits": CURATED_ROUTE_LIMITS,
        "stages": stages,
        "full_traceability_counts": context_pack.get("full_traceability_counts", {}),
        "rationale_es": build_route_rationale(stages),
        "validation": {"status": "pending", "errors": []},
    }
    errors = validate_curated_route(route, context_pack)
    route["validation"] = {
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "validator": "a2d_curated_route_validator",
    }
    return route


def validate_curated_route(curated_route: dict[str, Any], official_context_pack: dict[str, Any]) -> list[str]:
    """Validate no-invention, selection limits, and source grounding."""

    errors: list[str] = []
    allowed = {entry["id"]: entry for entry in official_context_pack.get("entries", [])}
    seen_ids: set[str] = set()
    for stage in curated_route.get("stages", []):
        node_type = stage.get("type", "")
        selected = stage.get("selected", [])
        limit = CURATED_ROUTE_LIMITS.get(node_type)
        if limit is None:
            errors.append(f"unknown stage type: {node_type}")
            continue
        if len(selected) > limit:
            errors.append(f"{node_type} selected {len(selected)} items; limit is {limit}")
        for item in selected:
            node_id = item.get("id", "")
            if node_id not in allowed:
                errors.append(f"invented id selected: {node_id}")
                continue
            context = allowed[node_id]
            if context.get("type") != node_type:
                errors.append(f"{node_id} selected under {node_type}, but context type is {context.get('type')}")
            if node_id in seen_ids:
                errors.append(f"duplicate selected id: {node_id}")
            seen_ids.add(node_id)
            if not (context.get("official_url") or context.get("source_ref")):
                errors.append(f"{node_id} has no source grounding")
            if context.get("source_ref") == "missing_source_ref" and not context.get("official_url"):
                errors.append(f"{node_id} has missing_source_ref and no official_url")
            if not item.get("reason_es"):
                errors.append(f"{node_id} is missing reason_es")
    return errors


def rank_candidates(
    entries: list[dict[str, Any]],
    selected_ids: set[str],
    capability_response: dict[str, Any],
) -> list[SelectionCandidate]:
    ranked = [to_candidate(entry, capability_response) for entry in entries if entry.get("id") not in selected_ids]
    ranked.sort(key=lambda item: (-item.rank_score, item.id))
    return ranked


def to_candidate(entry: dict[str, Any], capability_response: dict[str, Any]) -> SelectionCandidate:
    text = f"{entry.get('id', '')} {entry.get('name', '')} {entry.get('description', '')}".lower()
    node_type = entry.get("type", "")
    score = 0
    if entry.get("official_url"):
        score += 30
    if entry.get("source_ref") and entry.get("source_ref") != "missing_source_ref":
        score += 20
    if entry.get("official_context_available"):
        score += 10
    score += sum(8 for hint in SPECIFIC_NODE_HINTS if hint in text)
    score -= sum(5 for hint in GENERIC_NODE_HINTS if hint in text)
    if node_type == "cve" and entry.get("id") == capability_response.get("normalized_input"):
        score += 100
    if node_type == "cwe" and entry.get("id") == "CWE-306":
        score += 80
    if node_type == "attack" and entry.get("id") == "T1190":
        score += 80
    if node_type == "d3fend" and entry.get("id") in {"D3-SU", "D3-AI", "D3-AVE", "D3-NTA", "D3-FA"}:
        score += 60
    return SelectionCandidate(
        id=entry.get("id", ""),
        type=node_type,
        name=entry.get("name", entry.get("id", "")),
        description=entry.get("description", ""),
        official_link=entry.get("official_url", ""),
        source_ref=entry.get("source_ref", "missing_source_ref"),
        rank_score=score,
        reason_es=selection_reason_es(entry, score),
    )


def candidate_to_record(candidate: SelectionCandidate, rank: int) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "type": candidate.type,
        "name": candidate.name,
        "official_link": candidate.official_link,
        "source_ref": candidate.source_ref,
        "rank": rank,
        "score": candidate.rank_score,
        "reason_es": candidate.reason_es,
    }


def selection_reason_es(entry: dict[str, Any], score: int) -> str:
    node_type = entry.get("type", "")
    node_id = entry.get("id", "")
    if node_id == "CWE-306":
        return "Seleccionado porque representa ausencia de autenticación en una función crítica y debe gobernar rutas de authentication bypass."
    if node_id == "T1190":
        return "Seleccionado porque conecta la vulnerabilidad con explotación de una aplicación o servicio expuesto."
    if node_type == "d3fend" and node_id in {"D3-SU", "D3-AI", "D3-AVE", "D3-NTA", "D3-FA"}:
        return "Seleccionado por utilidad defensiva directa para actualización, inventario, enumeración, tráfico o análisis de artefactos."
    if entry.get("official_url"):
        return "Seleccionado por cercanía al grafo y disponibilidad de enlace oficial verificable."
    if entry.get("source_ref") and entry.get("source_ref") != "missing_source_ref":
        return "Seleccionado por trazabilidad disponible en el bundle y relevancia dentro de la ruta."
    return f"Seleccionado por ranking determinístico de relevancia defensiva (score {score})."


def build_route_rationale(stages: list[dict[str, Any]]) -> str:
    selected_total = sum(len(stage.get("selected", [])) for stage in stages)
    available_total = sum(stage.get("available_count", 0) for stage in stages)
    return (
        "La ruta curada selecciona un subconjunto verificable de mayor relevancia defensiva "
        f"({selected_total} nodos seleccionados de {available_total} candidatos). "
        "El grafo completo permanece disponible como trazabilidad; la selección no confirma cobertura real del entorno."
    )


def infer_official_source_type(node: dict[str, Any]) -> str:
    node_type = node.get("type", "")
    url = (node.get("official_link") or node.get("url") or "").lower()
    source_ref = (node.get("source_ref") or "").lower()
    text = f"{url} {source_ref}"
    if "nvd.nist.gov" in text or "nvd" in source_ref:
        return "nvd"
    if "cve.org" in text:
        return "cve_org"
    if "cisa" in text or "kev" in text:
        return "cisa_kev"
    if node_type == "cwe":
        return "mitre_cwe"
    if node_type == "capec":
        return "mitre_capec"
    if node_type == "attack":
        return "mitre_attack"
    if node_type == "d3fend":
        return "mitre_d3fend"
    return "bundle_official_link" if url else "bundle_source_ref"


def compact_facts(*, name: str, description: str) -> list[str]:
    facts = []
    if name:
        facts.append(name.strip())
    if description:
        cleaned = " ".join(description.split())
        facts.append(cleaned[:360])
    return facts[:3]


def count_entries(entries: list[dict[str, Any]]) -> dict[str, int]:
    return {node_type: sum(1 for entry in entries if entry.get("type") == node_type) for node_type in THREAT_CHAIN}
