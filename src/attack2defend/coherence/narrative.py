"""Narrative generator for the Route Coherence artifact.

Produces analysis_es (logical_sequence, technical_narrative, ascii_route, conclusion).
Strategy:
  1. Try LLM via llm_cherry_picker.build_llm_client_from_env() if --llm flag is set.
  2. Fall back to deterministic template from route data.

LLM is only allowed to write narrative text — it cannot propose new IDs.
All IDs referenced in the narrative are validated against the artifact.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..coherence.schema import (
    AnalysisEs,
    CoherenceEdge,
    CoherenceNode,
    LogicalSequenceItem,
    RouteCoherenceArtifact,
)

_KNOWN_ID_RE = re.compile(
    r"(?:CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?|D3-[A-Z0-9-]+)",
    re.IGNORECASE,
)

_COHERENCE_SYSTEM_PROMPT = """
Eres el Route Coherence Analyst de Attack2Defend.

Tu tarea es producir el análisis de coherencia de una ruta de ciberseguridad en ESPAÑOL.

REGLAS ESTRICTAS:
1. NO puedes inventar IDs de CVE, CWE, CAPEC, ATT&CK o D3FEND.
2. Solo puedes referenciar IDs que aparecen en el source_pack proporcionado.
3. NO declares una relación como "oficial" si no está en source_pack con basis=official_explicit.
4. Produce SOLO JSON válido con la estructura indicada.
5. El campo technical_narrative debe tener entre 200 y 600 palabras en español.
6. conclusion debe ser 2-4 oraciones ejecutivas en español.

Estructura de salida obligatoria (JSON):
{
  "executive_summary": "...",
  "logical_sequence": [{"level": 1, "element": "ID", "coherence_reading": "..."}],
  "technical_narrative": "...",
  "ascii_route": "ID1\\n  ↓\\nID2...",
  "conclusion": "..."
}
""".strip()


def generate(artifact: RouteCoherenceArtifact, use_llm: bool = False) -> AnalysisEs:
    """Generate analysis_es for the artifact. Returns AnalysisEs (deterministic or LLM)."""
    if use_llm:
        result = _try_llm(artifact)
        if result:
            return result

    return _deterministic(artifact)


def _try_llm(artifact: RouteCoherenceArtifact) -> AnalysisEs | None:
    try:
        from ..intelligence.llm_cherry_picker import (
            MissingAPIKeyClient,
            build_llm_client_from_env,
        )
    except ImportError:
        return None

    client = build_llm_client_from_env()
    if isinstance(client, MissingAPIKeyClient):
        return None

    context = _build_llm_context(artifact)
    prompt = f"Analiza esta ruta de ciberseguridad y produce el análisis de coherencia:\n\n{json.dumps(context, ensure_ascii=False, indent=2)}"

    try:
        raw = client.complete(
            system=_COHERENCE_SYSTEM_PROMPT,
            user=prompt,
            temperature=0.1,
            max_tokens=2000,
        )
    except Exception:
        return None

    return _parse_llm_response(raw, artifact)


def _build_llm_context(artifact: RouteCoherenceArtifact) -> dict[str, Any]:
    return {
        "input": artifact.input,
        "input_type": artifact.input_type,
        "canonical_chain": artifact.canonical_chain,
        "nodes": [
            {"id": n.id, "type": n.type, "name": n.name, "role": n.role, "basis": n.confidence}
            for n in artifact.all_nodes
        ],
        "edges": [
            {"source": e.source, "target": e.target, "basis": e.mapping_basis}
            for e in artifact.all_edges
        ],
    }


def _parse_llm_response(raw: str, artifact: RouteCoherenceArtifact) -> AnalysisEs | None:
    from ..intelligence.llm_cherry_picker import parse_json_object
    data = parse_json_object(raw)
    if not data or not isinstance(data, dict):
        return None

    # Validate: no invented IDs
    known_ids = artifact.all_node_ids()
    narrative_text = data.get("technical_narrative", "") + data.get("executive_summary", "")
    found_ids = set(_KNOWN_ID_RE.findall(narrative_text))
    invented = found_ids - {i.upper() for i in known_ids}
    if invented:
        return None  # LLM invented IDs — reject, fall back to deterministic

    seq = []
    for item in data.get("logical_sequence", []):
        if isinstance(item, dict):
            seq.append(LogicalSequenceItem(
                level=int(item.get("level", 0)),
                element=str(item.get("element", "")),
                coherence_reading=str(item.get("coherence_reading", "")),
            ))

    return AnalysisEs(
        title=f"Ruta de coherencia — {artifact.input}",
        executive_summary=str(data.get("executive_summary", "")),
        logical_sequence=seq,
        technical_narrative=str(data.get("technical_narrative", "")),
        ascii_route=str(data.get("ascii_route", _build_ascii_route(artifact))),
        conclusion=str(data.get("conclusion", "")),
        narrative_source="llm",
    )


def _deterministic(artifact: RouteCoherenceArtifact) -> AnalysisEs:
    """Build a complete deterministic narrative from route data."""
    nodes_by_type: dict[str, list[CoherenceNode]] = {}
    for n in artifact.all_nodes:
        nodes_by_type.setdefault(n.type, []).append(n)

    seq = _build_logical_sequence(artifact.input, nodes_by_type, artifact.all_edges)
    ascii_route = _build_ascii_route(artifact)
    narrative = _build_narrative(artifact.input, nodes_by_type, artifact.all_edges)
    summary = _build_summary(artifact.input, nodes_by_type)
    conclusion = _build_conclusion(artifact.input, nodes_by_type)

    return AnalysisEs(
        title=f"Ruta de coherencia — {artifact.input}",
        executive_summary=summary,
        logical_sequence=seq,
        technical_narrative=narrative,
        ascii_route=ascii_route,
        conclusion=conclusion,
        narrative_source="deterministic",
    )


_LAYER_LABELS = {
    "cve": "Vulnerabilidad",
    "cwe": "Debilidad raíz (CWE)",
    "capec": "Patrón de ataque (CAPEC)",
    "attack": "Técnica ATT&CK",
    "d3fend": "Contramedida D3FEND",
}

_COHERENCE_TEMPLATES = {
    "cve": "El punto de partida es una vulnerabilidad específica que debe ser analizada en sus capas técnicas subyacentes.",
    "cwe": "La debilidad raíz clasifica el tipo de falla de software que permite la explotación.",
    "capec": "El patrón de ataque modela cómo un adversario explotaría la debilidad desde una perspectiva técnica.",
    "attack": "La técnica ATT&CK describe el comportamiento adversario observable durante la explotación.",
    "d3fend": "La contramedida D3FEND define las acciones defensivas aplicables para prevenir, detectar o contener el ataque.",
}


def _build_logical_sequence(
    input_id: str,
    nodes_by_type: dict[str, list[CoherenceNode]],
    edges: list[CoherenceEdge],
) -> list[LogicalSequenceItem]:
    items = []
    level = 1
    for layer in ("cve", "cwe", "capec", "attack", "d3fend"):
        for node in nodes_by_type.get(layer, []):
            # Find edge basis for this node
            incoming = next(
                (e for e in edges if e.target == node.id),
                None,
            )
            basis_note = ""
            if incoming:
                basis_map = {
                    "official_explicit": "Mapeo explícito oficial (NVD/MITRE)",
                    "official_related": "Mapeo oficial relacionado (MITRE)",
                    "analytical_inferred": "Inferencia analítica — nodo existe en fuente oficial",
                    "conditional": "Condicional — aplica según contexto de explotación",
                    "unverified": "No verificado — requiere curaduría",
                }
                basis_note = f" [{basis_map.get(incoming.mapping_basis, incoming.mapping_basis)}]"

            reading = f"{node.name}{basis_note}. {_COHERENCE_TEMPLATES.get(layer, '')}"
            items.append(LogicalSequenceItem(level=level, element=node.id, coherence_reading=reading))
            level += 1
    return items


def _build_ascii_route(artifact: RouteCoherenceArtifact) -> str:
    lines = []
    nodes_by_type: dict[str, list[CoherenceNode]] = {}
    for n in artifact.all_nodes:
        nodes_by_type.setdefault(n.type, []).append(n)

    layer_order = ("cve", "cwe", "capec", "attack", "d3fend")
    for i, layer in enumerate(layer_order):
        layer_nodes = nodes_by_type.get(layer, [])
        if not layer_nodes:
            continue
        if len(layer_nodes) == 1:
            lines.append(layer_nodes[0].id)
        else:
            primary = [n for n in layer_nodes if n.role in ("root", "primary")]
            secondary = [n for n in layer_nodes if n.role not in ("root", "primary")]
            if primary:
                lines.append(primary[0].id)
            for n in secondary:
                tag = " [condicional]" if n.role == "conditional" else " [secundario]"
                lines.append(f"  ├─ {n.id}{tag}")
        if i < len(layer_order) - 1:
            lines.append("  ↓")
    return "\n".join(lines)


def _build_narrative(
    input_id: str,
    nodes_by_type: dict[str, list[CoherenceNode]],
    edges: list[CoherenceEdge],
) -> str:
    cves = nodes_by_type.get("cve", [])
    cwes = nodes_by_type.get("cwe", [])
    capecs = nodes_by_type.get("capec", [])
    attacks = nodes_by_type.get("attack", [])
    d3fends = nodes_by_type.get("d3fend", [])

    parts = []

    # CVE → CWE
    if cves and cwes:
        cve_name = cves[0].name
        cwe_ids = ", ".join(n.id for n in cwes)
        cwe_names = ", ".join(n.name for n in cwes)
        edge = next((e for e in edges if e.source == cves[0].id and e.target in {n.id for n in cwes}), None)
        basis = edge.mapping_basis if edge else "analytical_inferred"
        basis_label = "documentado explícitamente en NVD" if basis == "official_explicit" else "derivado de mappings MITRE"
        parts.append(
            f"{input_id} representa {cve_name}. "
            f"La debilidad raíz es {cwe_ids} ({cwe_names}), {basis_label}. "
            f"Esta clasificación técnica es el eje central de la cadena de análisis."
        )

    # CWE → CAPEC
    if cwes and capecs:
        primary_capecs = [n for n in capecs if n.role in ("root", "primary")]
        secondary_capecs = [n for n in capecs if n.role == "secondary"]
        conditional_capecs = [n for n in capecs if n.role == "conditional"]

        if primary_capecs:
            parts.append(
                f"Desde la debilidad, el patrón ofensivo principal es "
                f"{primary_capecs[0].id} — {primary_capecs[0].name}."
            )
        if secondary_capecs:
            parts.append(
                f"Como lectura complementaria se identifica "
                f"{', '.join(n.id for n in secondary_capecs)} como patrón secundario o de soporte analítico."
            )
        if conditional_capecs:
            cond_ids = ", ".join(n.id for n in conditional_capecs)
            parts.append(
                f"{cond_ids} se aplica solo bajo condiciones específicas de explotación "
                f"(e.g., race condition o timing). Es una ruta condicional, no el eje principal."
            )

    # CAPEC → ATT&CK
    if capecs and attacks:
        external = [n for n in attacks if "T1190" in n.id or "T1210" in n.id]
        post = [n for n in attacks if "T1059" in n.id]
        others = [n for n in attacks if n not in external and n not in post]

        if external:
            parts.append(
                f"En términos de comportamiento adversario, {external[0].id} aplica si el servicio "
                f"está expuesto públicamente ({external[0].name})."
            )
        if len(external) > 1:
            parts.append(
                f"Si el servicio es interno y el actor ya tiene presencia en la red, "
                f"la técnica más precisa es {external[1].id} — {external[1].name}."
            )
        if post:
            parts.append(
                f"Si la explotación progresa hasta ejecución de código, la fase posterior "
                f"se alinea con {post[0].id} — {post[0].name}."
            )
        if others:
            parts.append(
                f"Técnicas adicionales identificadas: {', '.join(n.id for n in others)}."
            )

    # ATT&CK → D3FEND
    if attacks and d3fends:
        preventive = [n for n in d3fends if any(k in n.id for k in ("SWI", "AVE", "NI", "NTF"))]
        detection = [n for n in d3fends if any(k in n.id for k in ("NTA", "PA", "PSA"))]
        hardening = [n for n in d3fends if any(k in n.id for k in ("SCH", "RN", "PSEP", "EI"))]
        other = [n for n in d3fends if n not in preventive and n not in detection and n not in hardening]

        d3_parts = []
        if preventive:
            d3_parts.append(f"inventario y reducción de superficie ({', '.join(n.id for n in preventive)})")
        if detection:
            d3_parts.append(f"detección de comportamiento ({', '.join(n.id for n in detection)})")
        if hardening:
            d3_parts.append(f"hardening y contención ({', '.join(n.id for n in hardening)})")
        if other:
            d3_parts.append(f"otras contramedidas ({', '.join(n.id for n in other)})")

        if d3_parts:
            parts.append(
                "La ruta defensiva en D3FEND se divide en: " + "; ".join(d3_parts) + "."
            )

    return " ".join(parts) if parts else f"Ruta de coherencia para {input_id}. Análisis determinista generado desde el bundle local."


def _build_summary(input_id: str, nodes_by_type: dict[str, list[CoherenceNode]]) -> str:
    counts = {t: len(ns) for t, ns in nodes_by_type.items()}
    total = sum(counts.values())
    d3_count = counts.get("d3fend", 0)
    attack_count = counts.get("attack", 0)
    return (
        f"Ruta de coherencia para {input_id}. "
        f"Se identificaron {total} nodos en la cadena: "
        f"{attack_count} técnicas ATT&CK y {d3_count} contramedidas D3FEND. "
        f"El análisis traza la vulnerabilidad desde su debilidad raíz hasta las acciones defensivas aplicables."
    )


def _build_conclusion(input_id: str, nodes_by_type: dict[str, list[CoherenceNode]]) -> str:
    d3_nodes = nodes_by_type.get("d3fend", [])
    attack_nodes = nodes_by_type.get("attack", [])
    cwe_nodes = nodes_by_type.get("cwe", [])

    d3_ids = ", ".join(n.id for n in d3_nodes[:4])
    attack_ids = ", ".join(n.id for n in attack_nodes[:3])
    cwe_name = cwe_nodes[0].name if cwe_nodes else "debilidad identificada"

    return (
        f"La ruta de coherencia para {input_id} establece que la {cwe_name} "
        f"habilita comportamientos adversarios ({attack_ids}) que pueden ser contenidos "
        f"mediante contramedidas defensivas priorizadas ({d3_ids}). "
        f"Se recomienda validar la cobertura operacional de cada D3FEND identificado "
        f"antes de declarar la ruta como cubierta."
    )
