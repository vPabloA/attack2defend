"""LLM-polished narrative generation for curated Attack2Defend routes.

This module sits on top of the deterministic curated route. It does not change
the selected IDs or relax the validator. The LLM may only rewrite the
consultative narrative, node reasons and operational guidance using the official
context pack and the already-selected route as source material.

If an LLM is unavailable or validation fails, the module falls back to a
deterministic narrative built from the same local artifacts.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone
from typing import Any

from .curated_route import CURATED_ROUTE_LIMITS
from .llm_cherry_picker import (
    AiCherryPickerConfig,
    MissingAPIKeyClient,
    ProviderCallError,
    adapter_metadata,
    build_llm_client_from_env,
    build_provider_client,
    _model_for_provider,
    parse_json_object,
    sanitize_body,
)

NARRATIVE_STAGE_ORDER = ("cve", "cwe", "capec", "attack", "d3fend")
NARRATIVE_ID_RE = re.compile(r"(?:CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?|D3-[A-Z0-9-]+)", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _node_stage_payload(curated_route: dict[str, Any]) -> list[dict[str, Any]]:
    curated_route = _effective_curated_route(curated_route)
    stages: list[dict[str, Any]] = []
    for stage in curated_route.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        selected = []
        for item in stage.get("selected", []) or []:
            if not isinstance(item, dict):
                continue
            selected.append(
                {
                    "id": item.get("id", ""),
                    "type": item.get("type", ""),
                    "name": item.get("name", ""),
                    "description": item.get("description", ""),
                    "official_link": item.get("official_link", ""),
                    "source_ref": item.get("source_ref", ""),
                    "rank": item.get("rank"),
                    "score": item.get("score"),
                    "reason_es": item.get("reason_es", ""),
                }
            )
        stages.append(
            {
                "type": stage.get("type", ""),
                "label": stage.get("label", ""),
                "available_count": stage.get("available_count", 0),
                "selected": selected,
            }
        )
    return stages


def _selected_ids(curated_route: dict[str, Any]) -> set[str]:
    curated_route = _effective_curated_route(curated_route)
    ids: set[str] = {str(curated_route.get("normalized_input") or curated_route.get("input") or "").upper()}
    for stage in curated_route.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        for item in stage.get("selected", []) or []:
            if isinstance(item, dict) and item.get("id"):
                ids.add(str(item["id"]).upper())
    return {item for item in ids if item}


def _effective_curated_route(curated_route: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(curated_route, dict):
        return {}
    if curated_route.get("stages"):
        return curated_route
    for nested_key in ("defensive_curated_route", "curated_route", "route"):
        nested = curated_route.get(nested_key)
        if isinstance(nested, dict):
            synthetic = _synthetic_stage_route(curated_route, nested)
            if synthetic.get("stages"):
                return synthetic
    if any(key in curated_route for key in ("cve", "cwes", "cwe", "capecs", "capec", "attacks", "attack", "d3fends", "d3fend")):
        synthetic = _synthetic_stage_route(curated_route, curated_route)
        if synthetic.get("stages"):
            return synthetic
    return curated_route


def _synthetic_stage_route(root_route: dict[str, Any], selection_payload: dict[str, Any]) -> dict[str, Any]:
    def _normalize_item(item: dict[str, Any], stage_type: str) -> dict[str, Any]:
        return {
            "id": str(item.get("id") or "").strip(),
            "type": str(item.get("type") or stage_type).strip() or stage_type,
            "name": str(item.get("name") or item.get("id") or "").strip(),
            "description": str(item.get("description") or "").strip(),
            "official_link": str(item.get("official_link") or item.get("official_url") or item.get("url") or "").strip(),
            "source_ref": str(item.get("source_ref") or item.get("source") or "missing_source_ref").strip() or "missing_source_ref",
            "rank": item.get("rank"),
            "score": item.get("score"),
            "reason_es": str(item.get("reason_es") or "").strip(),
        }

    def _stage_payload(stage_type: str, label: str, items: Any) -> dict[str, Any]:
        normalized: list[dict[str, Any]] = []
        if isinstance(items, dict):
            normalized.append(_normalize_item(items, stage_type))
        elif isinstance(items, list):
            normalized.extend(_normalize_item(item, stage_type) for item in items if isinstance(item, dict))
        return {
            "type": stage_type,
            "label": label,
            "available_count": len(normalized),
            "selected": normalized,
        }

    stages = [
        _stage_payload("cve", "CVE", selection_payload.get("cve") or selection_payload.get("cves")),
        _stage_payload("cwe", "CWE", selection_payload.get("cwes") or selection_payload.get("cwe")),
        _stage_payload("capec", "CAPEC", selection_payload.get("capecs") or selection_payload.get("capec")),
        _stage_payload("attack", "ATT&CK", selection_payload.get("attacks") or selection_payload.get("attack")),
        _stage_payload("d3fend", "D3FEND", selection_payload.get("d3fends") or selection_payload.get("d3fend")),
    ]

    synthetic = {
        "schema_version": str(root_route.get("schema_version") or selection_payload.get("schema_version") or "1.0"),
        "input": str(root_route.get("input") or selection_payload.get("input") or selection_payload.get("normalized_input") or ""),
        "normalized_input": str(
            root_route.get("normalized_input")
            or selection_payload.get("normalized_input")
            or root_route.get("input")
            or selection_payload.get("input")
            or ""
        ),
        "mode": str(root_route.get("mode") or selection_payload.get("mode") or "official_rag_grounded"),
        "selection_method": str(root_route.get("selection_method") or selection_payload.get("selection_method") or "deterministic_prefilter"),
        "runtime_public_api_calls": bool(
            root_route.get("runtime_public_api_calls", selection_payload.get("runtime_public_api_calls", False))
        ),
        "stages": stages,
        "full_traceability_counts": dict(selection_payload.get("full_traceability_counts") or root_route.get("full_traceability_counts") or {}),
        "rationale_es": str(root_route.get("rationale_es") or selection_payload.get("rationale_es") or "").strip(),
        "validation": copy.deepcopy(root_route.get("validation") or selection_payload.get("validation") or {}),
        "llm_adapter": copy.deepcopy(root_route.get("llm_adapter") or selection_payload.get("llm_adapter") or {}),
    }
    return synthetic


def _stage_nodes_from_context(official_context_pack: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    stages = {stage: [] for stage in NARRATIVE_STAGE_ORDER}
    for entry in official_context_pack.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        node_type = str(entry.get("type") or "").lower()
        if node_type in stages:
            stages[node_type].append(entry)
    return stages


def build_route_narrative_system_prompt() -> str:
    return """
You are Attack2Defend's route-narrative writer.
Use only the provided official_context_pack and curated_route.
You must not invent IDs, products, versions, impact, or coverage.
You must not introduce any node, stage, recommendation or detection not already grounded in the selected route.
Rewrite the route into polished Spanish that is concise, consultative, and templated enough for a SOC briefing.
Return valid json only.
""".strip()


def build_route_narrative_user_prompt(
    capability_response: dict[str, Any],
    official_context_pack: dict[str, Any],
    curated_route: dict[str, Any],
) -> str:
    payload = {
        "task": "Merge the official descriptions into a polished defensive narrative.",
        "output_format": "json",
        "rules": [
            "Use only the selected route and official context pack.",
            "Keep the same selected IDs and do not add new IDs.",
            "Only refer to IDs listed in selected_ids.",
            "Rewrite reasons in Spanish with a short template-like style.",
            "If the context does not support a claim, mark it as no confirmado or keep it generic.",
            "Do not change the route selection or validation result.",
        ],
        "output_schema": {
            "status": "llm_polished",
            "summary_es": "string",
            "executive_summary_es": "string",
            "decision_context_es": "string",
            "risk_rationale_es": "string",
            "consultative_conclusion_es": ["string"],
            "recommended_validations": [
                {
                    "owner": "string",
                    "text": "string",
                    "evidence_expected": ["string"],
                    "source_ids": ["string"],
                }
            ],
            "suggested_detections": [
                {
                    "text": "string",
                    "source_ids": ["string"],
                }
            ],
            "stage_summaries": [
                {"type": "cve", "text": "string"}
            ],
            "node_reasons": [
                {"id": "CVE-2024-0001", "reason_es": "string"}
            ],
        },
        "capability_response": {
            "input": capability_response.get("input", ""),
            "normalized_input": capability_response.get("normalized_input", ""),
            "input_type": capability_response.get("input_type", ""),
            "coverage_status": capability_response.get("coverage_status", ""),
            "confidence": capability_response.get("confidence", ""),
            "priority": capability_response.get("priority", {}),
            "owners": capability_response.get("owners", []),
        },
        "official_context_pack": {
            "input": official_context_pack.get("input", ""),
            "normalized_input": official_context_pack.get("normalized_input", ""),
            "full_traceability_counts": official_context_pack.get("full_traceability_counts", {}),
            "entries": official_context_pack.get("entries", []),
        },
        "curated_route": {
            "input": curated_route.get("input", ""),
            "normalized_input": curated_route.get("normalized_input", ""),
            "mode": curated_route.get("mode", ""),
            "selection_method": curated_route.get("selection_method", ""),
            "limits": CURATED_ROUTE_LIMITS,
            "rationale_es": curated_route.get("rationale_es", ""),
            "stages": _node_stage_payload(curated_route),
            "full_traceability_counts": curated_route.get("full_traceability_counts", {}),
        },
        "selected_ids": sorted(_selected_ids(curated_route)),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_deterministic_route_narrative(
    capability_response: dict[str, Any],
    official_context_pack: dict[str, Any],
    curated_route: dict[str, Any],
) -> dict[str, Any]:
    curated_route = _effective_curated_route(curated_route)
    selected_ids = _selected_ids(curated_route)
    stages = _stage_nodes_from_context(official_context_pack)
    selected_count = sum(len(stage.get("selected", []) or []) for stage in curated_route.get("stages", []) or [])
    selected_names = [
        str(item.get("name") or item.get("id") or "").strip()
        for stage in curated_route.get("stages", []) or []
        if isinstance(stage, dict)
        for item in stage.get("selected", []) or []
        if isinstance(item, dict)
    ]
    stage_summaries = []
    for stage in curated_route.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        stage_type = str(stage.get("type") or "").lower()
        stage_label = str(stage.get("label") or stage_type.upper())
        stage_selected = [item for item in stage.get("selected", []) or [] if isinstance(item, dict)]
        if stage_selected:
            stage_summaries.append(
                {
                    "type": stage_type,
                    "text": f"{stage_label}: {', '.join(str(item.get('name') or item.get('id') or '').strip() for item in stage_selected[:3])}.",
                }
            )

    route_overview = " ".join(item["text"] for item in stage_summaries if item.get("type") != "route").strip()
    if not route_overview:
        route_overview = f"Ruta seleccionada: {', '.join(selected_names[:5])}."

    node_reasons = []
    for stage in curated_route.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        for item in stage.get("selected", []) or []:
            if not isinstance(item, dict):
                continue
            reason = str(item.get("reason_es") or "").strip()
            if not reason:
                reason = "Seleccionado por trazabilidad oficial y relevancia defensiva en la ruta."
            node_reasons.append({"id": str(item.get("id") or "").upper(), "reason_es": reason})

    narrative = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "status": "deterministic_fallback",
        "summary_es": (
            f"{capability_response.get('normalized_input') or capability_response.get('input') or 'La consulta'} "
            f"se resume en {route_overview} La ruta conserva {selected_count} nodos seleccionados y solo usa el bundle local."
        ),
        "executive_summary_es": (
            f"Lectura defensiva para {capability_response.get('normalized_input') or capability_response.get('input') or 'la ruta'}. "
            f"{route_overview} La selección mantiene {selected_count} nodos curados y la trazabilidad del bundle local."
        ),
        "decision_context_es": (
            f"La vista combina {len(official_context_pack.get('entries', []) or [])} entradas oficiales cacheadas, "
            f"{len(selected_ids)} IDs seleccionados y un contexto de prioridad "
            f"{(capability_response.get('priority') or {}).get('final_priority', 'unknown')}. {route_overview}"
        ),
        "risk_rationale_es": (
            f"La prioridad operativa inicial es {(capability_response.get('priority') or {}).get('final_priority', 'unknown')} "
            "porque la lectura sigue limitada al alcance del bundle local y a la evidencia ya seleccionada."
        ),
        "consultative_conclusion_es": [
            "La ruta debe leerse como un briefing defensivo, no como una declaración de cobertura real.",
            "La priorización depende de la evidencia operativa, la exposición y la completitud de la cadena seleccionada.",
            "Las acciones de cierre y validación siguen siendo las responsables de convertir la ruta en decisión.",
        ],
        "recommended_validations": [
            {
                "owner": "Vulnerability Manager",
                "text": "Confirmar activos afectados y versión o condición vulnerable.",
                "evidence_expected": ["Inventario/CMDB", "versión instalada o condición", "referencia al advisory"],
                "source_ids": [item for item in [capability_response.get("normalized_input") or capability_response.get("input") or ""] if item],
            },
            {
                "owner": "SOC",
                "text": "Revisar logs y evidencia asociada a la ruta priorizada.",
                "evidence_expected": ["consulta o export", "resultado: hallazgo o descarte", "ventana temporal definida"],
                "source_ids": [item["id"] for item in node_reasons[:2] if item.get("id")],
            },
        ],
        "suggested_detections": [
            {
                "text": "Acceso anómalo al servicio expuesto",
                "source_ids": [item for item in [capability_response.get("normalized_input") or capability_response.get("input") or ""] if item],
            },
            {
                "text": "Ejecución de comandos o actividad secundaria posterior a la explotación",
                "source_ids": [item["id"] for item in node_reasons if str(item.get("id") or "").startswith("T")][:2],
            },
        ],
        "stage_summaries": stage_summaries or [
            {
                "type": "route",
                "text": f"Ruta seleccionada: {', '.join(selected_names[:5])}.",
            }
        ],
        "node_reasons": node_reasons,
        "node_reason_by_id": {item["id"]: item["reason_es"] for item in node_reasons if item.get("id")},
        "node_reason_source": "deterministic_fallback",
    }
    return narrative


def validate_route_narrative(
    narrative: dict[str, Any],
    *,
    curated_route: dict[str, Any],
) -> dict[str, Any]:
    curated_route = _effective_curated_route(curated_route)
    allowed_ids = _selected_ids(curated_route)
    text = json.dumps(narrative, ensure_ascii=False)
    referenced = sorted({match.group(0).upper() for match in NARRATIVE_ID_RE.finditer(text)})
    invented = [identifier for identifier in referenced if identifier not in allowed_ids]

    required_text_fields = ("summary_es", "executive_summary_es", "decision_context_es", "risk_rationale_es")
    missing_text_fields = [field for field in required_text_fields if not str(narrative.get(field) or "").strip()]
    node_reasons = narrative.get("node_reasons", []) if isinstance(narrative.get("node_reasons"), list) else []
    node_reason_ids = {
        str(item.get("id") or "").upper()
        for item in node_reasons
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    }
    missing_reason_ids = sorted(allowed_ids - node_reason_ids)
    empty_reason_ids = sorted(
        str(item.get("id") or "").upper()
        for item in node_reasons
        if isinstance(item, dict) and not str(item.get("reason_es") or "").strip()
    )

    status = "pass" if not invented and not missing_text_fields and not missing_reason_ids and not empty_reason_ids else "fail"
    return {
        "status": status,
        "invented_ids": invented,
        "missing_text_fields": missing_text_fields,
        "missing_reason_ids": missing_reason_ids,
        "empty_reason_ids": empty_reason_ids,
        "referenced_ids": referenced,
    }


def _merge_llm_narrative_with_deterministic(
    deterministic: dict[str, Any],
    proposed: dict[str, Any],
) -> dict[str, Any]:
    merged = copy.deepcopy(deterministic)
    text_fields = (
        "summary_es",
        "executive_summary_es",
        "decision_context_es",
        "risk_rationale_es",
        "consultative_conclusion_es",
        "recommended_validations",
        "suggested_detections",
        "stage_summaries",
    )
    for field in text_fields:
        value = proposed.get(field)
        if value:
            merged[field] = copy.deepcopy(value)

    if str(proposed.get("status") or "").strip():
        merged["status"] = str(proposed["status"])

    reason_map: dict[str, str] = {}
    for item in deterministic.get("node_reasons", []) or []:
        if isinstance(item, dict) and str(item.get("id") or "").strip():
            reason_map[str(item["id"]).upper()] = str(item.get("reason_es") or "")

    for item in proposed.get("node_reasons", []) or []:
        if not isinstance(item, dict):
            continue
        node_id = str(item.get("id") or "").strip().upper()
        reason = str(item.get("reason_es") or "").strip()
        if node_id and reason:
            reason_map[node_id] = reason

    merged["node_reasons"] = [
        {"id": node_id, "reason_es": reason}
        for node_id, reason in reason_map.items()
        if node_id and reason
    ]
    merged["node_reason_by_id"] = {item["id"]: item["reason_es"] for item in merged["node_reasons"]}
    merged["node_reason_source"] = "llm_polished"
    return merged


def apply_route_narrative(
    curated_route: dict[str, Any],
    narrative: dict[str, Any],
) -> dict[str, Any]:
    polished = copy.deepcopy(_effective_curated_route(curated_route))
    reason_map = narrative.get("node_reason_by_id")
    if not isinstance(reason_map, dict):
        reason_map = {
            str(item.get("id") or "").upper(): str(item.get("reason_es") or "")
            for item in narrative.get("node_reasons", []) or []
            if isinstance(item, dict)
        }

    if str(narrative.get("summary_es") or "").strip():
        polished["rationale_es"] = str(narrative["summary_es"])

    for stage in polished.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        for item in stage.get("selected", []) or []:
            if not isinstance(item, dict):
                continue
            node_id = str(item.get("id") or "").upper()
            reason = str(reason_map.get(node_id) or "").strip()
            if reason:
                item["reason_es"] = reason
    return polished


def build_route_narrative(
    capability_response: dict[str, Any],
    official_context_pack: dict[str, Any],
    curated_route: dict[str, Any],
    *,
    config: AiCherryPickerConfig | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Generate a route narrative, preferring the configured LLM when enabled."""

    cfg = config or AiCherryPickerConfig.from_env()
    curated_route = _effective_curated_route(curated_route)
    deterministic = build_deterministic_route_narrative(capability_response, official_context_pack, curated_route)

    if cfg.mode != "llm":
        deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="mode_not_llm")
        return deterministic

    if cfg.allow_external_knowledge or cfg.runtime_public_api_calls:
        deterministic["llm_adapter"] = adapter_metadata(
            cfg, used=False, fallback_reason="unsafe_external_knowledge_or_runtime_api"
        )
        return deterministic

    if client is not None:
        providers_to_try: list[tuple[str, str, Any]] = [(cfg.provider, cfg.model, client)]
    elif cfg.provider == "auto":
        providers_to_try = []
        for provider_name in cfg.provider_order:
            provider_client = build_provider_client(provider_name, transport=None)
            if isinstance(provider_client, MissingAPIKeyClient):
                continue
            model_name = _model_for_provider(provider_name)
            providers_to_try.append((provider_name, model_name, provider_client))
        if not providers_to_try:
            deterministic["llm_adapter"] = adapter_metadata(
                cfg,
                used=False,
                fallback_reason="missing_api_key",
                providers_attempted=list(cfg.provider_order),
            )
            return deterministic
    else:
        single = build_llm_client_from_env(cfg)
        if isinstance(single, MissingAPIKeyClient):
            try:
                single.complete_json(system_prompt="", user_prompt="", config=cfg)
            except Exception:
                deterministic["llm_adapter"] = adapter_metadata(cfg, used=False, fallback_reason="missing_api_key")
                return deterministic
        providers_to_try = [(cfg.provider, cfg.model, single)]

    system_prompt = build_route_narrative_system_prompt()
    user_prompt = build_route_narrative_user_prompt(capability_response, official_context_pack, curated_route)
    provider_errors: list[ProviderCallError] = []
    used_provider = cfg.provider
    used_model = cfg.model
    proposed: dict[str, Any] | None = None

    for provider_name, model_name, provider_client in providers_to_try:
        per_cfg = AiCherryPickerConfig(
            mode=cfg.mode,
            provider=provider_name,
            model=model_name,
            temperature=cfg.temperature,
            max_output_tokens=cfg.max_output_tokens,
            require_validation=cfg.require_validation,
            allow_external_knowledge=cfg.allow_external_knowledge,
            runtime_public_api_calls=cfg.runtime_public_api_calls,
            timeout_seconds=cfg.timeout_seconds,
            provider_order=cfg.provider_order,
        )
        try:
            proposed = provider_client.complete_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                config=per_cfg,
            )
            used_provider = provider_name
            used_model = model_name
            break
        except ProviderCallError as pce:
            provider_errors.append(pce)
            continue
        except Exception as exc:  # pragma: no cover - defensive
            provider_errors.append(
                ProviderCallError(
                    provider=provider_name,
                    model=model_name,
                    endpoint_sanitized="unknown",
                    http_status=None,
                    error_type=type(exc).__name__,
                    message=sanitize_body(str(exc), max_length=200),
                )
            )
            continue

    if proposed is None:
        first_type = provider_errors[0].error_type if provider_errors else "unknown"
        deterministic["llm_adapter"] = adapter_metadata(
            cfg,
            used=False,
            fallback_reason=f"provider_error:{first_type}",
            provider_errors=provider_errors,
            providers_attempted=[provider for provider, _, _ in providers_to_try],
        )
        return deterministic

    # Normalize and validate the model output.
    try:
        if not isinstance(proposed, dict):
            proposed = parse_json_object(json.dumps(proposed, ensure_ascii=False))
    except Exception:
        deterministic["llm_adapter"] = adapter_metadata(
            cfg,
            used=False,
            fallback_reason="validation_failed",
            provider_errors=provider_errors,
            providers_attempted=[provider for provider, _, _ in providers_to_try],
            used_provider=used_provider,
            used_model=used_model,
        )
        return deterministic

    proposed = _merge_llm_narrative_with_deterministic(deterministic, proposed)
    validation = validate_route_narrative(proposed, curated_route=curated_route)
    if validation["status"] != "pass":
        deterministic["llm_adapter"] = adapter_metadata(
            cfg,
            used=False,
            fallback_reason="validation_failed",
            errors=[
                *(f"invented id: {item}" for item in validation["invented_ids"]),
                *(f"missing text field: {item}" for item in validation["missing_text_fields"]),
                *(f"missing node reason: {item}" for item in validation["missing_reason_ids"]),
                *(f"empty node reason: {item}" for item in validation["empty_reason_ids"]),
            ],
            provider_errors=provider_errors,
            providers_attempted=[provider for provider, _, _ in providers_to_try],
            used_provider=used_provider,
            used_model=used_model,
        )
        return deterministic

    proposed["schema_version"] = "1.0"
    proposed["generated_at"] = proposed.get("generated_at") or now_iso()
    proposed["status"] = "llm_polished"
    proposed["node_reason_by_id"] = {
        str(item.get("id") or "").upper(): str(item.get("reason_es") or "")
        for item in proposed.get("node_reasons", []) or []
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    }
    proposed["llm_adapter"] = adapter_metadata(
        cfg,
        used=True,
        fallback_reason="",
        provider_errors=provider_errors,
        providers_attempted=[provider for provider, _, _ in providers_to_try],
        used_provider=used_provider,
        used_model=used_model,
    )
    return proposed
