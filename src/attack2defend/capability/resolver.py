"""Bundle-first capability resolver for Attack2Defend.

The resolver is deterministic by design: it only reads a local knowledge
bundle, never calls public APIs, never calls an LLM, and never mutates source
data. Capability responses separate the threat route from operational defense
readiness, then connect both maps through explicit bridges.
"""

from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any


CAPABILITY_NAME = "attack2defend.resolve_defense_route"

THREAT_TYPES = {"cve", "cwe", "capec", "attack", "d3fend"}
DEFENSE_TYPES = {"control", "detection", "evidence", "gap", "action"}
TRANSIT_TYPES = {"artifact"}

THREAT_RELATIONSHIPS = {
    "has_weakness",
    "has_related_weakness",
    "vulnerability_has_weakness",
    "may_enable_attack_pattern",
    "weakness_enables_attack_pattern",
    "child_of",
    "may_map_to_attack_technique",
    "attack_pattern_maps_to_technique",
    "may_be_defended_by",
    "may_be_detected_by",
    "technique_mitigated_by_countermeasure",
    "may_lead_to_post_exploitation",
    "subtechnique_of",
    "affects_or_requires_artifact",
    "affects_product_or_platform",
}

DEFENSE_RELATIONSHIP_MAP = {
    "implemented_by": "implemented_by_control",
    "protected_by_control": "implemented_by_control",
    "enables_detection": "validated_by_detection",
    "validated_by_detection": "validated_by_detection",
    "requires_evidence": "requires_evidence",
    "missing_evidence_creates_gap": "missing_evidence_creates_gap",
    "closed_by_action": "closed_by_action",
}

BRIDGE_RELATIONSHIPS = {
    ("d3fend", "control"): "implemented_by_control",
    ("attack", "detection"): "should_be_detected_by",
    ("attack", "evidence"): "requires_evidence",
    ("cve", "action"): "requires_action",
    ("gap", "action"): "closed_by_action",
    ("control", "detection"): "validated_by_detection",
    ("detection", "evidence"): "requires_evidence",
    ("evidence", "gap"): "missing_evidence_creates_gap",
}

MAX_GRAPH_NODES = 160
MAX_EXPANSION_PER_NODE = 16


def resolve_defense_route(
    request: dict[str, Any] | str,
    *,
    bundle_path: str | Path = "data/knowledge-bundle.json",
) -> dict[str, Any]:
    """Resolve an Attack2Defend capability response from a local bundle."""

    raw_input = request.get("input", "") if isinstance(request, dict) else str(request)
    normalized_input = normalize_identifier(raw_input)
    bundle_file = Path(bundle_path)
    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    resolver = CapabilityResolver(bundle=bundle, generated_from=str(bundle_file))
    return resolver.resolve(raw_input=raw_input, normalized_input=normalized_input)


class CapabilityResolver:
    """Resolve two-map capability output from a loaded knowledge bundle."""

    def __init__(self, *, bundle: dict[str, Any], generated_from: str) -> None:
        self.bundle = bundle
        self.generated_from = generated_from
        self.nodes = {normalize_identifier(node["id"]): node for node in bundle.get("nodes", [])}
        self.coverage = {normalize_identifier(k): v for k, v in bundle.get("coverage", {}).items()}
        self.outgoing: dict[str, list[dict[str, Any]]] = {}
        self.incoming: dict[str, list[dict[str, Any]]] = {}
        for edge in bundle.get("edges", []):
            source = normalize_identifier(edge.get("source", ""))
            target = normalize_identifier(edge.get("target", ""))
            if not source or not target:
                continue
            self.outgoing.setdefault(source, []).append(edge)
            self.incoming.setdefault(target, []).append(edge)

    def resolve(self, *, raw_input: str, normalized_input: str) -> dict[str, Any]:
        input_type = self._node_type(normalized_input) or infer_input_type(normalized_input) or "unknown"
        if normalized_input not in self.nodes:
            return self._unresolved(raw_input, normalized_input, input_type)

        visited_ids, used_edges = self._walk(normalized_input, input_type)
        threat_ids = sorted(node_id for node_id in visited_ids if self._node_type(node_id) in THREAT_TYPES)
        defense_ids = sorted(node_id for node_id in visited_ids if self._node_type(node_id) in DEFENSE_TYPES)

        related_ids = set(threat_ids) | {normalized_input}
        synthetic_gaps, synthetic_actions = self._derived_operational_nodes(related_ids)
        coverage_defense_ids = self._coverage_defense_ids(related_ids)
        defense_ids = sorted(set(defense_ids) | coverage_defense_ids | {node["id"] for node in synthetic_gaps + synthetic_actions})
        defense_ids = sorted(set(defense_ids) | self._defense_closure(defense_ids))

        bridges = self._build_bridges(used_edges, threat_ids, defense_ids, synthetic_gaps, synthetic_actions)
        coverage_records = [self.coverage[node_id] for node_id in threat_ids if node_id in self.coverage]
        owners = sorted({owner for record in coverage_records for owner in record.get("owners", [])})

        threat_nodes = [self._node_record(node_id) for node_id in threat_ids]
        controls = [self._node_record(node_id) for node_id in defense_ids if self._synthetic_type(node_id) == "control"]
        detections = [self._node_record(node_id) for node_id in defense_ids if self._synthetic_type(node_id) == "detection"]
        evidence = [self._node_record(node_id) for node_id in defense_ids if self._synthetic_type(node_id) == "evidence"]
        gaps = [self._node_record(node_id) for node_id in defense_ids if self._synthetic_type(node_id) == "gap"]
        actions = [self._node_record(node_id) for node_id in defense_ids if self._synthetic_type(node_id) == "action"]

        threat_edges = [
            self._edge_record(edge)
            for edge in used_edges
            if self._edge_is_inside(edge, THREAT_TYPES)
        ]
        threat_status, threat_missing = self._threat_status(input_type, threat_ids, bridges)
        defense_status, defense_missing = self._defense_status(controls, detections, evidence, gaps, actions, threat_ids)
        priority = self._priority(threat_ids, controls, detections, evidence, gaps, actions)
        confidence = self._confidence(used_edges, threat_status, defense_status)
        official_links = self._official_links(threat_ids)
        source_refs = self._source_refs(used_edges, threat_ids, defense_ids)
        recommended_actions = self._recommended_actions(actions, gaps, priority)

        return {
            "capability": CAPABILITY_NAME,
            "input": raw_input,
            "normalized_input": normalized_input,
            "input_type": input_type,
            "coverage_status": defense_status if defense_status != "unresolved" else threat_status,
            "confidence": confidence,
            "executive_summary_es": self._executive_summary(threat_status, defense_status, priority["final_priority"]),
            "decision_context_es": self._decision_context(threat_nodes, controls, detections, evidence, gaps, actions),
            "risk_rationale_es": self._risk_rationale(priority, detections, evidence, gaps),
            "threat_route_map": {
                "status": threat_status,
                "nodes": threat_nodes,
                "edges": threat_edges,
                "missing_segments": threat_missing,
                "official_links": official_links,
                "source_refs": source_refs,
            },
            "defense_readiness_map": {
                "status": defense_status,
                "summary_es": self._defense_summary(defense_status, controls, detections, evidence, actions),
                "controls": controls,
                "detections": detections,
                "evidence": evidence,
                "gaps": gaps,
                "actions": actions,
                "gap_explanation_es": self._gap_explanation(gaps, defense_missing),
                "missing_segments": defense_missing,
                "source_refs": source_refs,
            },
            "bridges": bridges,
            "priority": priority,
            "recommended_actions": recommended_actions,
            "owners": owners,
            "official_links": official_links,
            "source_refs": source_refs,
            "integration_context": {
                "gti_ready": True,
                "mcp_security_ready": True,
                "mcp_server_ready": False,
                "requires_runtime_enrichment": False,
            },
            "bundle_metadata": self._bundle_metadata(),
            "generated_from": self.generated_from,
        }

    def _walk(self, start: str, input_type: str) -> tuple[set[str], list[dict[str, Any]]]:
        allow_reverse = input_type != "cve"
        visited = {start}
        used_edges: list[dict[str, Any]] = []
        queue: deque[tuple[str, int]] = deque([(start, 0)])

        while queue and len(visited) < MAX_GRAPH_NODES:
            current, depth = queue.popleft()
            if depth >= 6:
                continue
            for edge, neighbor in self._candidate_edges(current, allow_reverse):
                if not self._edge_is_relevant(edge, current, neighbor):
                    continue
                if edge not in used_edges:
                    used_edges.append(edge)
                neighbor_type = self._node_type(neighbor)
                if neighbor_type not in THREAT_TYPES | DEFENSE_TYPES | TRANSIT_TYPES:
                    continue
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))
                if len(visited) >= MAX_GRAPH_NODES:
                    break

        return visited, used_edges

    def _candidate_edges(self, node_id: str, allow_reverse: bool) -> list[tuple[dict[str, Any], str]]:
        candidates = [(edge, normalize_identifier(edge.get("target", ""))) for edge in self.outgoing.get(node_id, [])]
        if allow_reverse:
            candidates.extend((edge, normalize_identifier(edge.get("source", ""))) for edge in self.incoming.get(node_id, []))
        candidates = [candidate for candidate in candidates if candidate[1] in self.nodes]
        candidates.sort(key=lambda item: self._edge_sort_key(item[0]))
        return candidates[:MAX_EXPANSION_PER_NODE]

    def _derived_operational_nodes(self, related_ids: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        gaps: list[dict[str, Any]] = []
        actions: list[dict[str, Any]] = []
        for node_id in sorted(related_ids):
            node = self.nodes.get(node_id, {})
            coverage = self.coverage.get(node_id, {})
            for index, gap_text in enumerate(coverage.get("gaps", []), start=1):
                if self._node_type(normalize_identifier(gap_text)) == "gap":
                    continue
                gaps.append(
                    {
                        "id": f"GAP-{node_id}-{index}",
                        "type": "gap",
                        "name": gap_text,
                        "description": gap_text,
                        "metadata": {"source_ref": f"coverage:{node_id}", "related_id": node_id},
                    }
                )
            required_action = node.get("metadata", {}).get("required_action", "")
            if required_action:
                actions.append(
                    {
                        "id": f"ACTION-{node_id}-REMEDIATE",
                        "type": "action",
                        "name": "Apply required remediation",
                        "description": required_action,
                        "metadata": {"source_ref": f"node:{node_id}:metadata.required_action", "related_id": node_id},
                    }
                )
        return gaps, actions

    def _coverage_defense_ids(self, related_ids: set[str]) -> set[str]:
        defense_ids: set[str] = set()
        for node_id in related_ids:
            record = self.coverage.get(node_id, {})
            for key in ("controls", "detections", "evidence", "gaps", "actions"):
                defense_ids.update(normalize_identifier(value) for value in record.get(key, []))
        return {node_id for node_id in defense_ids if self._node_type(node_id) in DEFENSE_TYPES}

    def _defense_closure(self, seed_ids: list[str]) -> set[str]:
        discovered = {node_id for node_id in seed_ids if self._node_type(node_id) in DEFENSE_TYPES}
        queue: deque[str] = deque(sorted(discovered))
        while queue and len(discovered) < MAX_GRAPH_NODES:
            current = queue.popleft()
            current_type = self._node_type(current)
            for edge in self.outgoing.get(current, []):
                target = normalize_identifier(edge.get("target", ""))
                target_type = self._node_type(target)
                relationship = edge.get("relationship", "")
                if target_type not in DEFENSE_TYPES:
                    continue
                if not allowed_transition(current_type, target_type, relationship):
                    continue
                if target not in discovered:
                    discovered.add(target)
                    queue.append(target)
        return discovered

    def _build_bridges(
        self,
        used_edges: list[dict[str, Any]],
        threat_ids: list[str],
        defense_ids: list[str],
        synthetic_gaps: list[dict[str, Any]],
        synthetic_actions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        bridges: list[dict[str, Any]] = []
        threat_set = set(threat_ids)
        defense_set = set(defense_ids)
        for edge in used_edges:
            source = normalize_identifier(edge.get("source", ""))
            target = normalize_identifier(edge.get("target", ""))
            source_type = self._node_type(source)
            target_type = self._node_type(target)
            relation = DEFENSE_RELATIONSHIP_MAP.get(edge.get("relationship", ""))
            if relation and (source in threat_set | defense_set) and target in defense_set:
                bridges.append(self._bridge_record(source, target, relation, edge))
        for source in sorted(threat_set | defense_set):
            for edge in self.outgoing.get(source, []):
                target = normalize_identifier(edge.get("target", ""))
                relation = DEFENSE_RELATIONSHIP_MAP.get(edge.get("relationship", ""))
                if relation and target in defense_set:
                    bridges.append(self._bridge_record(source, target, relation, edge))

        for threat_id in sorted(threat_set):
            coverage = self.coverage.get(threat_id, {})
            if self._node_type(threat_id) == "attack":
                for detection_id in coverage.get("detections", []):
                    if normalize_identifier(detection_id) in defense_set:
                        bridges.append(self._bridge_record(threat_id, normalize_identifier(detection_id), "should_be_detected_by", None))
                for evidence_id in coverage.get("evidence", []):
                    if normalize_identifier(evidence_id) in defense_set:
                        bridges.append(self._bridge_record(threat_id, normalize_identifier(evidence_id), "requires_evidence", None))

        actions_by_related = {
            action.get("metadata", {}).get("related_id"): action for action in synthetic_actions
        }
        for action in synthetic_actions:
            related_id = action.get("metadata", {}).get("related_id")
            if related_id in threat_set and self._node_type(related_id) == "cve":
                bridges.append(self._bridge_record(related_id, action["id"], "requires_action", None))
        for gap in synthetic_gaps:
            related_id = gap.get("metadata", {}).get("related_id")
            action = actions_by_related.get(related_id)
            if action:
                bridges.append(self._bridge_record(gap["id"], action["id"], "closed_by_action", None))

        return dedupe_records(bridges, key_fields=("source", "target", "relationship"))

    def _controls_for_d3fend(self, d3fend_id: str) -> list[str]:
        controls = []
        for edge in self.outgoing.get(d3fend_id, []):
            if edge.get("relationship") in {"implemented_by", "protected_by_control"}:
                target = normalize_identifier(edge.get("target", ""))
                if self._node_type(target) == "control":
                    controls.append(target)
        return controls

    def _node_record(self, node_id: str) -> dict[str, Any]:
        node = self.nodes.get(node_id) or self._synthetic_node(node_id)
        node_type = node.get("type", self._synthetic_type(node_id))
        source_ref = self._node_source_ref(node)
        record = {
            "id": node["id"],
            "type": node_type,
            "name": node.get("name", node["id"]),
            "description": node.get("description", ""),
            "url": node.get("url", ""),
            "official_link": official_link(node),
            "source_ref": source_ref,
            "metadata": node.get("metadata", {}),
        }
        if node_type in DEFENSE_TYPES and source_ref == "missing_source_ref":
            record["metadata"] = {**record["metadata"], "source_gap": "missing_source_ref"}
        return record

    def _synthetic_node(self, node_id: str) -> dict[str, Any]:
        for coverage_id, record in self.coverage.items():
            for index, gap_text in enumerate(record.get("gaps", []), start=1):
                if node_id == f"GAP-{coverage_id}-{index}":
                    return {
                        "id": node_id,
                        "type": "gap",
                        "name": gap_text,
                        "description": gap_text,
                        "metadata": {"source_ref": f"coverage:{coverage_id}", "related_id": coverage_id},
                    }
        if node_id.startswith("ACTION-") and node_id.endswith("-REMEDIATE"):
            related_id = node_id.removeprefix("ACTION-").removesuffix("-REMEDIATE")
            node = self.nodes.get(related_id, {})
            return {
                "id": node_id,
                "type": "action",
                "name": "Apply required remediation",
                "description": node.get("metadata", {}).get("required_action", ""),
                "metadata": {"source_ref": f"node:{related_id}:metadata.required_action", "related_id": related_id},
            }
        return {"id": node_id, "type": "unknown", "name": node_id, "metadata": {}}

    def _edge_record(self, edge: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": normalize_identifier(edge.get("source", "")),
            "target": normalize_identifier(edge.get("target", "")),
            "relationship": edge.get("relationship", ""),
            "confidence": edge.get("confidence", "unknown"),
            "source_ref": edge.get("source_ref", ""),
        }

    def _bridge_record(
        self,
        source: str,
        target: str,
        relationship: str,
        edge: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "source": source,
            "target": target,
            "relationship": relationship,
            "confidence": edge.get("confidence", "derived_from_bundle") if edge else "derived_from_bundle",
            "source_ref": (edge.get("source_ref") or "bundle_edge") if edge else "bundle_derived",
        }

    def _official_links(self, threat_ids: list[str]) -> list[dict[str, str]]:
        return [
            {
                "node_id": node_id,
                "node_type": self._node_type(node_id),
                "url": self._node_record(node_id)["official_link"],
                "source": "official_framework",
            }
            for node_id in threat_ids
            if self._node_record(node_id)["official_link"]
        ]

    def _source_refs(self, edges: list[dict[str, Any]], threat_ids: list[str], defense_ids: list[str]) -> list[str]:
        refs = {edge.get("source_ref", "") for edge in edges if edge.get("source_ref")}
        for node_id in set(threat_ids) | set(defense_ids):
            node = self.nodes.get(node_id) or self._synthetic_node(node_id)
            source = self._node_source_ref(node)
            if source and source != "missing_source_ref":
                refs.add(source)
        return sorted(refs)

    def _threat_status(
        self,
        input_type: str,
        threat_ids: list[str],
        bridges: list[dict[str, Any]],
    ) -> tuple[str, list[str]]:
        if not threat_ids:
            return "unresolved", ["threat_route"]
        present = {self._node_type(node_id) for node_id in threat_ids}
        expected = expected_threat_types(input_type)
        missing = [node_type for node_type in expected if node_type not in present]
        if expected and not missing:
            return "complete", []
        if len(present) == 1 and not bridges:
            return "catalog-only", missing
        return "partial", missing

    def _defense_status(
        self,
        controls: list[dict[str, Any]],
        detections: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
        actions: list[dict[str, Any]],
        threat_ids: list[str],
    ) -> tuple[str, list[str]]:
        missing = []
        if not controls:
            missing.append("control")
        if not detections:
            missing.append("detection")
        if not evidence:
            missing.append("evidence")
        has_unclosed_gap = bool(gaps) and len(actions) < len(gaps)
        if has_unclosed_gap:
            missing.append("action")
        if not any([controls, detections, evidence, gaps, actions]):
            return "unresolved", missing or ["defense_readiness"]
        if controls and detections and evidence and actions and not has_unclosed_gap:
            return "ready", []
        if any(self._node_type(node_id) == "attack" for node_id in threat_ids) and not detections:
            return "detection-gap", missing
        if detections and not evidence:
            return "evidence-gap", missing
        if has_unclosed_gap:
            return "action-gap", missing
        return "partial-defense", missing

    def _priority(
        self,
        threat_ids: list[str],
        controls: list[dict[str, Any]],
        detections: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
        actions: list[dict[str, Any]],
    ) -> dict[str, str]:
        has_attack = any(self._node_type(node_id) == "attack" for node_id in threat_ids)
        has_threat = bool(threat_ids)
        has_defense = any([controls, detections, evidence, gaps, actions])
        if not has_threat:
            final = "unknown"
        elif has_threat and not has_defense:
            final = "high"
        elif has_attack and not detections:
            final = "high"
        elif detections and not evidence:
            final = "medium"
        elif gaps and len(actions) < len(gaps):
            final = "medium"
        elif evidence and (controls or detections or actions):
            final = "low"
        else:
            final = "medium"
        return {
            "threat_relevance": "known" if has_threat else "unknown",
            "exposure": "known" if any(self.nodes.get(node_id, {}).get("metadata", {}).get("product") for node_id in threat_ids) else "unknown",
            "defense_gap": final,
            "final_priority": final,
            "rationale": "Priority derived from bundle coverage only. GTI enrichment not applied.",
            "rationale_es": spanish_priority_rationale(final),
        }

    def _confidence(self, edges: list[dict[str, Any]], threat_status: str, defense_status: str) -> str:
        confidences = {edge.get("confidence", "") for edge in edges}
        if threat_status == "unresolved":
            return "low"
        if any(value.startswith("internal_") or value == "curated" for value in confidences):
            return "high" if defense_status in {"ready", "partial-defense"} else "medium"
        if confidences:
            return "medium"
        return "low"

    def _edge_is_relevant(self, edge: dict[str, Any], current: str, neighbor: str) -> bool:
        relationship = edge.get("relationship", "")
        if relationship not in THREAT_RELATIONSHIPS | set(DEFENSE_RELATIONSHIP_MAP):
            return False
        source = normalize_identifier(edge.get("source", ""))
        target = normalize_identifier(edge.get("target", ""))
        if current == source and neighbor == target:
            return allowed_transition(self._node_type(source), self._node_type(target), relationship)
        if current == target and neighbor == source:
            return allowed_transition(self._node_type(source), self._node_type(target), relationship)
        return False

    def _edge_is_inside(self, edge: dict[str, Any], allowed_types: set[str]) -> bool:
        return (
            self._node_type(normalize_identifier(edge.get("source", ""))) in allowed_types
            and self._node_type(normalize_identifier(edge.get("target", ""))) in allowed_types
        )

    def _node_type(self, node_id: str) -> str:
        return self.nodes.get(node_id, {}).get("type", "")

    def _synthetic_type(self, node_id: str) -> str:
        return self._node_type(node_id) or self._synthetic_node(node_id).get("type", "")

    def _node_source_ref(self, node: dict[str, Any]) -> str:
        metadata = node.get("metadata", {})
        return metadata.get("source_ref") or metadata.get("mapping_file") or metadata.get("source") or "missing_source_ref"

    def _edge_sort_key(self, edge: dict[str, Any]) -> tuple[int, int, str, str]:
        confidence = edge.get("confidence", "")
        relationship = edge.get("relationship", "")
        priority = 0 if confidence.startswith("internal_") else 1 if confidence == "curated" else 2
        rel_priority = 0 if relationship in set(DEFENSE_RELATIONSHIP_MAP) else 1
        if relationship == "may_be_detected_by":
            rel_priority = -1
        return (priority, rel_priority, relationship, normalize_identifier(edge.get("target", "")))

    def _recommended_actions(
        self,
        actions: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
        priority: dict[str, str],
    ) -> list[dict[str, str]]:
        if actions:
            return [
                {
                    "id": action["id"],
                    "type": "action",
                    "description_es": action.get("description")
                    or "Ejecutar la accion de remediacion registrada en el bundle.",
                    "owner_guidance_es": "Asignar al owner operativo indicado en coverage y validar evidencia de cierre.",
                    "source_ref": action.get("source_ref", "bundle_derived"),
                    "related_gap_id": gaps[0]["id"] if gaps else "",
                }
                for action in actions
            ]
        if gaps:
            return [
                {
                    "id": "ACTION-VALIDATE-GAPS",
                    "type": "action",
                    "description_es": "Validar los gaps reportados y definir una accion de cierre con owner y evidencia verificable.",
                    "owner_guidance_es": "SOC coordina la validacion; AppSec o Infra ejecuta segun el activo afectado.",
                    "source_ref": "bundle_derived",
                    "related_gap_id": gaps[0]["id"],
                }
            ]
        if priority["final_priority"] == "high":
            return [
                {
                    "id": "ACTION-CREATE-DEFENSE-COVERAGE",
                    "type": "action",
                    "description_es": "Crear cobertura defensiva minima: control, Detection y Evidence para la ruta de amenaza encontrada.",
                    "owner_guidance_es": "SOC debe definir la deteccion; Infra o AppSec debe confirmar el control aplicable.",
                    "source_ref": "bundle_derived",
                    "related_gap_id": "",
                }
            ]
        return []

    def _executive_summary(self, threat_status: str, defense_status: str, priority: str) -> str:
        return (
            f"Attack2Defend resolvio la consulta con threat route '{threat_status}' "
            f"y defense readiness '{defense_status}'. La prioridad operativa inicial es '{priority}' "
            "y se deriva solo del bundle local."
        )

    def _decision_context(
        self,
        threat_nodes: list[dict[str, Any]],
        controls: list[dict[str, Any]],
        detections: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
        actions: list[dict[str, Any]],
    ) -> str:
        return (
            f"La ruta contiene {len(threat_nodes)} nodos de amenaza, {len(controls)} Control, "
            f"{len(detections)} Detection, {len(evidence)} Evidence, {len(gaps)} Gap y "
            f"{len(actions)} Action. Los resultados son consumibles por CLI, API futura, MCP futuro y mcp-security."
        )

    def _risk_rationale(self, priority: dict[str, str], detections: list[dict[str, Any]], evidence: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> str:
        if priority["final_priority"] == "high":
            return "La prioridad es alta porque existe ruta de amenaza sin cobertura defensiva suficiente en el bundle."
        if detections and not evidence:
            return "La prioridad es media porque hay Detection, pero falta Evidence verificable para sostener la decision."
        if gaps:
            return "La prioridad es media porque el bundle declara gaps que requieren validacion y accion de cierre."
        return "La prioridad es baja o desconocida segun la cobertura local disponible; no se aplico enriquecimiento GTI."

    def _defense_summary(
        self,
        status: str,
        controls: list[dict[str, Any]],
        detections: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        actions: list[dict[str, Any]],
    ) -> str:
        return (
            f"Defense Readiness esta en estado '{status}': {len(controls)} Control, "
            f"{len(detections)} Detection, {len(evidence)} Evidence y {len(actions)} Action."
        )

    def _gap_explanation(self, gaps: list[dict[str, Any]], missing: list[str]) -> str:
        if gaps:
            gap_names = "; ".join(gap["name"] for gap in gaps)
            return f"El bundle declara gaps operativos que deben cerrarse con evidencia: {gap_names}."
        if missing:
            return f"Faltan segmentos defensivos en el bundle: {', '.join(missing)}."
        return "No hay gaps defensivos declarados para esta ruta en el bundle local."

    def _unresolved(self, raw_input: str, normalized_input: str, input_type: str) -> dict[str, Any]:
        priority = {
            "threat_relevance": "unknown",
            "exposure": "unknown",
            "defense_gap": "unknown",
            "final_priority": "unknown",
            "rationale": "Priority derived from bundle coverage only. GTI enrichment not applied.",
            "rationale_es": "No hay prioridad calculable porque el input no existe en el bundle local.",
        }
        return {
            "capability": CAPABILITY_NAME,
            "input": raw_input,
            "normalized_input": normalized_input,
            "input_type": input_type,
            "coverage_status": "unresolved",
            "confidence": "low",
            "executive_summary_es": "Attack2Defend no encontro una ruta util en el bundle local.",
            "decision_context_es": "El input no existe como nodo local; no se inventaron mappings ni se llamaron APIs publicas.",
            "risk_rationale_es": "Sin ruta local no hay base suficiente para priorizar defensa desde Attack2Defend.",
            "threat_route_map": {
                "status": "unresolved",
                "nodes": [],
                "edges": [],
                "missing_segments": ["threat_route"],
                "official_links": [],
                "source_refs": [],
            },
            "defense_readiness_map": {
                "status": "unresolved",
                "summary_es": "No hay readiness defensivo relacionado en el bundle local.",
                "controls": [],
                "detections": [],
                "evidence": [],
                "gaps": [],
                "actions": [],
                "gap_explanation_es": "No hay evidencia local para declarar cobertura, gaps o acciones.",
                "missing_segments": ["defense_readiness"],
                "source_refs": [],
            },
            "bridges": [],
            "priority": priority,
            "recommended_actions": [],
            "owners": [],
            "official_links": [],
            "source_refs": [],
            "integration_context": {
                "gti_ready": True,
                "mcp_security_ready": True,
                "mcp_server_ready": False,
                "requires_runtime_enrichment": False,
            },
            "bundle_metadata": self._bundle_metadata(),
            "generated_from": self.generated_from,
        }

    def _bundle_metadata(self) -> dict[str, Any]:
        metadata = self.bundle.get("metadata", {})
        return {
            key: metadata[key]
            for key in ("builder_version", "contract_version", "counts", "generated_at", "mode", "warnings")
            if key in metadata
        }


def normalize_identifier(value: str) -> str:
    return value.strip().upper()


def infer_input_type(identifier: str) -> str | None:
    value = normalize_identifier(identifier)
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
        return "cve"
    if re.fullmatch(r"CWE-\d+", value):
        return "cwe"
    if re.fullmatch(r"CAPEC-\d+", value):
        return "capec"
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
        return "attack"
    if value.startswith("D3-"):
        return "d3fend"
    if value.startswith("CTRL-"):
        return "control"
    if value.startswith("DET-"):
        return "detection"
    if value.startswith("EV-"):
        return "evidence"
    if value.startswith("GAP-"):
        return "gap"
    if value.startswith("ACTION-"):
        return "action"
    return None


def official_link(node: dict[str, Any]) -> str:
    node_id = node.get("id", "")
    node_type = node.get("type", "")
    if node_type == "cve":
        return node.get("url") or f"https://www.cve.org/CVERecord?id={node_id}"
    if node_type == "cwe":
        return f"https://cwe.mitre.org/data/definitions/{node_id.removeprefix('CWE-')}.html"
    if node_type == "capec":
        return f"https://capec.mitre.org/data/definitions/{node_id.removeprefix('CAPEC-')}.html"
    if node_type == "attack":
        return f"https://attack.mitre.org/techniques/{node_id.replace('.', '/')}/"
    if node_type == "d3fend":
        return f"https://d3fend.mitre.org/technique/{node_id}/"
    return ""


def expected_threat_types(input_type: str) -> list[str]:
    if input_type == "cve":
        return ["cve", "cwe", "capec", "attack", "d3fend"]
    if input_type == "cwe":
        return ["cwe", "capec", "attack", "d3fend"]
    if input_type == "capec":
        return ["capec", "attack", "d3fend"]
    if input_type == "attack":
        return ["attack", "d3fend"]
    if input_type == "d3fend":
        return ["d3fend"]
    return []


def allowed_transition(source_type: str, target_type: str, relationship: str) -> bool:
    return (
        (
            relationship in {"has_weakness", "has_related_weakness", "vulnerability_has_weakness"}
            and source_type == "cve"
            and target_type == "cwe"
        )
        or (relationship in {"may_enable_attack_pattern", "weakness_enables_attack_pattern"} and source_type == "cwe" and target_type == "capec")
        or (relationship == "child_of" and source_type == "capec" and target_type == "capec")
        or (relationship in {"may_map_to_attack_technique", "attack_pattern_maps_to_technique"} and source_type == "capec" and target_type == "attack")
        or (
            relationship in {"may_be_defended_by", "may_be_detected_by", "technique_mitigated_by_countermeasure"}
            and source_type == "attack"
            and target_type == "d3fend"
        )
        or (relationship == "validated_by_detection" and source_type in {"attack", "artifact"} and target_type == "d3fend")
        or (relationship in {"may_lead_to_post_exploitation", "subtechnique_of"} and source_type == "attack" and target_type == "attack")
        or (relationship in {"affects_or_requires_artifact", "affects_product_or_platform"} and source_type in {"cve", "attack"} and target_type == "artifact")
        or (relationship in {"implemented_by", "protected_by_control"} and source_type == "d3fend" and target_type == "control")
        or (relationship in {"enables_detection", "validated_by_detection"} and source_type == "control" and target_type == "detection")
        or (relationship == "requires_evidence" and source_type == "detection" and target_type == "evidence")
        or (relationship == "missing_evidence_creates_gap" and source_type == "evidence" and target_type == "gap")
        or (relationship == "closed_by_action" and source_type == "gap" and target_type == "action")
    )


def spanish_priority_rationale(priority: str) -> str:
    if priority == "high":
        return "Prioridad alta: hay amenaza localmente relacionada y falta cobertura defensiva verificable."
    if priority == "medium":
        return "Prioridad media: existe cobertura parcial, pero faltan segmentos o evidencia para cerrar la decision."
    if priority == "low":
        return "Prioridad baja: el bundle contiene cobertura defensiva con evidencia o accion asociada."
    return "Prioridad desconocida: el bundle no contiene una ruta suficiente para priorizar."


def dedupe_records(records: list[dict[str, Any]], *, key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for record in records:
        key = tuple(record.get(field, "") for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return result
