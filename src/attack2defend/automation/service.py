"""Read-only automation service for Attack2Defend.

The canonical source of truth remains data/knowledge-bundle.json. This module
performs deterministic local resolution only; it never calls external APIs and
never mutates bundle, candidate, mapping or graph artifacts.
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[3]
NODE_ORDER = ["cve", "artifact", "cwe", "capec", "attack", "d3fend", "control", "detection", "evidence", "gap", "action"]
THREAT_TYPES = {"cve", "cwe", "capec", "attack"}
DEFENSE_TYPES = {"d3fend", "control", "detection", "evidence", "gap", "action"}
OWNER_BY_TYPE = {
    "control": "Security Architecture",
    "detection": "Detection Engineering",
    "evidence": "SOC",
    "gap": "Control Owner",
    "action": "Remediation Owner",
    "d3fend": "Security Engineering",
    "cve": "Vulnerability Management",
    "attack": "Threat Hunting",
}
TELEMETRY_HINTS = {
    "d3fend": ["Relevant control telemetry", "Configuration state", "Control hit/miss evidence"],
    "control": ["Control configuration", "Control logs", "Exception records"],
    "detection": ["SIEM alerts", "Detection rule matches", "Raw event samples"],
    "evidence": ["Evidence artifacts referenced by the bundle"],
    "attack": ["Telemetry mapped to the ATT&CK technique", "Endpoint/network/authentication logs"],
    "cve": ["Asset inventory", "Vulnerability scan findings", "Patch/remediation status"],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "parse_error", "path": rel(path), "error": str(exc)}


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = text(value).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


class AutomationService:
    """Deterministic, read-only Attack2Defend automation service."""

    def __init__(
        self,
        bundle_path: Path | str | None = None,
        data_dir: Path | str | None = None,
    ) -> None:
        self.data_dir = Path(data_dir) if data_dir else ROOT / "data"
        self.bundle_path = Path(bundle_path) if bundle_path else self.data_dir / "knowledge-bundle.json"
        self.bundle = load_json(self.bundle_path, {"metadata": {}, "nodes": [], "edges": [], "indexes": {}, "coverage": {}, "routes": []})
        self.nodes: list[dict[str, Any]] = list(self.bundle.get("nodes", []))
        self.edges: list[dict[str, Any]] = list(self.bundle.get("edges", []))
        self.node_by_id = {self.node_id(n): n for n in self.nodes if self.node_id(n)}
        self.outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for edge in self.edges:
            source, target = self.edge_source(edge), self.edge_target(edge)
            if source and target:
                self.outgoing[source].append(edge)
                self.incoming[target].append(edge)

    # --- Normalizers -----------------------------------------------------
    @staticmethod
    def node_id(node: dict[str, Any]) -> str:
        return text(node.get("id")).strip()

    @staticmethod
    def node_type(node: dict[str, Any]) -> str:
        return text(node.get("type") or "unknown").lower().strip()

    @staticmethod
    def edge_source(edge: dict[str, Any]) -> str:
        return text(edge.get("source") or edge.get("from")).strip()

    @staticmethod
    def edge_target(edge: dict[str, Any]) -> str:
        return text(edge.get("target") or edge.get("to")).strip()

    @staticmethod
    def edge_relationship(edge: dict[str, Any]) -> str:
        return text(edge.get("relationship") or edge.get("type") or "related_to").strip()

    @staticmethod
    def source_ref(obj: dict[str, Any]) -> str:
        return text(obj.get("source_ref") or obj.get("source_url") or obj.get("reference") or "").strip()

    def public_node(self, node: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": self.node_id(node),
            "type": self.node_type(node),
            "name": text(node.get("name") or node.get("title") or self.node_id(node)),
            "description": text(node.get("description")),
            "url": text(node.get("url")),
            "source_ref": self.source_ref(node),
            "source_feed": text(node.get("source_feed") or node.get("source_kind")),
            "metadata": node.get("metadata", {}),
        }

    def public_edge(self, edge: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": self.edge_source(edge),
            "target": self.edge_target(edge),
            "relationship": self.edge_relationship(edge),
            "confidence": text(edge.get("confidence")),
            "source_ref": self.source_ref(edge),
            "source_feed": text(edge.get("source_feed")),
            "source_kind": text(edge.get("source_kind")),
            "deterministic": edge.get("deterministic"),
            "inferred": edge.get("inferred"),
            "retrieved_at": text(edge.get("retrieved_at")),
            "transform_version": text(edge.get("transform_version")),
        }

    # --- Core resolution -------------------------------------------------
    def find_node_id(self, identifier: str) -> str | None:
        raw = text(identifier).strip()
        if not raw:
            return None
        if raw in self.node_by_id:
            return raw
        upper = raw.upper()
        for node_id in self.node_by_id:
            if node_id.upper() == upper:
                return node_id
        lower = raw.lower()
        for node_id, node in self.node_by_id.items():
            haystack = f"{node_id} {node.get('name','')} {node.get('description','')}".lower()
            if lower in haystack:
                return node_id
        return None

    def route_walk(self, root: str, depth: int = 8, direction: str = "forward") -> tuple[list[str], list[dict[str, Any]]]:
        seen_nodes = {root}
        seen_edges: set[tuple[str, str, str]] = set()
        nodes = [root]
        edges: list[dict[str, Any]] = []
        q: deque[tuple[str, int]] = deque([(root, 0)])
        while q:
            cur, d = q.popleft()
            if d >= depth:
                continue
            candidates: list[dict[str, Any]] = []
            if direction in {"forward", "both"}:
                candidates.extend(self.outgoing.get(cur, []))
            if direction in {"backward", "both"}:
                candidates.extend(self.incoming.get(cur, []))
            for edge in candidates:
                source, target, reln = self.edge_source(edge), self.edge_target(edge), self.edge_relationship(edge)
                nxt = target if source == cur else source
                edge_key = (source, reln, target)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append(edge)
                if nxt and nxt not in seen_nodes:
                    seen_nodes.add(nxt)
                    nodes.append(nxt)
                    q.append((nxt, d + 1))
        return nodes, edges

    def resolve_route(self, identifier: str, depth: int = 8) -> dict[str, Any]:
        root = self.find_node_id(identifier)
        if not root:
            return self._response("completed_with_gaps", input=identifier, warnings=[f"No node found for {identifier}"], route={"nodes": [], "edges": []}, coverage_gaps=["No route root found in knowledge-bundle.json"])
        node_ids, edges = self.route_walk(root, depth=depth, direction="forward")
        nodes = [self.node_by_id[nid] for nid in node_ids if nid in self.node_by_id]
        grouped = {t: [self.public_node(n) for n in nodes if self.node_type(n) == t] for t in NODE_ORDER}
        source_refs = self.collect_source_refs(nodes, edges)
        gaps = self.route_gaps(nodes, edges, root)
        status = "completed" if not gaps else "completed_with_gaps"
        return self._response(
            status,
            input=identifier,
            normalized_input=root,
            root=self.public_node(self.node_by_id[root]),
            route={"nodes": [self.public_node(n) for n in nodes], "edges": [self.public_edge(e) for e in edges], "by_type": grouped},
            threat_chain={k: grouped.get(k, []) for k in ["cve", "cwe", "capec", "attack", "d3fend"]},
            coverage_gaps=gaps,
            source_refs=source_refs,
        )

    def batch_resolve_route(self, identifiers: list[str]) -> dict[str, Any]:
        results = [self.resolve_route(item) for item in identifiers]
        return self._response("completed", inputs=identifiers, results=results, result_count=len(results))

    # --- SOC rendering ---------------------------------------------------
    def build_soc_action_pack(self, identifier: str) -> dict[str, Any]:
        route = self.resolve_route(identifier)
        route_data = route.get("route", {})
        nodes = route_data.get("nodes", [])
        by_type: dict[str, list[dict[str, Any]]] = route_data.get("by_type", {})
        source_refs = route.get("source_refs", [])
        gaps = list(route.get("coverage_gaps", []))
        controls = by_type.get("control", []) + by_type.get("d3fend", [])
        detections = by_type.get("detection", [])
        evidence = by_type.get("evidence", [])
        actions = by_type.get("action", [])
        if not by_type.get("d3fend"):
            gaps.append("No D3FEND countermeasure linked to this route.")
        if not evidence:
            gaps.append("No evidence node linked to this route; SOC validation requires explicit evidence collection.")
        if not detections:
            gaps.append("No detection node linked to this route; generate only detection candidates, not confirmed coverage.")
        if not source_refs:
            gaps.append("No source_ref available for this route; provenance must be reviewed before operational use.")
        recommendations = self.get_top_mitigations(identifier).get("top_3_recommendations", [])
        status = "completed" if not gaps else "completed_with_gaps"
        owners = unique([OWNER_BY_TYPE.get(n.get("type", ""), "SOC") for n in nodes]) or ["SOC"]
        soc_pack = {
            "executive_summary": self.executive_summary(identifier, by_type, gaps),
            "defensive_objective": self.defensive_objective(by_type),
            "threat_chain": {k: by_type.get(k, []) for k in ["cve", "cwe", "capec", "attack", "d3fend"]},
            "defense_readiness": {
                "controls": controls,
                "detections": detections,
                "evidence_required": evidence,
                "gaps": unique(gaps),
                "actions": actions or self.default_actions(by_type, gaps),
            },
            "top_3_recommendations": recommendations,
            "integration_hints": {
                "siem_queries": self.siem_query_hints(by_type),
                "soar_playbook_steps": self.soar_steps(by_type, gaps),
                "detection_candidates": self.detection_candidates(by_type, gaps),
            },
            "operational_metadata": {
                "owners": owners,
                "kev": self.is_kev(identifier),
                "cpe_affected": self.cpe_for(identifier),
                "severity": self.derive_severity(identifier, gaps),
                "closure_criteria": self.closure_criteria(by_type, gaps),
            },
        }
        return self._response(status, input=identifier, soc_pack=soc_pack, audit=self.audit_block(source_refs), coverage_gaps=unique(gaps), source_refs=source_refs)

    def explain_d3fend_for_soc(self, d3fend_id: str) -> dict[str, Any]:
        response = self.build_soc_action_pack(d3fend_id)
        response["d3fend_id"] = d3fend_id
        return response

    def get_top_mitigations(self, identifier: str) -> dict[str, Any]:
        route = self.resolve_route(identifier)
        nodes = route.get("route", {}).get("nodes", [])
        edges = route.get("route", {}).get("edges", [])
        by_id = {n["id"]: n for n in nodes}
        edge_refs = defaultdict(list)
        for edge in edges:
            edge_refs[edge.get("target", "")].append(edge.get("source_ref", ""))
            edge_refs[edge.get("source", "")].append(edge.get("source_ref", ""))
        candidates = [n for n in nodes if n.get("type") in {"d3fend", "control", "detection"}]
        scored: list[dict[str, Any]] = []
        for node in candidates:
            nid = node["id"]
            ntype = node.get("type", "")
            has_d3fend = 1.0 if ntype == "d3fend" else 0.5 if any(e.get("target") == nid or e.get("source") == nid for e in edges) else 0.0
            has_control_detection = 1.0 if ntype in {"control", "detection"} else 0.5 if any(n.get("type") in {"control", "detection"} for n in nodes) else 0.0
            has_evidence = 1.0 if any(n.get("type") == "evidence" for n in nodes) else 0.0
            refs = unique([node.get("source_ref", ""), *edge_refs[nid]])
            has_provenance = 1.0 if refs else 0.0
            has_gap_penalty = 0.0 if any(n.get("type") == "gap" for n in nodes) else 1.0
            score = round((0.35 * has_d3fend) + (0.25 * has_control_detection) + (0.20 * has_evidence) + (0.10 * has_provenance) + (0.10 * has_gap_penalty), 3)
            scored.append({
                "technique": nid,
                "name": node.get("name", nid),
                "action": self.recommendation_action(node),
                "confidence": score,
                "rationale": "Deterministic score from D3FEND/control/detection/evidence/provenance/gap coverage.",
                "source_refs": refs,
            })
        scored.sort(key=lambda item: item["confidence"], reverse=True)
        top = [{"rank": i + 1, **item} for i, item in enumerate(scored[:3])]
        gaps = [] if top else ["No D3FEND/control/detection mitigation candidate available in the route."]
        return self._response("completed" if top else "completed_with_gaps", input=identifier, top_3_recommendations=top, coverage_gaps=gaps)

    # --- Auxiliary artifacts --------------------------------------------
    def get_factory_status(self) -> dict[str, Any]:
        return self._response("completed", factory=load_json(self.data_dir / "intelligence" / "intelligence-factory-report.json", {"status": "not_generated"}))

    def get_golden_evaluation(self) -> dict[str, Any]:
        return self._response("completed", golden_evaluation=load_json(self.data_dir / "reports" / "golden-route-evaluation.json", {"status": "not_generated", "cases": []}))

    def get_graph_quality(self) -> dict[str, Any]:
        return self._response("completed", graph_quality=load_json(self.data_dir / "graph" / "graph-quality-report.json", {"status": "not_generated"}))

    def policy_inspect(self) -> dict[str, Any]:
        return self._response("completed", policy=load_json(self.data_dir / "intelligence" / "promotion_policy.json", {"status": "not_generated"}))

    def query_candidates(self, status: str | None = None, run_id: str | None = None, limit: int = 50) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        audit = self.data_dir / "candidates" / "audit_log.jsonl"
        if audit.exists():
            for line in audit.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if status and row.get("decision") != status and row.get("status") != status:
                    continue
                if run_id and row.get("run_id") != run_id:
                    continue
                rows.append(row)
        return self._response("completed", candidates=rows[:limit], count=len(rows[:limit]), filters={"status": status, "run_id": run_id})

    def search_knowledge(self, query: str, limit: int = 20) -> dict[str, Any]:
        q = text(query).lower().strip()
        results = []
        if q:
            for node in self.nodes:
                haystack = f"{self.node_id(node)} {node.get('name','')} {node.get('description','')}".lower()
                if q in haystack:
                    results.append(self.public_node(node))
                    if len(results) >= limit:
                        break
        return self._response("completed", query=query, results=results, count=len(results))

    def graph_explore(self, identifier: str, depth: int = 2, direction: str = "both") -> dict[str, Any]:
        root = self.find_node_id(identifier)
        if not root:
            return self._response("completed_with_gaps", input=identifier, nodes=[], edges=[], warnings=["Graph root not found"])
        node_ids, edges = self.route_walk(root, depth=depth, direction=direction)
        nodes = [self.public_node(self.node_by_id[nid]) for nid in node_ids if nid in self.node_by_id]
        return self._response("completed", input=identifier, depth=depth, direction=direction, nodes=nodes, edges=[self.public_edge(e) for e in edges], source="knowledge-bundle.json")

    def audit_provenance(self, identifier: str) -> dict[str, Any]:
        route = self.resolve_route(identifier)
        edges = route.get("route", {}).get("edges", [])
        nodes = route.get("route", {}).get("nodes", [])
        missing = [e for e in edges if not e.get("source_ref") and not e.get("source_feed")]
        source_refs = unique([*(n.get("source_ref", "") for n in nodes), *(e.get("source_ref", "") for e in edges)])
        return self._response("completed" if not missing else "completed_with_gaps", input=identifier, source_refs=source_refs, missing_provenance_edges=missing, missing_provenance_count=len(missing))

    def get_evidence_pack(self, identifier: str) -> dict[str, Any]:
        route = self.resolve_route(identifier)
        by_type = route.get("route", {}).get("by_type", {})
        evidence = by_type.get("evidence", [])
        gaps = list(route.get("coverage_gaps", []))
        if not evidence:
            gaps.append("No evidence node linked to this route.")
        return self._response("completed" if evidence else "completed_with_gaps", input=identifier, evidence=evidence, required_collection=self.evidence_collection_steps(by_type), coverage_gaps=unique(gaps), source_refs=route.get("source_refs", []))

    # --- SOC helpers -----------------------------------------------------
    def collect_source_refs(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[str]:
        return unique([*(self.source_ref(n) for n in nodes), *(self.source_ref(e) for e in edges)])

    def route_gaps(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]], root: str) -> list[str]:
        types = {self.node_type(n) for n in nodes}
        gaps: list[str] = []
        if not (types & DEFENSE_TYPES):
            gaps.append("Route does not reach a defensive D3FEND/control/detection/evidence/gap/action node.")
        if "d3fend" not in types:
            gaps.append("No D3FEND countermeasure mapped in route.")
        if "detection" not in types:
            gaps.append("No detection node mapped in route.")
        if "evidence" not in types:
            gaps.append("No evidence node mapped in route.")
        if not self.collect_source_refs(nodes, edges):
            gaps.append("No source_ref available for the resolved route.")
        return unique(gaps)

    def executive_summary(self, identifier: str, by_type: dict[str, list[dict[str, Any]]], gaps: list[str]) -> str:
        if by_type.get("d3fend"):
            return f"{identifier} has a deterministic defensive route with D3FEND-linked controls or countermeasures. SOC should validate telemetry, detection coverage and evidence before declaring coverage."
        return f"{identifier} resolves in the bundle, but the defensive route is incomplete. SOC should treat the result as a gap-driven action pack, not confirmed coverage."

    def defensive_objective(self, by_type: dict[str, list[dict[str, Any]]]) -> str:
        if by_type.get("d3fend"):
            names = ", ".join(n.get("name") or n.get("id") for n in by_type.get("d3fend", [])[:3])
            return f"Validate and operationalize D3FEND countermeasures: {names}."
        if by_type.get("attack"):
            return "Identify the defensive controls, detections and evidence needed to cover the mapped ATT&CK technique."
        return "Establish defensive coverage, required evidence and ownership for the resolved route."

    def default_actions(self, by_type: dict[str, list[dict[str, Any]]], gaps: list[str]) -> list[dict[str, Any]]:
        actions = []
        if gaps:
            actions.append({"owner": "SOC", "action": "Collect telemetry samples and validate whether the route has observable evidence.", "status": "recommended"})
            actions.append({"owner": "Detection Engineering", "action": "Convert detection candidates into validated Detection-as-Code only after confirming data sources.", "status": "recommended"})
            actions.append({"owner": "Control Owner", "action": "Document control ownership and closure criteria for unresolved gaps.", "status": "recommended"})
        return actions

    def recommendation_action(self, node: dict[str, Any]) -> str:
        ntype = node.get("type", "")
        name = node.get("name") or node.get("id")
        if ntype == "d3fend":
            return f"Validate whether the SOC stack can observe and enforce {name}; collect evidence of control effectiveness."
        if ntype == "control":
            return f"Confirm control configuration, owner and operational evidence for {name}."
        if ntype == "detection":
            return f"Validate detection logic, data source coverage and recent hits for {name}."
        return f"Review {name} as a defensive candidate."

    def detection_candidates(self, by_type: dict[str, list[dict[str, Any]]], gaps: list[str]) -> list[dict[str, Any]]:
        attacks = by_type.get("attack", [])
        d3fend = by_type.get("d3fend", [])
        candidates = []
        for attack in attacks[:3] or [{"id": "unknown", "name": "Mapped threat behavior"}]:
            mapped_d3 = [n.get("id") for n in d3fend[:3]]
            candidates.append({
                "name": f"SOC validation candidate for {attack.get('id', 'route')}",
                "description": "Caso de uso SOC Tier 1: validar señales observables del comportamiento mapeado, confirmar fuentes de datos disponibles y correlacionar con controles/evidencia antes de declarar cobertura.",
                "mapped_attack": [attack.get("id", "unknown")],
                "mapped_d3fend": mapped_d3,
                "required_data_sources": self.required_telemetry(by_type),
                "logic_outline": [
                    "Identificar eventos asociados al comportamiento o técnica mapeada.",
                    "Correlacionar con controles y evidencias disponibles en la ruta.",
                    "Registrar gaps cuando falten logs, owner, control o evidencia de efectividad.",
                ],
                "chronicle_yaral_candidate": "candidate_requires_validation",
                "sigma_candidate": "candidate_requires_validation",
                "splunk_candidate": "candidate_requires_validation",
                "status": "candidate_requires_validation",
            })
        return candidates

    def required_telemetry(self, by_type: dict[str, list[dict[str, Any]]]) -> list[str]:
        telemetry: list[str] = []
        for ntype, items in by_type.items():
            if items:
                telemetry.extend(TELEMETRY_HINTS.get(ntype, []))
        return unique(telemetry) or ["Relevant SOC telemetry must be identified for this route."]

    def siem_query_hints(self, by_type: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        hints = []
        for attack in by_type.get("attack", [])[:3]:
            hints.append({"platform": "generic", "query": f"Search for telemetry mapped to ATT&CK {attack.get('id')} and validate against D3FEND/evidence route.", "status": "template_requires_environment_mapping"})
        return hints

    def soar_steps(self, by_type: dict[str, list[dict[str, Any]]], gaps: list[str]) -> list[str]:
        steps = ["Resolve defensive route from local bundle.", "Collect required evidence and telemetry.", "Validate detection/control coverage."]
        if gaps:
            steps.append("Open remediation task for explicit coverage gaps.")
        return steps

    def evidence_collection_steps(self, by_type: dict[str, list[dict[str, Any]]]) -> list[str]:
        return ["Collect raw event samples.", "Attach control/detection configuration evidence.", "Document owner and timestamp.", "Record whether evidence closes or confirms a gap."]

    def closure_criteria(self, by_type: dict[str, list[dict[str, Any]]], gaps: list[str]) -> list[str]:
        criteria = ["All source_refs reviewed or provenance gaps accepted.", "Required telemetry sample attached.", "Detection/control owner identified."]
        if gaps:
            criteria.append("All coverage gaps either remediated or accepted with owner/date.")
        return criteria

    def is_kev(self, identifier: str) -> bool:
        kev = self.bundle.get("indexes", {}).get("kev", {})
        return text(identifier).upper() in {text(k).upper() for k in kev.keys()}

    def cpe_for(self, identifier: str) -> list[str]:
        cpe_index = self.bundle.get("indexes", {}).get("cpe_to_cve", {})
        target = text(identifier).upper()
        return [cpe for cpe, cves in cpe_index.items() if target in {text(c).upper() for c in cves}][:25]

    def derive_severity(self, identifier: str, gaps: list[str]) -> str:
        if self.is_kev(identifier):
            return "critical"
        if len(gaps) >= 3:
            return "high"
        if gaps:
            return "medium"
        return "informational"

    def audit_block(self, source_refs: list[str]) -> dict[str, Any]:
        return {"source_of_truth": "knowledge-bundle.json", "external_calls": False, "source_refs": source_refs, "generated_at": now_iso(), "bundle_path": rel(self.bundle_path)}

    def metadata(self) -> dict[str, Any]:
        return self._response("completed", metadata=self.bundle.get("metadata", {}), counts={"nodes": len(self.nodes), "edges": len(self.edges)}, bundle_path=rel(self.bundle_path))

    def health(self) -> dict[str, Any]:
        return self._response("ok", service="attack2defend-automation", bundle_exists=self.bundle_path.exists(), node_count=len(self.nodes), edge_count=len(self.edges))

    def _response(self, status: str, **payload: Any) -> dict[str, Any]:
        return {"status": status, "blocking": False, "timeout_waited_for_human": False, "errors": [], "warnings": payload.pop("warnings", []), **payload}
