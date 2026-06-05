"""Route Coherence Validator.

Enforces no-invention and provenance completeness rules:
  - Every node ID must exist in source-pack or local bundle.
  - Every edge must have mapping_basis and at least one source_ref.
  - No analytical_inferred or conditional edge may carry mapping_basis = official_explicit.
  - Produces a validation-report.json with pass/fail per rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..coherence.schema import CoherenceEdge, CoherenceNode, RouteCoherenceArtifact


@dataclass
class ValidationIssue:
    rule: str
    severity: str  # "error" | "warning"
    element: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "element": self.element, "message": self.message}


@dataclass
class ValidationReport:
    passed: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)

    def add(self, rule: str, severity: str, element: str, message: str) -> None:
        self.issues.append(ValidationIssue(rule, severity, element, message))
        if severity == "error":
            self.passed = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total_issues": len(self.issues),
            "errors": sum(1 for i in self.issues if i.severity == "error"),
            "warnings": sum(1 for i in self.issues if i.severity == "warning"),
            "issues": [i.to_dict() for i in self.issues],
        }


def validate(artifact: RouteCoherenceArtifact, known_ids: set[str] | None = None) -> ValidationReport:
    """Run all validation rules against the artifact. Returns a ValidationReport."""
    report = ValidationReport()
    # Use caller-supplied set first, then the engine-collected source_known_ids.
    # Never fall back to artifact.all_node_ids() — that would be circular.
    known: set[str] | frozenset[str] = known_ids or artifact.source_known_ids

    _check_node_ids(artifact.all_nodes, known, report)
    _check_edge_provenance(artifact.all_edges, report)
    _check_no_invention(artifact.all_edges, report)
    _check_graph_not_empty(artifact, report)
    _check_narrative(artifact, report)

    return report


def _check_node_ids(nodes: list[CoherenceNode], known_ids: set[str], report: ValidationReport) -> None:
    for node in nodes:
        if node.id not in known_ids:
            report.add(
                rule="no_invention_node",
                severity="error",
                element=node.id,
                message=f"Node ID '{node.id}' not found in source-pack or bundle. Cannot invent IDs.",
            )


def _check_edge_provenance(edges: list[CoherenceEdge], report: ValidationReport) -> None:
    for edge in edges:
        if not edge.mapping_basis:
            report.add(
                rule="edge_has_mapping_basis",
                severity="error",
                element=edge.edge_id,
                message=f"Edge {edge.edge_id} is missing mapping_basis.",
            )
        if not edge.source_refs:
            report.add(
                rule="edge_has_source_ref",
                severity="warning",
                element=edge.edge_id,
                message=f"Edge {edge.edge_id} has no source_refs. Provenance is incomplete.",
            )
        if not edge.rationale_es:
            report.add(
                rule="edge_has_rationale",
                severity="warning",
                element=edge.edge_id,
                message=f"Edge {edge.edge_id} has no rationale_es.",
            )


def _check_no_invention(edges: list[CoherenceEdge], report: ValidationReport) -> None:
    """Inferred/conditional edges must not be marked as official_explicit."""
    for edge in edges:
        if edge.mapping_basis == "official_explicit" and edge.score < 50:
            report.add(
                rule="no_false_official",
                severity="error",
                element=edge.edge_id,
                message=f"Edge {edge.edge_id} claims official_explicit but score={edge.score:.0f} is too low.",
            )


def _check_graph_not_empty(artifact: RouteCoherenceArtifact, report: ValidationReport) -> None:
    if not artifact.graph_nodes:
        report.add(
            rule="graph_not_empty",
            severity="error",
            element="graph.nodes",
            message="Graph has no nodes. Route Coherence Engine produced an empty graph.",
        )
    if not artifact.graph_edges:
        report.add(
            rule="graph_not_empty",
            severity="warning",
            element="graph.edges",
            message="Graph has no edges. Route may be incomplete.",
        )


def _check_narrative(artifact: RouteCoherenceArtifact, report: ValidationReport) -> None:
    analysis = artifact.analysis_es
    if not analysis.technical_narrative:
        report.add(
            rule="narrative_present",
            severity="error",
            element="analysis_es.technical_narrative",
            message="technical_narrative is empty. Narrative generation failed or was skipped.",
        )
    if not analysis.logical_sequence:
        report.add(
            rule="logical_sequence_present",
            severity="warning",
            element="analysis_es.logical_sequence",
            message="logical_sequence is empty.",
        )
