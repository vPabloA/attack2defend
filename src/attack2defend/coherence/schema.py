"""Dataclasses for the Route Coherence artifact.

These types are the internal contract between the coherence engine,
edge classifier, validator, narrative generator, and graph projection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


MappingBasis = str  # "official_explicit" | "official_related" | "analytical_inferred" | "conditional" | "unverified"
NodeRole = str      # "root" | "primary" | "secondary" | "conditional" | "defensive"
NodeConfidence = str  # "official" | "related" | "inferred" | "conditional" | "unverified"


@dataclass
class CoherenceNode:
    id: str
    type: str  # cve | cwe | capec | attack | d3fend
    name: str
    role: NodeRole = "primary"
    confidence: NodeConfidence = "inferred"
    description: str = ""
    url: str = ""
    source_refs: list[str] = field(default_factory=list)
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "role": self.role,
            "confidence": self.confidence,
            "description": self.description,
            "url": self.url,
            "source_refs": self.source_refs,
            "score": self.score,
        }


@dataclass
class CoherenceEdge:
    source: str
    target: str
    relationship: str
    mapping_basis: MappingBasis = "unverified"
    confidence: str = "low"
    score: float = 0.0
    source_refs: list[str] = field(default_factory=list)
    rationale_es: str = ""
    notes: str = ""

    @property
    def edge_id(self) -> str:
        return f"{self.source}→{self.target}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "mapping_basis": self.mapping_basis,
            "confidence": self.confidence,
            "score": self.score,
            "source_refs": self.source_refs,
            "rationale_es": self.rationale_es,
            "notes": self.notes,
        }


@dataclass
class LogicalSequenceItem:
    level: int
    element: str
    coherence_reading: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "element": self.element,
            "coherence_reading": self.coherence_reading,
        }


@dataclass
class AnalysisEs:
    title: str = ""
    executive_summary: str = ""
    logical_sequence: list[LogicalSequenceItem] = field(default_factory=list)
    technical_narrative: str = ""
    ascii_route: str = ""
    conclusion: str = ""
    narrative_source: str = "deterministic"  # "llm" | "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "executive_summary": self.executive_summary,
            "logical_sequence": [i.to_dict() for i in self.logical_sequence],
            "technical_narrative": self.technical_narrative,
            "ascii_route": self.ascii_route,
            "conclusion": self.conclusion,
            "narrative_source": self.narrative_source,
        }


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    title: str = ""
    subtitle: str = ""
    role: NodeRole = "primary"
    confidence: NodeConfidence = "inferred"
    source_refs: list[str] = field(default_factory=list)
    x_layer: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "title": self.title,
            "subtitle": self.subtitle,
            "role": self.role,
            "confidence": self.confidence,
            "source_refs": self.source_refs,
            "xLayer": self.x_layer,
        }


@dataclass
class GraphEdge:
    source: str
    target: str
    mapping_basis: MappingBasis = "unverified"
    label: str = ""
    rationale_es: str = ""
    source_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "mapping_basis": self.mapping_basis,
            "label": self.label,
            "rationale_es": self.rationale_es,
            "source_refs": self.source_refs,
        }


@dataclass
class ProvenanceIndex:
    official_explicit: list[str] = field(default_factory=list)
    official_related: list[str] = field(default_factory=list)
    analytical_inferred: list[str] = field(default_factory=list)
    conditional: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "official_explicit": self.official_explicit,
            "official_related": self.official_related,
            "analytical_inferred": self.analytical_inferred,
            "conditional": self.conditional,
            "unverified": self.unverified,
        }


@dataclass
class RouteCoherenceArtifact:
    input: str
    input_type: str = "unknown"
    status: str = "partial"  # complete | complete_with_inferred_edges | partial | degraded | failed
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Route nodes
    primary_nodes: list[CoherenceNode] = field(default_factory=list)
    secondary_nodes: list[CoherenceNode] = field(default_factory=list)
    conditional_nodes: list[CoherenceNode] = field(default_factory=list)
    defensive_nodes: list[CoherenceNode] = field(default_factory=list)
    all_nodes: list[CoherenceNode] = field(default_factory=list)
    all_edges: list[CoherenceEdge] = field(default_factory=list)

    # Analysis
    analysis_es: AnalysisEs = field(default_factory=AnalysisEs)

    # Graph
    graph_nodes: list[GraphNode] = field(default_factory=list)
    graph_edges: list[GraphEdge] = field(default_factory=list)

    # Provenance
    provenance: ProvenanceIndex = field(default_factory=ProvenanceIndex)

    # Source summary
    source_summary: dict[str, bool] = field(default_factory=dict)

    # Gaps
    gaps: list[dict[str, Any]] = field(default_factory=list)

    # IDs confirmed by external sources (baselines + bundle + live APIs).
    # Used by the validator for non-tautological node checks. Not serialized.
    source_known_ids: frozenset[str] = field(default_factory=frozenset)

    @property
    def canonical_chain(self) -> list[str]:
        """Primary path: one node per framework layer."""
        seen_types: set[str] = set()
        chain: list[str] = []
        for node in self.all_nodes:
            if node.type not in seen_types and node.role in ("root", "primary"):
                seen_types.add(node.type)
                chain.append(node.id)
        return chain

    def all_node_ids(self) -> set[str]:
        return {n.id for n in self.all_nodes}

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_type": "a2d_route_coherence",
            "schema_version": "1.0",
            "input": self.input,
            "input_type": self.input_type,
            "generated_at": self.generated_at,
            "status": self.status,
            "route": {
                "canonical_chain": self.canonical_chain,
                "primary_nodes": [n.to_dict() for n in self.primary_nodes],
                "secondary_nodes": [n.to_dict() for n in self.secondary_nodes],
                "conditional_nodes": [n.to_dict() for n in self.conditional_nodes],
                "defensive_nodes": [n.to_dict() for n in self.defensive_nodes],
                "all_nodes": [n.to_dict() for n in self.all_nodes],
                "all_edges": [e.to_dict() for e in self.all_edges],
            },
            "analysis_es": self.analysis_es.to_dict(),
            "graph": {
                "nodes": [n.to_dict() for n in self.graph_nodes],
                "edges": [e.to_dict() for e in self.graph_edges],
                "layout": "layered-lr",
            },
            "provenance": self.provenance.to_dict(),
            "source_summary": self.source_summary,
            "gaps": self.gaps,
            "validation_context": {
                "source_known_ids": sorted(self.source_known_ids),
                "source_known_ids_origin": "baseline + bundle + live resolvers",
            },
        }
