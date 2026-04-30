"""Core contracts for Attack2Defend.

The MVP intentionally keeps the data model small:
- nodes represent CVE/CWE/CAPEC/ATT&CK/D3FEND/control/detection/evidence/gap objects;
- edges represent relationships between nodes;
- route analysis is deterministic input plus optional AI interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    ATTACK = "attack"
    D3FEND = "d3fend"
    ARTIFACT = "artifact"
    CONTROL = "control"
    DETECTION = "detection"
    EVIDENCE = "evidence"
    GAP = "gap"


class CoverageStatus(str, Enum):
    COVERED = "covered"
    PARTIAL = "partial"
    MISSING = "missing"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class KnowledgeNode:
    id: str
    type: NodeType
    name: str
    description: str = ""
    url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("node.id cannot be empty")
        if not self.name.strip():
            raise ValueError("node.name cannot be empty")


@dataclass(frozen=True, slots=True)
class KnowledgeEdge:
    source: str
    target: str
    relationship: str
    source_framework: str = ""
    target_framework: str = ""
    confidence: str = "curated"
    source_ref: str = ""

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("edge.source cannot be empty")
        if not self.target.strip():
            raise ValueError("edge.target cannot be empty")
        if not self.relationship.strip():
            raise ValueError("edge.relationship cannot be empty")


@dataclass(frozen=True, slots=True)
class RouteRequest:
    input_id: str
    input_type: NodeType | None = None
    max_depth: int = 8

    def __post_init__(self) -> None:
        if not self.input_id.strip():
            raise ValueError("input_id cannot be empty")
        if self.max_depth < 1:
            raise ValueError("max_depth must be >= 1")


@dataclass(frozen=True, slots=True)
class RouteResult:
    input_id: str
    nodes: list[KnowledgeNode]
    edges: list[KnowledgeEdge]
    ordered_path: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.nodes)


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    target_id: str
    status: CoverageStatus = CoverageStatus.UNKNOWN
    controls: list[str] = field(default_factory=list)
    detections: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RouteAnalysis:
    route: RouteResult
    executive_summary: str = ""
    interpretation: str = ""
    cti_actions: list[str] = field(default_factory=list)
    threat_hunting_hypotheses: list[str] = field(default_factory=list)
    soc_actions: list[str] = field(default_factory=list)
    appsec_actions: list[str] = field(default_factory=list)
    infra_actions: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    escalation_criteria: list[str] = field(default_factory=list)
    recommended_decision: str = "validate"
    confidence: str = "medium"
