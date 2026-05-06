"""LangGraph curator state machine — the heart of the Defense Intelligence Navigator.

Architecture:
  load_bundle → scan_gaps → [conditional] → fetch_evidence
                                          ↘ write_candidates (no gaps / dry-run)
              fetch_evidence → [conditional] → propose_candidates
                                             ↘ write_candidates (no evidence)
              propose_candidates → generate_backlog → write_candidates → END

Invariants (enforced here):
  - dry_run=True → no LLM calls; gap scan still runs for reporting
  - All LLM outputs are CandidateProposal objects, never bundle edits
  - write_candidates writes to output_dir/{run_id}/, never to data/mappings/
  - The bundle loaded in load_bundle is IMMUTABLE for the entire graph run
"""

from __future__ import annotations

import json
import operator
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, TypedDict

_LANGGRAPH_AVAILABLE = False
_IMPORT_ERROR: str = ""

try:
    from langgraph.graph import END, START, StateGraph
    from pydantic import BaseModel, Field
    from typing import Literal

    _LANGGRAPH_AVAILABLE = True
except ImportError as _exc:
    _IMPORT_ERROR = str(_exc)

    # Minimal stubs so the module can be imported for type-checking
    class BaseModel:  # type: ignore[no-redef]
        pass

    def Field(*a: Any, **kw: Any) -> Any:  # type: ignore[misc]
        return None

    class Literal:  # type: ignore[no-redef]
        pass


# ------------------------------------------------------------------ #
# LangGraph state                                                      #
# ------------------------------------------------------------------ #


class CuratorState(TypedDict):
    """Mutable per-run state for the curator graph.

    Fields with Annotated[list, operator.add] accumulate across parallel nodes.
    All other fields use last-write-wins semantics.
    """

    # --- Inputs (set by caller, never mutated by nodes) ---
    bundle_path: str
    cache_dir: str
    output_dir: str
    run_id: str
    model: str
    dry_run: bool
    max_gaps: int
    gap_types: list[str]

    # --- Loaded by load_bundle ---
    bundle: dict[str, Any]

    # --- Detected by scan_gaps ---
    gaps: list[dict]

    # --- Evidence fetched by fetch_evidence ---
    evidence_by_gap: dict[str, list[dict]]

    # --- Accumulated across propose + generate_backlog ---
    candidates: Annotated[list[dict], operator.add]

    # --- Run metadata ---
    stats: dict[str, Any]
    errors: Annotated[list[str], operator.add]


# ------------------------------------------------------------------ #
# Pydantic structured output schemas (used with with_structured_output)
# ------------------------------------------------------------------ #

if _LANGGRAPH_AVAILABLE:

    class EdgeProposal(BaseModel):  # type: ignore[misc]
        source: str = Field(description="Source node ID (e.g. T1190, CWE-79)")
        target: str = Field(description="Target node ID (e.g. D3-HBCD, CAPEC-63)")
        relationship: str = Field(description="Canonical relationship name")
        confidence: Literal["high", "medium", "low"] = Field(  # type: ignore[valid-type]
            description="high=explicit source, medium=inferable, low=speculative"
        )
        evidence_url: str = Field(description="Public source URL — REQUIRED, no fabrication")
        evidence_excerpt: str = Field(description="Direct quote or summary from the source")
        gap_explanation: str = Field(description="Why this gap exists in the current bundle")
        justification: str = Field(description="Why this mapping is correct")
        status: Literal["proposed", "needs_evidence", "no_evidence"] = Field(  # type: ignore[valid-type]
            description="proposed if evidence found; needs_evidence if partial; no_evidence if none"
        )

    class ProposalBatch(BaseModel):  # type: ignore[misc]
        proposals: list[EdgeProposal] = Field(default_factory=list)
        gap_summary: str = Field(description="1-2 sentence overall assessment of the gaps")
        unresolvable: list[str] = Field(
            default_factory=list,
            description="gap_ids for which no mapping is appropriate",
        )

    class BacklogEntry(BaseModel):  # type: ignore[misc]
        title: str = Field(description="Short, actionable title")
        description: str = Field(description="Detailed description of the action")
        owner: Literal["soc", "ctem", "appsec", "infra", "detection-engineer"] = Field(  # type: ignore[valid-type]
            description="Team responsible for this item"
        )
        priority: Literal["critical", "high", "medium", "low"] = Field(  # type: ignore[valid-type]
            description="critical=immediate, high=this sprint, medium=next quarter, low=backlog"
        )
        gap_context: str = Field(description="The gap that motivated this item")
        references: list[str] = Field(default_factory=list, description="CVE/CWE/ATT&CK/D3FEND IDs")

    class BacklogBatch(BaseModel):  # type: ignore[misc]
        items: list[BacklogEntry] = Field(default_factory=list)
        summary: str = Field(description="1-2 sentence assessment of the action landscape")


# ------------------------------------------------------------------ #
# Graph node implementations                                           #
# ------------------------------------------------------------------ #


def _load_bundle(state: CuratorState) -> dict:
    path = Path(state["bundle_path"])
    if not path.exists():
        return {
            "bundle": {},
            "errors": [f"bundle not found: {path}"],
            "stats": {"phase": "load_bundle", "error": "bundle_not_found"},
        }
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
        node_count = len(bundle.get("nodes", []))
        edge_count = len(bundle.get("edges", []))
        return {
            "bundle": bundle,
            "stats": {
                "phase": "load_bundle",
                "bundle_nodes": node_count,
                "bundle_edges": edge_count,
            },
        }
    except Exception as exc:
        return {
            "bundle": {},
            "errors": [f"failed to parse bundle: {exc}"],
            "stats": {"phase": "load_bundle", "error": str(exc)},
        }


def _scan_gaps(state: CuratorState) -> dict:
    from .tools import scan_bundle_gaps

    bundle = state.get("bundle", {})
    if not bundle:
        return {
            "gaps": [],
            "stats": {**state.get("stats", {}), "phase": "scan_gaps", "gaps_found": 0},
        }
    gaps = scan_bundle_gaps(
        bundle,
        gap_types=state.get("gap_types", ["missing_d3fend", "missing_capec"]),
        max_gaps=state.get("max_gaps", 50),
    )
    by_type: dict[str, int] = {}
    for g in gaps:
        by_type[g["gap_type"]] = by_type.get(g["gap_type"], 0) + 1
    return {
        "gaps": gaps,
        "stats": {
            **state.get("stats", {}),
            "phase": "scan_gaps",
            "gaps_found": len(gaps),
            "gaps_by_type": by_type,
        },
    }


def _fetch_evidence(state: CuratorState) -> dict:
    from .tools import fetch_evidence_for_gaps

    gaps = state.get("gaps", [])
    cache_dir = Path(state.get("cache_dir", "data/raw"))
    evidence = fetch_evidence_for_gaps(gaps, cache_dir)
    total_items = sum(len(v) for v in evidence.values())
    gaps_with_evidence = sum(1 for v in evidence.values() if v)
    return {
        "evidence_by_gap": evidence,
        "stats": {
            **state.get("stats", {}),
            "phase": "fetch_evidence",
            "evidence_items": total_items,
            "gaps_with_evidence": gaps_with_evidence,
        },
    }


def _propose_candidates(state: CuratorState) -> dict:
    """Call LLM with structured output to propose mapping candidates."""
    from .candidates import (
        CandidateProposal,
        CandidateStatus,
        CandidateType,
        EvidenceRef,
        ProposedEdge,
    )
    from .prompts import (
        CURATOR_SYSTEM_PROMPT,
        PROPOSE_CANDIDATES_PROMPT,
        format_evidence_context,
        format_gap_context,
    )

    try:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage, SystemMessage
    except ImportError as exc:
        return {
            "candidates": [],
            "errors": [
                f"langchain-anthropic not installed: {exc}. "
                "Run: pip install 'attack2defend[ai]'"
            ],
        }

    gaps = state.get("gaps", [])
    evidence_by_gap = state.get("evidence_by_gap", {})
    run_id = state["run_id"]
    model_name = state.get("model", "claude-sonnet-4-6")

    llm = ChatAnthropic(
        model=model_name,
        temperature=0.0,
        max_tokens=4096,
    ).with_structured_output(ProposalBatch)  # type: ignore[attr-defined]

    gap_context_str = format_gap_context(gaps)
    evidence_context_str = format_evidence_context(evidence_by_gap)
    prompt = PROPOSE_CANDIDATES_PROMPT.format(
        gap_context=gap_context_str,
        evidence_context=evidence_context_str,
    )

    try:
        result: ProposalBatch = llm.invoke([  # type: ignore[assignment]
            SystemMessage(content=CURATOR_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
    except Exception as exc:
        return {
            "candidates": [],
            "errors": [f"LLM call failed in propose_candidates: {exc}"],
            "stats": {**state.get("stats", {}), "phase": "propose_candidates", "error": str(exc)},
        }

    now = datetime.now(timezone.utc).isoformat()
    candidates: list[dict] = []
    gap_map = {g["gap_id"]: g for g in gaps}

    for proposal in result.proposals:
        # Find the gap that triggered this proposal
        gap_id = f"gap-{proposal.source}-{proposal.target}"
        matching_gap = next(
            (g for g in gaps if g["source_id"] == proposal.source.upper()),
            None,
        )

        status = CandidateStatus.PENDING
        if proposal.status == "needs_evidence":
            status = CandidateStatus.NEEDS_EVIDENCE

        evidence_list: list[EvidenceRef] = []
        if proposal.evidence_url and proposal.evidence_url.startswith("http"):
            evidence_list.append(EvidenceRef(
                url=proposal.evidence_url,
                excerpt=proposal.evidence_excerpt[:400],
                confidence=proposal.confidence,
                retrieved_at=now,
            ))

        proposed_edge: ProposedEdge | None = None
        if proposal.status == "proposed" and proposal.evidence_url:
            proposed_edge = ProposedEdge(
                source=proposal.source.upper(),
                target=proposal.target.upper(),
                relationship=proposal.relationship,
                confidence=proposal.confidence,
                source_ref=proposal.evidence_url,
                source_kind="ai_candidate",
            )

        candidate = CandidateProposal.create(
            run_id=run_id,
            model=model_name,
            candidate_type=CandidateType.MAPPING_EDGE,
            input_id=proposal.source,
            gap_explanation=proposal.gap_explanation,
            justification=proposal.justification,
            evidence=evidence_list,
            proposed_edge=proposed_edge,
            status=status,
        )
        candidates.append(candidate.to_dict())

    return {
        "candidates": candidates,
        "stats": {
            **state.get("stats", {}),
            "phase": "propose_candidates",
            "candidates_proposed": len(candidates),
            "unresolvable_gaps": len(result.unresolvable),
        },
    }


def _generate_backlog(state: CuratorState) -> dict:
    """Call LLM with structured output to generate SOC/CTEM backlog items."""
    from .candidates import (
        BacklogItem,
        CandidateProposal,
        CandidateStatus,
        CandidateType,
    )
    from .prompts import (
        CURATOR_SYSTEM_PROMPT,
        GENERATE_BACKLOG_PROMPT,
        format_gap_summary,
    )

    try:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage, SystemMessage
    except ImportError as exc:
        return {
            "candidates": [],
            "errors": [f"langchain-anthropic not installed: {exc}"],
        }

    gaps = state.get("gaps", [])
    prior_candidates = state.get("candidates", [])
    run_id = state["run_id"]
    model_name = state.get("model", "claude-sonnet-4-6")

    llm = ChatAnthropic(
        model=model_name,
        temperature=0.0,
        max_tokens=4096,
    ).with_structured_output(BacklogBatch)  # type: ignore[attr-defined]

    gap_summary_str = format_gap_summary(gaps, prior_candidates)
    prompt = GENERATE_BACKLOG_PROMPT.format(
        gap_summary=gap_summary_str,
        candidates_summary=gap_summary_str,
    )

    try:
        result: BacklogBatch = llm.invoke([  # type: ignore[assignment]
            SystemMessage(content=CURATOR_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
    except Exception as exc:
        return {
            "candidates": [],
            "errors": [f"LLM call failed in generate_backlog: {exc}"],
            "stats": {**state.get("stats", {}), "phase": "generate_backlog", "error": str(exc)},
        }

    now = datetime.now(timezone.utc).isoformat()
    backlog_candidates: list[dict] = []

    for entry in result.items:
        backlog_item = BacklogItem(
            item_id=f"bl-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}",
            title=entry.title,
            description=entry.description,
            owner=entry.owner,
            priority=entry.priority,
            gap_context=entry.gap_context,
            references=list(entry.references),
        )
        candidate = CandidateProposal.create(
            run_id=run_id,
            model=model_name,
            candidate_type=CandidateType.BACKLOG_ITEM,
            input_id=entry.gap_context[:60],
            gap_explanation=entry.gap_context,
            justification=entry.description,
            backlog_items=[backlog_item],
            status=CandidateStatus.PENDING,
        )
        backlog_candidates.append(candidate.to_dict())

    return {
        "candidates": backlog_candidates,
        "stats": {
            **state.get("stats", {}),
            "phase": "generate_backlog",
            "backlog_items_generated": len(backlog_candidates),
        },
    }


def _write_candidates(state: CuratorState) -> dict:
    """Serialize all candidates to output_dir/run_id/ as individual JSON files."""
    from .candidates import CandidateProposal, write_candidate_batch

    candidates_raw = state.get("candidates", [])
    output_dir = Path(state.get("output_dir", "data/candidates"))
    run_id = state["run_id"]

    if not candidates_raw:
        return {
            "stats": {
                **state.get("stats", {}),
                "phase": "write_candidates",
                "candidates_written": 0,
                "output_dir": str(output_dir / run_id),
            },
        }

    candidates = [CandidateProposal.from_dict(c) for c in candidates_raw]

    try:
        written = write_candidate_batch(candidates, output_dir, run_id)
        # Also write a run manifest
        manifest = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": state.get("stats", {}),
            "gaps_found": len(state.get("gaps", [])),
            "candidates_written": len(written),
            "errors": state.get("errors", []),
            "files": [str(p.name) for p in written],
        }
        manifest_path = output_dir / run_id / "_run_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return {
            "stats": {
                **state.get("stats", {}),
                "phase": "write_candidates",
                "candidates_written": len(written),
                "output_dir": str(output_dir / run_id),
            },
        }
    except Exception as exc:
        return {
            "errors": [f"failed to write candidates: {exc}"],
            "stats": {
                **state.get("stats", {}),
                "phase": "write_candidates",
                "error": str(exc),
            },
        }


# ------------------------------------------------------------------ #
# Routing functions                                                    #
# ------------------------------------------------------------------ #


def _route_after_scan(state: CuratorState) -> str:
    if state.get("errors") and not state.get("bundle"):
        return "write_candidates"  # fatal error (bundle missing)
    if not state.get("gaps"):
        return "write_candidates"  # no gaps found
    if state.get("dry_run"):
        return "write_candidates"  # dry-run: skip LLM
    return "fetch_evidence"


def _route_after_evidence(state: CuratorState) -> str:
    ev = state.get("evidence_by_gap", {})
    has_any = any(items for items in ev.values() if items)
    if not has_any:
        return "write_candidates"  # no cache evidence → all needs_evidence
    return "propose_candidates"


# ------------------------------------------------------------------ #
# Graph builder                                                        #
# ------------------------------------------------------------------ #


def build_curator_graph() -> Any:
    """Build and compile the LangGraph curator state machine.

    Returns a CompiledStateGraph ready for invocation.
    Raises ImportError if langgraph is not installed.
    """
    if not _LANGGRAPH_AVAILABLE:
        raise ImportError(
            f"langgraph not available: {_IMPORT_ERROR}\n"
            "Install with: pip install 'attack2defend[ai]'"
        )

    graph = StateGraph(CuratorState)  # type: ignore[arg-type]

    # Nodes
    graph.add_node("load_bundle", _load_bundle)
    graph.add_node("scan_gaps", _scan_gaps)
    graph.add_node("fetch_evidence", _fetch_evidence)
    graph.add_node("propose_candidates", _propose_candidates)
    graph.add_node("generate_backlog", _generate_backlog)
    graph.add_node("write_candidates", _write_candidates)

    # Edges
    graph.add_edge(START, "load_bundle")
    graph.add_edge("load_bundle", "scan_gaps")
    graph.add_conditional_edges(
        "scan_gaps",
        _route_after_scan,
        {"fetch_evidence": "fetch_evidence", "write_candidates": "write_candidates"},
    )
    graph.add_conditional_edges(
        "fetch_evidence",
        _route_after_evidence,
        {"propose_candidates": "propose_candidates", "write_candidates": "write_candidates"},
    )
    graph.add_edge("propose_candidates", "generate_backlog")
    graph.add_edge("generate_backlog", "write_candidates")
    graph.add_edge("write_candidates", END)

    return graph.compile()


def make_initial_state(
    *,
    bundle_path: str,
    cache_dir: str,
    output_dir: str,
    model: str = "claude-sonnet-4-6",
    max_gaps: int = 50,
    gap_types: list[str] | None = None,
    dry_run: bool = False,
    run_id: str | None = None,
) -> CuratorState:
    """Construct a clean initial state for a curator run."""
    if run_id is None:
        run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    return CuratorState(
        bundle_path=bundle_path,
        cache_dir=cache_dir,
        output_dir=output_dir,
        run_id=run_id,
        model=model,
        dry_run=dry_run,
        max_gaps=max_gaps,
        gap_types=gap_types or [
            "missing_d3fend",
            "missing_capec",
            "missing_attack",
            "partial_coverage",
            "coverage_gap",
        ],
        bundle={},
        gaps=[],
        evidence_by_gap={},
        candidates=[],
        stats={},
        errors=[],
    )
