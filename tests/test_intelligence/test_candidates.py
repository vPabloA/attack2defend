"""Unit tests for the CandidateProposal data model.

These tests have zero external dependencies (no LangChain, no network).
They verify the core audit-trail invariants of the intelligence layer.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from attack2defend.intelligence.candidates import (
    BacklogItem,
    CandidateProposal,
    CandidateStatus,
    CandidateType,
    EvidenceRef,
    ProposedEdge,
    load_candidates_from_dir,
    write_candidate_batch,
)


# ------------------------------------------------------------------ #
# EvidenceRef                                                          #
# ------------------------------------------------------------------ #


def test_evidence_ref_roundtrip():
    ev = EvidenceRef(
        url="https://d3fend.mitre.org/technique/d3f:ApplicationHardening",
        excerpt="Application Hardening mitigates T1190",
        confidence="medium",
        retrieved_at="2026-05-06T00:00:00+00:00",
    )
    assert EvidenceRef.from_dict(ev.to_dict()) == ev


# ------------------------------------------------------------------ #
# ProposedEdge                                                         #
# ------------------------------------------------------------------ #


def test_proposed_edge_roundtrip():
    edge = ProposedEdge(
        source="T1190",
        target="D3-HBCD",
        relationship="technique_mitigated_by_countermeasure",
        confidence="medium",
        source_ref="https://d3fend.mitre.org/technique/d3f:ApplicationHardening",
        source_kind="ai_candidate",
    )
    assert ProposedEdge.from_dict(edge.to_dict()) == edge


def test_proposed_edge_to_mapping_record():
    edge = ProposedEdge(
        source="T1190",
        target="D3-HBCD",
        relationship="technique_mitigated_by_countermeasure",
        confidence="medium",
        source_ref="https://d3fend.mitre.org/technique/d3f:test",
    )
    rec = edge.to_mapping_record()
    assert rec["source"] == "T1190"
    assert rec["target"] == "D3-HBCD"
    assert rec["source_kind"] == "ai_promoted"   # always ai_promoted after promotion
    assert rec["evidence_url"] == edge.source_ref


def test_proposed_edge_ignores_unknown_fields():
    d = {
        "source": "CWE-79",
        "target": "CAPEC-86",
        "relationship": "weakness_enables_attack_pattern",
        "confidence": "high",
        "source_ref": "https://capec.mitre.org/data/definitions/86.html",
        "source_kind": "ai_candidate",
        "unknown_future_field": "ignored",
    }
    edge = ProposedEdge.from_dict(d)
    assert edge.source == "CWE-79"
    assert not hasattr(edge, "unknown_future_field")


# ------------------------------------------------------------------ #
# CandidateProposal factory + invariants                               #
# ------------------------------------------------------------------ #


def _make_full_candidate(run_id: str = "run-test-001") -> CandidateProposal:
    return CandidateProposal.create(
        run_id=run_id,
        model="claude-sonnet-4-6",
        candidate_type=CandidateType.MAPPING_EDGE,
        input_id="T1190",
        gap_explanation="T1190 has no D3FEND countermeasures in bundle",
        justification="D3FEND lists ApplicationHardening as countermeasure for T1190",
        evidence=[EvidenceRef(
            url="https://d3fend.mitre.org/technique/d3f:ApplicationHardening",
            excerpt="ApplicationHardening mitigates exploitation of T1190",
            confidence="medium",
            retrieved_at="2026-05-06T00:00:00+00:00",
        )],
        proposed_edge=ProposedEdge(
            source="T1190",
            target="D3-AH",
            relationship="technique_mitigated_by_countermeasure",
            confidence="medium",
            source_ref="https://d3fend.mitre.org/technique/d3f:ApplicationHardening",
        ),
    )


def test_candidate_create_generates_unique_ids():
    c1 = _make_full_candidate()
    c2 = _make_full_candidate()
    assert c1.candidate_id != c2.candidate_id


def test_candidate_id_format():
    c = _make_full_candidate()
    assert c.candidate_id.startswith("cand-")
    parts = c.candidate_id.split("-")
    assert len(parts) == 3
    assert len(parts[2]) == 8  # hex suffix


def test_candidate_status_defaults_to_pending():
    c = _make_full_candidate()
    assert c.status == CandidateStatus.PENDING


def test_candidate_requires_human_review_by_default():
    c = _make_full_candidate()
    assert c.requires_human_review is True


def test_candidate_roundtrip_json():
    c = _make_full_candidate()
    restored = CandidateProposal.from_json(c.to_json())
    assert restored.candidate_id == c.candidate_id
    assert restored.status == c.status
    assert restored.candidate_type == c.candidate_type
    assert restored.proposed_edge is not None
    assert restored.proposed_edge.source == "T1190"
    assert len(restored.evidence) == 1


def test_candidate_dict_has_string_enums():
    """Status and type must be strings in dict output (JSON-compatible)."""
    d = _make_full_candidate().to_dict()
    assert isinstance(d["status"], str)
    assert isinstance(d["candidate_type"], str)


# ------------------------------------------------------------------ #
# Promotion invariants                                                 #
# ------------------------------------------------------------------ #


def test_promotable_candidate_has_no_errors():
    c = _make_full_candidate()
    assert c.is_promotable()
    assert c.promotion_errors() == []


def test_rejected_candidate_not_promotable():
    c = _make_full_candidate()
    c.status = CandidateStatus.REJECTED
    errors = c.promotion_errors()
    assert any("rejected" in e for e in errors)
    assert not c.is_promotable()


def test_needs_evidence_not_promotable():
    c = _make_full_candidate()
    c.status = CandidateStatus.NEEDS_EVIDENCE
    assert not c.is_promotable()


def test_no_proposed_edge_not_promotable():
    c = CandidateProposal.create(
        run_id="run-test",
        model="test-model",
        candidate_type=CandidateType.MAPPING_EDGE,
        input_id="T1190",
        gap_explanation="gap",
        justification="reason",
        evidence=[EvidenceRef(
            url="https://example.com",
            excerpt="test",
            confidence="medium",
            retrieved_at="2026-05-06T00:00:00+00:00",
        )],
        proposed_edge=None,  # intentionally missing
    )
    assert not c.is_promotable()
    assert any("proposed_edge" in e for e in c.promotion_errors())


def test_empty_source_ref_not_promotable():
    c = _make_full_candidate()
    assert c.proposed_edge is not None
    c.proposed_edge.source_ref = ""
    assert not c.is_promotable()
    assert any("source_ref" in e for e in c.promotion_errors())


def test_empty_evidence_not_promotable():
    c = _make_full_candidate()
    c.evidence = []
    assert not c.is_promotable()
    assert any("evidence" in e for e in c.promotion_errors())


# ------------------------------------------------------------------ #
# Batch I/O                                                            #
# ------------------------------------------------------------------ #


def test_write_and_load_candidates_roundtrip():
    c1 = _make_full_candidate("run-batch-test")
    c2 = _make_full_candidate("run-batch-test")

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        written = write_candidate_batch([c1, c2], out_dir, "run-batch-test")
        assert len(written) == 2
        for p in written:
            assert p.exists()

        loaded = load_candidates_from_dir(out_dir)
        assert len(loaded) == 2
        loaded_ids = {c.candidate_id for c in loaded}
        assert c1.candidate_id in loaded_ids
        assert c2.candidate_id in loaded_ids


def test_load_candidates_from_missing_dir_returns_empty():
    loaded = load_candidates_from_dir(Path("/tmp/does-not-exist-attack2defend"))
    assert loaded == []


def test_load_candidates_skips_malformed_files():
    with tempfile.TemporaryDirectory() as tmp:
        bad_file = Path(tmp) / "bad.json"
        bad_file.write_text("not valid json at all {{{", encoding="utf-8")

        good = _make_full_candidate()
        good_file = Path(tmp) / f"{good.candidate_id}.json"
        good_file.write_text(good.to_json(), encoding="utf-8")

        loaded = load_candidates_from_dir(Path(tmp))
        assert len(loaded) == 1
        assert loaded[0].candidate_id == good.candidate_id


# ------------------------------------------------------------------ #
# BacklogItem                                                          #
# ------------------------------------------------------------------ #


def test_backlog_item_roundtrip():
    item = BacklogItem(
        item_id="bl-20260506-abc123",
        title="Deploy ApplicationHardening for T1190",
        description="Validate that WAF rules mitigate exploitation of T1190",
        owner="detection-engineer",
        priority="high",
        gap_context="T1190 missing D3FEND countermeasures",
        references=["T1190", "D3-AH", "CVE-2024-37079"],
    )
    restored = BacklogItem.from_dict(item.to_dict())
    assert restored == item
