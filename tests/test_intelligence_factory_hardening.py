"""Hardening tests for the Intelligence Factory pipeline.

Covers:
- validate_candidate with CandidateProposal-serialized data (compatibility)
- validate_candidate error paths
- promote_candidates dry-run: no files written to disk
- promote_candidates bundle-guard: detects bundle mutation
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from attack2defend.intelligence.candidates import (
    CandidateProposal,
    CandidateStatus,
    CandidateType,
    EvidenceRef,
    ProposedEdge,
)
from scripts.intelligence.validate_candidates import validate_candidate
from scripts.intelligence.promote_candidates import main as promote_main


# ── Helpers ──────────────────────────────────────────────────────────────


def _proposal() -> CandidateProposal:
    return CandidateProposal.create(
        run_id="run-test",
        model="gpt-5-nano",
        candidate_type=CandidateType.MAPPING_EDGE,
        input_id="CVE-2021-44228",
        gap_explanation="Log4Shell maps to T1190",
        justification="Confirmed via MITRE ATT&CK advisory",
        evidence=[
            EvidenceRef(
                url="https://attack.mitre.org/techniques/T1190/",
                excerpt="Exploit Public-Facing Application",
                confidence="high",
                retrieved_at="2026-01-01T00:00:00Z",
            )
        ],
        proposed_edge=ProposedEdge(
            source="CVE-2021-44228",
            target="T1190",
            relationship="attack_pattern_maps_to_technique",
            confidence="high",
            source_ref="https://attack.mitre.org/techniques/T1190/",
        ),
    )


def _dict(proposal: CandidateProposal) -> dict:
    """Serialise exactly as write_candidate_batch does (JSON round-trip)."""
    return json.loads(proposal.to_json())


# ── validate_candidate ────────────────────────────────────────────────────


def test_validate_candidate_accepts_valid_candidate_proposal() -> None:
    errors = validate_candidate(_dict(_proposal()))
    assert errors == [], f"unexpected errors: {errors}"


def test_validate_candidate_rejects_missing_required_fields() -> None:
    d = _dict(_proposal())
    del d["model"]
    errors = validate_candidate(d)
    assert "missing_model" in errors


def test_validate_candidate_rejects_missing_edge_source() -> None:
    d = _dict(_proposal())
    d["proposed_edge"]["source"] = ""
    errors = validate_candidate(d)
    assert "missing_edge_source" in errors


def test_validate_candidate_rejects_invalid_confidence() -> None:
    d = _dict(_proposal())
    d["proposed_edge"]["confidence"] = "extreme"
    errors = validate_candidate(d)
    assert any("invalid_confidence" in e for e in errors)


def test_validate_candidate_rejects_missing_evidence_ref() -> None:
    d = _dict(_proposal())
    d["evidence"][0]["url"] = ""
    errors = validate_candidate(d)
    assert "evidence_0_missing_source_ref_or_url" in errors


def test_validate_candidate_rejects_deterministic_true() -> None:
    d = _dict(_proposal())
    d["deterministic"] = True
    errors = validate_candidate(d)
    assert "ai_candidate_must_not_be_deterministic_true" in errors


def test_validate_candidate_passes_without_inferred_field() -> None:
    """CandidateProposal does not set inferred — validate_candidate must not error."""
    d = _dict(_proposal())
    d.pop("inferred", None)
    errors = validate_candidate(d)
    assert errors == [], f"unexpected errors: {errors}"


# ── promote_candidates dry-run ────────────────────────────────────────────


def test_promote_candidates_dry_run_writes_nothing_to_output_dir() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        candidates_dir = tmp / "candidates"
        candidates_dir.mkdir()
        output_dir = tmp / "mappings" / "ai_promoted"
        report_path = tmp / "report.json"
        audit_log = tmp / "audit_log.jsonl"

        # Write one valid scored candidate
        proposal = _proposal()
        candidate_dict = _dict(proposal)
        candidate_dict["score"] = {"final_score": 1.0}
        (candidates_dir / f"{proposal.candidate_id}.json").write_text(
            json.dumps(candidate_dict), encoding="utf-8"
        )

        rc = promote_main([
            "--candidates-dir", str(candidates_dir),
            "--output-dir", str(output_dir),
            "--report", str(report_path),
            "--audit-log", str(audit_log),
            "--promotion-mode", "dry_run",
            "--json-report",
        ])

        assert rc == 0
        assert not output_dir.exists() or not list(output_dir.iterdir()), \
            "dry_run must not write promoted mapping files"
        assert report_path.exists(), "report should always be written"
        report = json.loads(report_path.read_text())
        assert report["blocking"] is False
        assert report["timeout_waited_for_human"] is False
        assert report["promotion_mode"] == "dry_run"


def test_promote_candidates_never_modifies_bundle() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        bundle_path = tmp / "knowledge-bundle.json"
        bundle_path.write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
        bundle_hash_before = bundle_path.read_bytes()

        candidates_dir = tmp / "candidates"
        candidates_dir.mkdir()

        rc = promote_main([
            "--candidates-dir", str(candidates_dir),
            "--output-dir", str(tmp / "ai_promoted"),
            "--report", str(tmp / "report.json"),
            "--audit-log", str(tmp / "audit.jsonl"),
            "--bundle", str(bundle_path),
            "--promotion-mode", "policy_auto",
            "--json-report",
        ])

        assert rc == 0
        assert bundle_path.read_bytes() == bundle_hash_before, \
            "promote_candidates must never modify knowledge-bundle.json"
