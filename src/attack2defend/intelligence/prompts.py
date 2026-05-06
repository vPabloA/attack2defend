"""Prompt templates for the Defense Intelligence Curator.

All prompts enforce the static-first contract:
  - never invent mappings without a cited public source
  - separate confirmed / inferred / hypothetical evidence
  - declare missing evidence explicitly rather than guessing
  - produce structured, auditable JSON output
"""

from __future__ import annotations

CURATOR_SYSTEM_PROMPT = """
You are an Attack2Defend Defense Intelligence Curator.

Your role is to analyze gaps in a security knowledge bundle and propose
evidence-based mapping improvements for human review.

## Core rules

1. NEVER propose a mapping without citing a specific public source URL.
2. NEVER claim exploitation capability without direct evidence.
3. Separate evidence tiers:
   - confirmed: explicitly stated in a public source you can cite
   - inferred: reasonable pattern-based deduction from cited material
   - hypothetical: plausible but unverified — mark as needs_evidence
4. If you cannot find evidence for a proposed edge, set status = "needs_evidence"
   and explain exactly what evidence would be required.
5. If no mapping is possible or appropriate, set status = "no_evidence" with
   a clear explanation.
6. Produce only valid JSON matching the requested output schema.
7. Be specific: cite technique names, countermeasure IDs, CAPEC numbers.
8. Do not recommend vendor-specific products as D3FEND mappings.

## Output contract

Every proposal you produce becomes a *candidate* that requires human review
and explicit promotion before it ever touches the bundle. Your role is to
surface evidence and explain reasoning — a human makes the final call.

## Framing question

For every gap you analyze, answer:
"What do we know, what defense exists, what evidence do we need,
what gaps remain, and what concrete actions should be taken?"
""".strip()


PROPOSE_CANDIDATES_PROMPT = """
Analyze the following security intelligence gaps and propose evidence-based
mapping improvements. Each gap represents a missing link in the
CVE → CWE → CAPEC → ATT&CK → D3FEND → Control/Detection/Evidence chain.

## Gaps to analyze

{gap_context}

## Available evidence from public source cache

{evidence_context}

## Instructions

For each gap:
1. Examine the available evidence carefully.
2. Propose a mapping edge if the evidence supports it (status: "proposed").
3. If evidence is partial or ambiguous, set status: "needs_evidence" and
   describe exactly what additional evidence is required.
4. If no appropriate mapping exists, set status: "no_evidence" with explanation.
5. Assign confidence: "high" only if directly stated in a public source;
   "medium" if clearly inferable; "low" if speculative.
6. The evidence_url MUST be a real URL from the provided evidence context.
   Do not fabricate URLs.

Return a ProposalBatch JSON object.
""".strip()


GENERATE_BACKLOG_PROMPT = """
Based on the following security intelligence gaps and proposed mappings,
generate a prioritized SOC/CTEM action backlog.

## Context

Bundle gaps (security intelligence deficiencies):
{gap_summary}

Proposed new mappings (candidates awaiting promotion):
{candidates_summary}

## Instructions

Generate concrete, actionable backlog items for the following teams:
- soc: detection rules, alert tuning, incident response procedures
- ctem: continuous threat exposure management, attack surface validation
- appsec: application security hardening, code review focus areas
- infra: infrastructure hardening, network controls, patch management
- detection-engineer: telemetry gaps, data source collection, correlation rules

For each item:
1. Assign to exactly one owner team.
2. Assign priority: critical (immediate), high (this sprint), medium (next quarter), low (backlog).
3. Reference specific CVE/CWE/ATT&CK/D3FEND IDs where applicable.
4. Include the gap_context that motivated the item.
5. Be specific — avoid generic recommendations like "improve logging".

Return a BacklogBatch JSON object.
""".strip()


def format_gap_context(gaps: list[dict]) -> str:
    """Format gap records into a readable prompt section."""
    if not gaps:
        return "(no gaps found)"
    lines: list[str] = []
    for i, gap in enumerate(gaps, 1):
        lines.append(
            f"{i}. [{gap.get('gap_type', 'unknown')}] {gap.get('source_id', '?')}"
            f" ({gap.get('node_name', '')})\n"
            f"   Description: {gap.get('description', '')}\n"
            f"   Priority: {gap.get('priority', 'medium')}\n"
            f"   Route status: {gap.get('route_status', 'unknown')}"
        )
    return "\n\n".join(lines)


def format_evidence_context(evidence_by_gap: dict[str, list[dict]]) -> str:
    """Format evidence dict into a readable prompt section."""
    if not evidence_by_gap:
        return "(no cached evidence available — all gaps will be needs_evidence)"
    lines: list[str] = []
    for gap_id, items in evidence_by_gap.items():
        if not items:
            lines.append(f"[{gap_id}]: no evidence in cache")
            continue
        lines.append(f"[{gap_id}]:")
        for item in items[:5]:  # cap at 5 per gap to stay within context
            lines.append(f"  • {item.get('url', 'no-url')}")
            excerpt = item.get("excerpt", "")
            if excerpt:
                lines.append(f"    \"{excerpt[:200]}\"")
    return "\n".join(lines)


def format_gap_summary(gaps: list[dict], candidates: list[dict]) -> str:
    """Compact summary for backlog generation prompt."""
    gap_lines = [
        f"  - {g.get('gap_type')} on {g.get('source_id')} (priority={g.get('priority')})"
        for g in gaps
    ]
    cand_lines = [
        f"  - {c.get('proposed_edge', {}).get('source', '?')} → "
        f"{c.get('proposed_edge', {}).get('target', '?')} "
        f"[{c.get('status', 'pending')}]"
        for c in candidates
        if c.get("proposed_edge")
    ]
    return (
        f"Gaps ({len(gaps)}):\n" + ("\n".join(gap_lines) or "  (none)") + "\n\n"
        + f"Proposed mappings ({len(cand_lines)}):\n" + ("\n".join(cand_lines) or "  (none)")
    )
