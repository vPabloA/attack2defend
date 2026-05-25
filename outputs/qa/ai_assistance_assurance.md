# Attack2Defend AI Assistance Assurance Report

## Scope

This report closes Pasada 3 assurance for AI Assist in the 2D Graph Command Center.

AI is part of the product direction. The governance decision is not to remove AI, but to make AI operationally useful, economically bounded and clearly subordinate to the canonical analytical chain.

## Non-negotiable principle

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

AI Assist must explain, summarize, prioritize and draft candidates around this chain. It must not silently replace the chain.

## AI Assist implementation state

| Area | Status |
|---|---|
| AI Assist contract | Implemented in `contracts/AI_ASSISTANCE_CONTRACT.md` |
| AI tasks declared | Implemented |
| AI context packet | Implemented in `aiContextPacket.ts` |
| AI panel visible | Implemented in `GraphAiAssistPanel.tsx` |
| Runtime LLM invocation | Not implemented in this PR; buttons disabled pending backend/MCP capability |
| Provider/model metadata display | Planned in contract; panel currently shows task/scope/context/trust readiness |
| Cost controls | Implemented in context packet model |
| Candidate/context trust model | Implemented in provenance contract and UI wording |

## Approved AI tasks

| Task | Status | Notes |
|---|---|---|
| explain_visible_graph | Modeled | Uses visible graph scope. |
| summarize_gaps | Modeled | Requires gaps/evidence/action context. |
| suggest_validations | Modeled | Intended for SOC/Vulnerability Manager. |
| draft_detection_ideas | Modeled | Candidate only; not canonical. |
| generate_executive_summary | Modeled | For leadership/comittee communication. |
| create_hunting_hypothesis | Modeled | Candidate TH hypothesis. |

## Cost and context controls

| Control | Evidence |
|---|---|
| No full-bundle default context | `bundle_full_context_sent: false` in `AiContextPacket` |
| Scope minimization | `visible_nodes` and `visible_edges` only |
| Canonical chain included | `canonical_chain` included in packet |
| Cache strategy | `cache_key_basis` includes input, scope, bundle version and task |
| Runtime optionality | Graph remains useful without backend AI capability |

## Trust controls

| Control | Status |
|---|---|
| AI output cannot self-label canonical | Defined in AI contract |
| Candidate/context separation | Defined in AI contract and panel copy |
| Source refs included | AI packet includes `source_refs` |
| Confidence summary included | AI packet includes `confidence_summary` |
| Graph mutation by AI | Not implemented |
| Coverage mutation by AI | Not implemented |

## Analyst value retained

| Persona | AI value |
|---|---|
| SOC Analyst | Explain visible graph and summarize gaps. |
| Vulnerability Manager | Suggest validations and owner-oriented checks. |
| Detection Engineer | Draft candidate detection ideas from ATT&CK/D3FEND/evidence. |
| Threat Hunter | Create candidate hypotheses from CAPEC/ATT&CK/evidence. |
| SOC Leader | Generate executive summaries and decision context. |

## Assurance conclusion

AI Assist is correctly positioned as a governed analyst accelerator. It is represented in the UI, has a bounded context model, exposes trust semantics and does not mutate canonical graph truth in this PR.

Status: PASS for Pasada 3 design assurance. Runtime invocation remains a future backend/MCP integration task.
