# Attack2Defend AI Assistance Contract

## Status

Draft contract for Pasada 0. This document defines how AI assists the Attack2Defend Graph Command Center.

## AI posture

AI is a permanent product capability. It is used to make the analyst, Vulnerability Manager, Threat Hunter, Detection Engineer and SOC leader faster, clearer and more effective.

AI does not replace the canonical semantic spine:

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

AI assists the chain; it does not override it.

## Approved AI Assist tasks

| Task | User value | Required input scope |
|---|---|---|
| explain_visible_graph | Explain the visible route in SOC language. | Visible subgraph plus canonical chain. |
| summarize_gaps | Explain which gaps block closure. | Gaps, evidence, actions and canonical context. |
| suggest_validations | Suggest validation steps for SOC/Vulnerability Manager. | Selected node, visible scope, source refs and missing segments. |
| draft_detection_ideas | Draft candidate detection ideas. | ATT&CK, D3FEND, Detection, Evidence and source refs. |
| generate_executive_summary | Translate technical route into decision language. | Canonical chain, priority, gaps and confidence summary. |
| create_hunting_hypothesis | Produce TH hypothesis candidates. | CAPEC, ATT&CK, Evidence and known gaps. |

## AI output classification

| Classification | Meaning | UI requirement |
|---|---|---|
| context | Helpful explanation or background, not a candidate mapping. | Label as context. |
| candidate | Candidate validation/action/detection/hypothesis. | Label as candidate. |
| validated_candidate | Candidate passed deterministic validation gates. | Show validation basis. |
| canonical | Reserved for bundle/resolver truth. | AI must not self-label as canonical. |

## Required AI metadata

Every AI-assisted output should preserve these fields when available:

| Field | Purpose |
|---|---|
| task | Which AI Assist task was invoked. |
| input | Selected input, usually CVE/CWE/CAPEC/ATT&CK/D3FEND or defensive node. |
| visible_scope | Graph scope used as context. |
| provider | Provider used. |
| model | Model used. |
| generated_at | Timestamp for audit. |
| source_refs | Source references used in the prompt/context. |
| canonical_chain_refs | CVE/CWE/CAPEC/ATT&CK/D3FEND references used. |
| confidence_basis | Why the output is considered useful or limited. |
| cost_metadata | Tokens/cost/cache key when available. |
| trust_level | context, candidate or validated_candidate. |

## Cost and context controls

AI Assist must be economical by design.

| Control | Requirement |
|---|---|
| Scope minimization | Use visible subgraph or selected node context, not the full bundle by default. |
| Chain preservation | Always include canonical chain context when available. |
| Cache key | Prefer input + visible_scope + bundle_version + task + model. |
| Provider/model transparency | Show provider and model when available. |
| Fallback | If AI assist is unavailable, deterministic graph still works. |
| Analyst trigger | Prefer user-triggered assist for costly tasks. |
| Token discipline | Compress context into AI context packets. |

## Deterministic validation gates for AI candidates

AI candidate outputs must be validated before being treated as enabled operational actions.

| Candidate type | Required validation |
|---|---|
| Detection idea | Must link to ATT&CK/D3FEND/Evidence in visible context. |
| Validation step | Must link to selected node, gap, evidence or canonical stage. |
| Owner suggestion | Must be marked suggested unless owner exists in bundle/coverage. |
| Hunting hypothesis | Must link to CAPEC/ATT&CK/Evidence and remain hypothesis-labelled. |
| Executive summary | Must cite canonical chain and gaps/confidence if present. |
| Gap summary | Must reference actual visible gap/evidence/action nodes. |

## UI behavior

| UI element | Requirement |
|---|---|
| AI Assist Panel | Show task, provider/model, scope, timestamp and trust label. |
| Inspector AI explanation | Keep AI text clearly separated from canonical node/edge fields. |
| Candidate actions | Disabled until deterministic validation gates pass. |
| Export | AI context packet and AI candidate output must be exportable. |
| Error state | Failed AI assist must not break graph exploration. |

## Prohibited AI behavior

| Behavior | Reason |
|---|---|
| Self-promote output to canonical | Canonical truth belongs to bundle/resolver. |
| Hide source refs or confidence limitations | Breaks auditability. |
| Mutate canonical graph directly from a prompt | Breaks governance. |
| Create invisible mappings | Breaks trust. |
| Send entire bundle by default | Uncontrolled cost/context bloat. |
| Produce fake coverage status | Operational risk. |

## Accepted AI architecture patterns

| Pattern | Status |
|---|---|
| Precomputed ai-curated-route artifact | Approved. |
| On-demand backend/MCP mediated assist | Approved. |
| Cached enrichment artifact | Approved. |
| Direct browser-side mutation of canonical data | Not approved. |

## Pasada 0 Definition of Done

| Gate | Status target |
|---|---|
| AI Assist tasks defined | Required |
| Candidate/context taxonomy defined | Required |
| Cost controls defined | Required |
| Validation gates defined | Required |
| UI requirements defined | Required |
