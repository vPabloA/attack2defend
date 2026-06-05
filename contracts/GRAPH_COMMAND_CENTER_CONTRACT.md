# Attack2Defend Graph Command Center Contract

## Status

Draft contract for Pasada 0. This contract governs the 2D Graph Command Center before implementation work begins.

## Non-negotiable semantic principle

Attack2Defend is anchored on the canonical chain:

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

Every graph view, AI assist workflow, export, inspector panel and MCP-ready payload must preserve this chain as the primary analytical spine. Defense extensions may enrich the chain, but must not replace it.

## Product intent

The Graph Command Center is a SOC-operable decision surface. It helps analysts, Vulnerability Managers, Threat Hunters, Detection Engineers and SOC leaders understand how a vulnerability becomes an adversary-relevant technique and what defensive evidence, coverage, gaps and actions are required.

It is not a decorative graph and must not become a generic network visualization.

## Canonical chain and defense extension

| Stage | Role | Required behavior |
|---|---|---|
| CVE | Concrete vulnerability | Entry point for vulnerability-led analysis. |
| CWE | Root weakness | Explains the weakness class behind the CVE. |
| CAPEC | Attack pattern | Describes plausible adversary abuse pattern. |
| ATT&CK | Operational adversary technique | Connects the attack pattern to SOC/TH operational language. |
| D3FEND | Defensive countermeasure | Connects the technique to defensive capability. |
| Control | Preventive/corrective capability | Optional defense extension after D3FEND. |
| Detection | Rule, query, use case or detection logic | Optional defense extension used by SOC/Detection Engineering. |
| Evidence | Required telemetry or proof | Optional defense extension required to sustain a decision. |
| Gap | Blocking deficiency | Optional defense extension that prevents closure. |
| Action | Closure action | Optional defense extension with owner-oriented action. |

## Approved graph scopes

| Scope | Purpose | Required chain treatment |
|---|---|---|
| canonical_chain | Show only CVE → CWE → CAPEC → ATT&CK → D3FEND. | Must preserve stage order. |
| threat_route | Show the threat route plus relevant artifacts. | Must keep canonical stages distinguishable. |
| defense_readiness | Show D3FEND → Control → Detection → Evidence → Gap → Action. | Must preserve the D3FEND bridge to canonical chain. |
| gaps_only | Show evidence/gap/action blockers. | Must include canonical context or backlink. |
| evidence_view | Show detections and evidence requirements. | Must preserve related ATT&CK and D3FEND context. |
| owners_view | Show ownership and actionability. | Must preserve source chain context. |
| full_traceability | Show bounded active route traceability. | Must not default to rendering the whole bundle. |

## Source of truth and provenance

The canonical source of graph truth is the generated knowledge bundle and deterministic resolver output. AI and external context can assist, summarize or propose candidates, but must carry provenance and trust labels.

| Source type | Role | Trust level |
|---|---|---|
| canonical_bundle | Generated bundle data. | canonical |
| deterministic_resolver | Resolver-derived route/capability output. | canonical |
| ai_assisted_candidate | AI-generated explanation, candidate validation or draft action. | candidate or validated_candidate |
| external_enrichment | Cached or job-mediated external context. | context or validated_candidate |
| analyst_candidate | Analyst-proposed candidate. | candidate |
| runtime_assist | On-demand runtime assist output. | context or candidate |

## Required UI behavior

| Capability | Requirement |
|---|---|
| Search-first start | Do not draw a fake graph before an input is selected. |
| Canonical chain visibility | CVE → CWE → CAPEC → ATT&CK → D3FEND must be visible when present. |
| Inspector | Node/link inspector must expose source_ref, confidence, relationship, owner and official link when available. |
| Scope filters | Scope filters may hide/show data, but must not change truth. |
| Gap visibility | Gaps must be visually and operationally distinguishable. |
| Evidence visibility | Required evidence must be easy to find from Detection, ATT&CK and D3FEND context. |
| AI Assist | AI output must be marked as candidate/context and show provider/model/scope/timestamp when available. |
| Export | Exports must reflect canonical chain, visible graph, AI context packet and MCP-ready graph payloads. |
| Existing tabs | Existing Analysis, ATT&CK, D3FEND, Coverage and Export flows must remain intact. |

## Required export surfaces

| Export | Purpose |
|---|---|
| canonical_chain JSON | Portable representation of CVE → CWE → CAPEC → ATT&CK → D3FEND. |
| visible_graph JSON | Exact visible graph scope and current filters. |
| ai_context_packet JSON | Minimal context for AI assist tasks. |
| mcp-security graph payload | Agent-ready graph exploration payload. |
| graph_gap_paths payload | Blocking gap paths with canonical context. |
| graph_evidence_requirements payload | Evidence requirements linked to Detection, ATT&CK and D3FEND. |

## Governance rules

1. CVE → CWE → CAPEC → ATT&CK → D3FEND is the absolute semantic spine.
2. Defense extensions must start from or preserve D3FEND/canonical context.
3. AI Assist exists to reduce analyst and Vulnerability Manager cognitive load.
4. AI output must be marked as candidate/context unless validated by deterministic gates.
5. The browser UI must not silently mutate canonical graph truth.
6. Exports must preserve source_ref and confidence where available.
7. Fallback or degraded bundle state must be visible.
8. Graph rendering must be bounded by active route/scope, not whole-bundle default.
9. Buttons must have real handlers or explicit disabled reasons.
10. No fake metrics, fake coverage or fake owner assignment.

## Pasada 0 Definition of Done

| Gate | Status target |
|---|---|
| Canonical chain contract defined | Required |
| AI governance contract defined | Required |
| Provenance taxonomy defined | Required |
| Graph scopes defined | Required |
| PMO scope matrix created | Required |
| No implementation side effects | Required |
