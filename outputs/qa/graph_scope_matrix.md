# Attack2Defend Graph Command Center Scope Matrix

## Pasada 0 summary

This matrix defines the implementation and audit scope for the 2D Graph Command Center and AI Assist governance.

## Absolute semantic spine

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

All implementation work must preserve this chain as the primary analytical contract.

## Scope matrix

| Area | In scope | Out of scope for current graph initiative | Audit focus |
|---|---|---|---|
| Graph rendering | 2D Graph Command Center based on active route and selected scope. | Whole-bundle default render, decorative-only graph. | Does graph preserve canonical chain and bounded scope? |
| Canonical chain | CVE, CWE, CAPEC, ATT&CK, D3FEND stages as explicit graph spine. | Reordering the chain, collapsing stages without user visibility. | Are canonical stages visible and exported? |
| Defense extension | D3FEND → Control → Detection → Evidence → Gap → Action. | Defense nodes disconnected from canonical context. | Does every defense view preserve backlink/context to D3FEND or canonical chain? |
| AI Assist | Explain graph, summarize gaps, suggest validations, draft detections, executive summary, hunting hypotheses. | AI-generated canonical truth, silent graph mutation, fake coverage. | Are AI outputs labelled context/candidate/validated_candidate? |
| Provenance | source_ref, confidence, source_kind, provider/model/timestamp for AI. | Unlabeled data, hidden fallback/degraded states. | Can a reviewer identify where each visible fact came from? |
| Exports | canonical_chain, visible_graph, ai_context_packet, mcp graph payload, gap paths, evidence requirements. | Exports that contain data not visible or not derived from model. | Are exports reproducible and source-preserving? |
| MCP readiness | Payloads suitable for mcp-security consumption. | Full MCP server implementation in Pasada 0. | Are payload contracts stable enough for later capability implementation? |
| UI integration | New Graph Command Center tab while preserving existing tabs. | Full UI redesign. | Do Analysis/ATT&CK/D3FEND/Coverage/Export flows remain intact? |
| Cost control | Minimal AI context packet and cache-oriented metadata. | Sending full bundle by default. | Does AI context remain bounded to visible/selected graph? |

## Implementation pass gates

### Pasada 1 — Graph Core Contract

| Gate | Required evidence |
|---|---|
| Types extracted | Shared graph/domain types exist and are used without behavior regression. |
| canonicalChain model | Explicit stage model for CVE → CWE → CAPEC → ATT&CK → D3FEND. |
| graphModel | Deterministic conversion into nodes/links/scopes. |
| aiContextPacket | Minimal AI context preserving canonical chain and selected scope. |
| tests | Chain order, source_ref, confidence, valid links, stable exports. |

### Pasada 2 — 2D Graph Command Center UI

| Gate | Required evidence |
|---|---|
| 2D graph tab | Graph Command Center tab renders active route. |
| Inspector | Node/link detail exposes source_ref/confidence/owner/official link. |
| Filters | Scopes work without changing source truth. |
| AI Assist Panel | Tasks are visible and metadata/trust labels are represented. |
| Existing UI preserved | Existing tabs continue to work. |

### Pasada 3 — Export & Assurance

| Gate | Required evidence |
|---|---|
| canonical_chain export | JSON includes CVE/CWE/CAPEC/ATT&CK/D3FEND stages. |
| visible_graph export | JSON reflects current visible graph scope. |
| ai_context_packet export | JSON is minimal and task-oriented. |
| mcp payload export | Agent-ready graph payload exists. |
| QA report | Manual/automated validation evidence recorded. |
| AI assurance report | AI scope, cost, provenance and candidate labeling validated. |

## Risk register

| Risk | Impact | Control |
|---|---|---|
| Graph becomes visual noise | Low analyst adoption | Scope filters and active-route-first rendering. |
| AI output confused with canonical truth | Bad decisions | Trust labels and deterministic validation gates. |
| Missing provenance | Audit failure | Inspector/export must preserve source_ref/confidence. |
| Cost bloat | Unsustainable AI usage | AI context packet and cache metadata. |
| UI regression | Product instability | Add tab surgically; preserve existing views. |
| Defense nodes detached from canonical chain | Loss of semantic value | Defense views must preserve D3FEND/canonical backlink. |

## Pasada 0 acceptance checklist

| Item | Status |
|---|---|
| Graph Command Center contract created | Done |
| AI Assistance contract created | Done |
| Graph scope matrix created | Done |
| Canonical chain declared as non-negotiable | Done |
| AI included as governed analyst assist | Done |
| 2D-only scope confirmed | Done |
