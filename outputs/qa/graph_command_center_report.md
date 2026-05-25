# Attack2Defend Graph Command Center Final Assurance Report

## Scope

This report closes Pasada 3 for the Attack2Defend Graph Command Center initiative.

The delivered work covers:

- Pasada 0: Architecture and AI governance contracts.
- Pasada 1: Deterministic graph core contract.
- Pasada 2: 2D Graph Command Center UI surface.
- Pasada 3: Export, assurance and static QA controls.

## Non-negotiable semantic spine

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

This chain is present in contracts, graph model, AI context packet, exports and the 2D UI.

## Delivered capability map

| Capability | Status | Evidence |
|---|---|---|
| Architecture contract | Delivered | `contracts/GRAPH_COMMAND_CENTER_CONTRACT.md` |
| AI assistance contract | Delivered | `contracts/AI_ASSISTANCE_CONTRACT.md` |
| Scope matrix | Delivered | `outputs/qa/graph_scope_matrix.md` |
| Shared domain types | Delivered | `app/navigator-ui/src/types/attack2defend.ts` |
| Provenance types | Delivered | `app/navigator-ui/src/types/provenance.ts` |
| Canonical chain helpers | Delivered | `app/navigator-ui/src/graph/canonicalChain.ts` |
| Graph model | Delivered | `app/navigator-ui/src/graph/graphModel.ts` |
| Graph filters | Delivered | `app/navigator-ui/src/graph/graphFilters.ts` |
| Graph semantics | Delivered | `app/navigator-ui/src/graph/graphSemantics.ts` |
| AI context packet | Delivered | `app/navigator-ui/src/graph/aiContextPacket.ts` |
| Graph exports | Delivered | `app/navigator-ui/src/graph/graphExport.ts` |
| 2D graph explorer | Delivered | `app/navigator-ui/src/components/GraphExplorer2D.tsx` |
| Graph Command Center tab | Delivered | `app/navigator-ui/src/components/GraphCommandCenterTab.tsx` |
| Inspector | Delivered | `app/navigator-ui/src/components/GraphInspector.tsx` |
| Filters | Delivered | `app/navigator-ui/src/components/GraphFilters.tsx` |
| Legend | Delivered | `app/navigator-ui/src/components/GraphLegend.tsx` |
| AI Assist panel | Delivered | `app/navigator-ui/src/components/GraphAiAssistPanel.tsx` |
| Export panel | Delivered | `app/navigator-ui/src/components/GraphExportPanel.tsx` |
| Runtime entrypoint | Delivered | `app/navigator-ui/src/graphCommandCenterEntry.tsx` |
| Static QA script | Delivered | `scripts/qa_graph_command_center.py` |
| AI assurance | Delivered | `outputs/qa/ai_assistance_assurance.md` |

## Export assurance

| Export | Status | Function |
|---|---|---|
| Canonical chain JSON | Delivered | `exportCanonicalChain` |
| Visible graph JSON | Delivered | `exportVisibleGraph` |
| AI context packet JSON | Delivered | `exportAiContextPacket` |
| MCP-ready graph payload | Delivered | `exportMcpGraphPayload` |
| Gap paths payload | Delivered | `exportGapPaths` |
| Evidence requirements payload | Delivered | `exportEvidenceRequirements` |

## Static QA gates

A dependency-free static QA script was added:

```bash
python scripts/qa_graph_command_center.py
```

It checks:

| Gate | Expected result |
|---|---|
| Required files exist | PASS |
| 2D dependency exists | PASS |
| No 3D dependency terms | PASS |
| Canonical chain present | PASS |
| Required export capabilities present | PASS |
| AI context bounded controls present | PASS |

## Local/CI validation commands

From repository root:

```bash
python scripts/qa_graph_command_center.py
```

Then:

```bash
cd app/navigator-ui
npm install
npm run build
```

And from repository root:

```bash
make test
```

## Manual smoke test path

| Step | Expected result |
|---|---|
| Open UI | Existing navigator loads. |
| Search a known ID | Existing Analysis flow still works. |
| Click `Graph Command Center` | New 2D graph surface appears. |
| Scope `canonical_chain` | CVE → CWE → CAPEC → ATT&CK → D3FEND visible when present. |
| Scope `defense_readiness` | D3FEND → Control → Detection → Evidence → Gap → Action visible when present. |
| Scope `gaps_only` | Gaps/evidence/action context visible. |
| Hover/click node | Inspector updates with source_ref/confidence/trust/owners. |
| Hover link | Inspector updates with relationship/source_ref/confidence. |
| Export panel | Canonical, visible, AI, MCP, gap and evidence payloads render. |
| AI Assist panel | Tasks visible and disabled pending backend/MCP capability. |
| Return to existing tabs | Existing tabs still render. |

## Known implementation tradeoffs

| Tradeoff | Rationale | Follow-up |
|---|---|---|
| Graph Command Center mounted via separate entrypoint | Avoided rewriting `main.tsx` monolith and reduced regression risk. | Later consolidate into first-class React tab after local build passes. |
| AI Assist runtime disabled | Avoids fake buttons and unsupported runtime calls. | Wire backend/MCP capability in a future pass. |
| Fixed graph dimensions | Fast first 2D delivery. | Add responsive sizing after smoke tests. |
| Static QA cannot replace TypeScript build | Connector environment cannot execute local/CI commands. | Run CI/local commands before marking PR ready. |

## Risk register

| Risk | Current status | Control |
|---|---|---|
| Type drift between legacy types and shared types | Possible | Build/typecheck required. |
| Separate entrypoint event bridge | Accepted for Pasada 2/3 | Later refactor to native tab integration. |
| CSS isolation conflict | Low | Styles scoped under `graph-command-*`. |
| AI output over-trust | Controlled | Runtime disabled; candidate/context labels and contract in place. |
| 3D scope creep | Controlled | Static QA forbids 3D dependencies/terms. |

## Final Pasada 3 decision

Status: IMPLEMENTED, pending local/CI validation.

The Graph Command Center is ready for build validation and human smoke testing. It remains 2D-only, preserves the canonical chain, exposes AI as governed assistance, provides deterministic exports and prepares MCP-ready payloads without implementing runtime backend actions in this PR.
