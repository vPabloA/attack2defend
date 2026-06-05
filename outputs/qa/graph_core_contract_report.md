# Attack2Defend Graph Core Contract QA Report

## Scope

Pasada 1 implements the non-UI graph core contract for the 2D Graph Command Center.

No UI wiring was performed in this pass.

## Files added

| File | Purpose |
|---|---|
| `app/navigator-ui/src/types/attack2defend.ts` | Shared domain types for bundle, route, coverage and capability view. |
| `app/navigator-ui/src/types/provenance.ts` | Provenance and trust-level taxonomy. |
| `app/navigator-ui/src/graph/canonicalChain.ts` | Canonical CVE → CWE → CAPEC → ATT&CK → D3FEND helpers. |
| `app/navigator-ui/src/graph/graphSemantics.ts` | Node/link label, weight and status semantics. |
| `app/navigator-ui/src/graph/graphFilters.ts` | Scope filters for canonical chain, threat route, defense readiness, gaps, evidence, owners and full traceability. |
| `app/navigator-ui/src/graph/aiContextPacket.ts` | Minimal AI context packet builder. |
| `app/navigator-ui/src/graph/graphModel.ts` | Deterministic GraphViewModel builder. |
| `app/navigator-ui/src/graph/graphExport.ts` | Canonical, visible, MCP-ready, gap path, evidence and AI context exports. |
| `app/navigator-ui/src/graph/graphModel.contract.test.ts` | Compile-time/importable fixture contract test helper. |

## Implemented contracts

| Contract | Status |
|---|---|
| Canonical principle preserved | Implemented |
| Shared graph/domain types | Implemented |
| Provenance model | Implemented |
| Graph scopes | Implemented |
| Deterministic GraphViewModel | Implemented |
| AI context packet | Implemented |
| Canonical chain export | Implemented |
| Visible graph export | Implemented |
| MCP-ready graph payload | Implemented |
| Gap paths payload | Implemented |
| Evidence requirements payload | Implemented |

## Canonical principle

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

The chain is declared in `canonicalChain.ts` and carried in `GraphViewModel.principle`, canonical exports, AI context packets and MCP-ready payloads.

## AI Assist governance

The graph core creates `AiContextPacket` from the selected visible subgraph. It explicitly sets:

- `bundle_full_context_sent: false`
- `context_scope: visible_subgraph`
- `cache_key_basis: input + scope + bundle version + task`

This keeps AI assist economically bounded and subordinate to the graph contract.

## Manual audit notes

| Check | Result |
|---|---|
| UI components changed | No |
| Existing tabs modified | No |
| Runtime behavior changed | No direct runtime wiring in this pass |
| New external dependencies | No |
| 3D added | No |
| Browser API calls added | No |
| LLM calls added | No direct calls; only context packet model |

## Validation status

This pass was implemented through the GitHub connector. Local/CI execution was not available in this environment.

| Gate | Status |
|---|---|
| Static review | Completed |
| Contract fixture added | Completed |
| Build/typecheck | Pending local/CI execution |
| UI runtime smoke | Not applicable; no UI wiring yet |

## Required next validation command

```bash
cd app/navigator-ui
npm run build
```

And from repository root:

```bash
make test
```

## Pasada 1 result

Pasada 1 is ready for local/CI validation and subsequent Pasada 2 UI wiring.
