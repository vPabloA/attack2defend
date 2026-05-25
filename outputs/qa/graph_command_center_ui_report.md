# Attack2Defend Graph Command Center UI QA Report

## Scope

Pasada 2 implements the first 2D Graph Command Center UI surface.

## Files added or changed

| File | Purpose |
|---|---|
| `app/navigator-ui/package.json` | Adds `react-force-graph-2d` as the only graph rendering dependency. |
| `app/navigator-ui/index.html` | Mounts `#graph-command-root`, loads the Graph Command Center entrypoint and stylesheet. |
| `app/navigator-ui/src/graphCommandCenterEntry.tsx` | Runtime entrypoint that adds the Graph Command Center tab without rewriting `main.tsx`. |
| `app/navigator-ui/src/components/GraphCommandCenterTab.tsx` | Main Graph Command Center layout. |
| `app/navigator-ui/src/components/GraphExplorer2D.tsx` | 2D force graph canvas. |
| `app/navigator-ui/src/components/GraphInspector.tsx` | Node/link inspector with source_ref, confidence, owner and trust. |
| `app/navigator-ui/src/components/GraphFilters.tsx` | Graph scope selector. |
| `app/navigator-ui/src/components/GraphLegend.tsx` | Node type legend. |
| `app/navigator-ui/src/components/GraphAiAssistPanel.tsx` | Governed AI Assist panel with disabled runtime tasks until backend/MCP exists. |
| `app/navigator-ui/src/components/GraphExportPanel.tsx` | Exports canonical/visible/AI/MCP/gaps/evidence payloads. |
| `app/navigator-ui/src/types/react-force-graph-2d.d.ts` | Local module declaration for build resilience. |
| `app/navigator-ui/public/graphCommandCenter.css` | Isolated Graph Command Center CSS. |

## Architecture choice

`main.tsx` was intentionally left untouched. The new UI is mounted via `graphCommandCenterEntry.tsx` and `#graph-command-root` to reduce regression risk in existing tabs.

## Implemented behavior

| Behavior | Status |
|---|---|
| Adds Graph Command Center tab to existing nav | Implemented via runtime entrypoint |
| Renders 2D force graph | Implemented |
| Uses `GraphViewModel` | Implemented |
| Preserves `CVE → CWE → CAPEC → ATT&CK → D3FEND` principle | Implemented |
| Provides scope filters | Implemented |
| Provides inspector | Implemented |
| Provides legend | Implemented |
| Provides AI Assist panel | Implemented, runtime actions disabled pending backend/MCP capability |
| Provides export panel | Implemented |
| Avoids 3D | Implemented |
| Avoids new browser API enrichment | Implemented |

## Known validation requirements

This pass was implemented through the GitHub connector. Local/CI execution was not available in this environment.

Run:

```bash
cd app/navigator-ui
npm install
npm run build
```

Then from repository root:

```bash
make test
```

## Manual smoke path

1. Open UI.
2. Search a known node such as `CVE-2021-44228` or any bundle-supported ID.
3. Click `Graph Command Center` tab.
4. Validate the graph renders.
5. Change scopes: `canonical_chain`, `defense_readiness`, `gaps_only`, `evidence_view`.
6. Hover/click nodes and links; confirm inspector updates.
7. Confirm AI Assist buttons are visible but disabled with backend/MCP pending reason.
8. Confirm export textarea contains canonical, visible, AI context and MCP payloads.
9. Return to existing tabs and confirm they still render.

## Risk notes

| Risk | Control |
|---|---|
| Entry point uses DOM event bridge instead of direct React state | Keeps `main.tsx` untouched; safe for Pasada 2 but should be refactored in a later consolidation. |
| Build may expose type drift between legacy `main.tsx` types and shared types | Local/CI build required. |
| Fixed ForceGraph width | Acceptable for first pass; improve responsive sizing later. |

## Pasada 2 result

Pasada 2 is implemented and ready for local/CI validation.
