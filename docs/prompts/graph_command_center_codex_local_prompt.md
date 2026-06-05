# Codex Local Validation Prompt — Attack2Defend Graph Command Center

## Role

Act as Principal Frontend Architect, PMO Auditor, SOC Architecture Tool Developer, TypeScript strict-mode reviewer and UIX QA engineer.

You are validating PR #35 on branch:

```bash
feature/graph-command-center-p0
```

Repository:

```bash
vPabloA/attack2defend
```

## Non-negotiable principle

The product must preserve this semantic spine everywhere:

```text
CVE → CWE → CAPEC → ATT&CK → D3FEND
```

AI is allowed and expected as governed analyst assistance, but AI must not become silent canonical truth.

## Local setup

```bash
git fetch origin
git checkout feature/graph-command-center-p0
git pull --ff-only
python scripts/qa_graph_command_center.py
cd app/navigator-ui
npm install
npm run build
cd ../..
make test
```

## Mission

Validate, fix and harden Pasada 0-3 implementation without expanding scope.

## Scope allowed

You may modify only files related to:

- Graph Command Center contracts and QA reports.
- `app/navigator-ui/src/types/*`
- `app/navigator-ui/src/graph/*`
- `app/navigator-ui/src/components/Graph*.tsx`
- `app/navigator-ui/src/graphCommandCenterEntry.tsx`
- `app/navigator-ui/index.html`
- `app/navigator-ui/package.json`
- `app/navigator-ui/public/graphCommandCenter.css`
- `scripts/qa_graph_command_center.py`

## Hard restrictions

Do not add:

- `3d-force-graph`
- `react-force-graph-3d`
- `three`
- 3D graph functionality
- War Room UI
- browser-side public enrichment calls
- runtime LLM calls without backend/MCP capability
- fake enabled AI buttons
- canonical graph mutation from AI output

Do not rewrite `main.tsx` unless the build proves there is no safe alternative. If you must touch it, keep the patch surgical and explain exactly why.

## Validation tasks

### 1. Static QA

Run:

```bash
python scripts/qa_graph_command_center.py
```

Expected:

```text
PASS: Graph Command Center static QA checks passed
```

If it fails, fix the minimum code/docs necessary.

### 2. Dependency validation

Run:

```bash
cd app/navigator-ui
npm install
```

Validate:

- `react-force-graph-2d` is installed.
- No 3D dependency is introduced.
- Lockfile state is consistent with repo policy. If npm creates a lockfile and repo intentionally does not track one, document the decision instead of committing blindly.

### 3. TypeScript/build validation

Run:

```bash
npm run build
```

Fix all errors. Prioritize likely issues:

- Type drift between legacy `main.tsx` local types and shared `types/attack2defend.ts`.
- `react-force-graph-2d` typing gaps.
- `CANONICAL_CHAIN` typing.
- DOM event bridge typing.
- JSX strict-mode issues.
- Graph link source/target type normalization.
- Export object typing.

### 4. Repository tests

From repository root:

```bash
make test
```

Fix failures only if related to this PR. Do not alter unrelated test expectations.

### 5. Manual UI smoke

Start the UI:

```bash
cd app/navigator-ui
npm run dev
```

Open the app and validate:

| Step | Expected result |
|---|---|
| Load app | Existing Attack2Defend UI loads. |
| Search known ID | Existing Analysis tab still works. |
| Click `Graph Command Center` | New 2D graph view appears. |
| Scope `canonical_chain` | Shows canonical chain when available. |
| Scope `defense_readiness` | Shows D3FEND/Control/Detection/Evidence/Gap/Action when available. |
| Hover node | Inspector updates. |
| Hover link | Inspector updates. |
| Click node | Search input updates and graph remains stable. |
| AI Assist panel | Buttons visible but disabled with backend/MCP pending reason. |
| Export panel | JSON includes canonical, visible, AI context, MCP, gap and evidence payloads. |
| Return to existing tabs | Existing tabs still work. |

## Required checks before final commit

```bash
python scripts/qa_graph_command_center.py
cd app/navigator-ui
npm run build
cd ../..
make test
git diff --check
git status --short
```

## Expected output from Codex

When done, provide:

1. Summary of fixes.
2. Commands executed and results.
3. Files modified.
4. Remaining risks.
5. GO/NO-GO recommendation.

## GO criteria

Mark PR ready for review only if:

- Static QA passes.
- `npm run build` passes.
- `make test` passes or unrelated failures are clearly documented.
- No 3D dependencies exist.
- No browser public API enrichment was added.
- AI Assist remains governed and disabled until real backend/MCP capability exists.
- Existing tabs still work manually.

## NO-GO criteria

Keep PR as draft if:

- Build/typecheck fails.
- Graph tab breaks existing UI.
- AI buttons appear enabled without real handler.
- Any 3D dependency appears.
- Canonical chain is not visible/preserved.
- Exports are invalid JSON or missing required capabilities.
