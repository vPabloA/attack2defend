# Graph Command Center Local Validation Runbook

## Purpose

This runbook validates PR #35 locally before marking it Ready for Review.

## Branch

```bash
git fetch origin
git checkout feature/graph-command-center-p0
git pull --ff-only
```

## Validation order

Run validations in this exact order.

### 1. Static QA

```bash
python scripts/qa_graph_command_center.py
```

Expected:

```text
PASS: Graph Command Center static QA checks passed
```

### 2. Navigator install/build

```bash
cd app/navigator-ui
npm install
npm run build
```

Expected:

- TypeScript build passes.
- Vite build passes.
- No 3D packages are installed by this PR.

### 3. Repository test suite

```bash
cd ../..
make test
```

Expected:

- Test suite passes.
- Any unrelated failure must be explicitly documented before PR review.

### 4. Diff hygiene

```bash
git diff --check
git status --short
```

Expected:

- No whitespace errors.
- Only intentional files modified.

## Manual UI smoke test

Start UI:

```bash
cd app/navigator-ui
npm run dev
```

Then validate:

| Check | Expected result |
|---|---|
| App loads | Existing navigator shell loads. |
| Search ID | Existing Analysis tab renders. |
| Graph Command Center tab | Tab appears in nav. |
| Click Graph Command Center | 2D graph appears. |
| Canonical scope | Shows CVE → CWE → CAPEC → ATT&CK → D3FEND when route has those nodes. |
| Defense readiness scope | Shows D3FEND → Control → Detection → Evidence → Gap → Action when route has those nodes. |
| Inspector | Node/link hover updates details. |
| Export panel | JSON payloads render. |
| AI Assist panel | Buttons are disabled with backend/MCP pending reason. |
| Existing tabs | Returning to Analysis, ATT&CK, D3FEND, Coverage and Export works. |

## Remanent checklist

| Area | Check | Status |
|---|---|---|
| Dependency policy | Only `react-force-graph-2d` added | Pending local validation |
| 3D scope | No 3D dependency/terms | Covered by static QA |
| Canonical chain | Present in contracts/model/UI/exports | Covered by static QA |
| AI context | `bundle_full_context_sent: false` | Covered by static QA |
| Runtime AI | No fake enabled buttons | Manual smoke required |
| `main.tsx` | Not rewritten | Confirm by diff |
| CSS isolation | `graph-command-*` scoped | Manual smoke required |
| Build | `npm run build` | Pending local validation |
| Tests | `make test` | Pending local validation |

## GO / NO-GO

### GO

Proceed to Ready for Review only if:

- Static QA passes.
- `npm run build` passes.
- `make test` passes or unrelated failures are documented.
- Manual UI smoke passes.
- No 3D dependency appears.
- AI Assist buttons are not falsely enabled.

### NO-GO

Keep PR as Draft if:

- TypeScript fails.
- Existing tabs break.
- Graph tab does not render after selecting a known ID.
- Export panel emits invalid JSON.
- AI Assist appears as enabled without real backend/MCP handler.
- Any 3D dependency is introduced.

## Reviewer notes

The current Pasada 2 implementation uses a separate entrypoint bridge instead of rewriting `main.tsx`. This is an intentional low-regression strategy. A later consolidation pass may integrate the tab natively after build and smoke tests are green.
