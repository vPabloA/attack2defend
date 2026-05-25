# Graph Command Center Pasada 3B — Remnants and Local Validation

## Purpose

Pasada 3B documents remaining local validation tasks and Codex-local execution guidance for PR #35.

## Remnants closed in 3B

| Item | Action | Status |
|---|---|---|
| Canonical chain type width | Narrowed `CANONICAL_CHAIN` to strict canonical union. | Done |
| Codex local prompt | Added complete validation/fix prompt. | Done |
| Local validation runbook | Added step-by-step runbook. | Done |
| PR operational guidance | Updated via PR comment. | Done |

## Files added/updated in 3B

| File | Purpose |
|---|---|
| `app/navigator-ui/src/graph/canonicalChain.ts` | Type hardening for canonical chain. |
| `docs/prompts/graph_command_center_codex_local_prompt.md` | Prompt for Codex local validation/fix pass. |
| `docs/runbooks/graph_command_center_local_validation.md` | Local validation runbook. |
| `outputs/qa/graph_command_center_3b_remnants.md` | This report. |

## Required local branch commands

```bash
git fetch origin
git checkout feature/graph-command-center-p0
git pull --ff-only
```

## Required validation commands

```bash
python scripts/qa_graph_command_center.py
cd app/navigator-ui
npm install
npm run build
cd ../..
make test
git diff --check
git status --short
```

## Codex local prompt

Use:

```text
docs/prompts/graph_command_center_codex_local_prompt.md
```

## Human smoke checklist

| Check | Expected result |
|---|---|
| Existing UI loads | PASS |
| Search known ID | PASS |
| Existing Analysis tab works | PASS |
| Graph Command Center tab visible | PASS |
| Graph renders after selecting known ID | PASS |
| Canonical scope preserves CVE → CWE → CAPEC → ATT&CK → D3FEND | PASS |
| Defense readiness scope shows defensive extension when available | PASS |
| Inspector updates on node/link hover | PASS |
| AI Assist tasks are disabled pending backend/MCP | PASS |
| Export JSON renders all required payloads | PASS |
| Existing tabs still work after returning | PASS |

## Known risk that requires local validation

| Risk | Why local validation is required |
|---|---|
| TypeScript strict errors | Connector cannot run `npm run build`. |
| Dependency lockfile behavior | Local `npm install` may create/update lockfile depending repo policy. |
| Runtime event bridge | Browser smoke test required. |
| Force graph sizing | Manual UI validation required. |
| Existing tab interaction | Manual smoke required. |

## GO criteria

Move PR from Draft to Ready for Review only when:

- Static QA passes.
- `npm run build` passes.
- `make test` passes or unrelated failures are documented.
- Manual smoke passes.
- No 3D dependency exists.
- AI Assist remains governed and disabled until real backend/MCP exists.

## NO-GO criteria

Keep PR in Draft if:

- Build/typecheck fails.
- Existing tabs break.
- Graph tab fails to render.
- AI buttons are enabled without real handler.
- Exports are invalid or missing required capabilities.
- Any 3D dependency is introduced.

## Pasada 3B conclusion

Pasada 3B is complete. The PR is ready for local Codex validation and human smoke testing, but not yet ready for review until validation gates pass.
