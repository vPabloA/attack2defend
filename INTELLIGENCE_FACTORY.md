# Attack2Defend Intelligence Factory

Purpose: build governed defensive knowledge without letting AI mutate the canonical bundle directly.

## Core doctrine

```text
candidate -> validate -> score -> policy decision -> promote | queue | reject | block -> audit -> report
```

The pipeline is non-blocking by design. It is safe for CLI, CI, SOAR, MCP and future API usage.

## Never do this

- Do not call `input()` in automation paths.
- Do not wait for human approval.
- Do not poll for approval files.
- Do not write `data/knowledge-bundle.json` directly from AI or promotion scripts.
- Do not call OpenAI/Gemini/Anthropic from the browser runtime.

## Promotion modes

| Mode | Behavior |
|---|---|
| `dry_run` | Default safe mode. Scores and audits, writes no promoted mappings. |
| `policy_auto` | Promotes only candidates passing deterministic policy gates. |
| `review_queue` | Queues candidates for later review without blocking the flow. |
| `emergency_block` | Blocks promotion and records the decision without hanging. |

## Main commands

```bash
make curate-dry-run
make validate-candidates
make promote-candidates
make evaluate-golden
make validate-static-first
make validate-product
```

For automation:

```bash
python scripts/intelligence/promote_candidates.py \
  --promotion-mode policy_auto \
  --json-report
```

The JSON report always includes `blocking=false` and `timeout_waited_for_human=false` when the process completes normally.

## Files written

| Script | Writes |
|---|---|
| `run_curator.py` | `data/candidates/{run_id}/...` |
| `validate_candidates.py` | stdout/report only |
| `promote_candidates.py` | `data/mappings/ai_promoted/{run_id}.json`, `data/candidates/audit_log.jsonl`, `data/intelligence/intelligence-factory-report.json` |
| `evaluate_golden_routes.py` | `data/reports/golden-route-evaluation.json`, `.md` |
| `clean_candidates.py` | moves old candidate files to `data/candidates/archive/` only with `--execute` |

## Source of truth

`data/knowledge-bundle.json` remains the canonical artifact. Promoted mappings are absorbed only by the normal build path, for example:

```bash
make build-bundle
make validate
```

## Auditability

Every promotion decision writes one JSONL record to:

```text
data/candidates/audit_log.jsonl
```

Each record includes candidate id, policy version, policy reason, score, mode, bundle hash and output mapping path when applicable.
