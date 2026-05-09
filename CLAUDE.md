# Claude Code Instructions

This file is intentionally thin. `AGENTS.md` remains the canonical agent instruction source for this repository.

## Inheritance rule

Before changing code, read and follow `AGENTS.md` first. This file only adds execution guardrails for autonomous coding agents working on the ultra evolution branch.

## Execution guardrails

- Do not touch `main` directly.
- Do not create commits, tags, pushes, pull requests, or merges unless the human operator explicitly requests that action.
- Do not restructure directories for aesthetics.
- Preserve the static-first runtime: the browser UI must consume local artifacts only.
- Neo4j, API, MCP, RAG, vector search and LLM features are optional sidecars unless a later phase explicitly promotes them.
- Public framework data and internal/customer coverage data must stay separated.
- AI output is candidate-only. Validators and deterministic contracts win.

## Current Iteration 1 focus

- Canonical bundle contract.
- Mandatory edge provenance.
- Golden route seeds.
- No orphan edges.
- No anonymous relationships.
- No runtime public API dependency.
