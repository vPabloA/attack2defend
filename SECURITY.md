# Security Model

Attack2Defend is static-first and deterministic by default.

## Trust boundaries

- `data/knowledge-bundle.json` is the canonical source of truth.
- API and MCP are optional read-only adapters.
- The browser UI does not require API/MCP.
- The graph sidecar is derived output, not source of truth.

## Runtime restrictions

The automation layer must not:

- call external APIs at runtime;
- mutate `knowledge-bundle.json`;
- mutate `data/candidates/`;
- mutate `data/mappings/`;
- wait for human approval;
- require Neo4j, LanceDB, RAG, embeddings or vector DB;
- treat detection candidates as validated production rules.

## Handling uncertainty

If evidence, detection, D3FEND or provenance is missing, the system returns explicit gaps and `completed_with_gaps`.
