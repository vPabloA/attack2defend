# GA Readiness

## Functional gates

| Gate | Status |
|---|---|
| Canonical bundle validation | `make validate` |
| Product validation | `make validate-product` |
| Graph sidecar validation | `make graph-sidecar` |
| API contracts | `make validate-api` |
| MCP tools | `make validate-mcp` |
| Full GA gate | `make ga-check` |

## GO-GA criteria

- UI remains static-first.
- API/MCP are optional and read-only.
- SOC Action Pack is generated from local bundle/artifacts only.
- Missing evidence is expressed as a gap.
- No external runtime calls.
- No mutation of `knowledge-bundle.json`, `data/candidates/` or `data/mappings/`.
- No required Neo4j, LanceDB, RAG, embeddings or vector DB.

## Post-merge release step

After PMO approval and merge, create the release tag manually:

```bash
git tag v1.0.0-ga
git push origin v1.0.0-ga
```
