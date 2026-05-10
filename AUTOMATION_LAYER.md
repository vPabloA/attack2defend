# Attack2Defend Automation Layer

Attack2Defend exposes optional, read-only automation surfaces for SOC, SOAR and agentic workflows.

## Source of truth

```text
data/knowledge-bundle.json
```

API and MCP surfaces read from the bundle and derived artifacts only. They do not mutate canonical knowledge.

## REST API

Run locally:

```bash
make api-server
```

Useful endpoints:

```bash
curl http://127.0.0.1:8000/api/v1/health
curl http://127.0.0.1:8000/api/v1/route/CVE-2021-44228
curl http://127.0.0.1:8000/api/v1/soc-pack/CVE-2021-44228
curl http://127.0.0.1:8000/api/v1/graph/quality
```

Batch route:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/route/batch \
  -H 'Content-Type: application/json' \
  -d '{"ids":["CVE-2021-44228","T1190"]}'
```

## MCP server

Run locally:

```bash
make mcp-server
```

List tools:

```bash
python -m attack2defend.mcp.server --list-tools
```

Generate a config snippet:

```bash
python scripts/mcp/install.py
```

## Invariants

- Read-only by design.
- No external runtime API calls.
- No RAG, embeddings, LanceDB or vector DB.
- No Neo4j runtime requirement.
- No blocking human approval.
- Missing data becomes explicit gaps.
