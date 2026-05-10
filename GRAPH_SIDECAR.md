# Attack2Defend Graph Sidecar

Purpose: export the canonical `data/knowledge-bundle.json` into graph-consumable artifacts without making Neo4j, an API, or any external runtime mandatory.

## Doctrine

```text
knowledge-bundle.json remains the source of truth.
Graph artifacts are derived, reproducible sidecar outputs.
```

## What it generates

Run:

```bash
make graph-sidecar
```

Generated artifacts:

| Artifact | Purpose |
|---|---|
| `data/graph/nodes.csv` | Node import file |
| `data/graph/edges.csv` | Edge import file with provenance |
| `data/graph/schema.cypher` | Neo4j constraints/indexes |
| `data/graph/import.cypher` | Reproducible Neo4j import script |
| `data/graph/neo4j_queries.cypher` | Operational query pack |
| `data/graph/graph-summary.json` | Export metrics |
| `data/graph/graph-quality-report.json` | Structural quality and gap report |

## Commands

```bash
make build-bundle
make graph-export
make validate-graph
make graph-sidecar
```

## Optional Neo4j usage

Neo4j is not required for CI or product runtime. If you want to import manually, copy `nodes.csv` and `edges.csv` into Neo4j's import directory and run:

```bash
cypher-shell -f data/graph/schema.cypher
cypher-shell -f data/graph/import.cypher
```

The import script uses APOC for dynamic relationship types. If APOC is not available, use the CSV files directly or adapt the relationship import to a fixed type.

## Query pack

`data/graph/neo4j_queries.cypher` includes queries for:

- Full CVE defense route
- Orphan nodes
- Weak confidence edges
- Missing provenance
- ATT&CK techniques missing D3FEND/control/detection
- Detections missing evidence
- Top gaps by inbound paths
- AI-promoted edges
- Coverage by framework
- Route quality summary

## Quality report

`data/graph/graph-quality-report.json` includes:

- node count
- edge count
- orphan nodes
- weak edges
- missing provenance
- broken edges
- routes with or without defense path
- routes missing evidence
- AI-promoted edge count
- top structural gaps

## What this does not do

- Does not replace `knowledge-bundle.json`.
- Does not require Neo4j to run tests.
- Does not add MCP.
- Does not add an API.
- Does not add RAG, embeddings, or vector DB.
- Does not make the browser depend on Neo4j.
- Does not mutate the canonical bundle.

## Product interpretation

The graph sidecar exists to make defensive knowledge explorable and auditable. It is a product capability for analysis, demos, and future automation, not a new source of truth.
