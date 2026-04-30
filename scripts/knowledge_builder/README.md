# Threat Knowledge Builder

This directory will contain the scheduled data pipeline for Attack2Defend.

The builder is responsible for:

```text
fetch → normalize → link → validate → snapshot → publish
```

---

## Design rule

The navigator must not depend on public APIs at SOC runtime.

Public sources are consumed by a scheduled builder. The application consumes an internal snapshot.

---

## Planned stages

| Stage | Script | Responsibility |
|---|---|---|
| Fetch NVD/CVE | `fetch_nvd.py` | CVE metadata, CVSS, CWE, references, CPE. |
| Fetch CWE | `fetch_cwe.py` | CWE catalog and relationships. |
| Fetch CAPEC | `fetch_capec.py` | CAPEC attack patterns and related weaknesses. |
| Fetch ATT&CK | `fetch_attack.py` | ATT&CK STIX techniques, tactics, mitigations and data sources. |
| Fetch D3FEND | `fetch_d3fend.py` | D3FEND techniques, artifacts and ATT&CK relationships. |
| Fetch KEV | `fetch_kev.py` | CISA KEV prioritization context. |
| Normalize | `normalize_sources.py` | Convert sources into common node/edge objects. |
| Build graph | `build_graph.py` | Create route-friendly relationships. |
| Validate | `validate_bundle.py` | Schema, ID, duplicate and broken-edge validation. |
| Diff | `diff_snapshots.py` | Compare with previous snapshot. |
| Publish | `publish_snapshot.py` | Publish internal JSON/SQLite bundle. |

---

## MVP output

```text
data/
├── nodes.json
├── edges.json
├── indexes.json
└── metadata.json
```

---

## Quality gates

A build should fail if:

- required source is missing;
- schema validation fails;
- IDs are malformed;
- edges point to missing nodes;
- duplicate nodes conflict;
- massive relationship deletion happens without explicit override;
- internal coverage files would be overwritten.

## Current MVP builder

Run:

```bash
python scripts/knowledge_builder/build_knowledge_base.py
```

This generates deterministic seed artifacts for local runtime:

- `data/nodes.json`
- `data/edges.json`
- `data/indexes.json`
- `data/coverage.json`
- `data/routes.json`
- `data/metadata.json`
- `data/knowledge-bundle.json`
- `app/navigator-ui/public/data/knowledge-bundle.json`

The script fails if it detects broken edges (source/target not present in nodes).
