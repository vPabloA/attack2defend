# Threat Knowledge Builder

This directory contains the scheduled data pipeline for Attack2Defend.

The builder is responsible for:

```text
fetch → normalize → link → validate → snapshot → publish
```

---

## Cron / Job entrypoint

Use this file as the single scheduled job entrypoint:

```bash
python scripts/knowledge_builder/build_knowledge_base.py
```

Recommended cron example:

```cron
# Daily Attack2Defend knowledge sync at 02:30
30 2 * * * cd /opt/attack2defend && .venv/bin/python scripts/knowledge_builder/build_knowledge_base.py >> logs/knowledge_builder.log 2>&1
```

MVP behavior:

- reads curated route files from `data/samples/*.route.json`;
- normalizes nodes and edges;
- validates duplicate IDs and broken edges;
- writes `data/nodes.json`, `data/edges.json`, `data/indexes.json`, `data/metadata.json`;
- creates timestamped snapshots under `data/snapshots/` unless `--no-snapshot` is used.

---

## Commands

Build bundle:

```bash
python scripts/knowledge_builder/build_knowledge_base.py
```

Build without snapshot:

```bash
python scripts/knowledge_builder/build_knowledge_base.py --no-snapshot
```

Strict mode:

```bash
python scripts/knowledge_builder/build_knowledge_base.py --strict
```

Custom paths:

```bash
python scripts/knowledge_builder/build_knowledge_base.py \
  --source-dir data/samples \
  --output-dir data \
  --snapshot-dir data/snapshots
```

---

## Design rule

The navigator must not depend on public APIs at SOC runtime.

Public sources are consumed by a scheduled builder. The application consumes an internal snapshot.

---

## Planned stages

| Stage | Script | Responsibility |
|---|---|---|
| Orchestrate build | `build_knowledge_base.py` | Single cron/job entrypoint. Runs MVP bundle generation now; will orchestrate all future stages. |
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
├── metadata.json
└── snapshots/
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

---

## Future data sources

The MVP builder starts from curated sample routes. Future collectors should hydrate the same bundle contract from:

| Source | Purpose |
|---|---|
| NVD / CVE | CVE metadata, CVSS, CWE, references and CPE. |
| CISA KEV | Exploited-in-the-wild prioritization. |
| CWE | Weakness taxonomy. |
| CAPEC | Attack patterns. |
| ATT&CK STIX | Tactics, techniques, mitigations and data sources. |
| D3FEND | Defensive techniques, artifacts and attack-defense relationships. |
