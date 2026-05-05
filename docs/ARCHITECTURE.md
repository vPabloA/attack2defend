# Attack2Defend Architecture

## Purpose

Attack2Defend turns public security framework relationships into operational decisions.

It connects:

```text
CVE → CWE → CAPEC → ATT&CK → Digital Artifact → D3FEND → Control → Detection → Evidence → Gap
```

The product is intentionally simple:

- deterministic route resolution;
- local knowledge snapshots;
- AI-assisted explanation and action planning;
- exportable operational cards;
- future compatibility with `mcp-security` as a native capability and/or MCP tool.

---

## Main components

| Component | Responsibility | Runtime critical? |
|---|---|---|
| Threat Knowledge Builder | Fetch, normalize, link, validate and publish public framework data. | No; scheduled job. |
| Knowledge Store | Local snapshot consumed by the navigator. | Yes. |
| Route Resolver | Resolve an input ID into a framework route. | Yes. |
| Coverage Store | Internal controls, detections, owners, evidence and gaps. | Yes. |
| Coverage Enricher | Merge public route with internal coverage. | Yes. |
| AI Route Analyst | Explain route and generate CTI/TH/SOC actions. | Optional but high value. |
| Navigator UI | Route, actions, graph, MITRE views, coverage and export. | Yes. |
| Exporter | Markdown/YAML/JSON/Navigator layer outputs. | Optional. |

---

## Runtime rule

The SOC runtime should not depend directly on public APIs.

Bad:

```text
User search → public D3FEND/NVD API live call → response
```

Good:

```text
Scheduled sync → validated internal snapshot → user search → local response
```

---

## Data flow

```text
NVD / CVE / CWE / CAPEC / ATT&CK STIX / Galeax CVE2CAPEC / D3FEND / CISA KEV
        ↓
Collectors
        ↓
Raw Data Lake
        ↓
Normalizer
        ↓
Relationship Builder
        ↓
Validation Gates
        ↓
Versioned Snapshot
        ↓
Internal Knowledge Store
        ↓
Route Resolver
        ↓
Coverage Enricher
        ↓
AI Route Analyst
        ↓
Action Card / UI / Export
```

---

## Source model

| Source | Use |
|---|---|
| NVD / CVE | CVE metadata, CVSS, CWE, references, CPE. |
| Galeax CVE2CAPEC | Daily CVE→CWE route seed and CVE2CAPEC parity backbone for newly published CVEs. |
| CISA KEV | Exploited-in-the-wild prioritization. |
| CWE | Weakness taxonomy. |
| CAPEC | Attack patterns. |
| ATT&CK STIX | Tactics, techniques, sub-techniques, mitigations, data sources. |
| D3FEND API/Ontology | Defensive techniques, artifacts and ATT&CK-to-D3FEND relationships. |
| Internal coverage | Controls, detections, evidence, owners and gaps. |

---

## Deterministic vs AI responsibilities

| Layer | Deterministic | AI-assisted |
|---|---|---|
| CVE/CWE/CAPEC/ATT&CK/D3FEND mapping | Yes | No |
| KEV/enrichment | Yes | No |
| Coverage state | Yes | No |
| Priority base score | Yes | Optional explanation only |
| Route explanation | No | Yes |
| Hypothesis generation | No | Yes |
| CTI/TH/SOC action drafting | No | Yes |
| Incident confirmation | Human-governed | No |

---

## Future mcp-security integration

Attack2Defend should be implemented as a core engine with adapters:

```text
attack2defend_core
├── native_adapter     # direct module/capability inside mcp-security
└── mcp_adapter        # external MCP tool wrapper
```

This avoids duplicate logic.

### Candidate capability contracts

| Capability | Input | Output |
|---|---|---|
| `attack2defend.resolve_route` | ID + optional type | Route object |
| `attack2defend.enrich_context` | Route + asset/coverage context | Enriched route |
| `attack2defend.analyze_route` | Enriched route + audience | Route analysis card |
| `attack2defend.export_card` | Route analysis + format | Markdown/YAML/JSON |

---

## Quality gates

A snapshot must not be published if:

| Gate | Failure condition |
|---|---|
| Schema validation | `nodes`, `edges` or metadata violate contract. |
| ID validation | Invalid CVE/CWE/CAPEC/ATT&CK/D3FEND identifier. |
| Broken edges | Edge references missing nodes. |
| Duplicate nodes | Same ID appears with conflicting metadata. |
| Source freshness | Dataset is older than accepted threshold. |
| Diff sanity | Massive relation deletion without explicit override. |
| Coverage preservation | Internal coverage is overwritten by public data update. |

---

## MVP data stores

Start with JSON:

```text
data/
├── nodes.json
├── edges.json
├── indexes.json
├── metadata.json
├── coverage.yaml
└── detections.yaml
```

Upgrade later only if needed:

| Stage | Store |
|---|---|
| MVP | JSON bundle |
| Phase 2 | SQLite or DuckDB |
| Phase 3 | Graph DB only if route queries become complex |
