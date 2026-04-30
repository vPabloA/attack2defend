# Attack2Defend Navigator

**Attack2Defend** is a lightweight operational navigator that connects public threat knowledge to defensive action.

It is designed to map:

```text
CVE → CWE → CAPEC → MITRE ATT&CK → Digital Artifact → MITRE D3FEND → Control → Detection → Evidence → Gap
```

The goal is not to clone ATT&CK Navigator, D3FEND CAD, NSFW, or CVE2CAPEC. The goal is to build a simple, SOC-ready layer that turns framework relationships into **CTI actions, Threat Hunting hypotheses, Detection-as-Code metadata, CTEM decisions, and evidence of coverage**.

---

## Product thesis

Most tools stop at mapping:

```text
CVE/CWE/CAPEC/ATT&CK → D3FEND
```

Attack2Defend continues the route:

```text
ATT&CK technique
→ affected digital artifact
→ D3FEND defensive technique
→ internal control
→ detection logic
→ required evidence
→ operational gap
→ recommended action
```

In one sentence:

> **ATT&CK explains how the adversary acts. D3FEND explains how we defend the artifacts the adversary touches. Attack2Defend makes that route operational.**

---

## MVP scope

### In scope

| Capability | Description |
|---|---|
| Framework route resolver | Resolve known relationships across CVE, CWE, CAPEC, ATT&CK and D3FEND. |
| Static knowledge bundle | Load normalized `nodes.json` and `edges.json` generated from public sources or curated snapshots. |
| Route analysis contract | Produce structured outputs for route, interpretation, hypotheses, actions and evidence gaps. |
| CTI / TH action cards | Convert a route into CTI and Threat Hunting actions. |
| Coverage metadata | Track internal controls, detections, owners, evidence and gaps without overwriting them from public data. |
| Export-first design | Support Markdown/YAML/JSON outputs for reports, Detection-as-Code metadata and future integrations. |

### Out of scope for MVP

| Not now | Reason |
|---|---|
| Full graph database | JSON is enough for the first working navigator. |
| Runtime dependency on public APIs | SOC runtime should use internal snapshots. |
| Autonomous remediation | Human approval and ownership come first. |
| Heavy agent loop | Deterministic route first, AI interpretation second. |
| Rebuilding ATT&CK Navigator or D3FEND CAD | Use deep links/export instead of cloning native MITRE tools. |

---

## UX model

Default UX must stay simple:

```text
[Search CVE / CWE / CAPEC / ATT&CK / D3FEND]

Route:
CVE → CWE → CAPEC → ATT&CK → D3FEND

Actions:
CTI | Threat Hunting | SOC | AppSec | Infra | Cloud

Depth tabs:
Graph | MITRE Views | Coverage | Export
```

Recommended tabs:

| Tab | Purpose |
|---|---|
| Route | Simple linear path inspired by NSFW/CVE2CAPEC. |
| Actions | CTI, TH, SOC and engineering actions. |
| Graph | Auto-generated graph of the current route. |
| MITRE Views | Deep links and future exports to ATT&CK Navigator / D3FEND CAD-compatible views. |
| Coverage | Controls, detections, owners, evidence and gaps. |
| Export | Markdown, YAML, JSON and future ATT&CK Navigator layer. |

---

## Architecture

```text
Public sources
NVD / CVE / CWE / CAPEC / ATT&CK STIX / D3FEND / CISA KEV
        ↓
Threat Knowledge Builder
fetch → normalize → link → validate → snapshot
        ↓
Internal Knowledge Bundle
nodes.json + edges.json + indexes.json + metadata.json
        ↓
Route Resolver
input ID → related nodes → ordered route
        ↓
Coverage Enricher
controls + detections + evidence + owners + gaps
        ↓
AI Route Analyst
interpretation + hypotheses + actions + validation plan
        ↓
Navigator UI / API / Markdown / YAML / JSON
```

---

## Core rule

```text
The route is deterministic.
The analysis is assisted by AI.
The decision remains human-governed.
```

The AI must not invent mappings. It receives a resolved route and converts it into explanation, hypotheses, actions and evidence requirements.

---

## Repository layout

```text
attack2defend/
├── src/attack2defend/
│   ├── contracts.py
│   ├── resolver.py
│   └── analyst_prompt.py
├── data/samples/
│   └── log4shell.route.json
├── contracts/
│   └── route-analysis.schema.json
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CTEM_OPERATING_MODEL.md
│   └── UX_MODEL.md
├── scripts/knowledge_builder/
│   └── README.md
├── tests/
│   └── test_resolver.py
└── AGENTS.md
```

---

## First sample

The repository starts with a curated sample route for:

```text
CVE-2021-44228 / Log4Shell
```

Target route:

```text
CVE-2021-44228
→ CWE-917 / CWE-20 / CWE-502
→ CAPEC-136 / CAPEC-248
→ T1190 / T1059 / T1105 / T1071
→ D3FEND inventory, vulnerability enumeration, software update, network/process analysis
```

---

## Future integration with mcp-security

Attack2Defend should later become a module/capability in `mcp-security`:

```text
attack2defend_core
├── native_adapter
└── mcp_adapter
```

Recommended capability names:

| Capability | Responsibility |
|---|---|
| `attack2defend.resolve_route` | Deterministically resolve the framework route. |
| `attack2defend.enrich_context` | Add asset, KEV, coverage, detections and evidence context. |
| `attack2defend.analyze_route` | Use AI to generate interpretation, hypotheses and actions. |
| `attack2defend.export_card` | Export Markdown/YAML/JSON. |

---

## Development principles

1. Keep the route deterministic.
2. Keep the UI simple first, graph second.
3. Use public sources to build internal snapshots.
4. Never depend on public APIs at SOC runtime.
5. Preserve internal coverage data across public data updates.
6. Separate confirmed evidence, inference and hypothesis.
7. Every route must end in action, evidence or a declared gap.


## Quickstart (current MVP)

```bash
python scripts/knowledge_builder/build_knowledge_base.py
pytest -q
```
