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

## Current MVP Pro state

The project is no longer a single Log4Shell demo. The MVP now has:

| Capability | Status |
|---|---|
| Curated multi-route knowledge seeds | Ready |
| Local knowledge builder | Ready |
| Generated bundle contract | Ready |
| Search across CVE/CWE/CAPEC/ATT&CK/D3FEND/artifacts/controls/detections/evidence | Ready in UI |
| Bidirectional route traversal | Ready in UI |
| Coverage records | Ready |
| Controls/detections/evidence/gaps model | Ready |
| ATT&CK Navigator layer export starter | Ready |
| Google SecOps-inspired UI styling | Ready |
| AI agent / AI Route Analyst runtime | Pending |

Seed routes currently include:

| Input | Route purpose |
|---|---|
| `CVE-2021-44228` | Log4Shell route from CVE to weaknesses, attack path, D3FEND, controls, detections and evidence. |
| `T1567` | Exfiltration over web service route from ATT&CK to artifacts, D3FEND, controls and detections. |
| `CVE-2024-37079` | VMware vCenter exposure route to avoid CVE-only dead ends. |
| `CWE-79` | XSS route for AppSec/CWE-driven navigation. |
| `D3-MFA` | D3FEND-first reverse route for identity defense navigation. |

---

## Quick start

### Build the local knowledge bundle

The scheduled-job entrypoint is:

```bash
python scripts/knowledge_builder/build_knowledge_base.py
```

MVP output:

```text
data/nodes.json
data/edges.json
data/indexes.json
data/coverage.json
data/routes.json
data/metadata.json
data/knowledge-bundle.json
data/snapshots/<timestamp>/
app/navigator-ui/public/data/knowledge-bundle.json
```

Cron example:

```cron
# Daily Attack2Defend knowledge sync at 02:30
30 2 * * * cd /opt/attack2defend && .venv/bin/python scripts/knowledge_builder/build_knowledge_base.py >> logs/knowledge_builder.log 2>&1
```

### Run the MVP UI

```bash
cd app/navigator-ui
npm install
npm run dev
```

Build UI:

```bash
cd app/navigator-ui
npm run build
```

Recommended local validation flow:

```bash
python scripts/knowledge_builder/build_knowledge_base.py
cd app/navigator-ui
npm install
npm run build
npm run dev
```

---

## MVP scope

### In scope

| Capability | Description |
|---|---|
| Framework route resolver | Resolve known relationships across CVE, CWE, CAPEC, ATT&CK, artifacts, D3FEND, controls, detections and evidence. |
| Static knowledge bundle | Load normalized `knowledge-bundle.json` generated from curated snapshots and future public sources. |
| Route analysis contract | Produce structured outputs for route, interpretation, hypotheses, actions and evidence gaps. |
| CTI / TH action cards | Convert a route into CTI and Threat Hunting actions. |
| Coverage metadata | Track internal controls, detections, owners, evidence and gaps without overwriting them from public data. |
| Export-first design | Support Markdown/JSON and ATT&CK Navigator layer outputs. |

### Out of scope for MVP

| Not now | Reason |
|---|---|
| Full graph database | JSON is enough for the first working navigator. |
| Runtime dependency on public APIs | SOC runtime should use internal snapshots. |
| Autonomous remediation | Human approval and ownership come first. |
| Heavy agent loop | Deterministic route first, AI interpretation second. |
| Rebuilding ATT&CK Navigator or D3FEND CAD | Use deep links/export instead of cloning native MITRE tools. |
| AI agent execution | The only intentionally pending major capability. |

---

## UX model

Default UX must stay simple:

```text
[Search CVE / CWE / CAPEC / ATT&CK / D3FEND]

Route:
CVE → CWE → CAPEC → ATT&CK → Artifact → D3FEND → Control → Detection → Evidence

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
| MITRE Views | Deep links and ATT&CK Navigator layer export. |
| Coverage | Controls, detections, owners, evidence and gaps. |
| Export | Markdown, JSON and Navigator layer export. |

---

## Architecture

```text
Public sources / curated seeds
NVD / CVE / CWE / CAPEC / ATT&CK STIX / D3FEND / CISA KEV / internal mappings
        ↓
Threat Knowledge Builder
fetch/curate → normalize → link → validate → snapshot → publish
        ↓
Internal Knowledge Bundle
knowledge-bundle.json + nodes + edges + indexes + coverage + routes + metadata
        ↓
Navigator UI
search → route traversal → graph → coverage → export
        ↓
Future AI Route Analyst
interpretation + hypotheses + actions + validation plan
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
├── app/navigator-ui/
│   └── src/
├── src/attack2defend/
│   ├── contracts.py
│   ├── resolver.py
│   └── analyst_prompt.py
├── data/
│   ├── samples/
│   │   ├── log4shell.route.json
│   │   ├── t1567-exfiltration-web-service.route.json
│   │   ├── cve-2024-37079-vcenter.route.json
│   │   ├── cwe-79-xss.route.json
│   │   └── d3-mfa-identity.route.json
│   ├── nodes.json              # generated by builder
│   ├── edges.json              # generated by builder
│   ├── indexes.json            # generated by builder
│   ├── coverage.json           # generated by builder
│   ├── routes.json             # generated by builder
│   ├── metadata.json           # generated by builder
│   ├── knowledge-bundle.json   # generated by builder
│   └── snapshots/              # generated by builder
├── contracts/
│   └── route-analysis.schema.json
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CTEM_OPERATING_MODEL.md
│   └── UX_MODEL.md
├── scripts/knowledge_builder/
│   ├── build_knowledge_base.py # cron/job entrypoint
│   └── README.md
├── tests/
│   └── test_resolver.py
└── AGENTS.md
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
