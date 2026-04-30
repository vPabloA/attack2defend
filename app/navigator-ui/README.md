# Attack2Defend Navigator UI

MVP Pro frontend for the route-first Attack2Defend experience.

The UI is static-first and SOC-runtime safe:

1. It first loads the generated bundle from:

```text
public/data/knowledge-bundle.json
```

which is served in the browser as:

```text
/data/knowledge-bundle.json
```

2. If the generated bundle is missing, it falls back to:

```text
src/data/log4shell.route.json
```

This keeps local development resilient while preserving the production rule: the UI should consume a local snapshot, not live public APIs.

---

## Generate UI data

From repository root:

```bash
python scripts/knowledge_builder/build_knowledge_base.py
```

This writes the bundle to:

```text
app/navigator-ui/public/data/knowledge-bundle.json
```

---

## Tabs

| Tab | Purpose |
|---|---|
| Route | Search and navigate CVE/CWE/CAPEC/ATT&CK/D3FEND/artifact/control/detection/evidence nodes. |
| Actions | Deterministic CTI, Threat Hunting, SOC and owner action cards. |
| Graph | Auto-generated graph view of the active route. |
| MITRE Views | Official ATT&CK/D3FEND deep links and ATT&CK Navigator layer starter export. |
| Coverage | Internal coverage status: controls, detections, evidence, gaps and owners. |
| Export | Markdown, JSON and ATT&CK Navigator layer export. |

---

## Run locally

```bash
cd app/navigator-ui
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

---

## Build

```bash
cd app/navigator-ui
npm run build
```

---

## Human validation seeds

Use the search box to validate:

| Input | Purpose |
|---|---|
| `CVE-2021-44228` | CVE-first route. |
| `T1567` | ATT&CK-first exfiltration route. |
| `CVE-2024-37079` | Modern CVE route. |
| `CWE-79` | AppSec/CWE-first route. |
| `D3-MFA` | D3FEND-first identity route. |

Each seed should render Route, Actions, Graph, MITRE Views, Coverage and Export without relying on external APIs.

---

## UX rule

```text
Route first. Graph second. MITRE native views third.
```

---

## Current known pending capability

The AI Route Analyst runtime is intentionally not implemented yet. The current UI uses deterministic route actions and exports only.
