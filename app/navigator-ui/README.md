# Attack2Defend Navigator UI

First MVP frontend for the route-first UX.

It consumes:

```text
../../data/samples/log4shell.route.json
```

## Tabs

| Tab | Purpose |
|---|---|
| Route | Linear CVE → CWE → CAPEC → ATT&CK → D3FEND route. |
| Actions | CTI, Threat Hunting, SOC, AppSec and Infra actions. |
| Graph | Auto-generated graph view of the route. |
| MITRE Views | Official ATT&CK/D3FEND deep links and future export strategy. |
| Coverage | Internal coverage status: controls, detections, evidence and owners. |
| Export | Markdown and JSON export. |

## Run locally

```bash
cd app/navigator-ui
npm install
npm run dev
```

## Build

```bash
cd app/navigator-ui
npm run build
```

## UX rule

```text
Route first. Graph second. MITRE native views third.
```
