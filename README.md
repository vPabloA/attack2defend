# Attack2Defend Navigator

**Attack2Defend** is a simple static-first navigator that turns public security framework knowledge into SOC/CTEM action.

It connects and navigates:

```text
CVE → CWE → CAPEC → MITRE ATT&CK → Artifact → MITRE D3FEND → Control → Detection → Evidence → Gap
```

The browser UI does **not** call public APIs. Public sources are fetched by the scheduled builder, written into a local `knowledge-bundle.json`, validated, and served to the React UI.

---

## What it is

```text
Search → Route Flow → ATT&CK Layer → D3FEND CAD Graph → Coverage → Export
```

It is not a graph database, backend API, or AI agent runtime. The only intentionally pending major capability is **Agentic AI / AI Route Analyst**.

---

## Current status

| Capability | Status |
|---|---|
| React/Vite search-first UI | Ready |
| Deterministic curated seeds | Ready |
| Public ATT&CK collector | Ready |
| Public CWE collector | Ready |
| Public CAPEC collector | Ready |
| Public CISA KEV collector | Ready |
| Best-effort D3FEND enrichment | Ready |
| Optional NVD CVE enrichment | Ready |
| Bundle validator | Ready |
| Debian/Nginx/cron pre-prod runbook | Ready |
| Agentic AI / AI Route Analyst runtime | Pending |

---

## Quick start: curated mode

Curated mode is fast and works offline after clone. It uses `data/samples/*.route.json`.

```bash
python scripts/knowledge_builder/build_knowledge_base.py
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json
pytest -q
```

---

## Quick start: pre-production bootstrap

Use this when you want the first local knowledge base to hydrate from public sources.

```bash
bash scripts/bootstrap_preprod.sh
```

The script runs public-source mode, validates the bundle, mirrors the UI runtime data, and stores a `last-good` copy after successful validation.

Optional NVD recent enrichment is enabled automatically when `NVD_API_KEY` exists:

```bash
export NVD_API_KEY="<optional-api-key>"
bash scripts/bootstrap_preprod.sh
```

Manual equivalent:

```bash
python scripts/knowledge_builder/build_knowledge_base.py \
  --with-public-sources \
  --refresh-public-sources

python scripts/knowledge_builder/validate_bundle.py \
  data/knowledge-bundle.json \
  --require-public-sources \
  --min-nodes 100 \
  --min-edges 50
```

Generated outputs:

```text
data/nodes.json
data/edges.json
data/indexes.json
data/coverage.json
data/routes.json
data/metadata.json
data/knowledge-bundle.json
data/knowledge-bundle.last-good.json
data/raw/                         # public-source cache when enabled
data/snapshots/<timestamp>/
app/navigator-ui/public/data/knowledge-bundle.json
app/navigator-ui/public/data/knowledge-bundle.last-good.json
```

---

## Run the UI

```bash
cd app/navigator-ui
npm install
npm run dev
```

Build static UI:

```bash
cd app/navigator-ui
npm run build
```

The UI is **search-first**:

- Nothing is selected by default.
- No demo route is shown until the user searches.
- The UI loads `/data/knowledge-bundle.json` first.
- If the generated bundle is missing, it shows a visible fallback warning and uses the local Log4Shell sample only for development resilience.
- The **Clear** button resets query, active route, selected node and exports.

---

## Main tabs

| Tab | Purpose |
|---|---|
| Route Flow | Concatenated route across CVE/CWE/CAPEC/ATT&CK/Artifact/D3FEND/Control/Detection/Evidence/Gap. |
| ATT&CK Navigator | ATT&CK layer JSON preview/download for the active route. |
| D3FEND CAD | CAD-style D3FEND graph JSON preview/download for the active route. |
| Coverage | Coverage, detections, owners, evidence and gaps. |
| Export | Markdown, route JSON, ATT&CK layer JSON and D3FEND CAD graph JSON. |

---

## Debian pre-production deployment

Use the runbook:

```text
docs/PREPROD_DEPLOYMENT_DEBIAN.md
```

Recommended cron:

```cron
30 2 * * * cd /opt/attack2defend && . .venv/bin/activate && bash scripts/bootstrap_preprod.sh >> /var/log/attack2defend/knowledge_builder.log 2>&1
```

---

## Validation seeds

Guaranteed curated seeds:

| Input | Purpose |
|---|---|
| `CVE-2021-44228` | Log4Shell route from CVE to weakness, attack path, defense, controls, detections and evidence. |
| `T1567` | ATT&CK-first exfiltration route. |
| `CVE-2024-37079` | Modern CVE route. |
| `CWE-79` | AppSec/CWE-first route. |
| `D3-MFA` | D3FEND-first identity route. |

Public-source mode should also expose public nodes such as `T1190`, `CAPEC-63`, and broader CWE/CAPEC/ATT&CK catalog entries depending on source availability.

---

## What is intentionally not included yet

| Not included | Reason |
|---|---|
| Agentic AI / AI Route Analyst runtime | Next major capability; must consume resolved routes, not invent mappings. |
| Backend API | Static-first is enough for current pre-prod. |
| Graph database | JSON bundle is enough until route queries become complex. |
| Browser runtime public API calls | Public APIs belong in scheduled builder only. |
| Autonomous remediation | Human approval and ownership come first. |

---

## Repository layout

```text
attack2defend/
├── app/navigator-ui/                 # React/Vite/TypeScript UI
├── data/
│   ├── samples/                      # curated route seeds
│   ├── raw/                          # public-source cache when enabled
│   ├── knowledge-bundle.json         # generated bundle
│   └── snapshots/                    # generated snapshots
├── scripts/
│   ├── bootstrap_preprod.sh          # simple first-run/public refresh command
│   └── knowledge_builder/
│       ├── build_knowledge_base.py   # builder/cron entrypoint
│       ├── public_collectors.py      # dependency-free public collectors
│       └── validate_bundle.py        # dependency-free bundle validator
├── docs/
│   └── PREPROD_DEPLOYMENT_DEBIAN.md
└── tests/
```

---

## Development principles

1. Keep route resolution deterministic.
2. Use public sources only in the scheduled builder.
3. Never depend on public APIs at SOC runtime.
4. Preserve curated/internal coverage across public updates.
5. UI renders the bundle; it does not fetch external knowledge directly.
6. Keep the UX search-first and avoid demo-first behavior.
