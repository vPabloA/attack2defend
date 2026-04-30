# Attack2Defend Navigator

**Attack2Defend** is a static-first operational navigator that turns public security framework knowledge into SOC/CTEM action.

It maps and navigates:

```text
CVE → CWE → CAPEC → MITRE ATT&CK → Digital Artifact → MITRE D3FEND → Control → Detection → Evidence → Gap
```

The runtime UI does **not** call public APIs. Public knowledge is fetched by the scheduled builder, validated, snapshotted and served locally as `knowledge-bundle.json`.

---

## Current status

| Capability | Status |
|---|---|
| React/Vite Navigator UI | Ready |
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

Curated mode is fast and offline after clone. It uses `data/samples/*.route.json`.

```bash
python scripts/knowledge_builder/build_knowledge_base.py
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json
pytest -q
```

---

## Quick start: public-source mode

Public-source mode hydrates the bundle from ATT&CK, CWE, CAPEC, CISA KEV and best-effort D3FEND. It also preserves curated seeds and internal coverage.

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

Optional NVD enrichment for specific CVEs:

```bash
python scripts/knowledge_builder/build_knowledge_base.py \
  --with-public-sources \
  --with-nvd \
  --nvd-cve CVE-2021-44228 \
  --nvd-cve CVE-2024-37079
```

Optional recent NVD enrichment:

```bash
export NVD_API_KEY="<optional-api-key>"
python scripts/knowledge_builder/build_knowledge_base.py \
  --with-public-sources \
  --with-nvd \
  --nvd-recent-days 7
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
data/raw/                         # public-source cache when enabled
data/snapshots/<timestamp>/
app/navigator-ui/public/data/knowledge-bundle.json
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

The UI loads:

```text
/data/knowledge-bundle.json
```

If that file is missing, it falls back to the local Log4Shell sample for development resilience.

---

## Debian pre-production deployment

Use the runbook:

```text
docs/PREPROD_DEPLOYMENT_DEBIAN.md
```

Pre-production cron should run public-source mode:

```cron
30 2 * * * cd /opt/attack2defend && . .venv/bin/activate && python scripts/knowledge_builder/build_knowledge_base.py --with-public-sources --with-nvd --nvd-recent-days 7 && python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json --require-public-sources --min-nodes 100 --min-edges 50 >> /var/log/attack2defend/knowledge_builder.log 2>&1
```

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

> **ATT&CK explains how the adversary acts. D3FEND explains how we defend the artifacts the adversary touches. Attack2Defend makes that route operational.**

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

## Validation seeds

Guaranteed curated seeds:

| Input | Purpose |
|---|---|
| `CVE-2021-44228` | Log4Shell route from CVE to weakness, attack path, defense, controls, detections and evidence. |
| `T1567` | ATT&CK-first exfiltration route. |
| `CVE-2024-37079` | Modern CVE route. |
| `CWE-79` | AppSec/CWE-first route. |
| `D3-MFA` | D3FEND-first identity route. |

Public-source mode should also expose generic public nodes such as `T1190`, `CAPEC-63`, and broad CWE/CAPEC/ATT&CK catalog entries depending on source availability.

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
├── scripts/knowledge_builder/
│   ├── build_knowledge_base.py       # cron/job entrypoint
│   ├── public_collectors.py          # dependency-free public collectors
│   └── validate_bundle.py            # dependency-free bundle validator
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
6. Every route should end in action, evidence or a declared gap.
