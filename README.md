# Attack2Defend Navigator

**Attack2Defend** is a deterministic, static-first vulnerability-to-defense navigator. It is designed as a stronger successor pattern to CVE2CAPEC/NSFW-style navigation: first recover framework mapping parity, then extend the route into SOC/CTEM defensive evidence and actions.

```text
CVE → CWE → CAPEC → MITRE ATT&CK → Artifact → MITRE D3FEND → Control → Detection → Evidence → Gap → Action
```

The browser UI does **not** call public APIs. Public sources are fetched by the builder, merged with local curated mappings, validated, and published as a local `knowledge-bundle.json` consumed by React/Vite.

---

## Current operating model

| Layer | Responsibility |
|---|---|
| Public collectors | ATT&CK, CWE, CAPEC, CISA KEV, optional NVD, best-effort D3FEND at build time only. |
| Mapping backbone | NSFW/CVE2CAPEC-compatible mapping file under `data/mappings/`. |
| Curated defense mappings | Artifact, control, detection, evidence, gap and action relationships. |
| Semantic resolver | Phase-constrained routes with coverage status, confidence and missing segments. |
| UI | Static bundle renderer. No public runtime APIs. |

---

## Quick start: full local bootstrap

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make bootstrap-local-full
make test
make ui
```

Open the Vite URL, usually `http://localhost:5173`.

The generated UI bundle is mirrored to:

```text
app/navigator-ui/public/data/knowledge-bundle.json
```

---

## What you can search after bootstrap

| Input | Expected behavior |
|---|---|
| `CVE-2021-44228` | CVE→CWE→CAPEC/ATT&CK→artifact/control/detection/evidence/gap/action where mapped. |
| `CVE-2023-34362` | MOVEit-style vulnerable app route with product context and exploit-public-app path. |
| `CWE-79` | XSS route into CAPEC/ATT&CK and AppSec defensive controls. |
| `T1190` | Exploit public-facing application route into WAF/AppSec/SOC evidence and gaps. |
| `T1567` | Exfiltration route into egress monitoring evidence and actions. |
| `D3-MFA` | D3FEND-first/reverse navigation if present in bundle or curated seeds. |

New/arbitrary CVEs still require NVD/public-source enrichment or a curated mapping record. The UI must not invent missing mappings.

---

## Commands

| Command | Purpose |
|---|---|
| `make bootstrap-local-full` | Build base bundle, apply mapping backbone, validate, mirror to UI. |
| `make build-curated` | Build from curated sample routes only. |
| `make build-public` | Build with public sources. |
| `make build-backbone` | Apply local mapping backbone and curated defense mappings. |
| `make validate` | Validate bundle contract, mapping backbone and semantic routes. |
| `make test` | Run Python tests and Vite build. |
| `make ui` | Start React/Vite dev server. |
| `make preprod` | Public-source pre-prod bootstrap with mapping backbone. |

Optional public-source refresh:

```bash
A2D_REFRESH_PUBLIC_SOURCES=1 make bootstrap-local-full
```

Optional NVD enrichment:

```bash
export NVD_API_KEY="<optional-api-key>"
make bootstrap-local-full
```

---

## Repository layout

```text
attack2defend/
├── app/navigator-ui/                 # React/Vite static UI
├── contracts/                        # Mapping contract
├── data/
│   ├── mappings/                     # Mapping backbone and curated defense mappings
│   ├── samples/                      # curated route seeds
│   ├── raw/                          # public-source cache
│   ├── knowledge-bundle.json         # generated static bundle
│   └── knowledge-bundle.last-good.json
├── docs/
│   ├── LOCALHOST_DEPLOYMENT.md
│   └── PREPROD_DEPLOYMENT_DEBIAN.md
├── scripts/
│   ├── bootstrap_local_full.sh
│   ├── bootstrap_preprod.sh
│   ├── knowledge_builder/
│   └── mapping_builder/
└── tests/
```

---

## Validation gates

```bash
python scripts/knowledge_builder/validate_bundle.py \
  data/knowledge-bundle.json \
  --require-mapping-backbone \
  --require-semantic-routes \
  --min-mapping-files 1
```

A route is not considered complete just because it reaches ATT&CK or D3FEND. Complete means it reaches defensive context through controls, detections, evidence, gaps and actions.

---

## Design principles

1. Mappings are the product; the UI is the renderer.
2. Public API calls happen only in builder/cron, never in browser runtime.
3. Curated mappings must carry source, confidence and ownership.
4. Route resolution is semantic and phase-constrained, not free-form graph wandering.
5. Missing evidence becomes an explicit gap, not a silent failure.
6. The project must be useful immediately after clone, build and localhost startup.
