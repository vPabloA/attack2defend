# Attack2Defend v1.0.0-GA Release Notes

## Product story

Attack2Defend combines deterministic CVE/CWE/CAPEC/ATT&CK/D3FEND routing with provenance, intelligence governance, graph exploration, static-first product visibility and optional automation surfaces.

## Milestones

| PR | Capability |
|---|---|
| #26 | Provenance hardening and OpenAI-default offline cherry-picker |
| #28 | Intelligence Factory and policy-driven promotion |
| #29 | Static Product Visibility Layer |
| #30 | Optional Graph Sidecar and knowledge exploration |
| Final | MCP/API Automation Layer and SOC-actionable D3FEND output |

## GA capability set

- Static-first navigator.
- Canonical `knowledge-bundle.json` source of truth.
- Edge provenance validation.
- Intelligence Factory artifacts.
- Policy-driven non-blocking candidate promotion.
- Optional graph sidecar with CSV/Cypher/query pack.
- Optional REST API.
- Optional MCP-style stdio tool server.
- SOC Action Pack generation.
- GA readiness gate through `make ga-check`.

## Production rules

```text
Full graph is deterministic.
SOC output is evidence/gap aware.
LLM output is candidate-only.
The UI is static-first.
API/MCP are optional and read-only.
No browser public API calls.
No runtime external API calls.
No evidence, no confirmed coverage.
Validator wins.
```

## Recommended release gate

```bash
make ga-check
```

## Recommended tag after merge

```bash
git checkout main
git pull origin main
git tag -a v1.0.0-ga -m "Attack2Defend GA: static-first defense navigator with SOC-actionable automation layer"
git push origin v1.0.0-ga
```

## Deferred beyond GA

- GitHub Pages polish.
- Runtime integrations with SIEM/EDR/SOAR products.
- D3FEND XML ingestion refresh.
- Infrastructure validation using real enterprise inventory.
