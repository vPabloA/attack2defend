# Attack2Defend Capability Contract

## Capability

`attack2defend.resolve_defense_route`

Purpose: resolve one local bundle input into a machine-readable defense intelligence response that separates threat route logic from operational readiness.

Runtime rules:

- Reads only a local `knowledge-bundle.json`.
- Does not call public APIs.
- Does not call LLMs.
- Does not mutate the bundle.
- Does not invent framework mappings.

## Input

```json
{
  "input": "CVE-2023-34362"
}
```

Supported IDs:

- `cve`
- `cwe`
- `capec`
- `attack`
- `d3fend`
- `control`
- `detection`
- `evidence`
- `gap`
- `action`

## Output Model

The response has two maps:

- `threat_route_map`: only `cve`, `cwe`, `capec`, `attack`, `d3fend`.
- `defense_readiness_map`: only `control`, `detection`, `evidence`, `gap`, `action`.

Maps are connected by explicit `bridges`. Attack2Defend must not publish a single monolithic chain.

Allowed bridge pairs:

- `d3fend -> control`
- `attack -> detection`
- `attack -> evidence`
- `cve -> action`
- `gap -> action`
- `control -> detection`
- `detection -> evidence`
- `evidence -> gap`

Preferred relationship names:

- `implemented_by_control`
- `should_be_detected_by`
- `requires_evidence`
- `requires_action`
- `closed_by_action`
- `validated_by_detection`
- `missing_evidence_creates_gap`

## Status

`threat_route_map.status`:

- `complete`: expected framework route exists for the input class.
- `partial`: some route segments exist.
- `catalog-only`: only catalog data exists and no defensive bridge is present.
- `unresolved`: no useful local route exists.

`defense_readiness_map.status`:

- `ready`: has Control, Detection, Evidence, and Action.
- `partial-defense`: has some operational defense data.
- `detection-gap`: ATT&CK context exists and Detection is missing.
- `evidence-gap`: Detection exists and Evidence is missing.
- `action-gap`: Gap exists and Action is missing.
- `unresolved`: no related defensive data exists.

## Confidence And Priority

`confidence` is deterministic:

- `high`: curated/internal mappings support both route and readiness.
- `medium`: local public/curated route exists but readiness is partial.
- `low`: unresolved or catalog-only data.

Priority is bundle-only. GTI is intentionally not applied in this capability.

Rules:

- threat route exists + defense map empty = `high`
- ATT&CK exists + no Detection = `high`
- Detection exists + no Evidence = `medium`
- Gap exists + no Action = `medium`
- ready/complete with Evidence = `low`
- unresolved = `unknown`

## Official Links

Threat nodes should expose official links:

- `cve`: use `node.url`; fallback `https://www.cve.org/CVERecord?id=<CVE-ID>`
- `cwe`: `https://cwe.mitre.org/data/definitions/<N>.html`
- `capec`: `https://capec.mitre.org/data/definitions/<N>.html`
- `attack`: `https://attack.mitre.org/techniques/<TID with slash for subtechniques>/`
- `d3fend`: `https://d3fend.mitre.org/technique/<D3-ID>/`

Operational nodes must expose `source_ref`, `mapping_file`, or `metadata.source_ref` when present. If missing, emit `missing_source_ref`; do not invent URLs.

## Bilingual Output

Machine fields remain English: schema keys, node types, IDs, enums, relationships.

Human decision fields are Spanish:

- `executive_summary_es`
- `decision_context_es`
- `risk_rationale_es`
- `defense_readiness_map.summary_es`
- `defense_readiness_map.gap_explanation_es`
- `priority.rationale_es`
- `recommended_actions[].description_es`
- `recommended_actions[].owner_guidance_es`

## Integration Contract

The output is stable for CLI, future API, future MCP server, and `mcp-security` adapters.

`integration_context` declares readiness flags:

- `gti_ready`: contract can be enriched later by `attack2defend.enrich_vulnerability_with_gti`.
- `mcp_security_ready`: response can be consumed by an `mcp-security` adapter.
- `mcp_server_ready`: false until an Attack2Defend MCP server exists.
- `requires_runtime_enrichment`: false for this deterministic resolver.

TODO: add a future capability for GTI enrichment without changing this base resolver contract.
