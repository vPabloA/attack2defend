# Attack2Defend UIX Parity Contract

## Goal

Reach nsfw + CVE2CAPEC interaction parity without introducing AI, backend APIs or browser runtime public-source calls.

## Required UI behavior

| Capability | Requirement |
|---|---|
| Search-first start | No route is auto-selected on first load. |
| Framework detection | Input detects CVE, CPE, CWE, CAPEC, ATT&CK, D3FEND and Attack2Defend defensive IDs. |
| Autocomplete | Suggestions use `indexes.search` and show ID, type/name and source semantics where available. |
| Bidirectional navigation | UI uses `indexes.forward`, `indexes.reverse`, `incoming` and `outgoing`. |
| CPE panel | CPE/product nodes show vendor, product, version and related CVEs. |
| KEV badge | CVEs present in `indexes.kev` show known-exploited status and required action. |
| Multi-ID mode | Multiple selected IDs can intersect related nodes. |
| Route completeness | UI displays `semantic_routes[].coverage_status` and `missing_segments`. |
| Source/confidence visibility | Edge detail exposes relationship, source_ref, source_kind and confidence. |
| Export | Markdown, route JSON, ATT&CK layer JSON and D3FEND/CAD-like graph remain available. |
| Offline runtime | UI works from `/data/knowledge-bundle.json`; no external fetches except static bundle. |

## Forbidden UI behavior

- Do not call CVE, NVD, CWE, CAPEC, ATT&CK, D3FEND or CISA KEV from the browser.
- Do not synthesize missing mappings from naming similarity.
- Do not mark a route complete only because it reaches ATT&CK or D3FEND.
- Do not hide fallback mode; fallback must be visibly non-production.

## Parity view model

A route detail panel should expose:

```text
Input → Framework chain → Affected products/CPE → KEV priority → D3FEND countermeasures → Defensive route/gaps/actions
```

The initial parity target is not visual complexity. It is trustable navigation with visible source, confidence and missing-segment handling.
