# Attack2Defend Bundle Contract

## Purpose

The bundle is the only runtime data plane consumed by the static UI. Browser runtime must not call public APIs, infer missing relationships, or mutate route semantics.

## Contract version

Current target: `attack2defend.knowledge_bundle.v2`.

## Required top-level fields

| Field | Required | Purpose |
|---|---:|---|
| `metadata` | Yes | Build, source, count and mapping provenance. |
| `nodes` | Yes | Canonical framework, product, defense and SOC/CTEM nodes. |
| `edges` | Yes | Deterministic relationships between nodes. |
| `indexes` | Yes | Precomputed UI/runtime navigation indexes. |
| `coverage` | Yes | Coverage records by node ID. |
| `routes` | Yes | Raw route metadata. |
| `semantic_routes` | Required for parity gate | Phase-aware routes resolved at build time. |
| `coverage_summary` | Recommended | Route status distribution and readiness summary. |

## Required node types

`cve`, `cwe`, `capec`, `attack`, `d3fend`, `artifact`, `control`, `detection`, `evidence`, `gap`, `action`.

CPE is represented as an `artifact` node with `metadata.framework = "cpe"` so the UI can keep one node taxonomy while still exposing affected product/vendor/version semantics.

## Required edge provenance

Every relationship in `edges[]` must be auditable. The graph may contain deterministic public mappings, curated mappings, or explicitly marked inferred relationships, but it must never contain anonymous relationships.

Each edge must include:

| Field | Required | Purpose |
|---|---:|---|
| `source_feed` | Yes | Logical source feed or mapping family. |
| `source_ref` or `source_url` | Yes | Stable local reference, mapping file, cache key, source document or public URL. |
| `retrieved_at` | Yes | Retrieval, collection, mapping or bundle timestamp used for the edge. |
| `transform_version` | Yes | Builder, normalizer or enforcer version that produced or stamped the edge. |
| `confidence` | Yes | Confidence label used by route scoring and analyst explainability. |
| `deterministic` | Yes | Boolean. `true` when the edge comes from deterministic source data or curated mapping. |
| `inferred` | Yes | Boolean. `true` only when the edge is explicitly inference-derived. |

Optional integrity fields may be added later: `source_hash`, `bundle_hash`, `checksum_algorithm`, and `signature`. Do not describe provenance as cryptographic unless one of those integrity fields is actually produced.

## Required indexes for nsfw/CVE2CAPEC parity

```json
{
  "indexes": {
    "forward": {
      "cve_to_cwe": {},
      "cve_to_cpe": {},
      "cwe_to_capec": {},
      "capec_to_attack": {},
      "attack_to_d3fend": {}
    },
    "reverse": {
      "cwe_to_cve": {},
      "cpe_to_cve": {},
      "capec_to_cwe": {},
      "attack_to_capec": {},
      "d3fend_to_attack": {}
    },
    "cpe_to_cve": {},
    "kev": {},
    "search": []
  }
}
```

## Runtime rule

The UI may traverse, filter, intersect and render only what is present in `knowledge-bundle.json`. Missing relationships must be shown as missing segments or gaps; they must never be invented at runtime.

## Validation gate

```bash
python scripts/knowledge_builder/validate_edge_provenance.py data/knowledge-bundle.json
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json \
  --require-mapping-backbone \
  --require-semantic-routes \
  --require-framework-chain \
  --require-cpe-index \
  --require-kev-index \
  --require-bidirectional-indexes \
  --require-source-confidence \
  --require-search-index \
  --min-mapping-files 1
```

A bundle that fails this gate is not at nsfw/CVE2CAPEC parity.
