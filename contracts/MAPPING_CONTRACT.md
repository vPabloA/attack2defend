# Attack2Defend Mapping Contract

## Purpose

Mappings are the product. The UI is only a renderer. Every edge must be deterministic, attributable and safe to consume from a static bundle.

## Required mapping file shape

```json
{
  "schema_version": "attack2defend.mapping.v1",
  "description": "Human-readable mapping intent.",
  "license": "source-or-curation-license",
  "nodes": [],
  "mappings": []
}
```

## Required mapping record fields

| Field | Required | Meaning |
|---|---:|---|
| `from` | Yes | Source node ID. |
| `from_type` | Yes | Source node type. |
| `from_name` | Recommended | Human-readable source name. |
| `to` | Yes | Target node ID. |
| `to_type` | Yes | Target node type. |
| `to_name` | Recommended | Human-readable target name. |
| `relationship` | Recommended | Canonical relationship. If omitted, builder infers it by type pair. |
| `confidence` | Yes | Confidence label. |
| `source_ref` | Yes | File/source/reference used to justify the mapping. |
| `source_kind` | Recommended | `public-compatible`, `curated`, `override`, `deprecated`. |
| `owner` | Recommended for defensive mappings | SOC, AppSec, CTEM, Cloud, Infra, IAM. |
| `priority` | Optional | P0/P1/P2 action priority. |

## Valid node types

`cve`, `cwe`, `capec`, `attack`, `d3fend`, `artifact`, `control`, `detection`, `evidence`, `gap`, `action`.

## Canonical semantic route

```text
CVE → CWE → CAPEC → ATT&CK → Artifact → D3FEND → Control → Detection → Evidence → Gap → Action
```

## Canonical relationships

| From | To | Relationship |
|---|---|---|
| CVE | CWE | `vulnerability_has_weakness` |
| CWE | CAPEC | `weakness_enables_attack_pattern` |
| CAPEC | ATT&CK | `attack_pattern_maps_to_technique` |
| ATT&CK | D3FEND | `technique_mitigated_by_countermeasure` |
| ATT&CK/CAPEC | Artifact | `affects_or_requires_artifact` |
| CVE | Artifact | `affects_product_or_platform` |
| Artifact | Control | `protected_by_control` |
| Control | Detection | `validated_by_detection` |
| Detection | Evidence | `requires_evidence` |
| Evidence | Gap | `missing_evidence_creates_gap` |
| Gap | Action | `closed_by_action` |

A collector downloads. A curated mapping decides. Do not mark a route complete unless it reaches defensive evidence/gap/action semantics.
