# Attack2Defend v1.0.0-ga Release Notes

## Release Statement

**Attack2Defend v1.0.0-ga** is the first production-grade release of the static-first cyber defense navigator.

This release turns Attack2Defend into a usable security product: deterministic graph, curated defensive route, trust/evidence layer, canonical exports and optional validator-gated AI curation.

---

## Highlights

| Area | Result |
|---|---|
| Static-first UI | Browser runtime reads only local `knowledge-bundle.json`. No public API or LLM calls from UI. |
| Full traceability | Preserves `CVE → CWE → CAPEC → ATT&CK → D3FEND` graph evidence. |
| Curated decision | Presents a focused route for defensive validation instead of forcing graph-dump analysis. |
| Product Trust Layer | Adds evidence badges, source inspection, detection disclaimers, potential gaps and closure criteria. |
| AI curation | Optional offline Gemini/OpenAI/Anthropic cherry-picking, always candidate-only and validator-gated. |
| Canonical exports | Maintains NSFW-compatible and CVE2CAPEC-compatible export layouts. |

---

## Production Rules

```text
Full graph is deterministic.
Curated route is validator-gated.
LLM output is candidate-only.
The UI is static-first.
No browser public API calls.
No source, no selection.
No evidence, no promotion.
Validator wins.
```

---

## Validation

Before tagging this release, run:

```bash
make test
```

Optional deeper validation:

```bash
make bootstrap-local-full
python scripts/knowledge_builder/validate_bundle.py \
  data/knowledge-bundle.json \
  --require-mapping-backbone \
  --require-semantic-routes \
  --require-framework-chain \
  --require-cpe-index \
  --require-kev-index \
  --require-bidirectional-indexes \
  --require-source-confidence \
  --require-search-index \
  --min-mapping-files 1
python scripts/canonical_exports/validate_canonical.py
```

---

## Recommended Tag

```bash
git checkout main
git pull origin main
git tag -a v1.0.0-ga -m "Attack2Defend GA: static-first defense navigator with trust layer and validator-gated AI curation"
git push origin v1.0.0-ga
```
