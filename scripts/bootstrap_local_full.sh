#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUBLIC_FLAGS=(--with-public-sources)
VALIDATION_FLAGS=(
  --require-public-sources
  --require-mapping-backbone
  --require-semantic-routes
  --require-framework-chain
  --require-cpe-index
  --require-kev-index
  --require-bidirectional-indexes
  --require-source-confidence
  --require-search-index
  --min-nodes "80"
  --min-edges "60"
  --min-mapping-files "1"
)

if [[ "${A2D_REFRESH_PUBLIC_SOURCES:-0}" == "1" ]]; then
  PUBLIC_FLAGS+=(--refresh-public-sources)
fi

if [[ -n "${NVD_API_KEY:-}" ]]; then
  echo "NVD_API_KEY detected; enabling recent NVD enrichment."
  PUBLIC_FLAGS+=(--with-nvd --nvd-recent-days "7")
else
  echo "NVD_API_KEY not set; running without NVD recent enrichment."
fi

echo "[1/4] Building base knowledge bundle"
python scripts/knowledge_builder/build_knowledge_base.py "${PUBLIC_FLAGS[@]}"

echo "[2/4] Applying mapping backbone, CPE/KEV parity seeds and curated defense mappings"
python scripts/mapping_builder/apply_mapping_backbone.py --last-good

echo "[3/4] Validating mapping-backbone parity bundle"
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json "${VALIDATION_FLAGS[@]}"

echo "[4/4] Verifying UI runtime bundle mirror"
test -s app/navigator-ui/public/data/knowledge-bundle.json

echo "Attack2Defend local full bootstrap completed successfully."
echo "Generated: data/knowledge-bundle.json"
echo "Mirrored: app/navigator-ui/public/data/knowledge-bundle.json"
echo "Next: cd app/navigator-ui && npm install && npm run dev"
