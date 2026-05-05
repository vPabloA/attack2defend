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
  echo "[pre] Forcing compatible CVE2CAPEC raw sync"
  bash scripts/sync_cve2capec_raw.sh
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

echo "[2/6] Applying mapping backbone, CPE/KEV parity seeds and curated defense mappings"
python scripts/mapping_builder/apply_mapping_backbone.py --last-good

echo "[3/6] Validating mapping-backbone parity bundle"
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json "${VALIDATION_FLAGS[@]}"

echo "[4/6] Building NSFW + CVE2CAPEC canonical mapping exports"
python scripts/canonical_exports/build_canonical.py

echo "[5/6] Validating NSFW + CVE2CAPEC canonical exports"
python scripts/canonical_exports/validate_canonical.py

echo "[6/6] Verifying UI runtime bundle mirror"
test -s app/navigator-ui/public/data/knowledge-bundle.json
test -s app/navigator-ui/public/nsfw/data/cve_cwe.json
test -s app/navigator-ui/public/cve2capec/lastUpdate.txt

echo "Attack2Defend local full bootstrap completed successfully."
echo "Generated bundle: data/knowledge-bundle.json"
echo "NSFW exports:     data/canonical/nsfw/ + app/navigator-ui/public/nsfw/data/"
echo "CVE2CAPEC layout: data/canonical/cve2capec/ + app/navigator-ui/public/cve2capec/"
echo "Mirrored bundle:  app/navigator-ui/public/data/knowledge-bundle.json"
echo "Next: cd app/navigator-ui && npm install && npm run dev"
echo "  Defense Navigator: http://localhost:5173/"
echo "  NSFW Navigator:    http://localhost:5173/nsfw/"
