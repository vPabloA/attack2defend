#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[pre] Forcing compatible CVE2CAPEC raw sync"
bash scripts/sync_cve2capec_raw.sh

PUBLIC_FLAGS=(--with-public-sources --refresh-public-sources)
VALIDATION_FLAGS=(--require-public-sources --require-mapping-backbone --require-semantic-routes --min-nodes "100" --min-edges "60" --min-mapping-files "1")

if [[ -n "${NVD_API_KEY:-}" ]]; then
  echo "NVD_API_KEY detected; enabling recent NVD enrichment."
  PUBLIC_FLAGS+=(--with-nvd --nvd-recent-days "7")
else
  echo "NVD_API_KEY not set; running public-source bootstrap without NVD recent enrichment."
fi

echo "[1/4] Building public-source knowledge bundle"
python scripts/knowledge_builder/build_knowledge_base.py "${PUBLIC_FLAGS[@]}"

echo "[2/6] Applying mapping backbone and curated defense mappings"
python scripts/mapping_builder/apply_mapping_backbone.py --last-good

echo "[3/6] Validating public-source mapping-backbone bundle"
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json "${VALIDATION_FLAGS[@]}"

echo "[4/6] Building NSFW + CVE2CAPEC canonical mapping exports"
python scripts/canonical_exports/build_canonical.py

echo "[5/6] Validating NSFW + CVE2CAPEC canonical exports"
python scripts/canonical_exports/validate_canonical.py

echo "[6/6] Verifying UI runtime bundle mirror"
test -s app/navigator-ui/public/data/knowledge-bundle.json
test -s app/navigator-ui/public/nsfw/data/cve_cwe.json
test -s app/navigator-ui/public/cve2capec/lastUpdate.txt

mkdir -p logs

echo "Attack2Defend pre-production bootstrap completed successfully."
echo "Generated bundle: data/knowledge-bundle.json"
echo "NSFW exports:     data/canonical/nsfw/ + app/navigator-ui/public/nsfw/data/"
echo "CVE2CAPEC layout: data/canonical/cve2capec/ + app/navigator-ui/public/cve2capec/"
echo "Mirrored bundle:  app/navigator-ui/public/data/knowledge-bundle.json"
