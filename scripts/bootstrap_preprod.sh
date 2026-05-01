#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUBLIC_FLAGS=(--with-public-sources --refresh-public-sources)
VALIDATION_FLAGS=(--require-public-sources --min-nodes "100" --min-edges "50")

if [[ -n "${NVD_API_KEY:-}" ]]; then
  echo "NVD_API_KEY detected; enabling recent NVD enrichment."
  PUBLIC_FLAGS+=(--with-nvd --nvd-recent-days "7")
else
  echo "NVD_API_KEY not set; running public-source bootstrap without NVD recent enrichment."
fi

echo "[1/3] Building public-source knowledge bundle"
python scripts/knowledge_builder/build_knowledge_base.py "${PUBLIC_FLAGS[@]}"

echo "[2/3] Validating public-source knowledge bundle"
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json "${VALIDATION_FLAGS[@]}"

echo "[3/3] Verifying UI runtime bundle mirror"
test -s app/navigator-ui/public/data/knowledge-bundle.json

mkdir -p logs
cp data/knowledge-bundle.json data/knowledge-bundle.last-good.json
cp app/navigator-ui/public/data/knowledge-bundle.json app/navigator-ui/public/data/knowledge-bundle.last-good.json

echo "Attack2Defend pre-production bootstrap completed successfully."
echo "Generated: data/knowledge-bundle.json"
echo "Mirrored: app/navigator-ui/public/data/knowledge-bundle.json"
