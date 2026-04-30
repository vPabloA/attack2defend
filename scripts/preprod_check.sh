#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUBLIC_MODE="${ATTACK2DEFEND_PUBLIC_MODE:-0}"
BUILDER_ARGS=()
VALIDATOR_ARGS=(data/knowledge-bundle.json)

if [[ "$PUBLIC_MODE" == "1" || "$PUBLIC_MODE" == "true" ]]; then
  BUILDER_ARGS+=(--with-public-sources)
  VALIDATOR_ARGS+=(--require-public-sources --min-nodes 100 --min-edges 50)
fi

echo "[1/4] Building knowledge bundle"
python scripts/knowledge_builder/build_knowledge_base.py "${BUILDER_ARGS[@]}"

echo "[2/4] Validating knowledge bundle"
python scripts/knowledge_builder/validate_bundle.py "${VALIDATOR_ARGS[@]}"

echo "[3/4] Running Python tests"
pytest -q

echo "[4/4] Building Navigator UI"
cd app/navigator-ui
if [ -f package-lock.json ]; then
  npm ci
else
  npm install
fi
npm run build

echo "Attack2Defend pre-production validation completed successfully."
