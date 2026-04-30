#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/4] Building deterministic knowledge bundle"
python scripts/knowledge_builder/build_knowledge_base.py

echo "[2/4] Validating knowledge bundle"
python scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json

echo "[3/4] Running Python tests"
pytest -q

echo "[4/4] Building Navigator UI"
cd app/navigator-ui
npm install
npm run build

echo "Attack2Defend pre-production validation completed successfully."
