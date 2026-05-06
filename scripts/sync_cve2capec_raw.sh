#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CACHE_DIR="${1:-$ROOT_DIR/data/raw/cve2capec}"
YEAR="${A2D_CVE2CAPEC_YEAR:-$(date -u +%Y)}"
BASE_URL="https://raw.githubusercontent.com/Galeax/CVE2CAPEC/refs/heads/main"

mkdir -p "$CACHE_DIR/database" "$CACHE_DIR/resources"

download() {
  local relative_path="$1"
  local destination="$2"
  curl --fail --location --silent --show-error \
    "${BASE_URL}/${relative_path}" \
    --output "$destination"
}

echo "Syncing Galeax CVE2CAPEC raw cache for year ${YEAR}"
download "lastUpdate.txt" "$CACHE_DIR/lastUpdate.txt"
download "resources/cwe_db.json" "$CACHE_DIR/resources/cwe_db.json"
download "resources/capec_db.json" "$CACHE_DIR/resources/capec_db.json"
download "resources/techniques_db.json" "$CACHE_DIR/resources/techniques_db.json"
download "resources/defend_db.jsonl" "$CACHE_DIR/resources/defend_db.jsonl"
download "database/CVE-${YEAR}.jsonl" "$CACHE_DIR/database/CVE-${YEAR}.jsonl"

echo "CVE2CAPEC cache updated in $CACHE_DIR"
