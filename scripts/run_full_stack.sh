#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON:-python3}"
UI_DIR="app/navigator-ui"
API_HOST="${A2D_API_HOST:-127.0.0.1}"
API_PORT="${A2D_API_PORT:-8000}"
UI_HOST="${A2D_UI_HOST:-127.0.0.1}"
UI_PORT="${A2D_UI_PORT:-5173}"

PIDS=()

cleanup() {
  local exit_code=$?
  if ((${#PIDS[@]} > 0)); then
    kill "${PIDS[@]}" >/dev/null 2>&1 || true
  fi
  wait >/dev/null 2>&1 || true
  exit "$exit_code"
}

trap cleanup EXIT INT TERM

start_bg() {
  local name="$1"
  shift
  echo "[start] $name"
  "$@" &
  PIDS+=("$!")
}

echo "[1/6] Installing dependencies"
make install

echo "[2/6] Building local bundle, canonical exports and graph artifacts"
make build-product

echo "[3/6] Running validations"
make validate-product
make validate-api
make validate-mcp
make test

echo "[4/6] Verifying static-first runtime rules"
bash scripts/validate_static_first.sh

echo "[5/6] Starting local services"
start_bg "API server" "$PYTHON_BIN" -m attack2defend.api.app --host "$API_HOST" --port "$API_PORT"
start_bg "UI dev server" bash -lc "cd '$UI_DIR' && npm run dev -- --host '$UI_HOST' --port '$UI_PORT'"

echo "[6/6] Ready"
echo "API: http://$API_HOST:$API_PORT/api/v1/health"
echo "UI:  http://$UI_HOST:$UI_PORT/"
echo "Press Ctrl+C to stop both services."

wait
