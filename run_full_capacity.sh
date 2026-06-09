#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

export A2D_API_HOST="${A2D_API_HOST:-127.0.0.1}"
export A2D_API_PORT="${A2D_API_PORT:-8000}"
export A2D_UI_HOST="${A2D_UI_HOST:-127.0.0.1}"
export A2D_UI_PORT="${A2D_UI_PORT:-5173}"
export A2D_RUN_FULL_STACK="${A2D_RUN_FULL_STACK:-1}"

exec "$ROOT_DIR/run.sh" full
