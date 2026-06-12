#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export A2D_RUN_FULL_STACK="${A2D_RUN_FULL_STACK:-1}"

exec "$ROOT_DIR/run.sh" full
