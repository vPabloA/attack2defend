#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_DIR="$ROOT_DIR/app/navigator-ui"
DATA_DIRS=("$ROOT_DIR/data/intelligence" "$ROOT_DIR/data/candidates")
_TMPFILE="$(mktemp /tmp/a2d_static_first_hits.XXXXXX)"
trap 'rm -f "$_TMPFILE"' EXIT

fail=0

check_absent() {
  local label="$1"
  local pattern="$2"
  local path="$3"
  local include="${4:-}"   # optional: e.g. "*.json" to restrict file types
  local grep_args=(-RInE)
  [ -n "$include" ] && grep_args+=(--include="$include")
  if [ -e "$path" ] && grep "${grep_args[@]}" "$pattern" "$path" >"$_TMPFILE" 2>/dev/null; then
    echo "[FAIL] $label found in $path"
    cat "$_TMPFILE"
    fail=1
  else
    echo "[OK] $label absent in $path"
  fi
}

if [ -d "$UI_DIR" ]; then
  check_absent "OpenAI runtime endpoint" "api\.openai\.com" "$UI_DIR"
  check_absent "Anthropic runtime endpoint" "anthropic\.com" "$UI_DIR"
  check_absent "Gemini runtime endpoint" "generativelanguage\.googleapis\.com" "$UI_DIR"
  check_absent "NVD runtime endpoint" "services\.nist\.gov|nvd\.nist\.gov/.*/api" "$UI_DIR"
  check_absent "CISA runtime endpoint" "cisa\.gov/.*/api" "$UI_DIR"
  check_absent "Neo4j runtime dependency" "\bneo4j\b" "$UI_DIR"
  check_absent "MCP runtime dependency" "from ['\"]@modelcontextprotocol|require\(['\"]@modelcontextprotocol|import .*\bmcp\b" "$UI_DIR"
  check_absent "OpenAI SDK import" "from ['\"]openai|import .*openai|require\(['\"]openai" "$UI_DIR"
  check_absent "Anthropic SDK import" "from ['\"]@anthropic|import .*anthropic|require\(['\"]@anthropic" "$UI_DIR"
  check_absent "Google generative AI SDK import" "@google/generative-ai|google-generativeai" "$UI_DIR"
  check_absent "LangChain browser import" "langchain|@langchain" "$UI_DIR"
else
  echo "[WARN] UI directory not found: $UI_DIR"
fi

for dir in "${DATA_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    # Restrict to *.json only — config/YAML files may legitimately reference key names in comments
    check_absent "API key name leakage" "OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY" "$dir" "*.json"
    check_absent "Bearer token leakage" "Bearer[[:space:]]+[A-Za-z0-9._-]{12,}" "$dir" "*.json"
    check_absent "OpenAI-style secret leakage" "sk-[A-Za-z0-9]{10,}" "$dir" "*.json"
  else
    echo "[OK] optional data directory absent: $dir"
  fi
done

exit "$fail"
