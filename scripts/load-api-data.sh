#!/usr/bin/env bash
# Load API-shaped sample data into the real integrations' data streams: Claroty CTD asset and baseline, Microsoft
# Defender for Endpoint alerts and ServiceNow incidents. The real integrations pull these from vendor APIs; here the
# generator emits raw API JSON as Elasticsearch bulk lines and each integration's own ingest pipeline parses it.
# Fleet will not let a custom policy write into another package's data stream, hence this script.
#   load-api-data.sh [api-data|ticket-close]     (default api-data)
# api-data runs automatically from `run-scenario.sh scenario`; ticket-close from `run-scenario.sh ticket-close`.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
need python3
need jq

MODE="${1:-api-data}"
case "$MODE" in api-data | ticket-close) ;; *) die "unknown mode: $MODE (use api-data or ticket-close)" ;; esac

load_env
ensure_api_key

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
python3 "$LIB_DIR/generator/ot_generator.py" --mode "$MODE" >"$tmp" 2>/dev/null
docs=$(( $(grep -c . "$tmp") / 2 ))

es POST "/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary "@$tmp" || die "Elasticsearch unreachable"
require_2xx "bulk load API data"
[[ "$(printf '%s' "$HTTP_BODY" | jq -r '.errors')" == false ]] \
  || die "bulk load reported item errors: $(printf '%s' "$HTTP_BODY" | jq -c '[.items[]|select(.create.error)][0]' | head -c 600)"
log "$MODE: loaded $docs sample documents"
