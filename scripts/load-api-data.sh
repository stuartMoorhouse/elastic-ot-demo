#!/usr/bin/env bash
# Load API-shaped sample data into the real integrations' data streams: Claroty CTD asset and baseline, Microsoft
# Defender for Endpoint alerts and ServiceNow incidents. The real integrations pull these from vendor APIs; here the
# generator emits raw API JSON as Elasticsearch bulk lines and each integration's own ingest pipeline parses it.
# Fleet will not let a custom policy write into another package's data stream, hence this script.
#   load-api-data.sh [api-data|ticket-close|ews-defender [BASE_EPOCH]]     (default api-data)
# api-data runs automatically from `run-scenario.sh scenario`; ticket-close from `run-scenario.sh ticket-close`.
# ews-defender (the Defender alert on KPP-ENG-WS02 in the EWS correlation sequence) runs from `run-scenario.sh ews-compromise`.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
need python3
need jq

MODE="${1:-api-data}"
case "$MODE" in api-data | ticket-close | ews-defender) ;; *) die "unknown mode: $MODE (use api-data, ticket-close or ews-defender)" ;; esac

load_env
ensure_api_key

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
python3 "$LIB_DIR/generator/ot_generator.py" --mode "$MODE" ${2:+--base-time "$2"} >"$tmp" 2>/dev/null
docs=$(( $(grep -c . "$tmp") / 2 ))

es POST "/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary "@$tmp" || die "Elasticsearch unreachable"
require_2xx "bulk load API data"
[[ "$(printf '%s' "$HTTP_BODY" | jq -r '.errors')" == false ]] \
  || die "bulk load reported item errors: $(printf '%s' "$HTTP_BODY" | jq -c '[.items[]|select(.create.error)][0]' | head -c 600)"
log "$MODE: loaded $docs sample documents"
