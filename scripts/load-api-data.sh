#!/usr/bin/env bash
# Load API-shaped sample data into the real integrations' data streams: Claroty CTD asset and baseline, Microsoft
# Defender for Endpoint alerts and ServiceNow incidents. The real integrations pull these from vendor APIs; here the
# generator emits raw API JSON as Elasticsearch bulk lines and each integration's own ingest pipeline parses it.
# Fleet will not let a custom policy write into another package's data stream, hence this script.
#   load-api-data.sh [api-data|ticket-close|ews-defender [BASE_EPOCH]|integration-fill]     (default api-data)
# api-data runs automatically from `run-scenario.sh scenario`; ticket-close from `run-scenario.sh ticket-close`.
# integration-fill loads history for every Defender, ServiceNow, Claroty and FortiGate integration dashboard from
# scripts/fill/*.py. Run it once per deployment (each script anchors on a rounded hour, so a re-run within it adds nothing).
# ews-defender (the Defender alert on KPP-ENG-WS02 in the EWS correlation sequence) runs from `run-scenario.sh ews-compromise`.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
need python3
need jq

MODE="${1:-api-data}"
case "$MODE" in api-data | ticket-close | ews-defender | integration-fill) ;; *) die "unknown mode: $MODE (use api-data, ticket-close, ews-defender or integration-fill)" ;; esac

load_env
ensure_api_key

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if [[ $MODE == integration-fill ]]; then
  for f in "$LIB_DIR"/fill/*.py; do
    python3 "$f" >"$tmp"
    es POST "/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary "@$tmp" || die "Elasticsearch unreachable"
    require_2xx "bulk load $(basename "$f")"
    # 409 version conflicts on a re-run are expected (data streams only accept create); anything else is an error
    bad=$(printf '%s' "$HTTP_BODY" | jq '[.items[]|select(.create.error and .create.status!=409)]|length')
    [[ $bad -eq 0 ]] || die "$(basename "$f"): $bad bulk item errors: $(printf '%s' "$HTTP_BODY" | jq -c '[.items[]|select(.create.error and .create.status!=409)][0]' | head -c 600)"
    log "$(basename "$f"): loaded $(printf '%s' "$HTTP_BODY" | jq '[.items[]|select(.create.status==201)]|length') new documents"
  done
  exit 0
fi
python3 "$LIB_DIR/generator/ot_generator.py" --mode "$MODE" ${2:+--base-time "$2"} >"$tmp" 2>/dev/null
docs=$(( $(grep -c . "$tmp") / 2 ))

es POST "/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary "@$tmp" || die "Elasticsearch unreachable"
require_2xx "bulk load API data"
[[ "$(printf '%s' "$HTTP_BODY" | jq -r '.errors')" == false ]] \
  || die "bulk load reported item errors: $(printf '%s' "$HTTP_BODY" | jq -c '[.items[]|select(.create.error)][0]' | head -c 600)"
log "$MODE: loaded $docs sample documents"
