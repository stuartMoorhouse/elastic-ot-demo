#!/usr/bin/env bash
# Reset the demo to a clean state.
#   reset-demo.sh [--keep-data] [--rerun]
# - deletes cases tagged "ot-demo" (falls back to nothing destructive beyond that tag)
# - deletes the demo detection-rule alerts (falls back to closing them)
# - deletes all documents in the ten demo data streams, keeping the streams (skip with --keep-data)
# - refills all dashboards (24h backfill, API-shaped data, 14 days of integration history), then sends exactly five alerts:
#   3 benign Claroty alert types, the unmanaged-host threat and the one-shot EWS compromise sequence so the VPN/Defender/Claroty correlation rule fires once (skip with --keep-data)
# - sets demo_executed=false; with --rerun triggers the scenario again afterwards
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

KEEP_DATA=0
RERUN=0
for a in "$@"; do
  case "$a" in
    --keep-data) KEEP_DATA=1 ;;
    --rerun) RERUN=1 ;;
    *) die "unknown flag: $a (use --keep-data, --rerun)" ;;
  esac
done

RULES=("$CONFIG_DIR"/detection/*.json)
STREAMS=(logs-claroty_ctd.event-default logs-fortinet_fortigate.log-default logs-ot_endpoint.events-default logs-meta_data_kiosk.log-default logs-microsoft_defender_endpoint.log-default logs-servicenow.event-default logs-plc4x.telemetry-default logs-opcua.telemetry-default logs-claroty_ctd.asset-default logs-claroty_ctd.baseline-default)
ALERTS_INDEX=".alerts-security.alerts-default"

load_env
ensure_api_key

# ---- cases ---------------------------------------------------------------
kb GET "/api/cases/_find?tags=ot-demo&perPage=100" || die "Kibana unreachable"
require_2xx "find demo cases"
ids="$(printf '%s' "$HTTP_BODY" | jq -r '.cases[].id')"
if [[ -n $ids ]]; then
  # Cases API takes ids as a JSON array in the query string
  q="$(printf '%s\n' "$ids" | jq -Rsc 'split("\n") | map(select(length>0))' | jq -sRr '@uri')"
  kb DELETE "/api/cases?ids=$q"
  require_2xx "delete demo cases"
  log "deleted $(wc -l <<<"$ids" | tr -d ' ') demo case(s)"
else
  log "no demo cases found"
fi

# ---- alerts --------------------------------------------------------------
# Match on rule_id: the Claroty rule overrides the alert's rule name with the Claroty alert name.
names="$(jq -s -c '[.[].rule_id]' "${RULES[@]}")"
aq="$(jq -n --argjson n "$names" '{query:{bool:{filter:[{terms:{"kibana.alert.rule.rule_id":$n}}]}}}')"
if es POST "/$ALERTS_INDEX/_delete_by_query?refresh=true&conflicts=proceed" -d "$aq" && is_2xx; then
  log "deleted $(printf '%s' "$HTTP_BODY" | jq -r '.deleted') alert(s) for the demo rules"
else
  warn "alert delete not permitted (HTTP $HTTP_CODE); closing alerts instead"
  kb POST /api/detection_engine/signals/status -d "$(jq -n --argjson q "$aq" '{query:$q.query,status:"closed"}')"
  require_2xx "close alerts"
fi

# ---- data ----------------------------------------------------------------
if [[ $KEEP_DATA -eq 0 ]]; then
  for s in "${STREAMS[@]}"; do
    # Delete documents, not the data stream: a rule that runs while its stream is missing gets stuck on
    # "no matching indices". No refresh=true: that needs indices:admin/refresh, which the scoped key lacks.
    if es POST "/$s/_delete_by_query?conflicts=proceed" -d '{"query":{"match_all":{}}}' && is_2xx; then
      log "$s: deleted $(printf '%s' "$HTTP_BODY" | jq -r '.deleted') doc(s)"
    elif [[ $HTTP_CODE == 404 ]]; then
      log "$s: not present, skipping"
    else
      die "delete from $s failed: HTTP $HTTP_CODE $(printf '%s' "$HTTP_BODY" | head -c 400)"
    fi
  done
else
  log "--keep-data: leaving data streams untouched"
fi

if [[ $KEEP_DATA -eq 0 ]]; then
  # Refill every dashboard, then send exactly five alerts: 3 benign Claroty alert types, the unmanaged-host threat
  # and the EWS correlation alert. Noise stays off so nothing else reaches the alert rules.
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  "$HERE/run-scenario.sh" noise off || warn "could not stop noise generator"
  # 24h of background traffic, telemetry and Claroty history for the OT dashboards. It stops 10 minutes short of
  # now, so its background alerts (older than the rules' 5 minute lookback) cannot join the live alert groups.
  "$HERE/run-scenario.sh" backfill 24 10 || warn "backfill not sent"
  # Claroty assets and baselines, Defender alerts and ServiceNow incidents.
  "$HERE/load-api-data.sh" api-data || warn "API data not loaded"
  # 14 days of history for the Claroty, FortiGate, Defender and ServiceNow integration dashboards.
  "$HERE/load-api-data.sh" integration-fill || warn "integration history not loaded"
  "$HERE/run-scenario.sh" showcase || warn "showcase not sent"
  "$HERE/run-scenario.sh" threat || warn "threat not sent"
  "$HERE/run-scenario.sh" ews-compromise || warn "EWS compromise sequence not sent"
fi

env_set demo_executed false json
env_set scenario_triggered_at ""
log "reset complete (demo_executed=false)"

if [[ $RERUN -eq 1 ]]; then
  "$(dirname "${BASH_SOURCE[0]}")/run-scenario.sh" scenario
fi
