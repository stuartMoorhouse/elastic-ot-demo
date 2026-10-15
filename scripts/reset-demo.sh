#!/usr/bin/env bash
# Reset the demo to a clean state.
#   reset-demo.sh [--keep-data] [--rerun]
# - deletes cases tagged "ot-demo" (falls back to nothing destructive beyond that tag)
# - deletes the demo detection-rule alerts (falls back to closing them)
# - deletes all documents in the three demo data streams (skip with --keep-data)
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

RULE="$CONFIG_DIR/detection/claroty-suppressed-alert.json"
STREAMS=(logs-claroty_ctd.event-default logs-fortinet_fortigate.log-default logs-ot_endpoint.events-default)
ALERTS_INDEX=".alerts-security.alerts-default"

load_env
ensure_api_key

# ---- cases ---------------------------------------------------------------
kb GET "/api/cases/_find?tags=ot-demo&perPage=100" || die "Kibana unreachable"
require_2xx "find demo cases"
ids="$(printf '%s' "$HTTP_BODY" | jq -r '.cases[].id')"
if [[ -n $ids ]]; then
  q=""
  while IFS= read -r id; do q+="ids=$id&"; done <<<"$ids"
  kb DELETE "/api/cases?${q%&}"
  require_2xx "delete demo cases"
  log "deleted $(wc -l <<<"$ids" | tr -d ' ') demo case(s)"
else
  log "no demo cases found"
fi

# ---- alerts --------------------------------------------------------------
rname="$(jq -r '.name' "$RULE")"
aq="$(jq -n --arg n "$rname" '{query:{bool:{filter:[{term:{"kibana.alert.rule.name":$n}}]}}}')"
if es POST "/$ALERTS_INDEX/_delete_by_query?refresh=true&conflicts=proceed" -d "$aq" && is_2xx; then
  log "deleted $(printf '%s' "$HTTP_BODY" | jq -r '.deleted') alert(s) for rule '$rname'"
else
  warn "alert delete not permitted (HTTP $HTTP_CODE); closing alerts instead"
  kb POST /api/detection_engine/signals/status -d "$(jq -n --argjson q "$aq" '{query:$q.query,status:"closed"}')"
  require_2xx "close alerts"
fi

# ---- data ----------------------------------------------------------------
if [[ $KEEP_DATA -eq 0 ]]; then
  for s in "${STREAMS[@]}"; do
    if es POST "/$s/_delete_by_query?refresh=true&conflicts=proceed" -d '{"query":{"match_all":{}}}' && is_2xx; then
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

env_set demo_executed false json
env_set scenario_triggered_at ""
log "reset complete (demo_executed=false)"

if [[ $RERUN -eq 1 ]]; then
  "$(dirname "${BASH_SOURCE[0]}")/run-scenario.sh" scenario
fi
