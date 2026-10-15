#!/usr/bin/env bash
# Configure the Elastic deployment for the OT demo. Idempotent; safe to re-run.
#   1. wait for Elasticsearch and Kibana
#   2. create ot-assets index (skip if present) and load assets
#   3. create Fleet package policies (only if absent) for "ot-demo-policy"
#   4. import dashboards (overwrite=true)
#   5. create the detection rule (only if absent) and validate it
#   6. set config_ready=true in shared/env.json
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

POLICY_NAME="ot-demo-policy"
A_INDEX="$CONFIG_DIR/assets/ot-assets-index.json"
A_BULK="$CONFIG_DIR/assets/ot-assets.ndjson"
FLEET_DIR="$CONFIG_DIR/fleet"
DASH="$CONFIG_DIR/dashboards/ot-dashboards.ndjson"
RULE="$CONFIG_DIR/detection/claroty-suppressed-alert.json"

for f in "$A_INDEX" "$A_BULK" "$DASH" "$RULE"; do [[ -s $f ]] || die "missing config file: $f"; done

load_env
wait_for "Elasticsearch" "$ES_URL" "/" 900
ensure_api_key
wait_for "Kibana" "$KB_URL" "/api/status" 900 '.status.overall.level == "available"'

# ---- 2. asset index -------------------------------------------------------
es GET /ot-assets/_settings || die "Elasticsearch unreachable"
if [[ $HTTP_CODE == 200 ]]; then
  log "ot-assets exists, skipping creation"
else
  es PUT /ot-assets --data-binary "@$A_INDEX" || die "Elasticsearch unreachable"
  require_2xx "create ot-assets"
  log "created ot-assets"
fi
expected=$(( $(grep -c . "$A_BULK") / 2 ))
es GET /ot-assets/_count; require_2xx "count ot-assets"
have="$(printf '%s' "$HTTP_BODY" | jq -r '.count')"
if [[ $have -eq $expected ]]; then
  log "ot-assets already has $have documents, skipping bulk load"
else
  if [[ $have -gt 0 ]]; then
    log "ot-assets has $have docs, expected $expected; clearing and reloading"
    es POST "/ot-assets/_delete_by_query?refresh=true&conflicts=proceed" -d '{"query":{"match_all":{}}}'
    require_2xx "clear ot-assets"
  fi
  es POST "/_bulk?refresh=true" -H 'Content-Type: application/x-ndjson' --data-binary "@$A_BULK"
  require_2xx "bulk load assets"
  [[ "$(printf '%s' "$HTTP_BODY" | jq -r '.errors')" == false ]] || die "bulk load reported item errors: $(printf '%s' "$HTTP_BODY" | head -c 600)"
  log "loaded $expected assets"
fi

# ---- 3. Fleet package policies -------------------------------------------
kb GET "/api/fleet/agent_policies?perPage=100" || die "Kibana unreachable"
require_2xx "list agent policies"
policy_id="$(printf '%s' "$HTTP_BODY" | jq -r --arg n "$POLICY_NAME" '[.items[] | select(.name==$n)][0].id // empty')"
[[ -n $policy_id ]] || die "agent policy '$POLICY_NAME' not found in Fleet (expected to be created by infra/)"
log "agent policy $POLICY_NAME = $policy_id"

kb GET "/api/fleet/package_policies?perPage=200"; require_2xx "list package policies"
existing_names="$(printf '%s' "$HTTP_BODY" | jq -r '.items[].name')"

shopt -s nullglob
for f in "$FLEET_DIR"/*.json; do
  pname="$(jq -r '.name' "$f")"
  if grep -qxF "$pname" <<<"$existing_names"; then
    log "package policy '$pname' exists, skipping"
    continue
  fi
  pkg="$(jq -r '.package.name' "$f")"
  kb GET "/api/fleet/epm/packages/$pkg?prerelease=true"; require_2xx "look up package $pkg"
  ver="$(printf '%s' "$HTTP_BODY" | jq -r '.item.version // .response.version // empty')"
  [[ -n $ver ]] || die "could not resolve latest version of package $pkg"
  log "creating package policy '$pname' ($pkg $ver)"
  body="$(sed -e "s/__POLICY_ID__/$policy_id/g" -e "s/__PACKAGE_VERSION__/$ver/g" "$f")"
  printf '%s' "$body" | jq -e . >/dev/null || die "$f is not valid JSON after substitution"
  kb POST /api/fleet/package_policies -d "$body"
  require_2xx "create package policy $pname"
done

# ---- 4. dashboards --------------------------------------------------------
kb POST "/api/saved_objects/_import?overwrite=true" -F "file=@$DASH"
require_2xx "import dashboards"
[[ "$(printf '%s' "$HTTP_BODY" | jq -r '.success')" == true ]] || die "dashboard import not successful: $(printf '%s' "$HTTP_BODY" | head -c 800)"
log "imported $(printf '%s' "$HTTP_BODY" | jq -r '.successCount') saved objects"

# ---- 5. detection rule ----------------------------------------------------
rule_id="$(jq -r '.rule_id // empty' "$RULE")"
rule_name="$(jq -r '.name' "$RULE")"
found=0
if [[ -n $rule_id ]]; then
  kb GET "/api/detection_engine/rules?rule_id=$rule_id"
  [[ $HTTP_CODE == 200 ]] && found=1
else
  kb GET "/api/detection_engine/rules/_find?per_page=200"; require_2xx "list rules"
  printf '%s' "$HTTP_BODY" | jq -e --arg n "$rule_name" '.data[] | select(.name==$n)' >/dev/null 2>&1 && found=1
fi
if [[ $found -eq 1 ]]; then
  log "detection rule '$rule_name' exists, skipping creation"
else
  kb POST /api/detection_engine/rules --data-binary "@$RULE"
  require_2xx "create detection rule"
  log "created detection rule '$rule_name'"
fi
# validate: rule must exist, be enabled and carry alert suppression
if [[ -n $rule_id ]]; then
  kb GET "/api/detection_engine/rules?rule_id=$rule_id"; require_2xx "fetch detection rule"
  printf '%s' "$HTTP_BODY" | jq -e '.alert_suppression.group_by | length > 0' >/dev/null \
    || die "rule has no alert_suppression.group_by"
  [[ "$(printf '%s' "$HTTP_BODY" | jq -r '.enabled')" == true ]] || warn "rule is not enabled"
  log "rule validated (suppression group_by: $(printf '%s' "$HTTP_BODY" | jq -c '.alert_suppression.group_by'))"
fi

# ---- 6. done --------------------------------------------------------------
env_set config_ready true json
log "configuration complete (config_ready=true)"
