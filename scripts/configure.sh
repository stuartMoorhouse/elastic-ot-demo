#!/usr/bin/env bash
# Configure the Elastic deployment for the OT demo. Idempotent; safe to re-run.
#   1. wait for Elasticsearch and Kibana
#   2. create ot-assets index (skip if present) and load assets
#   3. create Fleet package policies (only if absent) for "ot-demo-policy"
#   4. import dashboards (overwrite=true)
#   5. create (or delete and recreate) the detection rules (config/detection/*.json) and validate them
#   6. set config_ready=true in shared/env.json
#   7. send the one-shot EWS compromise sequence that fires the correlation rule (best effort, needs SSH to the host)
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

POLICY_NAME="ot-demo-policy"
A_INDEX="$CONFIG_DIR/assets/ot-assets-index.json"
A_BULK="$CONFIG_DIR/assets/ot-assets.ndjson"
FLEET_DIR="$CONFIG_DIR/fleet"
DASH="$CONFIG_DIR/dashboards/ot-dashboards.ndjson"
RULES=("$CONFIG_DIR"/detection/*.json)

for f in "$A_INDEX" "$A_BULK" "$DASH" "${RULES[@]}"; do [[ -s $f ]] || die "missing config file: $f"; done

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
# additive mapping update so new fields (e.g. asset.purdue_level) reach an existing lookup index
es PUT /ot-assets/_mapping -d "$(jq -c '.mappings' "$A_INDEX")"
require_2xx "update ot-assets mapping"
expected=$(( $(grep -c . "$A_BULK") / 2 ))
# bulk index by _id is an upsert, so re-running refreshes asset metadata
es POST "/ot-assets/_bulk?refresh=true" -H 'Content-Type: application/x-ndjson' --data-binary "@$A_BULK"
require_2xx "bulk load assets"
[[ "$(printf '%s' "$HTTP_BODY" | jq -r '.errors')" == false ]] || die "bulk load reported item errors: $(printf '%s' "$HTTP_BODY" | head -c 600)"
log "loaded $expected assets"

# ---- 2b. install the real ServiceNow and Defender for Endpoint packages (no policy: no instance or tenant to pull from)
# Their templates and ingest pipelines parse the API-shaped sample data loaded by load-api-data.sh.
for pkg in servicenow microsoft_defender_endpoint; do
  kb GET "/api/fleet/epm/packages/$pkg?prerelease=true"; require_2xx "look up package $pkg"
  status="$(printf '%s' "$HTTP_BODY" | jq -r '.item.status // .response.status // empty')"
  if [[ $status == installed ]]; then
    log "package $pkg already installed"
  else
    pver="$(printf '%s' "$HTTP_BODY" | jq -r '.item.version // .response.version // empty')"
    [[ -n $pver ]] || die "could not resolve latest version of package $pkg"
    kb POST "/api/fleet/epm/packages/$pkg/$pver" -d '{"force":true}'; require_2xx "install package $pkg"
    log "installed package $pkg $pver"
  fi
done
# remove earlier custom stand-ins that were replaced (ServiceNow, Defender, USB laundry kiosk), if present
kb GET "/api/fleet/package_policies?perPage=200"; require_2xx "list package policies"
legacy="$(printf '%s' "$HTTP_BODY" | jq -c '[.items[] | select(.name=="servicenow-logs-ot-demo" or .name=="defender-logs-ot-demo" or .name=="usb-laundry-logs-ot-demo") | .id]')"
if [[ $legacy != "[]" ]]; then
  kb POST /api/fleet/package_policies/delete -d "{\"packagePolicyIds\":$legacy}"; require_2xx "delete legacy stand-in policies"
  log "removed superseded custom filestream policies (ServiceNow, Defender, USB laundry)"
fi

# ---- 2c. ingest pipelines referenced by custom Fleet policies (Meta Data Kiosk syslog -> ECS) -------
for f in "$CONFIG_DIR"/pipelines/*.json; do
  pname="$(basename "$f" .json)"
  es PUT "/_ingest/pipeline/$pname" --data-binary "@$f"; require_2xx "create ingest pipeline $pname"
  log "ingest pipeline $pname loaded"
done

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

# ---- 5. detection rules ---------------------------------------------------
for RULE in "${RULES[@]}"; do
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
  if [[ $found -eq 1 && -n $rule_id ]]; then
    # Recreate rather than PUT: an in-place update left the rule stuck on "Unable to find matching indices"
    # (searches=0) in this environment, while a freshly created rule runs normally.
    kb DELETE "/api/detection_engine/rules?rule_id=$rule_id"
    require_2xx "delete detection rule for recreation"
    kb POST /api/detection_engine/rules --data-binary "@$RULE"
    require_2xx "recreate detection rule"
    log "recreated detection rule '$rule_name'"
  elif [[ $found -eq 1 ]]; then
    log "detection rule '$rule_name' exists (no rule_id to update by), skipping"
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
done

# ---- 6. done --------------------------------------------------------------
env_set config_ready true json
log "configuration complete (config_ready=true)"

# ---- 7. EWS compromise sequence (fires the VPN -> Defender -> Claroty correlation rule once) ----
# Needs SSH to the host (Claroty and FortiGate lines go through the agent). Not fatal: run it later with
# ./scripts/run-scenario.sh ews-compromise. The agent must already be running its policy, or the lines are lost.
if "$LIB_DIR/run-scenario.sh" ews-compromise; then
  log "EWS compromise sequence sent; the correlation rule alerts on its next run (15m interval)"
else
  warn "EWS compromise sequence not sent; run ./scripts/run-scenario.sh ews-compromise once the host agent is up"
fi
