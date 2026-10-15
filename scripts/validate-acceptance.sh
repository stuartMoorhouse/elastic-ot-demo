#!/usr/bin/env bash
# Check acceptance criteria 1-7 and 9-12 via API and write results/acceptance-<timestamp>.json.
#   1 Fleet agent healthy (online)
#   2 docs in last 5 min per data stream, event.dataset set, no error.message
#   3 unified dashboard exists and data for the PLC (FortiGate rule hits, network events) is present
#   4 ES|QL LOOKUP JOIN against ot-assets for the PLC IP returns owner/zone/criticality/known_good=true
#   5 suppression: <=5 alerts for >=1000 raw Claroty events
#   6 case created from the alert and closed (false positive) via API within 180s
#   7 <=4 demo (non-managed) dashboards
#  10 USB laundry provenance: a clean scan and release of a file to KPP-ENG-WS01 exists (run the scenario first)
#  11 sample Defender alert for KPP-ENG-WS01 and ServiceNow incident updates exist (run the scenario first)
#  12 PLC telemetry (PLC4X S7 and OPC UA, sample data) is flowing; after `run-scenario.sh threat` the turbine speed
#     shows the setpoint excursion (>= 3100 rpm) that the unmanaged source caused
#   9 contrast: after `run-scenario.sh threat`, alerts from the unmanaged source (not in ot-assets) break out
#     as their own alert(s) instead of folding into the known-good group
#   8 terraform destroy: MANUAL (run `terraform -chdir=infra destroy` and confirm the GuardDuty
#     VPC cleanup provisioner completes); not checked here.
# Criterion 6 consumes the current grouped alert by creating a case; run reset-demo.sh afterwards.
# Env: PLC_IP (default 10.20.4.12), WINDOW (raw-event window for criterion 5, default 60m).
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PLC_IP="${PLC_IP:-10.20.4.12}"
WINDOW="${WINDOW:-60m}"
RULE="$CONFIG_DIR/detection/claroty-suppressed-alert.json"
STREAMS=(logs-claroty_ctd.event-default logs-fortinet_fortigate.log-default logs-ot_endpoint.events-default logs-usb_laundry.events-default logs-plc4x.telemetry-default logs-opcua.telemetry-default)
ALERTS_INDEX=".alerts-security.alerts-default"

load_env
ensure_api_key
mkdir -p "$RESULTS_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULTS_DIR/acceptance-$TS.json"
RES="$(mktemp)"
printf '[]' >"$RES"
FAILS=0

record() { # id name PASS|FAIL detail
  local tmp
  tmp="$(mktemp)"
  jq --arg id "$1" --arg n "$2" --arg s "$3" --arg d "$4" '. + [{criterion:($id|tonumber),name:$n,status:$s,detail:$d}]' "$RES" >"$tmp" && mv "$tmp" "$RES"
  printf '%-4s criterion %s: %s - %s\n' "$3" "$1" "$2" "$4"
  [[ $3 == PASS ]] || FAILS=$((FAILS + 1))
}

count() { # index json_query -> count or "ERR"
  if es POST "/$1/_count" -d "$2" && is_2xx; then printf '%s' "$HTTP_BODY" | jq -r '.count'; else printf 'ERR'; fi
}

# ---- 1 Fleet --------------------------------------------------------------
c1() {
  kb GET "/api/fleet/agents?perPage=100" || { record 1 "Fleet agent healthy" FAIL "Kibana unreachable"; return; }
  is_2xx || { record 1 "Fleet agent healthy" FAIL "HTTP $HTTP_CODE"; return; }
  local on total
  on="$(printf '%s' "$HTTP_BODY" | jq '[.items[] | select(.status=="online")] | length')"
  total="$(printf '%s' "$HTTP_BODY" | jq '.items | length')"
  if [[ $on -ge 1 ]]; then record 1 "Fleet agent healthy" PASS "$on of $total agents online"
  else record 1 "Fleet agent healthy" FAIL "$on of $total agents online"; fi
}

# ---- 2 data streams -------------------------------------------------------
c2() {
  local s q n bad detail="" ok=1
  q='{"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-5m"}}},{"exists":{"field":"event.dataset"}}]}}}'
  for s in "${STREAMS[@]}"; do
    n="$(count "$s" "$q")"
    bad="$(count "$s" '{"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-5m"}}},{"exists":{"field":"error.message"}}]}}}')"
    detail+="$s docs=$n errors=$bad; "
    if [[ $n == ERR || $bad == ERR || $n -lt 1 || $bad -ne 0 ]]; then ok=0; fi
  done
  if [[ $ok -eq 1 ]]; then record 2 "Data streams fresh and parsed" PASS "$detail"; else record 2 "Data streams fresh and parsed" FAIL "$detail"; fi
}

# ---- 3 / 7 dashboards -----------------------------------------------------
DASH_COUNT=""
dashboards() {
  kb GET "/api/saved_objects/_find?type=dashboard&per_page=100&fields=title" || return 1
  is_2xx || return 1
  DASH_COUNT="$(printf '%s' "$HTTP_BODY" | jq '[.saved_objects[] | select(.managed != true)] | length')"
  DASH_TITLES="$(printf '%s' "$HTTP_BODY" | jq -r '[.saved_objects[] | select(.managed != true) | .attributes.title] | join(", ")')"
}

c3() {
  local fg ep ru
  if ! dashboards; then record 3 "Unified OT dashboard" FAIL "cannot list dashboards (HTTP $HTTP_CODE)"; return; fi
  fg="$(count logs-fortinet_fortigate.log-default "{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"destination.ip\":\"$PLC_IP\"}},{\"exists\":{\"field\":\"rule.name\"}}]}}}")"
  ep="$(count logs-ot_endpoint.events-default "{\"query\":{\"term\":{\"labels.asset_name\":\"KPP-ENG-WS01\"}}}")"
  ru="$(count logs-fortinet_fortigate.log-default "{\"query\":{\"term\":{\"rule.name\":\"ENG-to-PLC-S7\"}}}")"
  if [[ ${DASH_COUNT:-0} -ge 1 && $fg != ERR && $ep != ERR && $fg -ge 1 && $ep -ge 1 ]]; then
    record 3 "Unified OT dashboard" PASS "dashboards=[$DASH_TITLES]; PLC firewall docs=$fg (ENG-to-PLC-S7 hits=$ru), endpoint docs=$ep"
  else
    record 3 "Unified OT dashboard" FAIL "dashboards=${DASH_COUNT:-0}; PLC firewall docs=$fg, endpoint docs=$ep"
  fi
}

c7() {
  if ! dashboards; then record 7 "Dashboards <= 4" FAIL "cannot list dashboards"; return; fi
  if [[ $DASH_COUNT -le 4 && $DASH_COUNT -ge 1 ]]; then record 7 "Dashboards <= 4" PASS "$DASH_COUNT demo dashboards (managed integration dashboards excluded)"
  else record 7 "Dashboards <= 4" FAIL "$DASH_COUNT demo dashboards"; fi
}

# ---- 4 asset lookup -------------------------------------------------------
c4() {
  local q body row
  q="FROM logs-fortinet_fortigate.log-default | WHERE destination.ip == \"$PLC_IP\" | LIMIT 1 | EVAL asset.ip = destination.ip | LOOKUP JOIN ot-assets ON asset.ip | KEEP asset.ip, asset.owner, network.zone, asset.criticality, asset.known_good"
  body="$(jq -n --arg q "$q" '{query:$q}')"
  if ! es POST "/_query?format=json" -d "$body" || ! is_2xx; then
    record 4 "Asset lookup (LOOKUP JOIN)" FAIL "ES|QL failed: HTTP $HTTP_CODE $(printf '%s' "$HTTP_BODY" | head -c 400)"; return
  fi
  row="$(printf '%s' "$HTTP_BODY" | jq -c '[.columns[].name] as $c | (.values[0] // []) as $v | reduce range(0; $c|length) as $i ({}; .[$c[$i]] = $v[$i])')"
  if printf '%s' "$row" | jq -e '.["asset.owner"] != null and .["network.zone"] != null and .["asset.criticality"] != null and (.["asset.known_good"] == true or .["asset.known_good"] == "true")' >/dev/null; then
    record 4 "Asset lookup (LOOKUP JOIN)" PASS "$row"
  else
    record 4 "Asset lookup (LOOKUP JOIN)" FAIL "unexpected result: $row"
  fi
}

# ---- 5 suppression --------------------------------------------------------
c5() {
  local rname raw alerts docs
  rname="$(jq -r '.name' "$RULE")"
  raw="$(count logs-claroty_ctd.event-default "{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"event.kind\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"now-$WINDOW\"}}}]}}}")"
  if ! es POST "/$ALERTS_INDEX/_search" -d "$(jq -n --arg n "$rname" '{size:0,query:{bool:{filter:[{term:{"kibana.alert.rule.name":$n}}]}},aggs:{docs:{sum:{field:"kibana.alert.suppression.docs_count"}}}}')" || ! is_2xx; then
    record 5 "Alert suppression" FAIL "alert search failed: HTTP $HTTP_CODE"; return
  fi
  alerts="$(printf '%s' "$HTTP_BODY" | jq -r '.hits.total.value')"
  docs="$(printf '%s' "$HTTP_BODY" | jq -r '.aggregations.docs.value // 0')"
  if [[ $raw != ERR && $raw -ge 1000 && $alerts -ge 1 && $alerts -le 5 ]]; then
    record 5 "Alert suppression" PASS "raw Claroty events (last $WINDOW)=$raw, alerts=$alerts, suppressed docs_count sum=$docs"
  else
    record 5 "Alert suppression" FAIL "raw Claroty events (last $WINDOW)=$raw, alerts=$alerts, suppressed docs_count sum=$docs (need raw>=1000 and 1<=alerts<=5)"
  fi
}

# ---- 6 case ---------------------------------------------------------------
c6() {
  local t0 rname trig alert_id alert_index case_id ver rule_id elapsed since="n/a" tmpl body
  t0="$(now_epoch)"
  trig="$(env_get scenario_triggered_at)"
  rname="$(jq -r '.name' "$RULE")"
  es POST "/$ALERTS_INDEX/_search" -d "$(jq -n --arg n "$rname" '{size:1,sort:[{"@timestamp":"desc"}],query:{bool:{filter:[{term:{"kibana.alert.rule.name":$n}}]}},_source:["kibana.alert.rule.uuid"]}')" || true
  alert_id="$(printf '%s' "$HTTP_BODY" | jq -r '.hits.hits[0]._id // empty')"
  alert_index="$(printf '%s' "$HTTP_BODY" | jq -r '.hits.hits[0]._index // empty')"
  rule_id="$(printf '%s' "$HTTP_BODY" | jq -r '.hits.hits[0]._source["kibana.alert.rule.uuid"] // .hits.hits[0]._source.kibana.alert.rule.uuid // empty')"
  [[ -n $alert_id ]] || { record 6 "Case from alert, closed FP" FAIL "no alert found for rule '$rname'"; return; }

  body="$(jq -n --arg d "Validation: Claroty S7 alerts from KPP-ENG-WS01 to KPP-PLC-T2" '{title:"KPP-PLC-T2 S7 alerts (validation)",description:$d,tags:["ot-demo","validation"],owner:"securitySolution",severity:"low",settings:{syncAlerts:false},connector:{id:"none",name:"none",type:".none",fields:null}}')"
  tmpl="$CONFIG_DIR/cases/case-template.json"
  if [[ -s $tmpl ]]; then
    body="$(jq -s '.[0] * .[1] | .tags = ((.tags // []) + ["ot-demo","validation"] | unique)' "$tmpl" <(printf '%s' "$body") 2>/dev/null || printf '%s' "$body")"
  fi
  kb POST /api/cases -d "$body" || true
  is_2xx || { record 6 "Case from alert, closed FP" FAIL "create case: HTTP $HTTP_CODE $(printf '%s' "$HTTP_BODY" | head -c 400)"; return; }
  case_id="$(printf '%s' "$HTTP_BODY" | jq -r '.id')"
  ver="$(printf '%s' "$HTTP_BODY" | jq -r '.version')"

  kb POST "/api/cases/$case_id/comments" -d "$(jq -n --arg a "$alert_id" --arg i "$alert_index" --arg r "$rule_id" --arg n "$rname" '{type:"alert",alertId:[$a],index:[$i],rule:{id:$r,name:$n},owner:"securitySolution"}')" || true
  is_2xx || { record 6 "Case from alert, closed FP" FAIL "attach alert: HTTP $HTTP_CODE $(printf '%s' "$HTTP_BODY" | head -c 400)"; return; }
  kb POST "/api/cases/$case_id/comments" -d '{"type":"user","comment":"False positive: KPP-ENG-WS01 is a known-good engineering workstation during the scheduled maintenance window (authorised logon and TIA Portal process observed). Closed by validation.","owner":"securitySolution"}' || true
  is_2xx || { record 6 "Case from alert, closed FP" FAIL "add note: HTTP $HTTP_CODE"; return; }
  # re-read version after comments
  kb GET "/api/cases/$case_id" || true; is_2xx && ver="$(printf '%s' "$HTTP_BODY" | jq -r '.version')"
  kb PATCH /api/cases -d "$(jq -n --arg id "$case_id" --arg v "$ver" '{cases:[{id:$id,version:$v,status:"closed",tags:["ot-demo","validation","false-positive"]}]}')" || true
  is_2xx || { record 6 "Case from alert, closed FP" FAIL "close case: HTTP $HTTP_CODE $(printf '%s' "$HTTP_BODY" | head -c 400)"; return; }
  [[ "$(printf '%s' "$HTTP_BODY" | jq -r '.[0].status')" == closed ]] || { record 6 "Case from alert, closed FP" FAIL "case not closed"; return; }

  elapsed=$(( $(now_epoch) - t0 ))
  [[ -n $trig ]] && since=$(( $(now_epoch) - trig ))
  if [[ $elapsed -le 180 ]]; then
    record 6 "Case from alert, closed FP" PASS "case $case_id created, alert attached, closed in ${elapsed}s via API (seconds since scenario trigger: $since)"
  else
    record 6 "Case from alert, closed FP" FAIL "took ${elapsed}s (>180s)"
  fi
}

# ---- 9 contrast scenario ---------------------------------------------------
c9() {
  local unk="${UNKNOWN_IP:-10.20.9.77}" rname n inv
  rname="$(jq -r '.name' "$RULE")"
  es POST "/$ALERTS_INDEX/_search" -d "$(jq -n --arg n "$rname" --arg ip "$unk" '{size:0,track_total_hits:true,query:{bool:{filter:[{term:{"kibana.alert.rule.name":$n}},{term:{"source.ip":$ip}}]}}}')" || true
  is_2xx || { record 9 "Contrast: unmanaged source breaks out" FAIL "alert search failed: HTTP $HTTP_CODE"; return; }
  n="$(printf '%s' "$HTTP_BODY" | jq -r '.hits.total.value')"
  es POST "/ot-assets/_count" -d "$(jq -n --arg ip "$unk" '{query:{term:{"asset.ip":$ip}}}')" || true
  is_2xx || { record 9 "Contrast: unmanaged source breaks out" FAIL "inventory lookup failed: HTTP $HTTP_CODE"; return; }
  inv="$(printf '%s' "$HTTP_BODY" | jq -r '.count')"
  if [[ $n -ge 1 && $inv -eq 0 ]]; then
    record 9 "Contrast: unmanaged source breaks out" PASS "$n separate alert(s) from $unk, which has $inv inventory records"
  else
    record 9 "Contrast: unmanaged source breaks out" FAIL "alerts from $unk=$n (need >=1), inventory records=$inv (need 0); run: ./scripts/run-scenario.sh threat and wait for the rule"
  fi
}

# ---- 10 USB laundry provenance --------------------------------------------
c10() {
  local n
  n="$(count logs-usb_laundry.events-default '{"query":{"bool":{"filter":[{"term":{"event.action":"file_released"}},{"term":{"usb_laundry.released_to":"KPP-ENG-WS01"}},{"term":{"usb_laundry.scan_verdict":"clean"}}]}}}')"
  if [[ ${n:-0} -ge 1 ]]; then
    record 10 "USB laundry provenance" PASS "$n clean file release(s) to KPP-ENG-WS01 in logs-usb_laundry.events-default"
  else
    record 10 "USB laundry provenance" FAIL "no clean file_released event to KPP-ENG-WS01 (run ./scripts/run-scenario.sh scenario)"
  fi
}

# ---- 11 sample Defender and ServiceNow data ---------------------------------
c11() {
  local d n
  d="$(count logs-microsoft_defender_endpoint.log-default '{"query":{"term":{"labels.asset_name":"KPP-ENG-WS01"}}}')"
  n="$(count logs-servicenow.event-default '{"query":{"term":{"servicenow.event.number.value":"INC0010231"}}}')"
  if [[ ${d:-0} -ge 1 && ${n:-0} -ge 1 ]]; then
    record 11 "Sample Defender and ServiceNow data" PASS "$d Defender alert(s) for KPP-ENG-WS01, $n ServiceNow update(s) for INC0010231 (sample data, integrations not configured)"
  else
    record 11 "Sample Defender and ServiceNow data" FAIL "Defender alerts=$d, ServiceNow updates=$n (run ./scripts/run-scenario.sh scenario)"
  fi
}

# ---- 12 PLC telemetry and process impact --------------------------------------
c12() {
  local p o hi
  p="$(count logs-plc4x.telemetry-default '{"query":{"range":{"@timestamp":{"gte":"now-30m"}}}}')"
  o="$(count logs-opcua.telemetry-default '{"query":{"range":{"@timestamp":{"gte":"now-30m"}}}}')"
  hi="$(count logs-plc4x.telemetry-default '{"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-30m"}}},{"range":{"plc4x.tags.turbine_speed_rpm":{"gte":3100}}}]}}}')"
  if [[ ${p:-0} -ge 1 && ${o:-0} -ge 1 && ${hi:-0} -ge 1 ]]; then
    record 12 "PLC telemetry and process impact" PASS "PLC4X docs=$p, OPC UA docs=$o (30m); $hi turbine speed reading(s) >= 3100 rpm after the unmanaged-source setpoint change (sample data)"
  else
    record 12 "PLC telemetry and process impact" FAIL "PLC4X=$p, OPC UA=$o, speed excursion readings=$hi; run noise on, then ./scripts/run-scenario.sh threat and wait 1-2 minutes"
  fi
}

c1; c2; c3; c4; c5; c6; c7; c9; c10; c11; c12

jq -n --arg ts "$TS" --arg crit8 "manual: run terraform -chdir=infra destroy and confirm GuardDuty VPC cleanup" \
  --slurpfile r "$RES" '{timestamp:$ts,results:$r[0],criterion_8:$crit8}' >"$OUT"
rm -f "$RES"
echo "Results written to $OUT"
if [[ $FAILS -eq 0 ]]; then echo "ALL CHECKED CRITERIA PASSED (criterion 8 is manual)"; else echo "$FAILS criteria FAILED"; exit 1; fi
