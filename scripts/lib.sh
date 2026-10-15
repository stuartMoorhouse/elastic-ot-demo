#!/usr/bin/env bash
# Shared helpers for the OT demo scripts. Source this file; do not execute it.
# Reads endpoints from shared/env.json, falling back to `terraform -chdir=infra output -json`.
# Secrets are never printed and never passed on curl argv (auth goes via a -K config stream).

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$LIB_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/shared/env.json}"
CONFIG_DIR="${CONFIG_DIR:-$ROOT_DIR/config}"
INFRA_DIR="${INFRA_DIR:-$ROOT_DIR/infra}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/results}"

ES_URL=""
KB_URL=""
API_KEY=""
AUTH_MODE="key"      # key | basic
TF_JSON=""
HTTP_CODE=""
HTTP_BODY=""
_BODY_FILE="$(mktemp)"
trap 'rm -f "$_BODY_FILE"' EXIT

log()  { printf '[%s] %s\n' "$(basename "$0")" "$*" >&2; }
warn() { printf '[%s] WARN: %s\n' "$(basename "$0")" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(basename "$0")" "$*" >&2; exit 1; }

need() {
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"; done
}

# ---- env.json -------------------------------------------------------------

env_init() {
  mkdir -p "$(dirname "$ENV_FILE")"
  if [[ ! -s $ENV_FILE ]]; then
    printf '{"elasticsearch_url":"","kibana_url":"","api_key":"","infra_ready":false,"config_ready":false,"demo_executed":false}\n' >"$ENV_FILE"
  fi
}

env_get() { # key -> value (empty if missing/null)
  env_init
  jq -r --arg k "$1" '.[$k] // empty | tostring' "$ENV_FILE"
}

env_set() { # key value [json]; value is a string unless third arg "json"
  env_init
  local tmp
  tmp="$(mktemp)"
  if [[ ${3:-} == json ]]; then
    jq --arg k "$1" --argjson v "$2" '.[$k] = $v' "$ENV_FILE" >"$tmp"
  else
    jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$ENV_FILE" >"$tmp"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

# ---- terraform fallback ---------------------------------------------------

tf_json() {
  if [[ -z $TF_JSON ]]; then
    command -v terraform >/dev/null 2>&1 || { TF_JSON='{}'; return 0; }
    TF_JSON="$(terraform -chdir="$INFRA_DIR" output -json 2>/dev/null)" || TF_JSON='{}'
    [[ -n $TF_JSON ]] || TF_JSON='{}'
  fi
  printf '%s' "$TF_JSON"
}

tf_out() { # first non-empty of the named outputs
  local n v
  for n in "$@"; do
    v="$(tf_json | jq -r --arg k "$n" '.[$k].value // empty | if type=="string" then . else tojson end')"
    if [[ -n $v ]]; then printf '%s' "$v"; return 0; fi
  done
  return 0
}

# ---- load endpoints and auth ---------------------------------------------

load_env() {
  need jq curl
  env_init
  ES_URL="$(env_get elasticsearch_url)"
  KB_URL="$(env_get kibana_url)"
  API_KEY="${OT_API_KEY:-$(env_get api_key)}"
  if [[ -z $ES_URL ]]; then ES_URL="$(tf_out elasticsearch_url)"; fi
  if [[ -z $KB_URL ]]; then KB_URL="$(tf_out kibana_url)"; fi
  [[ -n $ES_URL && -n $KB_URL ]] || die "elasticsearch_url/kibana_url not found in $ENV_FILE or terraform outputs. Deploy infra/ first."
  ES_URL="${ES_URL%/}"
  KB_URL="${KB_URL%/}"
  env_set elasticsearch_url "$ES_URL"
  env_set kibana_url "$KB_URL"
  if [[ -n $API_KEY ]]; then AUTH_MODE=key; else AUTH_MODE=basic; fi
}

_basic_creds() { # prints user:password (never to terminal by callers)
  local u="${OT_ES_USER:-}" p="${OT_ES_PASSWORD:-}"
  [[ -n $u ]] || u="$(tf_out elastic_username username)"
  [[ -n $p ]] || p="$(tf_out elastic_password password)"
  [[ -n $u && -n $p ]] || die "no API key and no username/password (set OT_ES_USER/OT_ES_PASSWORD or deploy infra/ so terraform outputs exist)"
  printf '%s:%s' "$u" "$p"
}

_cfg_escape() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }

_auth_cfg() { # curl config on stdout (consumed via process substitution)
  if [[ $AUTH_MODE == key ]]; then
    printf 'header = "Authorization: ApiKey %s"\n' "$(_cfg_escape "$API_KEY")"
  else
    printf 'user = "%s"\n' "$(_cfg_escape "$(_basic_creds)")"
  fi
}

# ---- HTTP helpers ---------------------------------------------------------
# _call BASE METHOD PATH [curl args...]  -> sets HTTP_CODE, HTTP_BODY. Returns 1 if unreachable.
_call() {
  local base=$1 method=$2 path=$3 a json=1 rc=0
  shift 3
  for a in "$@"; do [[ $a == -F || $a == --form || $a == [Cc]ontent-[Tt]ype:* ]] && json=0; done
  local hdrs=(-H 'kbn-xsrf: true' -H 'x-elastic-internal-origin: ot-demo')
  [[ $json -eq 1 ]] && hdrs+=(-H 'Content-Type: application/json')
  local cfg
  cfg="$(_auth_cfg)" || exit 1
  : >"$_BODY_FILE"
  HTTP_CODE="$(curl -sS -X "$method" --max-time "${CURL_MAX_TIME:-120}" -o "$_BODY_FILE" -w '%{http_code}' \
    -K <(printf '%s\n' "$cfg") "${hdrs[@]}" "$@" "$base$path" 2>"$_BODY_FILE.err")" || rc=$?
  HTTP_BODY="$(cat "$_BODY_FILE")"
  if [[ $rc -ne 0 ]]; then
    HTTP_CODE=000
    HTTP_BODY="$(cat "$_BODY_FILE.err" 2>/dev/null || true)"
    warn "cannot reach $base$path (curl exit $rc): ${HTTP_BODY:-no detail}. Is the deployment up and the URL correct?"
    rm -f "$_BODY_FILE.err"
    return 1
  fi
  rm -f "$_BODY_FILE.err"
  return 0
}

es() { _call "$ES_URL" "$@"; }   # es METHOD PATH [curl args]
kb() { _call "$KB_URL" "$@"; }   # kb METHOD PATH [curl args]

is_2xx() { [[ $HTTP_CODE =~ ^2[0-9][0-9]$ ]]; }

require_2xx() { # what
  is_2xx && return 0
  die "$1 failed: HTTP $HTTP_CODE: $(printf '%s' "$HTTP_BODY" | head -c 800)"
}

# JSON body helpers: es POST /x --data-binary @file  |  es POST /x -d "$json"
wait_for() { # label base path max_seconds [expected_jq_filter]
  local label=$1 base=$2 path=$3 max=${4:-600} filter=${5:-} t0 now
  t0=$(date +%s)
  while :; do
    if _call "$base" GET "$path" 2>/dev/null && is_2xx; then
      if [[ -z $filter ]] || printf '%s' "$HTTP_BODY" | jq -e "$filter" >/dev/null 2>&1; then
        log "$label is up"; return 0
      fi
    fi
    now=$(date +%s)
    (( now - t0 < max )) || die "$label not ready after ${max}s (last HTTP $HTTP_CODE)"
    sleep 10
  done
}

# ---- scoped API key -------------------------------------------------------

api_key_valid() {
  [[ -n $API_KEY ]] || return 1
  AUTH_MODE=key
  es GET /_security/_authenticate 2>/dev/null && is_2xx
}

ensure_api_key() { # [force]
  if [[ ${1:-} != force ]] && api_key_valid; then return 0; fi
  [[ $HTTP_CODE != 000 ]] || die "Elasticsearch unreachable at $ES_URL"
  log "creating scoped API key (using basic auth once)"
  AUTH_MODE=basic
  local body
  body='{
    "name": "ot-demo-scripts",
    "expiration": "30d",
    "role_descriptors": {
      "ot_demo": {
        "cluster": ["monitor", "manage_index_templates", "manage_ingest_pipelines"],
        "indices": [
          {"names": ["logs-claroty_ctd.*","logs-fortinet_fortigate.*","logs-ot_endpoint.*","logs-usb_laundry.*","logs-microsoft_defender_endpoint.*","logs-servicenow.*","logs-plc4x.*","logs-opcua.*","ot-assets"],
           "privileges": ["read","write","create_index","delete","view_index_metadata"]},
          {"names": [".alerts-security.alerts-*",".internal.alerts-security.alerts-*",".siem-signals-*"],
           "privileges": ["read","write","delete","view_index_metadata","maintenance"]}
        ],
        "applications": [{"application": "kibana-.kibana", "privileges": ["all"], "resources": ["*"]}]
      }
    }
  }'
  es POST /_security/api_key -d "$body" || die "cannot create API key (Elasticsearch unreachable)"
  require_2xx "create API key"
  API_KEY="$(printf '%s' "$HTTP_BODY" | jq -r '.encoded // empty')"
  [[ -n $API_KEY ]] || die "API key response had no .encoded field"
  env_set api_key "$API_KEY"
  AUTH_MODE=key
  log "API key stored in $ENV_FILE (not printed)"
}

# ---- misc -----------------------------------------------------------------

json_len_lines() { grep -c . "$1"; }

now_epoch() { date +%s; }
