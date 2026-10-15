#!/usr/bin/env bash
# Control the OT generator on the EC2 host over SSH.
#   run-scenario.sh noise on|off
#   run-scenario.sh backfill [HOURS]     (default 24)
#   run-scenario.sh scenario             (Karins false-positive storyline)
#   run-scenario.sh threat               (contrast: unmanaged source, not in inventory)
#   run-scenario.sh ticket-close         (sample ServiceNow incident closed after the case is closed)
#   run-scenario.sh status
# SSH details come from terraform outputs (ssh_command, or ec2_public_ip + infra/*.pem).
# Override with OT_SSH_CMD="ssh -i key.pem ubuntu@1.2.3.4".
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
need jq

GEN=/opt/ot-demo/ot_generator.py
UNIT=ot-generator.service
usage() { sed -n '2,8p' "${BASH_SOURCE[0]}" >&2; exit 2; }

ssh_cmd_array() {
  local cmd="${OT_SSH_CMD:-$(env_get ssh_command)}"
  [[ -n $cmd ]] || cmd="$(tf_out ssh_command ssh_cmd)"
  if [[ -z $cmd ]]; then
    local ip key
    ip="$(tf_out ec2_public_ip public_ip instance_public_ip)"
    key="$(find "$INFRA_DIR" -maxdepth 1 -name '*.pem' 2>/dev/null | head -n1)"
    [[ -n $ip && -n $key ]] || die "no ssh_command output and no ec2_public_ip + infra/*.pem; deploy infra/ first or set OT_SSH_CMD"
    cmd="ssh -i $key ubuntu@$ip"
  fi
  # terraform's ssh_command uses a key path relative to infra/
  cmd="${cmd//-i .\//-i $INFRA_DIR/}"
  # shellcheck disable=SC2206
  SSH=($cmd -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
}

remote() { "${SSH[@]}" "$@"; }

[[ $# -ge 1 ]] || usage
env_init
ssh_cmd_array
action=$1

case "$action" in
  noise)
    [[ ${2:-} == on || ${2:-} == off ]] || usage
    if [[ $2 == on ]]; then remote "sudo systemctl start $UNIT"; else remote "sudo systemctl stop $UNIT"; fi
    log "noise $2"
    ;;
  backfill)
    hours="${2:-24}"
    [[ $hours =~ ^[0-9]+$ ]] || die "HOURS must be an integer"
    remote "sudo python3 $GEN --mode backfill --hours $hours"
    ;;
  scenario)
    env_set scenario_triggered_at "$(now_epoch)"
    log "triggering scenario at $(date -u +%FT%TZ)"
    remote "sudo python3 $GEN --mode scenario"
    env_set demo_executed true json
    log "scenario sent; demo_executed=true"
    ;;
  threat)
    log "triggering contrast (threat) scenario at $(date -u +%FT%TZ)"
    remote "sudo python3 $GEN --mode threat"
    log "threat scenario sent"
    ;;
  ticket-close)
    remote "sudo python3 $GEN --mode ticket-close"
    log "sample ServiceNow incident closed"
    ;;
  status)
    remote "systemctl is-active $UNIT || true; ls -l /var/log/ot-demo/ 2>/dev/null || true"
    ;;
  *) usage ;;
esac
