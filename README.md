# OT Security Demo: Elastic as the Context Hub for Claroty

A demo showing how Elastic Security gives OT analysts one place to triage a Claroty CTD alert,
using Claroty, Fortinet FortiGate and endpoint data. The scenario is a suspected anomaly against a
PLC at the (fictional) Karins Power Plant, which the analyst verifies and closes as a false positive
in under three minutes.

Key points the demo makes:

- A handful of core dashboards, built visually, with no KQL needed to operate them.
- Elastic as the context hub: Claroty raises the alert, Elastic supplies firewall, endpoint and asset context.
- Repeated identical alerts are grouped by source, destination and signature into one contextualised incident (alert
  suppression), without discarding any raw event, so the analyst stays in the loop without clicking through thousands
  of duplicates. A contrast scenario shows an unknown source breaking out as its own alert.
- Claroty, FortiGate, endpoint and Meta Data Kiosk data are correlated in one place with asset metadata, alongside sample
  Microsoft Defender for Endpoint and ServiceNow data that shows how Elastic sits next to those tools, and sample PLC
  telemetry (PLC4X S7 and OPC UA shapes) that shows the process impact of a parameter change.

All data is synthetic. Claroty CEF and FortiGate field fidelity is approximate.

## Architecture

- Elastic Cloud 9.5 deployment (Elasticsearch, Kibana, Fleet), created with Terraform.
- One AWS spot EC2 instance running a Fleet-managed Elastic Agent with the Claroty CTD, Fortinet FortiGate
  Custom UDP Logs (Meta Data Kiosk syslog) and filestream (endpoint) integrations.
- A synthetic generator on the instance emits Claroty CEF, FortiGate syslog, ECS endpoint events, Meta Data Kiosk (OPSWAT MetaDefender Kiosk) syslog events, sample Defender and ServiceNow records (loaded through the real integrations' pipelines), and sample PLC4X and OPC UA telemetry.
- `ot-assets` lookup index holds asset metadata (owner, zone, criticality, known-good flag), joined at query time.
- Two detection rules (a Claroty query rule with alert suppression, and an ES|QL correlation rule), one case, and three dashboards delivered as code.

## Layout

| Path | Contents |
|---|---|
| `infra/` | Terraform: Elastic Cloud deployment, Fleet policy, VPC, EC2 spot host |
| `config/` | Assets, Fleet package policies, detection rule, case template, dashboards (see `config/README.md`) |
| `scripts/` | `configure.sh`, `run-scenario.sh`, `validate-acceptance.sh`, `reset-demo.sh`, `load-api-data.sh`, generator |
| `shared/env.json` | Endpoints, API key and readiness flags passed between scripts (gitignored) |
| `results/` | Acceptance check output |

## Quick start

Prerequisites: Terraform, `jq`, AWS profile `company` (account 461485115270), and `EC_API_KEY` set.

```bash
cp terraform.tfvars.example terraform.tfvars
terraform -chdir=infra init && terraform -chdir=infra apply
./scripts/configure.sh
./scripts/validate-acceptance.sh
```

Then follow `demo-steps.md`. Tear down with `terraform -chdir=infra destroy`.

## Correlation rule: VPN access, EWS compromise and PLC change

`config/detection/ot-ews-vpn-defender-claroty.json` is an ES|QL rule ("OT: VPN access, EWS compromise and PLC change
from same workstation") that joins three sources on the engineering workstation (EWS) IP: a FortiGate connection from the
VPN pool (10.99.0.0/24) to the EWS on RDP, SMB or WinRM, a Microsoft Defender alert on the EWS, and a Claroty CTD PLC
modification alert originating from the EWS, in that order. Each is low confidence alone; together they suggest stolen
remote-access credentials used to tamper with a PLC. It runs every 15 minutes over the last 255 minutes, is enabled by
default, and suppresses repeat alerts per EWS IP for 4 hours, so one sequence gives one alert.

Field mapping to this deployment (the integrations differ from generic ECS): the EWS IP is `destination.ip` for FortiGate,
`source.ip` for Claroty and `related.ip` for Defender (the Defender pipeline has no `host.ip`); the Claroty alert name is
`claroty_ctd.event.name`; the VPN user is `source.user.name`. Events are filtered to the chain's qualifying
events before grouping, so unrelated earlier events on the EWS do not break the ordering check, and `MV_EXPAND` joins
on every IP of a multi-homed host.

The sequence is sent once, by the demo scripts, on a separate workstation (`KPP-ENG-WS02`, 10.20.3.22) so the noise
generator and the ENG-WS01 false-positive storyline never trigger it:

- `./scripts/configure.sh` sends it as its last step (best effort; needs SSH to the host and a running agent).
- `./scripts/reset-demo.sh` clears the data and the rule's alerts, then sends it again (skipped with `--keep-data`).
- `./scripts/run-scenario.sh ews-compromise` sends it on demand.

The sequence, timed relative to the run: VPN-pool RDP to the EWS (6 min before), Defender alert "Suspicious PowerShell
command line" on it (4 min before), Claroty "PLC Program Download Detected" from it (2 and 1 min before). The rule raises
one high-severity alert for 10.20.3.22 on its next run, up to 15 minutes later. Open it in Security > Alerts.

Assumptions not verified against real products: the VPN pool CIDR and ports, the Claroty alert names other than
"PLC Program Download Detected", and the Defender evidence shape carrying `ipAddress`. The MITRE ATT&CK for ICS
techniques (T0836, T0843) are carried as tags and references because the rule `threat` field is Enterprise only.
After changing `scripts/generator/ot_generator.py`, run `terraform -chdir=infra apply` to ship it to the host.

## Status

Code is generated but not yet deployed. The dashboards, Fleet policy bodies and detection rule
schema have not been tested against a live 9.5 cluster. Alert suppression requires a Platinum,
Enterprise or trial license.
