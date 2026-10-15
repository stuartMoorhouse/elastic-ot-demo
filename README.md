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
- Claroty, FortiGate, endpoint and USB laundry data are correlated in one place with asset metadata, alongside sample
  Microsoft Defender for Endpoint and ServiceNow data that shows how Elastic sits next to those tools, and sample PLC
  telemetry (PLC4X S7 and OPC UA shapes) that shows the process impact of a parameter change.

All data is synthetic. Claroty CEF and FortiGate field fidelity is approximate.

## Architecture

- Elastic Cloud 9.5 deployment (Elasticsearch, Kibana, Fleet), created with Terraform.
- One AWS spot EC2 instance running a Fleet-managed Elastic Agent with the Claroty CTD, Fortinet FortiGate
  and filestream (endpoint and USB laundry) integrations.
- A synthetic generator on the instance emits Claroty CEF, FortiGate syslog, ECS endpoint events, USB laundry kiosk events, sample Defender and ServiceNow events, and sample PLC4X and OPC UA telemetry.
- `ot-assets` lookup index holds asset metadata (owner, zone, criticality, known-good flag), joined at query time.
- One detection rule with alert suppression, one case, and three dashboards delivered as code.

## Layout

| Path | Contents |
|---|---|
| `infra/` | Terraform: Elastic Cloud deployment, Fleet policy, VPC, EC2 spot host |
| `config/` | Assets, Fleet package policies, detection rule, case template, dashboards (see `config/README.md`) |
| `scripts/` | `configure.sh`, `run-scenario.sh`, `validate-acceptance.sh`, `reset-demo.sh`, generator |
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

## Status

Code is generated but not yet deployed. The dashboards, Fleet policy bodies and detection rule
schema have not been tested against a live 9.5 cluster. Alert suppression requires a Platinum,
Enterprise or trial license.
