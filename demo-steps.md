# Demo Steps: Karins Power Plant Alert Triage

Target length: 10 minutes, with the triage itself taking about 3 minutes.

## Before the customer joins

1. Confirm the stack is up: `./scripts/validate-acceptance.sh` shows criteria 1 to 3 passing.
2. Start background traffic: `./scripts/run-scenario.sh noise on`.
3. Reset any previous run: `./scripts/reset-demo.sh --keep-data`.
4. Open Kibana with three tabs: the three dashboards (OT Overview, Asset and Firewall Context,
   Alert Noise vs Incident Summary) and Security > Alerts.

## Script

### 1. Set the scene (1 min)

Say: "It is Monday morning. Claroty flags a suspected anomaly against a PLC at Karins Power Plant.
Normally you would check Claroty, the firewall logs and the endpoint tools one by one. Here it is
all in one place."

### 2. Trigger the alert burst (1 min)

Run: `./scripts/run-scenario.sh scenario`

Say: "The engineering workstation is talking to the turbine controller, and Claroty is raising the
same alert again and again."

### 3. Show the unified view (2 min)

Open **OT Overview**. Point out current alerts, top assets, sites and zones.

Open **Asset and Firewall Context** for KPP-PLC-T2 and KPP-ENG-WS01:
- Asset metadata: owner, zone, criticality.
- FortiGate: the policy that was hit, "ENG-to-PLC-S7".
- Recent network events and the related endpoint events (authorised engineer logon, TIA Portal process).

Say: "No query writing. These panels were built by picking fields."

Say: "The data is organised by Purdue level, the standard OT model: Level 1 is the PLCs and RTUs, Level 2 the HMI,
engineering workstation and historian, Level 3 the DMZ. We are covering network and endpoint together, so there are
no blind spots between layers (defence in depth)." Point to the Alerts by Purdue level panel on OT Overview.

### 4. Confirm it is a known good device (1 min)

On the asset panel, show that KPP-ENG-WS01 is flagged known good with a Monday maintenance window.

Say: "This lookup against our asset list answers whether this is a known device or noise."

Say: "That is asset management: the lookup tells us this workstation is authorised for this PLC and when it is allowed to
change it."

### 5. Show alert grouping (1 min)

Open **Alert Noise vs Incident Summary**: over a thousand raw Claroty events against a handful of alerts.
Then open Security > Alerts and show the single grouped alert with its suppressed-event count.

Say: "The analyst sees one contextualised incident, not a thousand duplicates, and a person still
makes the decision."

Say: "A program download to a Level 1 controller is a change-management event. The alert is tagged MITRE ATT&CK for ICS
T0843 Program Download, so if this were not a scheduled change it would be a real concern. Here the maintenance window
and the authorised logon show it is expected."

### 6. Close the case (1 min)

Create a case from the grouped alert, add a note ("Scheduled maintenance by control systems
engineering, known-good workstation, FortiGate policy ENG-to-PLC-S7"), and close it as a false positive.

Say: "Under three minutes, full context, and the turbines keep spinning."

### 7. Wrap up

- A few dashboards, not thousands.
- Claroty detects, Elastic provides context.
- Noise is grouped, humans stay in control.

## After the demo

```bash
./scripts/run-scenario.sh noise off
./scripts/reset-demo.sh
```

Run `terraform -chdir=infra destroy` when finished to stop AWS and Elastic Cloud costs.

## If something goes wrong

- Dashboard panel shows "Unknown column": run `./scripts/run-scenario.sh backfill` and wait a minute for data.
- No grouped alert appears: check the detection rule is enabled and the license supports suppression.
- Check generator state: `./scripts/run-scenario.sh status`.
