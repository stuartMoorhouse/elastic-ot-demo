# Demo Steps: Karins Power Plant Alert Triage

Target length: 12 minutes, with the triage itself taking about 3 minutes.

## What the demo answers

| Pain point | Where it is shown |
|---|---|
| Alert noise is overwhelming, and the team assumes it cannot be reduced | Steps 5 and 6: about a thousand duplicate alerts become a handful of incidents, every raw event is still available, and a real threat is not hidden in the noise |
| Slow, fragmented triage across Claroty, firewall, endpoint and USB laundry logs | Steps 3, 4 and 8: one place to see the alert, firewall rule hit, endpoint activity, USB laundry trail, asset metadata, the Defender verdict and the ServiceNow ticket status |

## Before the customer joins

1. Confirm the stack is up: `./scripts/validate-acceptance.sh` shows criteria 1 to 3 passing.
2. Start background traffic: `./scripts/run-scenario.sh noise on`.
3. Reset any previous run: `./scripts/reset-demo.sh`.
4. Open Kibana with the three dashboards (OT Overview, Asset and Firewall Context, Alert Noise vs Incident Summary)
   and Security > Alerts.

## Script

### 1. Set the scene (1 min)

Say: "It is Monday morning. Claroty flags a suspected anomaly against a PLC at Karins Power Plant.
Normally you would check Claroty, the firewall logs, the endpoint tools and the USB laundry one by one.
Here it is all in one place."

### 2. Trigger the alert burst (1 min)

Run: `./scripts/run-scenario.sh scenario`

Say: "The engineering workstation is talking to the turbine controller, and Claroty is raising the
same alert again and again."

### 3. Show the unified view (3 min)

Open **OT Overview**. Point out current alerts, top assets and the Alerts by Purdue level panel. At the bottom, the
OPC UA panel shows live substation values (breaker closed, voltage, current, frequency).

Say: "The data is organised by Purdue level, the standard OT model: Level 1 is the PLCs and RTUs, Level 2 the HMI,
engineering workstation and historian, Level 3 the DMZ. We cover network and endpoint together, so there are no
blind spots between layers (defence in depth)."

Open **Asset and Firewall Context** for KPP-PLC-T2 and KPP-ENG-WS01:
- Asset metadata: owner, zone, criticality.
- Alerts against the PLC by source: the source is KPP-ENG-WS01, known good.
- FortiGate: the policy that was hit, "ENG-to-PLC-S7".
- Related endpoint events: authorised engineer logon, TIA Portal process.
- Process impact check: Turbine 2 speed and vibration (PLC4X S7 sample telemetry) stay flat through the change.
- USB laundry trail: seven minutes earlier the engineer scanned `TurbineGovernor_v14.zap18` at the kiosk (clean) and
  released it to this workstation.

Say: "That is four sources, Claroty, the firewall, the endpoint and the USB laundry, in one view, with no query
writing. These panels were built by picking fields."

### 4. Confirm it is a known good device (1 min)

On the asset panel, show that KPP-ENG-WS01 is flagged known good with a Monday maintenance window.

Say: "This lookup against our asset list is asset management: it tells us this workstation is authorised for this
PLC and when it is allowed to change it."

### 5. Show alert grouping, and that nothing is discarded (2 min)

Run in a terminal while you talk: `./scripts/run-scenario.sh threat` (used in step 6).

Open **Alert Noise vs Incident Summary**: over a thousand raw Claroty events against a handful of grouped alerts.
Then show the two tables underneath: raw events by source, destination and alert, and the latest raw alert events.

Say: "The analyst reviews one contextualised incident, not a thousand duplicates, and a person still makes the
decision. Every raw event is still here to inspect, so nothing is hidden. Whether that meets your reading of the
NIS2 human-in-the-loop requirement is for your compliance team to confirm."

Say: "A program download to a Level 1 controller is a change-management event. The alert is tagged MITRE ATT&CK for ICS
T0843 Program Download. Here the maintenance window, the authorised logon and the clean USB scan show it is expected."

### 6. Show that a real threat is not hidden (2 min)

Open Security > Alerts, or **Asset and Firewall Context**. Show the second source in the alerts-by-source table.

Say: "Now a different source. This host is UNKNOWN, it is not in the asset inventory. It has no endpoint telemetry and
no USB laundry trail, it came in through a different firewall policy, Contractor-VPN-to-OT, and the severity is higher.
Because we group by source, it breaks out as its own alert instead of disappearing into the noise."

Scroll to the process impact check panels on **Asset and Firewall Context**.

Say: "And here is why it matters. Within minutes of that unknown host's program download, the turbine speed climbs from
3000 towards 3150 rpm and vibration roughly doubles. That is a parameter change with a real effect on the process, which
MITRE calls T0836 Modify Parameter. The same platform that holds the security data holds the PLC telemetry, so the
analyst sees the impact straight away. For the known-good change, the same panels stayed flat."

### 7. Close the case (1 min)

Create a case from the grouped alert for the engineering workstation, add a note ("Scheduled maintenance by control
systems engineering, known-good workstation, clean USB scan, FortiGate policy ENG-to-PLC-S7"), and close it as a false
positive. Leave the unknown-source alert open.

Say: "Under three minutes, full context, and the turbines keep spinning."

### 8. Where this fits with Defender and ServiceNow (2 min)

Back on **Asset and Firewall Context**, scroll to the last row.

- Microsoft Defender for Endpoint panel: recent alerts across the OT hosts. The KPP-ENG-WS01 alert is auto-resolved as a
  false positive, and one alert on KPP-HIST-01 is still being investigated.
- ServiceNow panel: incident activity. INC0010231 was opened from the Claroty alert (New, then In Progress, assigned to
  the OT SOC), alongside older incidents that are closed, in progress or on hold.

Run `./scripts/run-scenario.sh ticket-close` after closing the case in step 7, and show the incident move to Closed.

Say: "You keep Claroty feeding Defender and ServiceNow. Elastic sits alongside as the context hub, so the analyst sees
the Defender verdict and the ticket status next to the alert. This is sample data in the shape of the real Microsoft
Defender for Endpoint and ServiceNow integrations. In your environment those would be the real integrations, and a
Kibana connector can push the Elastic case to ServiceNow."

### 9. Wrap up

- A few dashboards, not thousands.
- Claroty detects, Elastic provides context.
- Noise is grouped, nothing is discarded, and an unknown source stands out.

## After the demo

```bash
./scripts/run-scenario.sh noise off
./scripts/reset-demo.sh
```

Run `terraform -chdir=infra destroy` when finished to stop AWS and Elastic Cloud costs.

## If something goes wrong

- Dashboard panel shows "Unknown column": run `./scripts/run-scenario.sh backfill` and wait a minute for data.
- No grouped alert appears: check the detection rule is enabled (it runs every minute) and the license supports suppression.
- No second source in step 6: run `./scripts/run-scenario.sh threat` and wait a minute.
- No turbine speed excursion in step 6: noise must be on (`./scripts/run-scenario.sh noise on`) when you run `threat`. The setpoint drift lasts 5 minutes and then reverts, so run `threat` at the start of step 5.
- No Defender or ServiceNow rows: run `./scripts/run-scenario.sh scenario` again.
- No USB trail: run `./scripts/run-scenario.sh scenario` again; the trail is written 7 minutes before the burst.
- Check generator state: `./scripts/run-scenario.sh status`.

## Notes

- All data is synthetic. The USB laundry log format is a placeholder until a sample from the customer's kiosk is available.
- The PLC telemetry (PLC4X S7 driver for the turbine PLC, an OPC UA client for the substation RTU) is sample data in the
  shape those collectors produce. There is no dedicated Elastic integration for them here; in practice they ship through
  Logstash, Kafka or Agent. The data goes to `logs-plc4x.telemetry-default` and `logs-opcua.telemetry-default`.
- The Defender and ServiceNow data is sample data with the real integrations' field names, written to streams named like
  the real datasets. Neither integration is configured. If the real integrations are installed later, their templates and
  pipelines apply to the same stream names.
