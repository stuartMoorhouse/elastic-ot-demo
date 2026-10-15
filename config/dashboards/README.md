# Dashboards

Produced by a throwaway Python generator (not committed) from one panel specification, emitting two formats. Nothing here was imported into a live Kibana.

- `ot-dashboards.ndjson`: 3 data views (`logs-claroty_ctd.*`, `logs-fortinet_fortigate.*`, `logs-ot_endpoint.*`) plus 3 dashboards in legacy saved-object form with by-value Lens ES|QL panels (`textBased` datasource). Import with `POST /api/saved_objects/_import?overwrite=true` (multipart, `kbn-xsrf` header). The Lens state was hand-written from memory of the 8.x/9.x format and is NOT verified against 9.5. Needs a UI check: open each dashboard after import and look for panels showing "Could not display panel".
- `api/01-ot-overview.json`, `api/02-asset-firewall-context.json`, `api/03-alert-noise-incident.json`: same dashboards in the declarative Dashboards API format (`POST /api/dashboards`, Kibana 9.4+). Schema (`type: vis`, `data_source.type: esql`, `metrics`/`rows`/`group_by` with `{column}`) was taken from the elastic-kibana:kibana-dashboards skill docs, not from a live 9.5. If the NDJSON import fails, use these as the fallback.

Exactly 3 dashboards exist in either path (limit is 4). Use one path only, not both, or you will create 6.

## Caveats

- Queries use ES|QL `LOOKUP JOIN ot-assets ON asset.ip` after `EVAL asset.ip = destination.ip`. Requires `ot-assets` to exist with `index.mode: lookup` (config/assets). Not run against a cluster.
- "Selected asset" is hard-coded to KPP-PLC-T2 (10.20.4.12) / KPP-ENG-WS01 (10.20.3.21) in the ES|QL of dashboard 2. Making it a picker (ES|QL variable control `?asset_ip`) is a UI step.
- Table panels with raw rows (no aggregation) are rendered as data tables with every column as a row dimension.
- Dashboard 2 endpoint panel assumes the generator emits `host.name`, `event.category`, `event.action`, `user.name`, `process.name`. ES|QL fails with "Unknown column" if a field has never been indexed. FortiGate rule panels need `policyname` in the syslog lines so `rule.name` is populated.
- Dashboard 3 reads `.alerts-security.alerts-default` (hidden index) and the rule name `OT - Claroty CTD alert (suppressed by asset and signature)`; they show data only after the detection rule has produced alerts.
- The panels reference the Claroty data view in the Lens `textBased` state for all panels; ES|QL ignores it for the query, but verify in the UI.

Note: `api/*.json` is a fallback in the Dashboards API format. It was updated for the Purdue rename only and is not kept in sync with later panel additions (raw-event drill-down, source known-good check, USB laundry trail). Use `ot-dashboards.ndjson`.
