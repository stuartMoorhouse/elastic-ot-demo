# config/ - Elastic solution configuration (generated, not deployed)

Nothing here has been applied to a cluster. Target: Elastic Cloud 9.5. All requests need the `kbn-xsrf: true` header for Kibana and the demo API key.

| File | Purpose | Endpoint |
|---|---|---|
| assets/ot-assets-index.json | Asset inventory index, `index.mode: lookup` (for ES\|QL LOOKUP JOIN) | `PUT /ot-assets` (Elasticsearch) |
| assets/ot-assets.ndjson | Six scenario assets with owner and maintenance window, `_id` = asset name | `POST /ot-assets/_bulk?refresh=wait_for` (Content-Type application/x-ndjson) |
| fleet/claroty_ctd.json | Claroty CTD package policy, TCP 127.0.0.1:9100 | `POST /api/fleet/package_policies` |
| fleet/fortinet_fortigate.json | FortiGate package policy, UDP 127.0.0.1:9004 | `POST /api/fleet/package_policies` |
| fleet/ot_endpoint_logs.json | Custom Logs (Filestream) policy, `/var/log/ot-demo/endpoint.ndjson`, ndjson parser, dataset `ot_endpoint.events` | `POST /api/fleet/package_policies` |
| detection/claroty-suppressed-alert.json | Query rule with alert suppression | `POST /api/detection_engine/rules` |
| cases/case-template.json | Body for the grouped-alert case | `POST /api/cases` |
| dashboards/ot-dashboards.ndjson | 3 data views + 3 dashboards (legacy saved objects) | `POST /api/saved_objects/_import` |
| dashboards/api/*.json | Same 3 dashboards, Dashboards API format (fallback or alternative) | `POST /api/dashboards` (9.4+) |

## How configure.sh should fill the Fleet placeholders

- `__POLICY_ID__`: `GET /api/fleet/agent_policies?perPage=100&kuery=ingest-agent-policies.name:"ot-demo-policy"` and take `items[0].id` (or filter `items[] | select(.name=="ot-demo-policy")`). The bodies use `policy_ids: ["__POLICY_ID__"]` (current API); the older single `policy_id` field is deprecated.
- `__PACKAGE_VERSION__`: `GET /api/fleet/epm/packages/<name>` and read `.item.version` (older stacks: `.response.version`). Names: `claroty_ctd`, `fortinet_fortigate`, `filestream`. Observed on main in the integrations repo: claroty_ctd 1.6.0 (Kibana ^8.19.2 || ^9.0.5), fortinet_fortigate 1.36.10 (^9.0.0), filestream 2.5.1 (^9.4.0). If a package is not installed, `POST /api/fleet/epm/packages/<name>/<version>` first (body `{"force":false}`).
- Make the three POSTs idempotent: check `GET /api/fleet/package_policies` for the `name` before creating.

## Deviations from the contract

1. **Claroty alert data stream.** The Claroty CTD package (1.6.0) has NO `alert` data stream. Syslog (TCP/UDP, CEF) feeds one combined data stream `event`, so alerts land in `logs-claroty_ctd.event-default` (dataset `claroty_ctd.event`), distinguished by `event.kind: alert` (set by the pipeline when CEF device event class id contains `Alert`). Dashboards and the rule use `logs-claroty_ctd.event-*`. Agent 3 checks should look at `logs-claroty_ctd.event-*`, not `.alert-`. The `asset` and `baseline` streams use the CEL/API input and are not enabled.
2. **Claroty listen port.** The input is TCP/UDP syslog (CEF) as expected; configured as TCP 127.0.0.1:9100 (package default is 9537).
3. **Custom logs package.** The `log` package is marked "Custom Logs (Deprecated)" (logfile input). `filestream` ("Custom Logs (Filestream)", requires Kibana ^9.4.0) is used instead; it has an explicit `parsers` var for ndjson.
4. **policy_ids** instead of `policy_id` (see above).

## Generator requirements implied by the pipelines (verified from package ingest pipelines)

- Claroty CEF: header event class id must be `Alert-<type>` (the agent replaces `Alert/` with `Alert-`), name = alert name (becomes `claroty_ctd.event.name`, used as the signature), extensions `CtdSourceIp`, `CtdDestinationIp` (-> `source.ip`, `destination.ip`), `CtdSourceHost`, `CtdDestinationHost`, `CtdAlertId`, `CtdAlertScore`, `CtdSourceZone`/`CtdDestinationZone`. Pipeline ECS: `event.kind=alert`, `event.category=threat`.
- FortiGate: key=value syslog with `policyid` (-> `rule.id`) and `policyname` (-> `rule.name`, e.g. `ENG-to-PLC-S7`), `srcip`, `dstip`, `dstport`, `action`.
- Endpoint NDJSON: one ECS JSON object per line with `@timestamp`, `host.name`, `event.category`, `event.action`, `user.name`, `process.name`. Do not set `data_stream.*`; do not set a conflicting `event.dataset`. Keys are decoded at the document root (ndjson `target: ""`, `overwrite_keys: true`).
- Detection rule suppression fields: `destination.ip` + `claroty_ctd.event.name`, 1 hour, `missing_fields_strategy: suppress`. Alert suppression for query rules needs a Platinum/Enterprise (or trial) license. Suppressed counts are in `kibana.alert.suppression.docs_count`. `max_signals` is 1000 so a 1000-event replay is not truncated (assumption). Attach the alert to the case with `POST /api/cases/{id}/comments` (`type: alert`, `alertId`, `index`, `rule: {id, name}`, `owner: securitySolution`); close as false positive with `PATCH /api/cases` (`status: closed`) plus a note.

## Verified vs assumed

Verified (read from elastic/integrations main, 2026-10): package names/versions/inputs/vars for claroty_ctd, fortinet_fortigate, filestream; Claroty and FortiGate ingest-pipeline field names; Dashboards API panel schema (from the skill docs).

Not verified (no live cluster, no docs MCP access): the simplified `inputs` key format in the Fleet bodies (`<policy_template>-<input>` and stream key `<package>.<dataset-or-template>`; the filestream stream key `filestream.filestream` is the least certain, and disabled inputs given as `{"enabled": false}` without streams); Detection Engine rule schema details; legacy Lens saved-object JSON for 9.5; ES|QL queries (LOOKUP JOIN with `ON asset.ip`, `TO_IP`, `?_tstart`/`?_tend` in dashboards) were not executed; `.alerts-security.alerts-default` queryable from ES|QL; `ecs@mappings` assumed to map ECS fields of the endpoint data stream (ip, keyword) dynamically. If a Fleet POST is rejected, create the policy once in the UI and copy `GET /api/fleet/package_policies/<id>` as the template.
