#!/usr/bin/env python3
"""Synthetic OT data generator for the Karins Power Plant demo (stdlib only).

Modes:
  noise     continuous background traffic + repetitive low-severity Claroty alerts
  backfill  history with historical timestamps (--hours N)
  ews-compromise  one-shot VPN hops and Claroty PLC configuration changes on KPP-ENG-WS02 (ews-defender adds the
            Defender alert between them as bulk lines)
  scenario  false-positive storyline (burst of identical Claroty alerts, FortiGate
            ENG-to-PLC-S7 hits, engineer logon + TIA Portal process)

Outputs:
  Claroty CEF   -> syslog TCP 127.0.0.1:9100
  FortiGate kv  -> syslog UDP 127.0.0.1:9004
  Meta Data Kiosk (OPSWAT MetaDefender Kiosk) syslog -> UDP 127.0.0.1:9514
  Endpoint ECS  -> /var/log/ot-demo/endpoint.ndjson (JSON lines)
Claroty CEF field fidelity is synthetic.
"""
import argparse
import hashlib
import json
import os
import random
import re
import socket
import sys
import time
from datetime import datetime, timezone

ASSETS = {
    "KPP-PLC-T2": "10.20.4.12", "KPP-RTU-SS1": "10.20.4.30",
    "KPP-ENG-WS01": "10.20.3.21", "KPP-HMI-01": "10.20.3.10",
    "KPP-HIST-01": "10.20.3.40", "FGT-KPP-OT01": "10.20.0.1",
    "KPP-USB-KIOSK01": "10.20.0.50", "KPP-ENG-WS02": "10.20.3.22",
}
PLC, RTU, ENG, HMI, HIST, FGT = (ASSETS[k] for k in (
    "KPP-PLC-T2", "KPP-RTU-SS1", "KPP-ENG-WS01", "KPP-HMI-01", "KPP-HIST-01", "FGT-KPP-OT01"))
NAME_BY_IP = {v: k for k, v in ASSETS.items()}
DEVNAME, DEVID = "FGT-KPP-OT01", "FGT60FTK2209XXXX"
SITE = "Karins Power Plant"

# (policyid, policyname, srcip, dstip, service, dstport, proto, srcintf, dstintf)
FLOWS = [
    (10, "ENG-to-PLC-S7", ENG, PLC, "S7", 102, 6, "port2", "port3"),
    (11, "HMI-to-PLC-Modbus", HMI, PLC, "MODBUS", 502, 6, "port2", "port3"),
    (12, "HMI-to-RTU-DNP3", HMI, RTU, "DNP3", 20000, 6, "port2", "port3"),
    (13, "HIST-to-PLC-Modbus", HIST, PLC, "MODBUS", 502, 6, "port2", "port3"),
    (14, "HIST-to-RTU-DNP3", HIST, RTU, "DNP3", 20000, 6, "port2", "port3"),
]
NOISE_ALERTS = [  # low severity, repetitive, from ENG-WS01 to PLC
    ("S7_READ_SCAN", "S7 Unauthorized Read/Scan", 3),
    ("PLC_PROG_DL", "PLC Program Download Detected", 3),
]
SCEN_ALERTS = [("S7_READ_SCAN", "S7 Unauthorized Read/Scan", 5),
               ("PLC_PROG_DL", "PLC Program Download Detected", 5)]
ENGINEER = "a.lindqvist"
# Contrast storyline: an unmanaged host that is not in the asset inventory reaches the PLC through a
# broad contractor policy. No endpoint telemetry exists for it (no agent installed).
UNKNOWN_SRC = "10.20.9.77"
FLOW_THREAT = (17, "Contractor-VPN-to-OT", UNKNOWN_SRC, PLC, "S7", 102, 6, "port1", "port3")
THREAT_ALERTS = [("PLC_PROG_DL", "PLC Program Download Detected", 8),
                 ("S7_READ_SCAN", "S7 Unauthorized Read/Scan", 7)]
# Correlation storyline (ews-compromise mode): stolen VPN credentials reach a second engineering workstation, Defender
# flags it, then Claroty sees it modify the PLC. Used by the "OT: VPN access, EWS compromise and PLC change" rule.
EWS2 = ASSETS["KPP-ENG-WS02"]
VPN_POOL_IP = "10.99.0.15"  # inside the rule's VPN pool CIDR 10.99.0.0/24
VPN_USER = "contractor.hale"
EWS_ALERT = ("PLC_CFG_CHG", "PLC Configuration Change", 9)
FLOW_VPN_EWS = (18, "SSLVPN-to-EWS-RDP", VPN_POOL_IP, EWS2, "RDP", 3389, 6, "ssl.root", "port2")
ENDPOINT_FILE = "/var/log/ot-demo/endpoint.ndjson"
KIOSK = "KPP-USB-KIOSK01"
# Raw Microsoft Defender for Endpoint alert and ServiceNow incident API records. They are bulk-loaded by
# scripts/load-api-data.sh and parsed by the real integrations' ingest pipelines (the integrations are
# installed but not configured, since there is no tenant or instance to pull from).
PLC4X_FILE = "/var/log/ot-demo/plc4x.ndjson"
OPCUA_FILE = "/var/log/ot-demo/opcua.ndjson"
OVERRIDE_FILE = "/var/log/ot-demo/.plc_override.json"  # written by the threat mode, read by noise
INCIDENT_NO = "INC0010231"
INCIDENT_SYS_ID = "9d385017c611228701d22104cc95c371"


def utc(ts=None):
    return datetime.fromtimestamp(ts, timezone.utc) if ts else datetime.now(timezone.utc)


def cef_escape(v):
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


ZONE_BY_NAME = {"KPP-PLC-T2": "Level 1 Control Network", "KPP-RTU-SS1": "Level 1 Control Network",
                "KPP-ENG-WS01": "Level 2 Process Network", "KPP-HMI-01": "Level 2 Process Network",
                "KPP-HIST-01": "Level 2 Process Network", "FGT-KPP-OT01": "Level 3 Control DMZ",
                "KPP-USB-KIOSK01": "Level 3 Control DMZ", "KPP-ENG-WS02": "Level 2 Process Network"}
ATYPE_BY_NAME = {"KPP-PLC-T2": "PLC", "KPP-RTU-SS1": "RTU", "KPP-ENG-WS01": "Endpoint", "KPP-HMI-01": "HMI",
                 "KPP-HIST-01": "Endpoint", "FGT-KPP-OT01": "Network Device", "KPP-USB-KIOSK01": "Endpoint", "KPP-ENG-WS02": "Endpoint"}
SITE_ID = "KPP-SITE-01"
CTD_SENSOR = "KPP-CTD-SENSOR01"
# Approximate Claroty categories for our two alert signatures (category strings are a best guess).
CATEGORY_BY_SIG = {"S7_READ_SCAN": "Security/Network Scan", "PLC_PROG_DL": "Integrity/PLC Code Download"}


def zone_of(ip):
    return ZONE_BY_NAME.get(NAME_BY_IP.get(ip), "Unclassified")


def atype_of(ip):
    return ATYPE_BY_NAME.get(NAME_BY_IP.get(ip), "Endpoint")


def ctd_line(ts, class_id, name, sev, ext):
    """One Claroty CTD CEF syslog line. The device event class ID selects the type the integration assigns
    (Alert-..., Event/..., ActivityLog, HealthCheck, Insight)."""
    t = utc(ts)
    full = {"rt": int(t.timestamp() * 1000)}
    full.update(ext)
    # CtdSite becomes observer.hostname (dashboard filter); CtdTimeGenerated becomes @timestamp.
    full["CtdSite"] = SITE
    full["CtdTimeGenerated"] = t.strftime("%b %d %Y %H:%M:%S")
    body = " ".join("%s=%s" % (k, cef_escape(v)) for k, v in full.items())
    return "<134>%s ctd-kpp CEF:0|Claroty|CTD|4.12.0|%s|%s|%d|%s" % (
        t.strftime("%b %d %H:%M:%S"), class_id, name, sev, body)


def claroty_line(ts, sig_id, name, sev, src, dst, proto="S7Comm"):
    sh, dh = NAME_BY_IP.get(src, src), NAME_BY_IP.get(dst, dst)
    ext = {
        "src": src, "dst": dst, "shost": sh, "dhost": dh,
        "CtdSourceIp": src, "CtdDestinationIp": dst, "CtdSourceHost": sh, "CtdDestinationHost": dh,
        "CtdSourceZone": zone_of(src), "CtdDestinationZone": zone_of(dst),
        "CtdSourceAssetType": atype_of(src), "CtdDestinationAssetType": atype_of(dst),
        "CtdProtocol": proto, "CtdCategory": CATEGORY_BY_SIG.get(sig_id, "Security/Other"),
        "CtdAlertScore": min(100, sev * 10), "CtdAlertStatus": "Unresolved", "CtdResolvedAs": "Unresolved",
        "CtdDeviceExternalId": SITE_ID,
        "proto": proto, "cs1Label": "site", "cs1": SITE,
        "cn1Label": "alert_id", "cn1": random.randint(100000, 999999),
        "CtdAlertId": random.randint(100000, 999999),
        "msg": name + " between %s and %s" % (sh, dh),
    }
    return ctd_line(ts, "Alert-%s" % sig_id, name, sev, ext)


EVENT_TYPES = [  # (name, category, message)
    ("Asset Information Change", "Integrity/Asset Information Change", "Information change detected on %s"),
    ("OT Operation", "Non-Risky/OT Operation", "Routine OT operation seen from %s"),
    ("Non-Risky Change", "Non-Risky/Configuration Change", "Routine configuration change seen on %s"),
]
CTD_USERS = ["a.lindqvist", "j.koskinen", "s.laine", "ctd.admin"]
ACTIVITIES = [  # (name, action, status, log type, message)
    ("User Login", "Logged in", "Success", "User", "User %s logged in to CTD"),
    ("User Login", "Logged in", "Failure", "User", "Failed login attempt for %s"),
    ("Site Mode", "Changed to Operational Mode", "Success", "System", "System was moved to [[Operational Mode]] by %s"),
    ("Alert Resolved", "Resolved alert", "Success", "User", "%s resolved an alert"),
]
INSIGHTS = [  # (name, severity, operating system)
    ("Open Ports", "Low", "Windows 10"),
    ("End Of Life Assets", "Medium", "Windows 7"),
    ("Insecure Remote Access", "High", "Windows 10"),
    ("Full Match CVEs", "High", "Siemens SIMATIC S7-1500"),
]


def claroty_event(sink, ts):
    name, cat, msg = random.choice(EVENT_TYPES)
    flow = random.choice(FLOWS)
    src, dst = flow[2], flow[3]
    sh, dh = NAME_BY_IP[src], NAME_BY_IP[dst]
    ext = {"CtdSourceIp": src, "CtdDestinationIp": dst, "CtdSourceHost": sh, "CtdDestinationHost": dh,
           "CtdSourceZone": zone_of(src), "CtdDestinationZone": zone_of(dst),
           "CtdProtocol": flow[4], "CtdCategory": cat, "CtdResolvedAs": random.choice(["Unresolved", "Resolved"]),
           "CtdEventTypeId": random.randint(1, 9), "CtdMessage": msg % dh,
           "CtdDeviceExternalId": SITE_ID, "CtdExternalId": random.randint(100, 9999)}
    sink.claroty(ctd_line(ts, "Event/" + name, name, random.randint(0, 3), ext))


def claroty_activity(sink, ts, user=None, which=None):
    name, action, status, ltype, msg = which or random.choice(ACTIVITIES)
    user = user or random.choice(CTD_USERS)
    ext = {"CtdUser": user, "CtdAction": action, "CtdActionStatus": status, "CtdLogType": ltype,
           "CtdMessage": msg % user}
    sink.claroty(ctd_line(ts, "ActivityLog", name, 0, ext))


def claroty_health(sink, ts):
    ext = {"CtdCpu": _fl(14 + random.gauss(0, 2.5)), "CtdMem": _fl(62 + random.gauss(0, 1.5)),
           "CtdUsedOptIcsranger": _fl(14.4 + random.gauss(0, 0.2)), "CtdUsedVar": _fl(36 + random.gauss(0, 0.3)),
           "CtdUsedTmp": _fl(7 + random.gauss(0, 0.5)), "CtdUnhandledEvents": random.randint(0, 60),
           "CtdSensorName": CTD_SENSOR, "CtdMessage": "Successfully ran health monitoring"}
    sink.claroty(ctd_line(ts, "HealthCheck", "Health", 0, ext))


def claroty_insight(sink, ts, src=None, dst=None, ghost=False, name=None, severity=None, os_name=None):
    n, sev, osn = random.choice(INSIGHTS)
    name, severity, os_name = name or n, severity or sev, os_name or osn
    src = src or random.choice([ENG, HMI, HIST])
    dst = dst or random.choice([PLC, RTU])
    ext = {"CtdSourceIp": src, "CtdDestinationIp": dst,
           "CtdSourceHost": NAME_BY_IP.get(src, src), "CtdDestinationHost": NAME_BY_IP.get(dst, dst),
           "CtdSourceZone": zone_of(src), "CtdDestinationZone": zone_of(dst),
           "CtdIsGhost": "true" if ghost else "false", "CtdInsightsSeverity": severity,
           "CtdOperatingSystem": os_name, "CtdInsightUser": random.choice(["svc_scada", "operator1"]),
           "CtdRiskScore": {"Low": 20, "Medium": 50, "High": 75, "Critical": 95}[severity],
           "CtdDeviceExternalId": SITE_ID, "CtdMessage": "%s: %s -> %s" % (name, NAME_BY_IP.get(src, src), NAME_BY_IP.get(dst, dst))}
    sink.claroty(ctd_line(ts, "Insight", name, {"Low": 2, "Medium": 5, "High": 7, "Critical": 10}[severity], ext))


# ---- Claroty REST API shaped data (Asset and Baseline data streams) ----
GHOST_IP = UNKNOWN_SRC
ASSET_DEFS = [  # (id, name, ip, vendor, model, firmware, asset_type__, class_type, risk, criticality__, ghost, mac)
    (101, "KPP-PLC-T2", PLC, "Siemens", "SIMATIC S7-1500 CPU 1516-3 PN/DP", "V2.9", "ePLC", "OT", 62, "eCritical", False, "00:1B:1B:4C:20:12"),
    (102, "KPP-RTU-SS1", RTU, "Schneider Electric", "SCADAPack 57x", "9.12", "eRTU", "OT", 48, "eCritical", False, "00:80:F4:21:0A:30"),
    (103, "KPP-ENG-WS01", ENG, "Dell", "Precision 5860 (TIA Portal V18)", "Windows 10 22H2", "eEndpoint", "IT", 35, "eHigh", False, "A4:BB:6D:10:03:21"),
    (104, "KPP-HMI-01", HMI, "Siemens", "SIMATIC HMI TP1500", "V17.0", "eHMI", "OT", 41, "eHigh", False, "00:1B:1B:2A:30:10"),
    (105, "KPP-HIST-01", HIST, "Dell", "PowerEdge R450 (historian)", "Windows Server 2019", "eEndpoint", "IT", 55, "eMedium", False, "B0:7B:25:44:A1:40"),
    (106, "FGT-KPP-OT01", FGT, "Fortinet", "FortiGate 60F", "FortiOS 7.4.3", "eNetworkDevice", "IT", 28, "eHigh", False, "90:6C:AC:11:22:01"),
    (107, "KPP-USB-KIOSK01", "10.20.0.50", "Generic", "Meta Data Kiosk", "3.4", "eEndpoint", "IT", 22, "eMedium", False, "00:50:56:AB:CD:50"),
    (109, "KPP-ENG-WS02", EWS2, "Dell", "Precision 5860 (TIA Portal V18)", "Windows 10 22H2", "eEndpoint", "IT", 35, "eHigh", False, "A4:BB:6D:10:03:22"),
    (108, GHOST_IP, GHOST_IP, None, None, None, "eEndpoint", "IT", 85, "eLow", True, "00:00:00:00:00:00"),
]
ZONE_ID = {"Level 1 Control Network": 1, "Level 2 Process Network": 2, "Level 3 Control DMZ": 3, "Unclassified": 9}


def _iso(ts):
    return utc(ts).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def asset_snapshot(sink, ts):
    first = _iso(ts - 90 * 86400)
    for aid, name, ip, vendor, model, fw, at, cls, risk, crit, ghost, mac in ASSET_DEFS:
        zone = ZONE_BY_NAME.get(name, "Unclassified")
        a = {"id": aid, "resource_id": "%d-1" % aid, "name": name, "display_name": name, "approved": not ghost,
             "asset_type__": at, "asset_type": {"ePLC": 0, "eRTU": 1, "eEndpoint": 2, "eHMI": 3, "eNetworkDevice": 4}.get(at, 2),
             "class_type": cls, "criticality__": crit, "criticality": {"eLow": 0, "eMedium": 1, "eHigh": 2, "eCritical": 3}[crit],
             "ghost": ghost, "ip": [ip], "ipv4": ip, "mac": [mac], "vendor": vendor, "model": model, "firmware": fw,
             "risk_level": max(0, min(100, risk + random.randint(-3, 3))), "num_alerts": random.randint(0, 6),
             "first_seen": first, "last_seen": _iso(ts), "last_entity_seen": _iso(ts), "last_updated": _iso(ts),
             "timestamp": _iso(ts), "site_id": 1, "site_name": SITE, "network_id": 1,
             "network": {"id": 1, "name": "Default", "resource_id": "1-1", "site_id": 1},
             "virtual_zone_id": ZONE_ID[zone], "virtual_zone_name": zone, "purdue_level": {"Level 1 Control Network": 1.0, "Level 2 Process Network": 2.0, "Level 3 Control DMZ": 3.0}.get(zone, 0.0),
             "valid": True, "parsed": True, "protocol": ["S7COMM"] if name == "KPP-PLC-T2" else ["MODBUS"]}
        sink.cassets(json.dumps(a), ts)


def _entity(ip):
    name = NAME_BY_IP.get(ip, ip)
    zone = ZONE_BY_NAME.get(name, "Unclassified")
    eid = next((d[0] for d in ASSET_DEFS if d[2] == ip), 0)
    return {"asset_name": name, "id": eid, "ipv4": ip, "mac": "00:1B:1B:00:00:%02X" % (eid % 256),
            "resource_id": "%d-1" % eid, "virtual_zone_id": ZONE_ID[zone], "virtual_zone_name": zone}


def baseline_snapshot(sink, ts):
    rows = [(f[2], f[3], f[4], f[5]) for f in FLOWS]
    rows.append((ENG, PLC, "S7COMM", 102))  # the engineering workstation's program download path
    n = 0
    for src, dst, svc, port in rows:
        n += 1
        sink.cbaseline(json.dumps({
            "id": 700 + n, "resource_id": "%d-1" % (700 + n), "approved": True, "category": 3, "category_access": 1,
            "description": "%s : approved communication between %s and %s" % (svc, NAME_BY_IP[src], NAME_BY_IP[dst]),
            "source_asset_id": next(d[0] for d in ASSET_DEFS if d[2] == src),
            "destination_asset_id": next(d[0] for d in ASSET_DEFS if d[2] == dst),
            "source_entity": _entity(src), "destination_entity": _entity(dst),
            "src_port": None, "dst_port": port, "protocol": svc, "frequency": 0, "has_values": False,
            "hash": random.getrandbits(62), "interval": None, "session_state": 3, "site_id": 1,
            "transmission": "TCP / %d" % port, "type": 0, "valid": True,
            "last_seen": _iso(ts), "last_updated": _iso(ts), "timestamp": _iso(ts)}), ts)
    # one baseline entry that is not valid: the unmanaged host reaching the PLC
    sink.cbaseline(json.dumps({
        "id": 799, "resource_id": "799-1", "approved": False, "category": 3, "category_access": 1,
        "description": "S7COMM : communication not in baseline between %s and %s" % (GHOST_IP, NAME_BY_IP[PLC]),
        "source_asset_id": 108, "destination_asset_id": 101, "source_entity": _entity(GHOST_IP), "destination_entity": _entity(PLC),
        "src_port": None, "dst_port": 102, "protocol": "S7COMM", "frequency": 0, "has_values": False,
        "hash": random.getrandbits(62), "interval": None, "session_state": 3, "site_id": 1,
        "transmission": "TCP / 102", "type": 0, "valid": False,
        "last_seen": _iso(ts), "last_updated": _iso(ts), "timestamp": _iso(ts)}), ts)


def claroty_history(sink, now):
    """Backdated CTD health, activity, event and insight records."""
    for k in range(36):  # 3 hours of health checks every 5 minutes
        claroty_health(sink, now - 10800 + k * 300)
    for _ in range(12):
        claroty_activity(sink, now - random.randint(600, 43200))
    for _ in range(60):
        claroty_event(sink, now - random.randint(300, 21600))
    for _ in range(10):
        claroty_insight(sink, now - random.randint(600, 86000))


def fgt_line(ts, flow, action="accept", level="notice", user=None):
    pid, pname, src, dst, svc, dport, proto, sif, dif = flow
    t = utc(ts)
    sent, rcvd = random.randint(200, 20000), random.randint(200, 40000)
    kv = [
        ("date", t.strftime("%Y-%m-%d")), ("time", t.strftime("%H:%M:%S")),
        ("devname", '"%s"' % DEVNAME), ("devid", '"%s"' % DEVID),
        ("eventtime", int(ts * 1e9)), ("tz", '"+0000"'),
        ("logid", '"0000000013"'), ("type", '"traffic"'), ("subtype", '"forward"'),
        ("level", '"%s"' % level), ("vd", '"root"'),
        ("srcip", src), ("srcport", random.randint(40000, 60000)), ("srcintf", '"%s"' % sif),
        ("srcintfrole", '"lan"'), ("dstip", dst), ("dstport", dport),
        ("dstintf", '"%s"' % dif), ("dstintfrole", '"lan"'),
        ("sessionid", random.randint(1000000, 9999999)), ("proto", proto),
        ("action", '"%s"' % action), ("policyid", pid), ("policytype", '"policy"'),
        ("policyname", '"%s"' % pname), ("service", '"%s"' % svc),
        ("trandisp", '"noop"'), ("duration", random.randint(1, 300)),
        ("sentbyte", sent), ("rcvdbyte", rcvd), ("sentpkt", sent // 100 + 1), ("rcvdpkt", rcvd // 100 + 1),
    ]
    if user:
        kv.insert(18, ("user", '"%s"' % user))
    return "<189>" + " ".join("%s=%s" % kv_ for kv_ in kv)


# Real public addresses so the pipeline's GeoIP and ASN lookups resolve (source/destination geo and organization).
# (ip, FortiGate country name)
ATTACKERS = [
    ("185.220.101.34", "Germany"), ("45.155.205.233", "Russian Federation"), ("61.177.172.140", "China"),
    ("218.92.0.107", "China"), ("89.248.165.52", "Netherlands"), ("80.82.77.139", "Netherlands"),
    ("162.142.125.10", "United States"), ("141.98.11.37", "Lithuania"), ("91.240.118.172", "Russian Federation"),
    ("1.234.83.11", "Korea, Republic of"), ("200.98.137.100", "Brazil"), ("103.203.57.4", "India"),
    ("5.188.62.76", "Russian Federation"), ("198.235.24.130", "United States"),
]
CLOUD = [
    ("8.8.8.8", "United States", "DNS", 53, 17), ("13.107.42.14", "United States", "HTTPS", 443, 6),
    ("52.84.150.10", "United States", "HTTPS", 443, 6), ("104.18.32.47", "United States", "HTTPS", 443, 6),
    ("17.253.144.10", "United States", "HTTPS", 443, 6), ("85.10.240.250", "Germany", "HTTPS", 443, 6),
    ("193.99.144.85", "Germany", "HTTPS", 443, 6), ("1.1.1.1", "Australia", "DNS", 53, 17),
    ("129.6.15.28", "United States", "NTP", 123, 17),
]
PROBE_PORTS = [("RDP", 3389), ("SSH", 22), ("TELNET", 23), ("S7", 102), ("MODBUS", 502), ("SMB", 445),
               ("HTTP", 80), ("HTTPS", 443)]
IPS_SIGS = [  # (attack, attackid, severity, service, port)
    ("S7.Comm.PLC.Stop.CPU", 59390, "critical", "S7", 102), ("Modbus.TCP.Write.Multiple.Coils", 52318, "high", "MODBUS", 502),
    ("MS.RDP.BlueKeep.Remote.Code.Execution", 49010, "critical", "RDP", 3389),
    ("SSH.Brute.Force.Login", 38292, "medium", "SSH", 22), ("Siemens.SIMATIC.S7.Buffer.Overflow", 55971, "high", "S7", 102),
    ("Telnet.Login.Brute.Force", 12053, "medium", "TELNET", 23), ("HTTP.URI.SQL.Injection", 15622, "high", "HTTP", 80),
    ("DNP3.Unsolicited.Response.Flood", 56007, "high", "DNP3", 20000),
]
WEB_BLOCKS = [("update-cdn-secure.top", "/dl/patch.exe", "Malicious Websites", 26),
              ("free-vpn-proxy.net", "/", "Proxy Avoidance", 59), ("kpp-portal-login.xyz", "/signin", "Phishing", 61),
              ("cdn.torrent-tracker.org", "/announce", "Peer-to-peer File Sharing", 40),
              ("onedrive-share-docs.ru", "/view", "Phishing", 61)]
VIRUS_NAMES = [("W32/Agent.ZX!tr", "setup_update.exe"), ("EICAR_TEST_FILE", "eicar.com"),
               ("W32/Kryptik.HNT!tr", "TurbineGovernor_patch.zip"), ("VBA/Agent.TD!tr", "shift_report.xlsm")]
APP_BLOCKS = [("BitTorrent", "P2P", "high"), ("TeamViewer", "Remote.Access", "elevated"),
              ("AnyDesk", "Remote.Access", "elevated"), ("Tor", "Proxy", "critical"), ("Dropbox", "Storage.Backup", "medium")]
VPN_USERS = ["contractor.hale", "vendor.siemens", "a.lindqvist", "m.virtanen", "admin", "svc_backup", "j.smith"]


IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def fgt_event(ts, logid, typ, subtype, level, extra):
    t = utc(ts)
    kv = [("date", t.strftime("%Y-%m-%d")), ("time", t.strftime("%H:%M:%S")),
          ("devname", '"%s"' % DEVNAME), ("devid", '"%s"' % DEVID), ("eventtime", int(ts * 1e9)), ("tz", '"+0000"'),
          ("logid", '"%s"' % logid), ("type", '"%s"' % typ), ("subtype", '"%s"' % subtype),
          ("level", '"%s"' % level), ("vd", '"root"')]
    for k, v in extra:
        kv.append((k, v if not isinstance(v, str) or IPV4.match(v) else '"%s"' % v))
    return "<188>" + " ".join("%s=%s" % kv_ for kv_ in kv)


def _fgt_flow(src, sport, sif, srole, dst, dif, drole, dport, proto, svc, extra_country=None):
    kv = [("srcip", src), ("srcport", sport), ("srcintf", sif), ("srcintfrole", srole)]
    if extra_country:
        kv.append(("srccountry", extra_country))
    kv += [("dstip", dst), ("dstport", dport), ("dstintf", dif), ("dstintfrole", drole)]
    return kv


def fgt_external(ts):
    """Internet-facing traffic, UTM detections and device events so the FortiGate overview has failures and geography."""
    r = random.random() * 100
    internal = random.choice([PLC, HMI, ENG, HIST, RTU, FGT])
    atk, atk_c = random.choice(ATTACKERS)
    sess = random.randint(1000000, 9999999)
    if r < 24:  # inbound probe, denied at the WAN
        svc, dport = random.choice(PROBE_PORTS)
        return fgt_event(ts, "0000000013", "traffic", "forward", "warning", _fgt_flow(
            atk, random.randint(1024, 65000), "port1", "wan", internal, "port3", "lan", dport, 6, svc, atk_c) + [
            ("sessionid", sess), ("proto", 6), ("action", "deny"), ("policyid", 0), ("policytype", "policy"),
            ("policyname", "Implicit Deny"), ("service", svc), ("trandisp", "noop"), ("duration", 0),
            ("sentbyte", 0), ("rcvdbyte", 0), ("sentpkt", 1), ("rcvdpkt", 0), ("crscore", 30), ("craction", 131072),
            ("crlevel", "high")])
    if r < 46:  # outbound to the internet (updates, DNS, NTP, cloud)
        ip, c, svc, dport, proto = random.choice(CLOUD)
        src = random.choice([HIST, ENG, HMI])
        denied = random.random() < 0.08
        sent, rcvd = random.randint(200, 8000), random.randint(500, 90000)
        return fgt_event(ts, "0000000013", "traffic", "forward", "warning" if denied else "notice", [
            ("srcip", src), ("srcport", random.randint(40000, 60000)), ("srcintf", "port2"), ("srcintfrole", "lan"),
            ("dstip", ip), ("dstcountry", c), ("dstport", dport), ("dstintf", "port1"), ("dstintfrole", "wan"),
            ("sessionid", sess), ("proto", proto), ("action", "deny" if denied else "accept"), ("policyid", 20),
            ("policytype", "policy"), ("policyname", "OT-Outbound-Updates"), ("service", svc),
            ("trandisp", "snat"), ("duration", random.randint(1, 120)), ("sentbyte", 0 if denied else sent),
            ("rcvdbyte", 0 if denied else rcvd), ("sentpkt", 1 if denied else sent // 100 + 1),
            ("rcvdpkt", 0 if denied else rcvd // 100 + 1)])
    if r < 54:  # implicit deny of an internal host trying something it should not
        src = random.choice([ENG, HMI, HIST])
        ip, c, svc, dport, proto = random.choice(CLOUD)
        return fgt_event(ts, "0000000013", "traffic", "forward", "warning", [
            ("srcip", src), ("srcport", random.randint(40000, 60000)), ("srcintf", "port2"), ("srcintfrole", "lan"),
            ("dstip", ip), ("dstcountry", c), ("dstport", 25), ("dstintf", "port1"), ("dstintfrole", "wan"),
            ("sessionid", sess), ("proto", 6), ("action", "deny"), ("policyid", 0), ("policytype", "policy"),
            ("policyname", "Implicit Deny"), ("service", "SMTP"), ("trandisp", "noop"), ("duration", 0),
            ("sentbyte", 0), ("rcvdbyte", 0)])
    if r < 64:  # IPS signature hit
        attack, aid, sev, svc, dport = random.choice(IPS_SIGS)
        dropped = random.random() < 0.8
        return fgt_event(ts, "0419016384", "utm", "ips", "alert" if sev == "critical" else "warning", [
            ("eventtype", "signature"), ("severity", sev), ("srcip", atk), ("srccountry", atk_c), ("srcintf", "port1"),
            ("srcintfrole", "wan"), ("dstip", internal), ("dstintf", "port3"), ("dstintfrole", "lan"),
            ("sessionid", sess), ("action", "dropped" if dropped else "detected"), ("proto", 6), ("service", svc),
            ("policyid", 11), ("attack", attack), ("srcport", random.randint(1024, 65000)), ("dstport", dport),
            ("direction", "incoming"), ("attackid", aid), ("profile", "OT-IPS"),
            ("ref", "http://www.fortinet.com/ids/VID%d" % aid), ("incidentserialno", random.randint(10**8, 10**9)),
            ("msg", "industrial: %s," % attack), ("crscore", 50 if sev == "critical" else 30), ("craction", 4096),
            ("crlevel", "critical" if sev == "critical" else "high")])
    if r < 72:  # web filter block
        host, url, cat, catn = random.choice(WEB_BLOCKS)
        ip, c, _, _, _ = random.choice(CLOUD)
        return fgt_event(ts, "0316013056", "utm", "webfilter", "warning", [
            ("eventtype", "ftgd_blk"), ("policyid", 20), ("sessionid", sess), ("srcip", random.choice([ENG, HIST, HMI])),
            ("srcport", random.randint(40000, 60000)), ("srcintf", "port2"), ("srcintfrole", "lan"), ("dstip", ip),
            ("dstcountry", c), ("dstport", 443), ("dstintf", "port1"), ("dstintfrole", "wan"), ("proto", 6),
            ("service", "HTTPS"), ("hostname", host), ("profile", "OT-Web"), ("action", "blocked"), ("reqtype", "direct"),
            ("url", "https://%s%s" % (host, url)), ("cat", catn), ("catdesc", cat),
            ("msg", "URL belongs to a denied category in policy")])
    if r < 76:  # antivirus
        vname, fname = random.choice(VIRUS_NAMES)
        return fgt_event(ts, "0211008192", "utm", "virus", "warning", [
            ("eventtype", "infected"), ("virus", vname), ("filename", fname), ("dtype", "Virus"), ("policyid", 20),
            ("sessionid", sess), ("srcip", random.choice([ENG, HIST])), ("srcintf", "port2"), ("srcintfrole", "lan"),
            ("dstip", "85.10.240.250"), ("dstcountry", "Germany"), ("dstport", 443), ("dstintf", "port1"),
            ("dstintfrole", "wan"), ("proto", 6), ("service", "HTTPS"), ("profile", "OT-AV"), ("action", "blocked"),
            ("direction", "incoming"), ("ref", "http://www.fortinet.com/ve?vn=%s" % vname),
            ("msg", "File is infected."), ("crscore", 50), ("craction", 2), ("crlevel", "critical")])
    if r < 82:  # application control
        app, cat, risk = random.choice(APP_BLOCKS)
        ip, c, _, _, _ = random.choice(CLOUD)
        return fgt_event(ts, "1059028704", "utm", "app-ctrl", "warning", [
            ("eventtype", "signature"), ("appid", random.randint(10000, 50000)), ("srcip", random.choice([ENG, HIST, HMI])),
            ("srcintf", "port2"), ("srcintfrole", "lan"), ("dstip", ip), ("dstcountry", c), ("dstintf", "port1"),
            ("dstintfrole", "wan"), ("proto", 6), ("service", "HTTPS"), ("policyid", 20), ("sessionid", sess),
            ("applist", "OT-AppControl"), ("action", "block"), ("app", app), ("appcat", cat), ("apprisk", risk),
            ("srcport", random.randint(40000, 60000)), ("dstport", 443), ("msg", "%s: %s," % (cat, app))])
    if r < 89:  # SSL VPN login failure
        user = random.choice(VPN_USERS)
        return fgt_event(ts, "0101039426", "event", "vpn", "alert", [
            ("logdesc", "SSL VPN login fail"), ("action", "ssl-login-fail"), ("tunneltype", "ssl-web"),
            ("tunnelid", 0), ("remip", atk), ("user", user), ("group", "N/A"), ("dst_host", "N/A"),
            ("reason", random.choice(["sslvpn_login_permission_denied", "sslvpn_login_unknown_user",
                                      "sslvpn_login_password_expired"])),
            ("msg", "SSL user failed to logged in")])
    if r < 92:  # SSL VPN tunnel up (success)
        user = random.choice(["a.lindqvist", "vendor.siemens", "contractor.hale"])
        ip, c = random.choice(ATTACKERS[6:9])
        return fgt_event(ts, "0101039424", "event", "vpn", "information", [
            ("logdesc", "SSL VPN tunnel up"), ("action", "tunnel-up"), ("tunneltype", "ssl-tunnel"),
            ("tunnelid", random.randint(1, 99999)), ("remip", ip), ("user", user), ("group", "OT-Remote-Access"),
            ("tunnelip", "10.212.134.%d" % random.randint(2, 100)), ("status", "success"),
            ("msg", "SSL tunnel established")])
    if r < 96:  # admin login failure
        return fgt_event(ts, "0100032002", "event", "system", "alert", [
            ("logdesc", "Admin login failed"), ("sn", "0"), ("user", random.choice(["admin", "root", "fgtadmin", "n.aaltonen"])),
            ("ui", "https(%s)" % atk), ("method", "https"), ("srcip", atk), ("dstip", FGT), ("action", "login"),
            ("status", "failed"), ("reason", random.choice(["name_invalid", "passwd_invalid"])),
            ("msg", "Administrator admin login failed from https(%s) because of invalid user name" % atk)])
    if r < 98:  # interface or HA events
        return random.choice([
            fgt_event(ts, "0100020099", "event", "system", "warning", [
                ("logdesc", "Interface status changed"), ("action", "interface-stat-change"), ("status", "DOWN"),
                ("interface", "port1"), ("msg", "Link monitor: interface port1 was DOWN")]),
            fgt_event(ts, "0100020100", "event", "system", "notice", [
                ("logdesc", "Interface status changed"), ("action", "interface-stat-change"), ("status", "UP"),
                ("interface", "port1"), ("msg", "Link monitor: interface port1 was UP")])])
    return fgt_event(ts, "0100044546", "event", "system", "information", [  # config change
        ("logdesc", "Attribute configured"), ("user", random.choice(["n.aaltonen", "admin"])), ("ui", "GUI(10.20.3.21)"),
        ("action", "Edit"), ("cfgtid", random.randint(10**6, 10**7)), ("cfgpath", "firewall.policy"),
        ("cfgobj", str(random.choice([10, 11, 12, 17, 20]))), ("cfgattr", "logtraffic[disable->all]"),
        ("msg", "Edit firewall.policy")])


def ep_doc(ts, host, category, action, user=None, proc=None, src=None, dst=None, dport=None, outcome="success", cmd=None):
    d = {
        "@timestamp": utc(ts).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(ts * 1000) % 1000),
        "event": {"category": [category], "action": action, "outcome": outcome,
                  "kind": "event", "dataset": "ot_endpoint.events"},
        "host": {"name": host, "ip": [ASSETS[host]], "os": {"family": "windows"}},
        "data_stream": {"type": "logs", "dataset": "ot_endpoint.events", "namespace": "default"},
        # Agent host metadata overwrites host.*, so carry the OT asset name in a label too.
        "labels": {"site": SITE, "demo": "ot-demo", "asset_name": host},
    }
    if user:
        d["user"] = {"name": user, "domain": "KPP"}
    if proc:
        d["process"] = {"name": proc, "pid": random.randint(1000, 9000)}
        if cmd:
            d["process"]["command_line"] = cmd
    if src:
        d["source"] = {"ip": src}
    if dst:
        d["destination"] = {"ip": dst, "port": dport}
        d["network"] = {"transport": "tcp"}
    return json.dumps(d)


KIOSK_PID = 4312
KIOSK_VERSION = "4.7.3.2454"


def kiosk_line(ts, code, log_type, body, sev=6):
    """One OPSWAT MetaDefender Kiosk syslog line (BSD format, product ID MDM):
    <PRI> ISO8601 host MDM[pid] eventCode='...', logType='...', message
    The header layout follows the OPSWAT documentation. The JSON message bodies for file, session and device
    events are ASSUMED (not publicly documented): validate against a real export from the customer's kiosk."""
    pri = 1 * 8 + sev  # facility user (1)
    stamp = utc(ts).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    if isinstance(body, dict):
        body = json.dumps(body, separators=(",", ":"))
    return "<%d> %s %s MDM[%d] eventCode='%s', logType='%s', %s" % (pri, stamp, KIOSK, KIOSK_PID, code, log_type, body)


def _ts(ts):
    return utc(ts).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(ts * 1000) % 1000)


def _api_ts(ts):
    """Defender API timestamp style, 7 fractional digits."""
    return utc(ts).strftime("%Y-%m-%dT%H:%M:%S.") + "%07dZ" % (int(ts * 10**7) % 10**7)


def defender_alert_doc(ts, host, user, title, description, severity="Informational", status="Resolved",
                       classification="FalsePositive", determination="Other", investigation="Benign",
                       category="Discovery", assigned="Automated investigation", incident=448201, threat=None,
                       source="WindowsDefenderAtp", ip=None):
    """Raw Microsoft Defender for Endpoint alert as returned by the API (microsoft_defender_endpoint.log input)."""
    resolved = status == "Resolved"
    return json.dumps({
        "id": "da637%015d_%d" % (random.randint(1, 10**15 - 1), random.randint(10**8, 10**9)),
        "incidentId": incident, "investigationId": incident - 440000, "assignedTo": assigned,
        "severity": severity, "status": status,
        "classification": classification if resolved else None,
        "determination": determination if resolved else None,
        "investigationState": investigation, "detectionSource": source, "category": category,
        "threatFamilyName": threat, "title": title, "description": description,
        "alertCreationTime": _api_ts(ts), "firstEventTime": _api_ts(ts - 30), "lastEventTime": _api_ts(ts - 5),
        "lastUpdateTime": _api_ts(ts + 2), "resolvedTime": _api_ts(ts + 2) if resolved else None,
        "machineId": hashlib.sha1(host.encode()).hexdigest(), "computerDnsName": host,
        "rbacGroupName": None, "aadTenantId": "7c1d0a3e-d66c-4c7e-9e30-40034eb7c6f3", "relatedUser": None,
        "comments": [],
        "evidence": ({"entityType": "Ip", "ipAddress": ip, "accountName": user, "domainName": "KPP"} if ip else
                     {"entityType": "User", "accountName": user, "domainName": "KPP"})})


def servicenow_doc(ts, state_value, state_display, assigned_to=None, close_notes=None, number=INCIDENT_NO,
                   short="Claroty CTD: PLC Program Download Detected on KPP-PLC-T2 (Karins Power Plant)",
                   priority=(3, "3 - Moderate"), group=("ot-security", "OT Security"), opened_ts=None,
                   category=("ot_security", "OT security"), close_code="False positive"):
    """Raw ServiceNow incident record (display values and values per field) for the servicenow.event pipeline."""
    def dv(v, d=None):
        return {"display_value": d if d is not None else str(v), "value": str(v)}

    def stamp(t):
        x = utc(t).strftime("%Y-%m-%d %H:%M:%S")
        return {"display_value": x, "value": x}
    sys_id = hashlib.md5(number.encode()).hexdigest()
    opened = opened_ts if opened_ts is not None else ts - 60
    rec = {
        "table_name": "incident", "sys_id": dv(sys_id), "number": dv(number), "short_description": dv(short),
        "description": dv(short), "category": dv(*category),
        "state": dv(state_value, state_display), "priority": dv(priority[0], priority[1]),
        "urgency": dv(2, "2 - Medium"), "impact": dv(2, "2 - Medium"), "active": dv("true" if state_value not in (6, 7) else "false"),
        "assignment_group": dv(group[0], group[1]),
        "assigned_to": dv(assigned_to or "", assigned_to or ""),
        "caller_id": dv("claroty.integration", "Claroty CTD"),
        "opened_by": dv("claroty.integration", "Claroty CTD"), "opened_at": stamp(opened),
        "sys_created_on": stamp(opened), "sys_created_by": dv("claroty.integration"),
        "sys_updated_on": stamp(ts), "sys_updated_by": dv(assigned_to or "claroty.integration"),
        "close_notes": dv(close_notes or "", close_notes or ""), "close_code": dv(close_code if close_notes else "", close_code if close_notes else ""),
        "closed_at": stamp(ts) if close_notes and state_value in (6, 7) else dv("", ""),
    }
    return json.dumps(rec)


def _fl(x, nd=2):
    return round(float(x), nd)  # always a float so dynamic mapping picks a float type


def plc_values(ts, ov=None):
    """Process values read from the turbine PLC. During a setpoint override the speed, vibration and
    temperature drift towards the new setpoint over `ramp` seconds (parameter-modification storyline)."""
    sp, frac = 3000.0, 0.0
    if ov and ov["start"] <= ts <= ov["until"]:
        sp = float(ov["setpoint"])
        frac = min(1.0, (ts - ov["start"]) / float(ov.get("ramp", 90)))
    return {
        "turbine_speed_rpm": _fl(3000.0 + (sp - 3000.0) * frac + random.gauss(0, 3)),
        "governor_setpoint_rpm": _fl(sp),
        "bearing_temp_c": _fl(68.0 + 8.0 * frac + random.gauss(0, 0.6)),
        "vibration_mm_s": _fl(2.1 + 2.8 * frac + random.gauss(0, 0.12)),
        "load_mw": _fl(48.0 + 6.0 * frac + random.gauss(0, 0.4)),
    }


def plc4x_doc(ts, vals):
    """Telemetry polled from KPP-PLC-T2 by a PLC4X S7 driver (sample data, no dedicated Elastic integration)."""
    return json.dumps({
        "@timestamp": _ts(ts),
        "data_stream": {"type": "logs", "dataset": "plc4x.telemetry", "namespace": "default"},
        "event": {"kind": "metric", "category": ["process"], "type": ["info"], "dataset": "plc4x.telemetry"},
        "labels": {"site": SITE, "demo": "ot-demo", "asset_name": "KPP-PLC-T2"},
        "observer": {"product": "PLC4X S7 driver", "vendor": "Apache PLC4X"},
        "plc4x": {"driver": "s7", "connection": "s7://%s:102" % PLC, "tags": vals},
        "tags": ["sample-data"],
    })


def opcua_doc(ts):
    """Substation values read from KPP-RTU-SS1 through an OPC UA client (sample data)."""
    return json.dumps({
        "@timestamp": _ts(ts),
        "data_stream": {"type": "logs", "dataset": "opcua.telemetry", "namespace": "default"},
        "event": {"kind": "metric", "category": ["process"], "type": ["info"], "dataset": "opcua.telemetry"},
        "labels": {"site": SITE, "demo": "ot-demo", "asset_name": "KPP-RTU-SS1"},
        "observer": {"product": "OPC UA client", "vendor": "OPC Foundation"},
        "opcua": {"endpoint": "opc.tcp://%s:4840" % HIST, "status_code": "Good", "tags": {
            "breaker_closed": True,
            "bus_voltage_kv": _fl(132.0 + random.gauss(0, 0.3)),
            "line_current_a": _fl(210.0 + random.gauss(0, 4)),
            "frequency_hz": _fl(50.0 + random.gauss(0, 0.015), 3)}},
        "tags": ["sample-data"],
    })


def read_override(path):
    try:
        with open(path) as f:
            ov = json.load(f)
        return ov if ov.get("until", 0) > time.time() else None
    except (OSError, ValueError):
        return None


def telemetry_tick(sink, ts, ov=None):
    sink.plc4x(plc4x_doc(ts, plc_values(ts, ov)))
    sink.opcua(opcua_doc(ts))


DEFENDER_BACKGROUND = [  # (title, description, severity, status, classification, determination, investigation, host, user, category, assigned)
    ("Unsigned driver loaded", "A driver without a valid signature was loaded by the HMI runtime.", "Informational", "Resolved", "FalsePositive", "Other", "Benign", "KPP-HMI-01", "svc_scada", "SuspiciousActivity", "Automated investigation"),
    ("Remote Desktop connection from jump host", "RDP session from the control DMZ jump host matches an allowed administration path.", "Informational", "Resolved", "FalsePositive", "Other", "Benign", "KPP-HIST-01", "svc_scada", "LateralMovement", "Automated investigation"),
    ("Suspicious PowerShell command line", "PowerShell was run with an encoded command. Confirmed as an approved security test.", "Low", "Resolved", "TruePositive", "SecurityTesting", "SuccessfullyRemediated", "KPP-HMI-01", "operator1", "Execution", "n.aaltonen@kpp.example"),
    ("Software installer launched from removable media", "An installer ran from removable media that was scanned at the Meta Data Kiosk.", "Informational", "Resolved", "FalsePositive", "Other", "Benign", "KPP-ENG-WS01", "m.virtanen", "Execution", "Automated investigation"),
    ("Potentially unwanted application detected", "A bundled utility on the historian was flagged as potentially unwanted. Under review.", "Low", "InProgress", "Unknown", "NotAvailable", "Running", "KPP-HIST-01", "svc_scada", "UnwantedSoftware", "OT SOC analyst"),
]

# More alerts for a 7 day history: (title, description, severity, category, threat family, detection source, hosts, users)
DEFENDER_EXTRA = [
    ("Malware detected on removable media", "A file copied from a USB device matched a known trojan signature and was quarantined.", "High", "Malware", "Trojan:Win32/Wacatac", "WindowsDefenderAv", ["KPP-ENG-WS01", "KPP-USB-KIOSK01"], ["m.virtanen", "j.koskinen"]),
    ("Ransomware behavior detected", "Rapid file renames with a new extension were blocked on the file server.", "High", "Ransomware", "Ransom:Win32/Cerber", "WindowsDefenderAtp", ["KPP-FILE-01", "KPP-OFFICE-PC07"], ["s.laine", "svc_backup"]),
    ("Credential dumping attempt", "Access to LSASS memory was blocked.", "High", "CredentialAccess", "HackTool:Win32/Mimikatz", "WindowsDefenderAtp", ["KPP-HIST-01", "KPP-OFFICE-PC12"], ["svc_scada", "j.smith"]),
    ("Suspicious scheduled task created", "A scheduled task running an unsigned binary was created outside a change window.", "Medium", "Persistence", None, "WindowsDefenderAtp", ["KPP-HMI-01", "KPP-HIST-01"], ["operator1", "svc_scada"]),
    ("Suspicious network connection to rare external host", "The host connected to an IP address never seen in this environment.", "Medium", "CommandAndControl", None, "CustomTI", ["KPP-OFFICE-PC07", "KPP-OFFICE-PC12"], ["j.smith", "s.laine"]),
    ("Office application spawned a script interpreter", "A macro-enabled workbook launched PowerShell.", "Medium", "Execution", "Trojan:O97M/Obfuse", "WindowsDefenderAv", ["KPP-OFFICE-PC07", "KPP-FILE-01"], ["s.laine", "j.smith"]),
    ("Anomalous account activity", "A service account signed in from multiple hosts within a short interval.", "Medium", "InitialAccess", None, "AAD", ["KPP-FILE-01", "KPP-HIST-01"], ["svc_backup", "svc_scada"]),
    ("Port scan from internal host", "The host probed many ports on the control network segment.", "Medium", "Discovery", None, "WindowsDefenderAtp", ["KPP-ENG-WS01", "KPP-OFFICE-PC12"], ["a.lindqvist", "j.smith"]),
    ("Unsigned driver loaded", "A driver without a valid signature was loaded.", "Low", "SuspiciousActivity", None, "WindowsDefenderAtp", ["KPP-HMI-01", "KPP-HIST-01"], ["svc_scada"]),
    ("Remote access tool installed", "A remote administration tool was installed by a standard user.", "Low", "UnwantedSoftware", "PUA:Win32/RemoteAdmin", "WindowsDefenderAv", ["KPP-OFFICE-PC07", "KPP-ENG-WS01"], ["j.smith", "m.virtanen"]),
    ("Browser extension flagged", "An unapproved browser extension was detected.", "Informational", "SuspiciousActivity", None, "WindowsDefenderAtp", ["KPP-OFFICE-PC07", "KPP-OFFICE-PC12"], ["s.laine", "j.smith"]),
    ("Engineering software communicated with an industrial controller", "Siemens TIA Portal connected to a PLC. Matches an allowed engineering workflow.", "Informational", "Discovery", None, "WindowsDefenderAtp", ["KPP-ENG-WS01"], ["a.lindqvist"]),
]


def api_history(sink, now):
    """Backdated Defender alerts and ServiceNow incidents so the panels look lived-in."""
    for i, m in enumerate(DEFENDER_BACKGROUND):
        for k in range(2):
            ts = now - (1800 + i * 5400 + k * 25000 + random.randint(0, 1800))
            sink.defender(defender_alert_doc(ts, m[7], m[8], m[0], m[1], severity=m[2], status=m[3],
                                             classification=m[4], determination=m[5], investigation=m[6],
                                             category=m[9], assigned=m[10], incident=448100 + i * 10 + k), ts)
    for i, m in enumerate(DEFENDER_EXTRA):
        for k in range(random.randint(2, 5)):
            ts = now - random.uniform(3600, 7 * 86400)
            sev = m[2]
            roll = random.random()
            if sev in ("High", "Medium") and roll < 0.35:
                status, cls, det, inv, who = "New", "Unknown", "NotAvailable", "Queued", None
            elif roll < 0.55:
                status, cls, det, inv, who = "InProgress", "Unknown", "NotAvailable", "Running", "OT SOC analyst"
            elif sev in ("High", "Medium") and roll < 0.85:
                status, cls, det, inv, who = "Resolved", "TruePositive", "Malware" if m[4] else "SecurityTesting", "SuccessfullyRemediated", "n.aaltonen@kpp.example"
            else:
                status, cls, det, inv, who = "Resolved", "FalsePositive", "Other", "Benign", "Automated investigation"
            sink.defender(defender_alert_doc(ts, random.choice(m[6]), random.choice(m[7]), m[0], m[1], severity=sev,
                                             status=status, classification=cls, determination=det, investigation=inv,
                                             category=m[3], assigned=who, incident=448300 + i * 10 + k, threat=m[4],
                                             source=m[5]), ts)
    H = 3600.0
    incidents = [  # (number, short description, priority, group, [(hours ago, state, assignee, close note)])
        ("INC0010188", "FortiGate FGT-KPP-OT01: firmware advisory review", (3, "3 - Moderate"),
         ("network-ops", "Network Operations"),
         [(21, (1, "New"), None, None), (20.5, (2, "In Progress"), "N. Aaltonen", None),
          (18, (7, "Closed"), "N. Aaltonen", "Advisory reviewed, no action needed for the installed firmware.")]),
        ("INC0010197", "Claroty CTD: Unusual Modbus write from KPP-HMI-01 (false positive)", (3, "3 - Moderate"),
         ("ot-security", "OT Security"),
         [(9, (1, "New"), None, None), (8.8, (2, "In Progress"), "J. Koskinen", None),
          (8.5, (7, "Closed"), "J. Koskinen", "Operator setpoint adjustment confirmed with the shift lead.")]),
        ("INC0010203", "KPP-HIST-01: Defender alert, potentially unwanted application", (2, "2 - High"),
         ("ot-security", "OT Security"),
         [(5, (1, "New"), None, None), (4.5, (2, "In Progress"), "OT SOC analyst", None)]),
        ("INC0010209", "Meta Data Kiosk: scan engine signature update", (4, "4 - Low"),
         ("ot-security", "OT Security"),
         [(14, (1, "New"), None, None), (13, (3, "On Hold"), "S. Laine", None)]),
        ("INC0010214", "Claroty CTD: S7 Unauthorized Read/Scan from KPP-ENG-WS01 (maintenance window)", (3, "3 - Moderate"),
         ("ot-security", "OT Security"),
         [(2.2, (1, "New"), None, None), (2.1, (2, "In Progress"), "OT SOC analyst", None),
          (1.8, (7, "Closed"), "OT SOC analyst", "False positive: scheduled maintenance, known-good workstation.")]),
    ]
    P1, P2, P3, P4 = (1, "1 - Critical"), (2, "2 - High"), (3, "3 - Moderate"), (4, "4 - Low")
    GRP = {"ot": ("ot-security", "OT Security"), "net": ("network-ops", "Network Operations"),
           "svc": ("service-desk", "Service Desk"), "soc": ("it-security", "IT Security")}
    CAT = {"sec": ("ot_security", "OT security"), "net": ("network", "Network"), "hw": ("hardware", "Hardware"),
           "sw": ("software", "Software"), "inq": ("inquiry", "Inquiry / Help")}
    templates = [  # (short description, priority, group, category, people)
        ("Claroty CTD: PLC Program Download Detected on KPP-PLC-T2", P1, "ot", "sec", ["J. Koskinen", "S. Laine"]),
        ("Defender: ransomware behavior on KPP-FILE-01", P1, "soc", "sec", ["N. Aaltonen", "T. Berg"]),
        ("Defender: credential dumping attempt on KPP-HIST-01", P2, "ot", "sec", ["J. Koskinen"]),
        ("FortiGate: repeated SSL VPN login failures from external hosts", P2, "net", "net", ["N. Aaltonen", "R. Lund"]),
        ("FortiGate: IPS critical signature on port1", P2, "net", "net", ["R. Lund"]),
        ("FortiGate: interface port1 flapping", P3, "net", "net", ["R. Lund", "N. Aaltonen"]),
        ("Claroty CTD: new unmanaged asset 10.20.9.77 seen on control network", P3, "ot", "sec", ["S. Laine", "J. Koskinen"]),
        ("Meta Data Kiosk: file blocked, policy violation", P3, "ot", "sec", ["S. Laine"]),
        ("KPP-HMI-01 slow to respond", P4, "svc", "hw", ["E. Voss", "M. Haas"]),
        ("Request: remote access for vendor Siemens", P4, "svc", "inq", ["E. Voss"]),
        ("Historian disk usage above 85 percent", P3, "svc", "hw", ["M. Haas", "E. Voss"]),
        ("Patch window request for KPP-ENG-WS01", P4, "svc", "sw", ["M. Haas"]),
        ("Defender: PUA on engineering workstation", P3, "soc", "sw", ["T. Berg", "N. Aaltonen"]),
    ]
    notes = ["Resolved after investigation, no further action.", "Confirmed benign, tuned the detection.",
             "Remediated and verified with the owner.", "Duplicate of an existing incident.", "Vendor fix applied."]
    for j in range(26):
        short, prio, g, c, people = random.choice(templates)
        number = "INC00%d" % (10100 + j * 3)
        opened_h = random.uniform(2, 14 * 24)
        who = random.choice(people)
        steps = [(opened_h, (1, "New"), None, None), (opened_h - random.uniform(0.1, 1.5), (2, "In Progress"), who, None)]
        roll = random.random()
        if roll < 0.2:
            steps.append((max(opened_h - random.uniform(1.5, 6), 0.3), (3, "On Hold"), who, None))
        elif roll < 0.75:
            dur = random.uniform(1, 40) if prio[0] > 1 else random.uniform(0.5, 6)
            steps.append((max(opened_h - dur, 0.2), (random.choice([6, 7]), "Resolved"), who, random.choice(notes)))
            if steps[-1][1][0] == 7:
                steps[-1] = (steps[-1][0], (7, "Closed"), who, steps[-1][3])
        steps = [st for st in steps if st[0] > 0.1]
        incidents.append((number, short, prio, GRP[g], steps, CAT[c]))
    for number, short, prio, grp, steps, *cat in incidents:
        opened = now - steps[0][0] * H
        for hrs, (sv, sd), who, note in steps:
            t = now - hrs * H
            sink.servicenow(servicenow_doc(t, sv, sd, assigned_to=who, close_notes=note, number=number,
                                           short=short, priority=prio, group=grp, opened_ts=opened,
                                           **({"category": cat[0]} if cat else {}),
                                           close_code="Solved (Permanently)" if sv == 6 else "False positive"), t)


class Sink:
    """Handles TCP (reconnecting), UDP and file output, or stdout in dry-run."""

    def __init__(self, a):
        self.a, self.tcp, self.udp, self.f, self.pf, self.of = a, None, None, None, None, None
        self.samples = {}
        if not a.dry_run:
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            d = os.path.dirname(a.endpoint_file)
            os.makedirs(d, exist_ok=True)
            self.f = open(a.endpoint_file, "a", buffering=1)
            self.pf = open(a.plc4x_file, "a", buffering=1)
            self.of = open(a.opcua_file, "a", buffering=1)

    def _connect(self):
        while True:
            try:
                s = socket.create_connection((self.a.host, self.a.claroty_port), timeout=10)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.tcp = s
                return
            except OSError as e:
                print("claroty tcp connect failed (%s), retrying in 5s" % e, file=sys.stderr)
                time.sleep(5)

    def claroty(self, line):
        if self.a.dry_run:
            return self._dry("claroty", line)
        for _ in range(3):
            try:
                if not self.tcp:
                    self._connect()
                self.tcp.sendall((line + "\n").encode())
                return
            except OSError:
                try:
                    self.tcp.close()
                except Exception:
                    pass
                self.tcp = None
        print("claroty send failed, dropping line", file=sys.stderr)

    def fgt(self, line):
        if self.a.dry_run:
            return self._dry("fortigate", line)
        try:
            self.udp.sendto(line.encode(), (self.a.host, self.a.fortigate_port))
        except OSError as e:
            print("fortigate send failed: %s" % e, file=sys.stderr)

    def ep(self, line):
        if self.a.dry_run:
            return self._dry("endpoint", line)
        self.f.write(line + "\n")

    def kiosk(self, line):
        if self.a.dry_run:
            return self._dry("meta_data_kiosk", line)
        try:
            self.udp.sendto(line.encode(), (self.a.host, self.a.kiosk_port))
        except OSError as e:
            print("meta data kiosk send failed: %s" % e, file=sys.stderr)

    def defender(self, line, ts):
        self._bulk("microsoft_defender_endpoint.log", line, ts)

    def servicenow(self, line, ts):
        # _conf is normally added by the integration's CEL input; the pipeline reads it.
        self._bulk("servicenow.event", line, ts, {"_conf": {"tz_offset": "UTC", "timestamp_field": "sys_updated_on",
                                                    "data_has_display_values": "true", "date_format_preference": "MMdd"}})

    def plc4x(self, line):
        if self.a.dry_run:
            return self._dry("plc4x", line)
        self.pf.write(line + "\n")

    def opcua(self, line):
        if self.a.dry_run:
            return self._dry("opcua", line)
        self.of.write(line + "\n")

    def _bulk(self, dataset, line, ts, extra=None):
        """REST API shaped data (Claroty assets and baseline, Defender alerts, ServiceNow incidents) is emitted as
        Elasticsearch bulk lines for scripts/load-api-data.sh. Fleet will not let a custom policy write into an
        integration's own data stream, and these integrations pull from vendor APIs we cannot reach. The raw API JSON
        goes in `message` and the integration's ingest pipeline parses it."""
        print(json.dumps({"create": {"_index": "logs-%s-default" % dataset}}))
        doc = {"@timestamp": _ts(ts), "message": line,
               "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
               "event": {"dataset": dataset}, "tags": ["sample-data"]}
        if extra:
            doc.update(extra)
        print(json.dumps(doc))

    def cassets(self, line, ts):
        self._bulk("claroty_ctd.asset", line, ts)

    def cbaseline(self, line, ts):
        self._bulk("claroty_ctd.baseline", line, ts)

    def _dry(self, kind, line):
        n = self.samples.get(kind, 0)
        self.samples[kind] = n + 1
        if n < self.a.samples:
            print("[%s] %s" % (kind, line))


def normal_tick(sink, ts):
    flow = random.choice(FLOWS)
    sink.fgt(fgt_line(ts, flow))
    if random.random() < 0.6:
        sink.fgt(fgt_external(ts))
    if random.random() < 0.5:
        sink.ep(ep_doc(ts, NAME_BY_IP[flow[2]], "network", "connection_attempted",
                       src=flow[2], dst=flow[3], dport=flow[5]))
    if random.random() < 0.2:
        h = random.choice(["KPP-HMI-01", "KPP-HIST-01"])
        p = random.choice(["wincc_rt.exe", "svchost.exe", "historian_svc.exe"])
        sink.ep(ep_doc(ts, h, "process", "start", user="svc_scada", proc=p))
    if random.random() < 0.05:
        sink.ep(ep_doc(ts, "KPP-HMI-01", "authentication", "logon", user="operator1"))
    if random.random() < 0.008:  # roughly one media session a minute at the default event rate
        usb_session(sink, ts, random.choice(USB_USERS), random.choice(USB_FILES),
                    verdict="blocked" if random.random() < 0.1 else "clean")
    if random.random() < 0.001:
        kiosk_login_failure(sink, ts, random.choice(USB_USERS))


def usb_session(sink, ts, user, file_name, verdict="clean"):
    """Kiosk session: login, device inserted, session started, file scanned (allowed or blocked), session ended."""
    sid = "%08X" % random.getrandbits(32)
    dev = random.choice(USB_DEVICES)
    serial = "%012X" % random.getrandbits(48)
    sha = "%064x" % random.getrandbits(256)
    sink.kiosk(kiosk_line(ts, "100002", "sessionLog", {"userId": user, "message": "User successful login"}))
    sink.kiosk(kiosk_line(ts + 4, "100008", "sessionLog", {
        "sessionId": sid, "userId": user, "deviceType": "USB Storage", "deviceManufacturer": dev[0],
        "deviceModel": dev[1], "deviceSerialNumber": serial, "message": "Device connected"}))
    sink.kiosk(kiosk_line(ts + 6, "100010", "sessionLog", {"sessionId": sid, "userId": user, "message": "Session started"}))
    if verdict == "clean":
        sink.kiosk(kiosk_line(ts + 20, "100000", "fileLog", {
            "sessionId": sid, "userId": user, "fileName": file_name, "sha256": sha,
            "scanResult": "Allowed", "scanResultDescription": "No threat detected"}))
        totals = (1, 0)
    else:
        sink.kiosk(kiosk_line(ts + 20, "100001", "fileLog", {
            "sessionId": sid, "userId": user, "fileName": file_name, "sha256": sha,
            "scanResult": "Blocked", "scanResultDescription": "Threat detected by %d of 8 engines" % random.randint(2, 6)}, sev=4))
        totals = (0, 1)
    sink.kiosk(kiosk_line(ts + 26, "200000", "sessionLog", {
        "sessionId": sid, "userId": user, "totalFilesScanned": 1, "totalFilesAllowed": totals[0],
        "totalFilesBlocked": totals[1], "message": "Session ended"}))


def kiosk_login_failure(sink, ts, user):
    sink.kiosk(kiosk_line(ts, "100006", "sessionLog", {"userId": user, "message": "Authentication failed"}, sev=4))


USB_DEVICES = [("SanDisk", "Ultra USB 3.0"), ("Kingston", "DataTraveler 100 G3"), ("Samsung", "BAR Plus")]
USB_USERS = ["m.virtanen", "j.koskinen", "s.laine"]
USB_FILES = ["vendor_firmware_update.zip", "shift_report.xlsx", "hmi_screens_backup.zip", "plc_diag_log.csv"]


def noise_alert(sink, ts):
    sid, name, sev = random.choice(NOISE_ALERTS)
    sink.claroty(claroty_line(ts, sid, name, sev, ENG, PLC))


def run_noise(a, sink):
    print("noise mode: ~%.1f alerts/min, ~%.1f events/s" % (a.alert_rate, a.event_rate), file=sys.stderr)
    nxt_alert = time.time()
    nxt_tel = nxt_health = nxt_event = nxt_act = nxt_ins = time.time()
    n = 0
    while True:
        now = time.time()
        normal_tick(sink, now)
        if now >= nxt_tel:
            telemetry_tick(sink, now, read_override(a.override_file))
            nxt_tel = now + 5.0
        if now >= nxt_health:
            claroty_health(sink, now)
            nxt_health = now + 60.0
        if now >= nxt_event:
            claroty_event(sink, now)
            nxt_event = now + random.expovariate(1 / 45.0)
        if now >= nxt_act:
            claroty_activity(sink, now)
            nxt_act = now + random.expovariate(1 / 300.0)
        if now >= nxt_ins:
            claroty_insight(sink, now)
            nxt_ins = now + random.expovariate(1 / 600.0)

        if now >= nxt_alert:
            noise_alert(sink, now)
            nxt_alert = now + random.expovariate(a.alert_rate / 60.0) if a.alert_rate > 0 else now + 3600
        n += 1
        if a.dry_run and n >= a.samples * 6:
            return
        time.sleep(random.expovariate(a.event_rate))


def run_backfill(a, sink):
    end = time.time()
    start = end - a.hours * 3600
    step = 60.0 / max(a.backfill_events_per_min, 1)
    claroty_history(sink, end)
    ts, nxt_alert, nxt_tel, count = start, start, start, 0
    alert_gap = 60.0 / max(a.alert_rate, 0.01)
    while ts < end:
        normal_tick(sink, ts)
        if ts >= nxt_tel:
            telemetry_tick(sink, ts)
            nxt_tel = ts + 30.0
        if ts >= nxt_alert:
            noise_alert(sink, ts)
            nxt_alert = ts + alert_gap * random.uniform(0.5, 1.5)
        ts += step
        count += 1
        if a.dry_run and count >= a.samples * 6:
            break
        if not a.dry_run and count % 500 == 0:
            time.sleep(0.05)  # pace for the agent
    print("backfill done: %d ticks over %.1fh" % (count, a.hours), file=sys.stderr)


def run_scenario(a, sink):
    t0 = time.time()
    # Provenance: the engineer scanned the project file at the Meta Data Kiosk before the change.
    claroty_history(sink, t0)
    claroty_activity(sink, t0 - 90, user=ENGINEER, which=ACTIVITIES[0])  # engineer logs in to CTD
    for k in range(90):  # 45 minutes of steady turbine telemetry (the process is unaffected by the change)
        telemetry_tick(sink, t0 - 2700 + k * 30)
    usb_session(sink, t0 - 420, ENGINEER, "TurbineGovernor_v14.zap18")
    # Engineer logon, then TIA Portal (maintenance window)
    sink.ep(ep_doc(t0, "KPP-ENG-WS01", "authentication", "logon", user=ENGINEER))
    sink.ep(ep_doc(t0 + 5, "KPP-ENG-WS01", "process", "start", user=ENGINEER,
                   proc="Siemens.Automation.Portal.exe",
                   cmd='"C:\\Program Files\\Siemens\\Automation\\Portal V18\\Bin\\Siemens.Automation.Portal.exe"'))
    sink.ep(ep_doc(t0 + 8, "KPP-ENG-WS01", "network", "connection_attempted", user=ENGINEER,
                   proc="Siemens.Automation.Portal.exe", src=ENG, dst=PLC, dport=102))
    sink.claroty(ctd_line(t0 + 8, "Event/Asset Information Change", "Asset Information Change", 3, {
        "CtdSourceIp": ENG, "CtdDestinationIp": PLC, "CtdSourceHost": "KPP-ENG-WS01", "CtdDestinationHost": "KPP-PLC-T2",
        "CtdSourceZone": zone_of(ENG), "CtdDestinationZone": zone_of(PLC), "CtdProtocol": "S7Comm",
        "CtdCategory": "Integrity/Asset Information Change", "CtdResolvedAs": "Unresolved", "CtdEventTypeId": 4,
        "CtdMessage": "Information change detected on KPP-PLC-T2 (program version)", "CtdDeviceExternalId": SITE_ID}))
    flow = FLOWS[0]
    n = max(a.scenario_events, 1000)
    spread = a.scenario_seconds
    for i in range(n):
        ts = t0 + 10 + spread * i / n
        sid, name, sev = SCEN_ALERTS[0] if i % 4 else SCEN_ALERTS[1]
        sink.claroty(claroty_line(ts, sid, name, sev, ENG, PLC))
        if i % 5 == 0:
            sink.fgt(fgt_line(ts, flow))
        if i % 50 == 0:
            sink.ep(ep_doc(ts, "KPP-ENG-WS01", "network", "connection_attempted", user=ENGINEER,
                           proc="Siemens.Automation.Portal.exe", src=ENG, dst=PLC, dport=102))
        if not a.dry_run and spread > 0 and i % 50 == 0:
            time.sleep(spread / (n / 50.0))
    print("scenario done: %d claroty alerts sent" % n, file=sys.stderr)


def run_api_data(a, sink):
    """Everything that is API-shaped, as bulk lines on stdout: Claroty asset and baseline snapshots, Defender alerts
    (history plus the alert on the engineering workstation) and ServiceNow incidents (history plus the open incident
    for the Claroty alert). Timestamps are relative to now."""
    now = time.time()
    for hrs in (3, 2, 1, 0):
        asset_snapshot(sink, now - hrs * 3600)
    for hrs in (2, 0):
        baseline_snapshot(sink, now - hrs * 3600)
    api_history(sink, now)
    sink.defender(defender_alert_doc(
        now - 75, "KPP-ENG-WS01", ENGINEER, "Engineering software communicated with an industrial controller",
        "Siemens TIA Portal opened a connection to a PLC on the control network. Matches an allowed engineering "
        "workflow for this device, so the alert was auto-resolved."), now - 75)
    sink.servicenow(servicenow_doc(now - 60, 1, "New"), now - 60)
    sink.servicenow(servicenow_doc(now - 25, 2, "In Progress", assigned_to="OT SOC analyst", opened_ts=now - 60), now - 25)


def run_ews_compromise(a, sink):
    """One-shot sequence for the "OT: VPN access, EWS compromise and PLC change" rule, sent through the agent (run on
    the host by `run-scenario.sh ews-compromise`). Relative to the base time: VPN-pool RDP to KPP-ENG-WS02 (-6 min),
    then Claroty PLC configuration changes from it (-2 and -1 min). The Defender alert in between (-4 min) is bulk loaded
    by the ews-defender mode. A separate workstation keeps the ENG-WS01 false-positive storyline and its noise alerts
    from interfering with the rule's ordering check."""
    t0 = a.base_time or time.time()
    for i in range(3):
        t = t0 - 360 + i * 20
        sink.fgt(fgt_line(t, FLOW_VPN_EWS, user=VPN_USER))
    # A distinct alert name keeps this alert separate from the ENG-WS01 noise alerts in the Alerts table; the rule matches it.
    sid, name, sev = EWS_ALERT
    for i in range(2):
        sink.claroty(claroty_line(t0 - 120 + i * 60, sid, name, sev, EWS2, PLC))
    print("ews-compromise done: VPN %s -> %s, Claroty PLC configuration change from it" % (VPN_POOL_IP, EWS2), file=sys.stderr)


def run_ews_defender(a, sink):
    """The Defender alert in the EWS sequence (bulk line, parsed by the Defender integration's pipeline). The
    pipeline maps evidence.ipAddress to related.ip, which the rule uses as the Defender side of the EWS IP join."""
    t = (a.base_time or time.time()) - 240
    sink.defender(defender_alert_doc(
        t, "KPP-ENG-WS02", VPN_USER, "Suspicious PowerShell command line",
        "PowerShell ran an encoded command on the engineering workstation shortly after a remote desktop logon, "
        "followed by an engineering software launch from an unusual parent process.",
        severity="High", status="New", classification=None, determination=None, investigation="Running",
        category="Execution", assigned=None, incident=448299, source="WindowsDefenderAtp", ip=EWS2), t)


def run_ticket_close(a, sink):
    """Analyst closed the case in Elastic: the ServiceNow incident is closed as a false positive (bulk line)."""
    t = time.time()
    sink.servicenow(servicenow_doc(t, 7, "Closed", assigned_to="OT SOC analyst", opened_ts=t - 180,
                                   close_notes="False positive: scheduled maintenance, known-good workstation, clean USB scan."), t)


def run_threat(a, sink):
    """A handful of alerts from a source that is not in the inventory, via a different firewall policy."""
    t0 = time.time()
    ov = {"start": t0, "until": t0 + 300, "setpoint": 3150.0, "ramp": 90}
    if not a.dry_run:
        with open(a.override_file, "w") as f:  # noise telemetry follows this for 5 minutes
            json.dump(ov, f)
    n = 12
    for i in range(n):
        ts = t0 + i * 2.5
        telemetry_tick(sink, ts, ov)
        if i % 4 == 0:  # Claroty insight: communication from a ghost (unconfirmed) asset
            claroty_insight(sink, ts, src=UNKNOWN_SRC, dst=PLC, ghost=True, name="External Communication",
                            severity="High", os_name="Unknown")
        sid, name, sev = THREAT_ALERTS[0] if i % 3 else THREAT_ALERTS[1]
        sink.claroty(claroty_line(ts, sid, name, sev, UNKNOWN_SRC, PLC))
        sink.fgt(fgt_line(ts, FLOW_THREAT))
    print("threat done: %d claroty alerts sent from unmanaged host %s" % (n, UNKNOWN_SRC), file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", required=True, choices=["noise", "backfill", "scenario", "threat", "ticket-close", "api-data", "ews-compromise", "ews-defender"])
    p.add_argument("--hours", type=float, default=24, help="backfill window")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, dest="claroty_port", default=9100, help="Claroty CEF TCP port")
    p.add_argument("--claroty-port", type=int, dest="claroty_port", help=argparse.SUPPRESS)
    p.add_argument("--fortigate-port", type=int, default=9004)
    p.add_argument("--endpoint-file", default=ENDPOINT_FILE)
    p.add_argument("--kiosk-port", type=int, default=9514, help="Meta Data Kiosk syslog UDP port")
    p.add_argument("--plc4x-file", default=PLC4X_FILE)
    p.add_argument("--opcua-file", default=OPCUA_FILE)
    p.add_argument("--override-file", default=OVERRIDE_FILE)

    p.add_argument("--alert-rate", type=float, default=6.0, help="noise Claroty alerts per minute")
    p.add_argument("--event-rate", type=float, default=2.0, help="noise normal events per second")
    p.add_argument("--backfill-events-per-min", type=int, default=30)
    p.add_argument("--scenario-events", type=int, default=1200, help="Claroty alerts in burst (min 1000)")
    p.add_argument("--scenario-seconds", type=float, default=60.0, help="burst duration")
    p.add_argument("--seed", type=int)
    p.add_argument("--base-time", type=float, help="epoch seconds the ews-compromise sequence is anchored to (default now)")
    p.add_argument("--dry-run", action="store_true", help="print samples to stdout, send nothing")
    p.add_argument("--samples", type=int, default=3, help="dry-run samples per stream")
    a = p.parse_args()
    if a.seed is not None:
        random.seed(a.seed)
    if a.mode in ("api-data", "ticket-close", "ews-defender"):
        a.dry_run = True  # prints bulk lines only: no sockets and no files are opened
    sink = Sink(a)
    try:
        {"noise": run_noise, "backfill": run_backfill, "scenario": run_scenario, "threat": run_threat, "ticket-close": run_ticket_close, "api-data": run_api_data, "ews-compromise": run_ews_compromise, "ews-defender": run_ews_defender}[a.mode](a, sink)
    except KeyboardInterrupt:
        pass
    if a.dry_run:
        print("dry-run counts: %s" % json.dumps(sink.samples), file=sys.stderr)


if __name__ == "__main__":
    main()
