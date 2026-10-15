#!/usr/bin/env python3
"""Synthetic OT data generator for the Karins Power Plant demo (stdlib only).

Modes:
  noise     continuous background traffic + repetitive low-severity Claroty alerts
  backfill  history with historical timestamps (--hours N)
  scenario  false-positive storyline (burst of identical Claroty alerts, FortiGate
            ENG-to-PLC-S7 hits, engineer logon + TIA Portal process)

Outputs:
  Claroty CEF   -> syslog TCP 127.0.0.1:9100
  FortiGate kv  -> syslog UDP 127.0.0.1:9004
  Endpoint ECS  -> /var/log/ot-demo/endpoint.ndjson (JSON lines)
Claroty CEF field fidelity is synthetic.
"""
import argparse
import hashlib
import json
import os
import random
import socket
import sys
import time
from datetime import datetime, timezone

ASSETS = {
    "KPP-PLC-T2": "10.20.4.12", "KPP-RTU-SS1": "10.20.4.30",
    "KPP-ENG-WS01": "10.20.3.21", "KPP-HMI-01": "10.20.3.10",
    "KPP-HIST-01": "10.20.3.40", "FGT-KPP-OT01": "10.20.0.1",
    "KPP-USB-KIOSK01": "10.20.0.50",
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
ENDPOINT_FILE = "/var/log/ot-demo/endpoint.ndjson"
USB_FILE = "/var/log/ot-demo/usb_laundry.ndjson"
KIOSK = "KPP-USB-KIOSK01"
# Sample data shaped like the Microsoft Defender for Endpoint (log) and ServiceNow (event) integrations.
# Neither integration is configured; the documents carry the real field names for demonstration only.
DEFENDER_FILE = "/var/log/ot-demo/defender.ndjson"
SERVICENOW_FILE = "/var/log/ot-demo/servicenow.ndjson"
PLC4X_FILE = "/var/log/ot-demo/plc4x.ndjson"
OPCUA_FILE = "/var/log/ot-demo/opcua.ndjson"
OVERRIDE_FILE = "/var/log/ot-demo/.plc_override.json"  # written by the threat mode, read by noise
INCIDENT_NO = "INC0010231"
INCIDENT_SYS_ID = "9d385017c611228701d22104cc95c371"


def utc(ts=None):
    return datetime.fromtimestamp(ts, timezone.utc) if ts else datetime.now(timezone.utc)


def cef_escape(v):
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def claroty_line(ts, sig_id, name, sev, src, dst, proto="S7Comm"):
    t = utc(ts)
    ext = {
        "rt": int(t.timestamp() * 1000), "src": src, "dst": dst,
        "shost": NAME_BY_IP.get(src, src), "dhost": NAME_BY_IP.get(dst, dst),
        "CtdSourceIp": src, "CtdDestinationIp": dst,
        "CtdSourceHost": NAME_BY_IP.get(src, src), "CtdDestinationHost": NAME_BY_IP.get(dst, dst),
        "proto": proto, "cat": "Security", "cs1Label": "site", "cs1": SITE,
        "cs2Label": "zone", "cs2": "Level 1 Control Network", "cn1Label": "alert_id",
        "cn1": random.randint(100000, 999999),
        "CtdAlertId": random.randint(100000, 999999),
        "msg": name + " between %s and %s" % (NAME_BY_IP.get(src, src), NAME_BY_IP.get(dst, dst)),
    }
    body = " ".join("%s=%s" % (k, cef_escape(v)) for k, v in ext.items())
    return "<134>%s ctd-kpp CEF:0|Claroty|CTD|4.12.0|Alert-%s|%s|%d|%s" % (
        t.strftime("%b %d %H:%M:%S"), sig_id, name, sev, body)


def fgt_line(ts, flow, action="accept", level="notice"):
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
    return "<189>" + " ".join("%s=%s" % kv_ for kv_ in kv)


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


def usb_doc(ts, action, user, file_name=None, sha256=None, verdict=None, released_to=None, serial=None, outcome="success"):
    """Synthetic USB laundry (media sanitisation kiosk) event. The schema is a placeholder: replace
    with the customer's real kiosk log format once a sample is available."""
    d = {
        "@timestamp": utc(ts).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(ts * 1000) % 1000),
        "event": {"category": ["file"], "action": action, "outcome": outcome,
                  "kind": "event", "dataset": "usb_laundry.events"},
        "data_stream": {"type": "logs", "dataset": "usb_laundry.events", "namespace": "default"},
        "labels": {"site": SITE, "demo": "ot-demo", "asset_name": KIOSK},
        "user": {"name": user, "domain": "KPP"},
        "usb_laundry": {"media_serial": serial or "USB-%06d" % random.randint(100000, 999999), "engines": 5},
    }
    if file_name:
        d["file"] = {"name": file_name}
        if sha256:
            d["file"]["hash"] = {"sha256": sha256}
    if verdict:
        d["usb_laundry"]["scan_verdict"] = verdict
        d["usb_laundry"]["threats_found"] = 0 if verdict == "clean" else random.randint(1, 3)
    if released_to:
        d["usb_laundry"]["released_to"] = released_to
    return json.dumps(d)


def _ts(ts):
    return utc(ts).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(ts * 1000) % 1000)


def defender_alert_doc(ts, host, user, message, description, status="Resolved", classification="FalsePositive",
                       determination="Other", investigation="Benign", risk="Low", severity=1,
                       assigned="Automated investigation", action="Discovery", incident="448201"):
    """Microsoft Defender for Endpoint alert (microsoft_defender_endpoint.log shape)."""
    return json.dumps({
        "@timestamp": _ts(ts),
        "data_stream": {"type": "logs", "dataset": "microsoft_defender_endpoint.log", "namespace": "default"},
        "event": {"kind": "alert", "category": ["host"], "type": ["info"], "action": action, "severity": severity,
                  "dataset": "microsoft_defender_endpoint.log", "provider": "defender_endpoint",
                  "id": "da637%015d_1364969609" % random.randint(1, 10**15 - 1)},
        "message": message,
        "rule": {"description": description},
        "host": {"name": host, "risk": {"calculated_level": risk}, "os": {"platform": "Windows10"}},
        "labels": {"site": SITE, "demo": "ot-demo", "asset_name": host},
        "user": {"name": user, "domain": "KPP"},
        "observer": {"name": "WindowsDefenderAtp", "product": "Defender for Endpoint", "vendor": "Microsoft"},
        "microsoft": {"defender_endpoint": {
            "status": status, "classification": classification, "determination": determination,
            "investigationState": investigation, "incidentId": incident, "assignedTo": assigned,
            "lastUpdateTime": _ts(ts + 2),
            "evidence": {"accountName": user, "domainName": "KPP", "entityType": "User"}}},
        "tags": ["microsoft-defender-endpoint", "forwarded", "sample-data"],
    })


def servicenow_doc(ts, state_value, state_display, assigned_to=None, close_notes=None, number=INCIDENT_NO,
                   short="Claroty CTD: PLC Program Download Detected on KPP-PLC-T2 (Karins Power Plant)",
                   asset="KPP-PLC-T2", priority=(3, "3 - Moderate"), group=("ot-security", "OT Security"),
                   opened_ts=None):
    """ServiceNow incident record (servicenow.event shape)."""
    def dv(v, d=None):
        return {"display_value": d if d is not None else v, "value": v}
    sys_id = hashlib.md5(number.encode()).hexdigest()
    opened = opened_ts if opened_ts is not None else ts - 60
    ev = {
        "number": dv(number), "sys_id": {"value": sys_id}, "table_name": "incident",
        "short_description": dv(short),
        "priority": dv(priority[0], priority[1]), "state": dv(state_value, state_display),
        "assignment_group": dv(group[0], group[1]),
        "opened_at": {"display_value": _ts(opened), "value": _ts(opened)},
        "sys_updated_on": {"display_value": _ts(ts), "value": _ts(ts)},
        "sys_created_by": dv("claroty.integration"),
        "sys_updated_by": dv(assigned_to or "claroty.integration"),
    }
    if assigned_to:
        ev["assigned_to"] = dv(assigned_to)
    if close_notes:
        ev["close_notes"] = dv(close_notes)
        ev["closed_at"] = {"display_value": _ts(ts), "value": _ts(ts)}
    return json.dumps({
        "@timestamp": _ts(ts),
        "data_stream": {"type": "logs", "dataset": "servicenow.event", "namespace": "default"},
        "event": {"kind": "event", "category": ["configuration"], "type": ["info"], "dataset": "servicenow.event",
                  "id": sys_id},
        "labels": {"site": SITE, "demo": "ot-demo", "asset_name": asset},
        "servicenow": {"event": ev},
        "tags": ["incident", "forwarded", "servicenow-event", "sample-data"],
    })


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


DEFENDER_BACKGROUND = [  # (message, description, severity, status, classification, determination, investigation, risk, host, user)
    ("Unsigned driver loaded", "A driver without a valid signature was loaded by the HMI runtime.", 1, "Resolved", "FalsePositive", "Other", "Benign", "Low", "KPP-HMI-01", "svc_scada"),
    ("Remote Desktop connection from jump host", "RDP session from the control DMZ jump host matches an allowed administration path.", 1, "Resolved", "FalsePositive", "Other", "Benign", "Low", "KPP-HIST-01", "svc_scada"),
    ("Suspicious PowerShell command line", "PowerShell was run with an encoded command. Confirmed as an approved security test.", 2, "Resolved", "TruePositive", "SecurityTesting", "SuccessfullyRemediated", "Low", "KPP-HMI-01", "operator1"),
    ("Software installer launched from removable media", "An installer ran from removable media that was scanned at the USB laundry kiosk.", 1, "Resolved", "FalsePositive", "Other", "Benign", "Low", "KPP-ENG-WS01", "m.virtanen"),
    ("Potentially unwanted application detected", "A bundled utility on the historian was flagged as potentially unwanted. Under review.", 2, "InProgress", "Unknown", "NotAvailable", "Running", "Medium", "KPP-HIST-01", "svc_scada"),
]


def background_defender(sink, ts):
    m = random.choice(DEFENDER_BACKGROUND)
    sink.defender(defender_alert_doc(ts, m[8], m[9], m[0], m[1], status=m[3], classification=m[4],
                                     determination=m[5], investigation=m[6], risk=m[7], severity=m[2],
                                     incident=str(random.randint(448000, 449999))))


def history(sink, now):
    """Backdated Defender alerts and ServiceNow incidents so the panels look lived-in."""
    for i, m in enumerate(DEFENDER_BACKGROUND):
        for k in range(2):
            ts = now - (1800 + i * 5400 + k * 25000 + random.randint(0, 1800))
            sink.defender(defender_alert_doc(ts, m[8], m[9], m[0], m[1], status=m[3], classification=m[4],
                                             determination=m[5], investigation=m[6], risk=m[7], severity=m[2],
                                             incident=str(448100 + i * 10 + k)))
    H = 3600.0
    incidents = [  # (number, short description, asset, priority, group, [(hours ago, state, assignee, close note)])
        ("INC0010188", "FortiGate FGT-KPP-OT01: firmware advisory review", "FGT-KPP-OT01", (3, "3 - Moderate"),
         ("network-ops", "Network Operations"),
         [(21, (1, "New"), None, None), (20.5, (2, "In Progress"), "N. Aaltonen", None),
          (18, (7, "Closed"), "N. Aaltonen", "Advisory reviewed, no action needed for the installed firmware.")]),
        ("INC0010197", "Claroty CTD: Unusual Modbus write from KPP-HMI-01 (false positive)", "KPP-HMI-01", (3, "3 - Moderate"),
         ("ot-security", "OT Security"),
         [(9, (1, "New"), None, None), (8.8, (2, "In Progress"), "J. Koskinen", None),
          (8.5, (7, "Closed"), "J. Koskinen", "Operator setpoint adjustment confirmed with the shift lead.")]),
        ("INC0010203", "KPP-HIST-01: Defender alert, potentially unwanted application", "KPP-HIST-01", (2, "2 - High"),
         ("ot-security", "OT Security"),
         [(5, (1, "New"), None, None), (4.5, (2, "In Progress"), "OT SOC analyst", None)]),
        ("INC0010209", "USB laundry kiosk: scan engine signature update", "KPP-USB-KIOSK01", (4, "4 - Low"),
         ("ot-security", "OT Security"),
         [(14, (1, "New"), None, None), (13, (3, "On Hold"), "S. Laine", None)]),
        ("INC0010214", "Claroty CTD: S7 Unauthorized Read/Scan from KPP-ENG-WS01 (maintenance window)", "KPP-PLC-T2", (3, "3 - Moderate"),
         ("ot-security", "OT Security"),
         [(2.2, (1, "New"), None, None), (2.1, (2, "In Progress"), "OT SOC analyst", None),
          (1.8, (7, "Closed"), "OT SOC analyst", "False positive: scheduled maintenance, known-good workstation.")]),
    ]
    for number, short, asset, prio, grp, steps in incidents:
        opened = now - steps[0][0] * H
        for hrs, (sv, sd), who, note in steps:
            sink.servicenow(servicenow_doc(now - hrs * H, str(sv), sd, assigned_to=who, close_notes=note,
                                           number=number, short=short, asset=asset, priority=prio,
                                           group=grp, opened_ts=opened))


class Sink:
    """Handles TCP (reconnecting), UDP and file output, or stdout in dry-run."""

    def __init__(self, a):
        self.a, self.tcp, self.udp, self.f, self.uf, self.df, self.sf, self.pf, self.of = a, None, None, None, None, None, None, None, None
        self.samples = {}
        if not a.dry_run:
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            d = os.path.dirname(a.endpoint_file)
            os.makedirs(d, exist_ok=True)
            self.f = open(a.endpoint_file, "a", buffering=1)
            os.makedirs(os.path.dirname(a.usb_file), exist_ok=True)
            self.uf = open(a.usb_file, "a", buffering=1)
            self.df = open(a.defender_file, "a", buffering=1)
            self.sf = open(a.servicenow_file, "a", buffering=1)
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

    def usb(self, line):
        if self.a.dry_run:
            return self._dry("usb", line)
        self.uf.write(line + "\n")

    def defender(self, line):
        if self.a.dry_run:
            return self._dry("defender", line)
        self.df.write(line + "\n")

    def servicenow(self, line):
        if self.a.dry_run:
            return self._dry("servicenow", line)
        self.sf.write(line + "\n")

    def plc4x(self, line):
        if self.a.dry_run:
            return self._dry("plc4x", line)
        self.pf.write(line + "\n")

    def opcua(self, line):
        if self.a.dry_run:
            return self._dry("opcua", line)
        self.of.write(line + "\n")

    def _dry(self, kind, line):
        n = self.samples.get(kind, 0)
        self.samples[kind] = n + 1
        if n < self.a.samples:
            print("[%s] %s" % (kind, line))


def normal_tick(sink, ts):
    flow = random.choice(FLOWS)
    sink.fgt(fgt_line(ts, flow))
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
                    release_to=random.choice(["KPP-HMI-01", "KPP-HIST-01"]),  # not the engineering workstation
                    verdict="blocked" if random.random() < 0.1 else "clean")


def usb_session(sink, ts, user, file_name, release_to=None, verdict="clean"):
    """media inserted -> scan -> release (clean) or block."""
    serial = "USB-%06d" % random.randint(100000, 999999)
    sha = "%064x" % random.getrandbits(256)
    sink.usb(usb_doc(ts, "media_inserted", user, serial=serial))
    sink.usb(usb_doc(ts + 20, "scan_completed", user, file_name, sha, verdict=verdict, serial=serial,
                     outcome="success" if verdict == "clean" else "failure"))
    if verdict == "clean":
        sink.usb(usb_doc(ts + 25, "file_released", user, file_name, sha, verdict="clean",
                         released_to=release_to or "KPP-ENG-WS01", serial=serial))
    else:
        sink.usb(usb_doc(ts + 25, "file_blocked", user, file_name, sha, verdict=verdict, serial=serial,
                         outcome="failure"))


USB_USERS = ["m.virtanen", "j.koskinen", "s.laine"]
USB_FILES = ["vendor_firmware_update.zip", "shift_report.xlsx", "hmi_screens_backup.zip", "plc_diag_log.csv"]


def noise_alert(sink, ts):
    sid, name, sev = random.choice(NOISE_ALERTS)
    sink.claroty(claroty_line(ts, sid, name, sev, ENG, PLC))


def run_noise(a, sink):
    print("noise mode: ~%.1f alerts/min, ~%.1f events/s" % (a.alert_rate, a.event_rate), file=sys.stderr)
    nxt_alert = time.time()
    nxt_tel = nxt_def = time.time()
    n = 0
    while True:
        now = time.time()
        normal_tick(sink, now)
        if now >= nxt_tel:
            telemetry_tick(sink, now, read_override(a.override_file))
            nxt_tel = now + 5.0
        if now >= nxt_def:
            background_defender(sink, now)
            nxt_def = now + random.expovariate(1 / 600.0)
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
    history(sink, end)
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
    # Provenance: the engineer scanned the project file at the USB laundry kiosk before the change.
    history(sink, t0)
    for k in range(90):  # 45 minutes of steady turbine telemetry (the process is unaffected by the change)
        telemetry_tick(sink, t0 - 2700 + k * 30)
    usb_session(sink, t0 - 420, ENGINEER, "TurbineGovernor_v14.zap18", release_to="KPP-ENG-WS01")
    # Sample Defender for Endpoint alert on the workstation (informational, auto-resolved) and the
    # ServiceNow incident that Claroty opens for the alert (New, then In Progress).
    sink.defender(defender_alert_doc(
        t0 + 3, "KPP-ENG-WS01", ENGINEER,
        "Engineering software communicated with an industrial controller",
        "Siemens TIA Portal opened a connection to a PLC on the control network. Matches an allowed engineering "
        "workflow for this device, so the alert was auto-resolved."))
    sink.servicenow(servicenow_doc(t0 + 2, "1", "New"))
    sink.servicenow(servicenow_doc(t0 + 6, "2", "In Progress", assigned_to="OT SOC analyst"))
    # Engineer logon, then TIA Portal (maintenance window)
    sink.ep(ep_doc(t0, "KPP-ENG-WS01", "authentication", "logon", user=ENGINEER))
    sink.ep(ep_doc(t0 + 5, "KPP-ENG-WS01", "process", "start", user=ENGINEER,
                   proc="Siemens.Automation.Portal.exe",
                   cmd='"C:\\Program Files\\Siemens\\Automation\\Portal V18\\Bin\\Siemens.Automation.Portal.exe"'))
    sink.ep(ep_doc(t0 + 8, "KPP-ENG-WS01", "network", "connection_attempted", user=ENGINEER,
                   proc="Siemens.Automation.Portal.exe", src=ENG, dst=PLC, dport=102))
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


def run_ticket_close(a, sink):
    """Analyst closed the case in Elastic: the ServiceNow incident is closed as a false positive."""
    sink.servicenow(servicenow_doc(time.time(), "7", "Closed", assigned_to="OT SOC analyst",
                                   close_notes="False positive: scheduled maintenance, known-good workstation, clean USB scan."))
    print("ticket-close done: %s closed" % INCIDENT_NO, file=sys.stderr)


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
        sid, name, sev = THREAT_ALERTS[0] if i % 3 else THREAT_ALERTS[1]
        sink.claroty(claroty_line(ts, sid, name, sev, UNKNOWN_SRC, PLC))
        sink.fgt(fgt_line(ts, FLOW_THREAT))
    print("threat done: %d claroty alerts sent from unmanaged host %s" % (n, UNKNOWN_SRC), file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", required=True, choices=["noise", "backfill", "scenario", "threat", "ticket-close"])
    p.add_argument("--hours", type=float, default=24, help="backfill window")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, dest="claroty_port", default=9100, help="Claroty CEF TCP port")
    p.add_argument("--claroty-port", type=int, dest="claroty_port", help=argparse.SUPPRESS)
    p.add_argument("--fortigate-port", type=int, default=9004)
    p.add_argument("--endpoint-file", default=ENDPOINT_FILE)
    p.add_argument("--usb-file", default=USB_FILE)
    p.add_argument("--defender-file", default=DEFENDER_FILE)
    p.add_argument("--plc4x-file", default=PLC4X_FILE)
    p.add_argument("--opcua-file", default=OPCUA_FILE)
    p.add_argument("--override-file", default=OVERRIDE_FILE)
    p.add_argument("--servicenow-file", default=SERVICENOW_FILE)
    p.add_argument("--alert-rate", type=float, default=6.0, help="noise Claroty alerts per minute")
    p.add_argument("--event-rate", type=float, default=2.0, help="noise normal events per second")
    p.add_argument("--backfill-events-per-min", type=int, default=30)
    p.add_argument("--scenario-events", type=int, default=1200, help="Claroty alerts in burst (min 1000)")
    p.add_argument("--scenario-seconds", type=float, default=60.0, help="burst duration")
    p.add_argument("--seed", type=int)
    p.add_argument("--dry-run", action="store_true", help="print samples to stdout, send nothing")
    p.add_argument("--samples", type=int, default=3, help="dry-run samples per stream")
    a = p.parse_args()
    if a.seed is not None:
        random.seed(a.seed)
    sink = Sink(a)
    try:
        {"noise": run_noise, "backfill": run_backfill, "scenario": run_scenario, "threat": run_threat, "ticket-close": run_ticket_close}[a.mode](a, sink)
    except KeyboardInterrupt:
        pass
    if a.dry_run:
        print("dry-run counts: %s" % json.dumps(sink.samples), file=sys.stderr)


if __name__ == "__main__":
    main()
