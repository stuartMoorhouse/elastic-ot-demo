#!/usr/bin/env python3
"""Backfill ServiceNow Table API records so every ServiceNow integration dashboard has data.

Prints Elasticsearch bulk NDJSON (action line + document line) on stdout. Each document is shaped like the existing
incident documents from scripts/generator/ot_generator.py (servicenow_doc / Sink._bulk): the raw Table API record, with
value and display_value per field, is placed in `message` and the installed logs-servicenow.event ingest pipeline
parses it. The dashboards filter on the `tags` field (the integration adds one tag per polled table), so every
document carries a table tag.

Idempotency: the integration pipeline replaces _id with a fingerprint of sys_id + sys_updated_on + table_name, and
all of those are deterministic here. Re-running with the same --now (printed on stderr) produces the same _ids, so a
second load only yields 409 version conflicts. The default --now is the current time rounded down to the hour.

Usage: python3 scripts/fill/servicenow.py [--now EPOCH] > servicenow.ndjson
       curl -XPOST $ES/_bulk -H 'Content-Type: application/x-ndjson' --data-binary @servicenow.ndjson
"""
import argparse
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timezone

INDEX = "logs-servicenow.event-default"
DATASET = "servicenow.event"
SITE = "Karins Power Plant"
GROUP_CO = "Karins Energy Group"
CONF = {"tz_offset": "UTC", "timestamp_field": "sys_updated_on", "data_has_display_values": "true",
        "date_format_preference": "MMdd"}

NOW = 0.0
OUT = []


STATUS_CODES = {
    "install_status": {"Installed": "1", "In use": "1", "On order": "2", "In maintenance": "3", "In stock": "6", "Retired": "7"},
    "operational_status": {"Operational": "1", "Non-Operational": "2", "Repair in Progress": "3", "DR Standby": "4", "Ready": "5"},
}


class Ts(float):
    """Marks a field as a ServiceNow date-time (rendered as yyyy-MM-dd HH:mm:ss, UTC)."""


def T(h):
    return Ts(NOW - h * 3600.0)


def fmt(t):
    return datetime.fromtimestamp(float(t), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def iso(t):
    return datetime.fromtimestamp(float(t), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def dv(v, d=None):
    if isinstance(v, bool):
        v = "true" if v else "false"
    v = str(v)
    return {"display_value": v if d is None else str(d), "value": v}


def R(display):
    """Reference field: the value is a sys_id, the display value is the record name."""
    return (hashlib.md5(("ref:" + display).encode()).hexdigest(), display)


def conv(v):
    if isinstance(v, dict):
        return v
    if isinstance(v, Ts):
        return dv(fmt(v))
    if isinstance(v, tuple):
        return dv(v[0], v[1])
    return dv(v)


def emit(table, key, t_upd, fields, tags, extra=None):
    """One raw Table API record -> one bulk document. `key` identifies the record, t_upd is sys_updated_on."""
    sys_id = hashlib.md5(("%s:%s" % (table, key)).encode()).hexdigest()
    rec = {"table_name": table, "sys_id": dv(sys_id)}
    for k, v in fields.items():
        if k in STATUS_CODES and isinstance(v, str):
            v = (STATUS_CODES[k][v], v)  # the package pipeline converts these .value fields to long
        rec[k] = conv(v)
    created = fields.get("sys_created_on")
    rec["sys_created_on"] = conv(created if created is not None else Ts(t_upd - 3600))
    rec.setdefault("sys_created_by", dv("admin"))
    rec["sys_updated_on"] = dv(fmt(t_upd))
    rec.setdefault("sys_updated_by", dv("admin"))
    rec.setdefault("sys_mod_count", dv(1))
    doc = {"@timestamp": iso(t_upd), "message": json.dumps(rec),
           "data_stream": {"type": "logs", "dataset": DATASET, "namespace": "default"},
           "event": {"dataset": DATASET}, "tags": list(tags) + ["sample-data"], "_conf": CONF}
    if extra:
        doc.update(extra)
    _id = "fill-sn-" + hashlib.sha1(("%s:%s:%d" % (table, key, int(t_upd))).encode()).hexdigest()[:24]
    OUT.append(json.dumps({"create": {"_index": INDEX, "_id": _id}}))
    OUT.append(json.dumps(doc))


def snaps(table, key, hours, base, tags, per=None, extra=None):
    """Emit one document per snapshot hour (hours ago, newest last). `per(i, n)` returns field overrides."""
    n = len(hours)
    for i, h in enumerate(hours):
        f = dict(base)
        if per:
            f.update(per(i, n))
        emit(table, key, NOW - h * 3600.0, f, tags, extra)


def jitter(seed, lo, hi):
    return random.Random(seed).uniform(lo, hi)


# --------------------------------------------------------------------------------------------------------------
# People, groups
# --------------------------------------------------------------------------------------------------------------
CRIT = {1: ("1", "1 - most critical"), 2: ("2", "2 - somewhat critical"), 3: ("3", "3 - less critical"),
        4: ("4", "4 - not critical")}
# user_name, full name, title, department, roles, vip, criticality, active, groups
USERS = [
    ("a.lindqvist", "Anna Lindqvist", "Control Systems Engineer", "Control Systems Engineering", "itil,snc_internal", False, 2, True,
     ["Control Systems Engineering", "Change Advisory Board"]),
    ("j.koskinen", "Juha Koskinen", "OT SOC Analyst", "OT Security", "itil,sn_si.analyst,snc_internal", False, 2, True,
     ["OT SOC", "OT Security"]),
    ("s.laine", "Sanna Laine", "OT SOC Analyst", "OT Security", "itil,sn_si.analyst,snc_internal", False, 2, True,
     ["OT SOC", "OT Security"]),
    ("n.aaltonen", "Niko Aaltonen", "Network Engineer", "Network Operations", "itil,network_admin,snc_internal", False, 3, True,
     ["Network Operations", "Change Advisory Board"]),
    ("r.lund", "Rasmus Lund", "Network Engineer", "Network Operations", "itil,network_admin", False, 3, True, ["Network Operations"]),
    ("m.virtanen", "Mikko Virtanen", "Plant Operator", "Plant Operations", "snc_internal", False, 2, True, ["Plant Operations"]),
    ("o.rantanen", "Olli Rantanen", "Shift Supervisor", "Plant Operations", "snc_internal,approver_user", False, 1, True,
     ["Plant Operations", "Change Advisory Board"]),
    ("e.voss", "Eva Voss", "Service Desk Agent", "Service Desk", "itil", False, 4, True, ["Service Desk"]),
    ("m.haas", "Markus Haas", "Service Desk Agent", "Service Desk", "itil", False, 4, True, ["Service Desk"]),
    ("t.berg", "Tuomas Berg", "IT Security Analyst", "IT Security", "itil,sn_si.analyst", False, 2, True, ["IT Security", "OT SOC"]),
    ("k.nieminen", "Karin Nieminen", "Plant Manager", "Plant Management", "snc_internal,approver_user", True, 1, True,
     ["Plant Operations", "Change Advisory Board"]),
    ("h.makela", "Heli Makela", "Turbine Controls Lead", "Turbine Controls", "itil,snc_internal,approver_user", True, 1, True,
     ["Turbine Controls", "Control Systems Engineering", "Change Advisory Board"]),
    ("p.salo", "Pekka Salo", "Substation Automation Engineer", "Substation Automation", "itil,snc_internal", False, 2, True,
     ["Substation Automation"]),
    ("l.heikkinen", "Laura Heikkinen", "Plant IT / OT Data Lead", "Plant IT", "itil,admin,snc_internal", True, 2, True,
     ["Plant IT", "Change Advisory Board"]),
    ("claroty.integration", "Claroty CTD", "Integration Account", "OT Security", "rest_service", False, 3, True, ["OT Security"]),
    ("svc_backup", "Backup Service", "Service Account", "Plant IT", "rest_service", False, 3, True, ["Plant IT"]),
    ("contractor.hale", "James Hale", "Contractor", "Control Systems Engineering", "snc_external", False, 4, False,
     ["Control Systems Engineering"]),
    ("vendor.siemens", "Siemens Service", "Vendor Support", "Turbine Controls", "snc_external", False, 3, False, ["Turbine Controls"]),
    ("i.former", "Ilkka Former", "Former Operator", "Plant Operations", "snc_internal", False, 4, False, ["Plant Operations"]),
]
FULL = {u[0]: u[1] for u in USERS}
GROUPS = [  # name, description, manager user_name, active
    ("OT Security", "Owns OT detections, Claroty CTD and Defender triage", "j.koskinen", True),
    ("OT SOC", "24x7 OT security operations centre", "s.laine", True),
    ("Network Operations", "FortiGate, switching and remote access", "n.aaltonen", True),
    ("Service Desk", "First line support for plant IT", "e.voss", True),
    ("IT Security", "Corporate IT security", "t.berg", True),
    ("Control Systems Engineering", "PLC, HMI and engineering workstation changes", "a.lindqvist", True),
    ("Plant Operations", "Control room operations and shift supervisors", "o.rantanen", True),
    ("Turbine Controls", "Turbine governor and protection systems", "h.makela", True),
    ("Substation Automation", "RTUs and substation telemetry", "p.salo", True),
    ("Plant IT", "Servers, historian, backups", "l.heikkinen", True),
    ("Change Advisory Board", "Approves normal and emergency changes", "k.nieminen", True),
    ("Legacy Vendor Support", "Retired vendor access group", "l.heikkinen", False),
]
OPS = ["a.lindqvist", "j.koskinen", "s.laine", "n.aaltonen", "r.lund", "e.voss", "m.haas", "t.berg", "h.makela", "p.salo",
       "l.heikkinen"]
OPS_NAMES = [FULL[u] for u in OPS]


def users():
    tags = ["sys_user"]
    for ui, (un, name, title, dept, roles, vip, crit, active, _g) in enumerate(USERS):
        first, last = name.split(" ", 1) if " " in name else (name, "")
        base = {"user_name": un, "name": name, "first_name": first, "last_name": last, "title": title,
                "department": R(dept), "roles": roles, "vip": vip, "active": active,
                "email": "%s@karins-power.example" % un, "business_criticality": CRIT[crit],
                "location": R(SITE), "company": R(SITE), "locked_out": False, "failed_attempts": 0,
                "employee_number": "KPP%04d" % (1000 + ui), "time_zone": "Europe/Helsinki", "source": "ldap",
                "sys_created_by": dv("admin"), "sys_created_on": T(24 * 400)}
        if not active:
            emit("sys_user", un, NOW - (24 * 20 + ui) * 3600.0, dict(base, last_login_time=T(24 * 25 + ui),
                                                                    last_login=T(24 * 25 + ui)), tags)
            continue
        hrs = [24 * 21 + ui * 3, 24 * 11 + ui * 2, 24 * 4 + ui, 2 + ui * 1.1]  # last_login_time gets later each time
        if un in ("claroty.integration", "svc_backup"):
            hrs = [24 * 9, 24 * 3, 0.5 + ui * 0.1]
        n = len(hrs)

        def per(i, n, un=un, hrs=hrs):
            lt = T(hrs[i] + 0.1)
            return {"last_login_time": lt, "last_login": lt, "locked_out": un == "m.virtanen" and i == n - 2,
                    "failed_attempts": 3 if (un == "m.virtanen" and i == n - 2) else 0}
        snaps("sys_user", un, hrs, base, tags, per)


def groups():
    tags = ["sys_user_group"]
    for gi, (name, desc, mgr, active) in enumerate(GROUPS):
        base = {"name": name, "description": desc, "active": active, "manager": R(FULL[mgr]),
                "email": "%s@karins-power.example" % name.lower().replace(" ", "-").replace("/", "-"),
                "type": R("it" if "Security" in name or "IT" in name else "operations"), "cost_center": R("CC-4%d00" % (gi % 6 + 1)),
                "default_assignee": R(FULL[mgr]), "include_members": False, "exclude_manager": False}
        hrs = [24 * 25 + gi, 6 + gi * 1.3] if active else [24 * 27]
        snaps("sys_user_group", name, hrs, base, tags)


def memberships():
    tags = ["sys_user_grmember"]
    k = 0
    for un, name, *_r in USERS:
        for g in USERS[[u[0] for u in USERS].index(un)][8]:
            k += 1
            h = 6 + (k * 37) % 700 if k % 4 else 1 + (k % 20)
            emit("sys_user_grmember", "%s:%s" % (un, g), NOW - h * 3600.0,
                 {"user": R(name), "group": R(g), "sys_created_on": T(h + 24)}, tags)


# --------------------------------------------------------------------------------------------------------------
# Locations and departments
# --------------------------------------------------------------------------------------------------------------
LOCATIONS = [  # name, city, country, company, lat, lon, tz, stock_room
    (SITE, "Kotka", "Finland", SITE, 60.4664, 26.9458, "Europe/Helsinki", False),
    ("Karins Power Plant / Control Room", "Kotka", "Finland", SITE, 60.4665, 26.9459, "Europe/Helsinki", False),
    ("Karins Power Plant / Level 1 Control Network (Turbine Hall)", "Kotka", "Finland", SITE, 60.4662, 26.9455, "Europe/Helsinki", False),
    ("Karins Power Plant / Level 2 Process Network", "Kotka", "Finland", SITE, 60.4666, 26.9461, "Europe/Helsinki", False),
    ("Karins Power Plant / Level 3 Control DMZ", "Kotka", "Finland", SITE, 60.4667, 26.9462, "Europe/Helsinki", False),
    ("Karins Power Plant / Turbine Hall T2", "Kotka", "Finland", SITE, 60.4661, 26.9453, "Europe/Helsinki", False),
    ("Karins Power Plant / Substation 1", "Kotka", "Finland", SITE, 60.4650, 26.9440, "Europe/Helsinki", False),
    ("Karins Power Plant / Server Room", "Kotka", "Finland", SITE, 60.4668, 26.9463, "Europe/Helsinki", False),
    ("Karins Power Plant / USB Kiosk Lobby", "Kotka", "Finland", SITE, 60.4669, 26.9457, "Europe/Helsinki", False),
    ("Karins Power Plant / Spares Store", "Kotka", "Finland", SITE, 60.4660, 26.9449, "Europe/Helsinki", True),
    ("Karins Energy Group HQ", "Espoo", "Finland", GROUP_CO, 60.2055, 24.6559, "Europe/Helsinki", False),
    ("Karins DR Site Tampere", "Tampere", "Finland", GROUP_CO, 61.4978, 23.7610, "Europe/Helsinki", False),
    ("Karins Stockholm Trading Office", "Stockholm", "Sweden", GROUP_CO, 59.3293, 18.0686, "Europe/Stockholm", False),
    ("Siemens Service Centre Munich", "Munich", "Germany", "Siemens", 48.1351, 11.5820, "Europe/Berlin", False),
    ("Fortinet Support Sophia Antipolis", "Valbonne", "France", "Fortinet", 43.6163, 7.0556, "Europe/Paris", False),
    ("Karins Training Centre Tallinn", "Tallinn", "Estonia", GROUP_CO, 59.4370, 24.7536, "Europe/Tallinn", False),
]
CCODE = {"Finland": "FI", "Sweden": "SE", "Germany": "DE", "France": "FR", "Estonia": "EE"}


def locations():
    tags = ["cmn_location"]
    for li, (name, city, country, co, lat, lon, tz, stock) in enumerate(LOCATIONS):
        base = {"name": name, "full_name": name, "city": city, "country": country, "company": R(co), "latitude": lat,
                "longitude": lon, "time_zone": tz, "stock_room": stock, "street": "Voimalaitoksentie %d" % (1 + li),
                "zip": "4%04d" % (800 + li), "contact": R(FULL[OPS[li % len(OPS)]]), "duplicate": False}
        h = [24 * 28 + li, 5 + li * 1.7] if li % 3 == 0 else [4 + li * 1.9]
        # host.geo.country is the field the dashboard panel reads; the package pipeline only fills country_name.
        snaps("cmn_location", name, h, base, tags, extra={"host": {"geo": {"country": country,
                                                                          "country_iso_code": CCODE[country]}}})
    deps = [("Control Systems Engineering", "a.lindqvist", 6), ("OT Security", "j.koskinen", 5), ("Plant Operations", "o.rantanen", 18),
            ("Plant IT", "l.heikkinen", 7), ("Turbine Controls", "h.makela", 8)]
    for i, (d, head, cnt) in enumerate(deps):
        emit("cmn_department", d, NOW - (9 + i * 3) * 3600.0,
             {"name": d, "dept_head": R(FULL[head]), "head_count": cnt, "company": R(SITE), "primary_contact": R(FULL[head]),
              "description": "%s department at %s" % (d, SITE), "id": "D-%03d" % (10 + i)}, ["cmn_department"])


# --------------------------------------------------------------------------------------------------------------
# Incidents (tag "incident"), problems, changes
# --------------------------------------------------------------------------------------------------------------
PRIO = {1: ("1", "1 - Critical"), 2: ("2", "2 - High"), 3: ("3", "3 - Moderate"), 4: ("4", "4 - Low")}
SEV = {1: ("1", "1 - High"), 2: ("2", "2 - Medium"), 3: ("3", "3 - Low")}
IMPACT = {1: ("1", "1 - High"), 2: ("2", "2 - Medium"), 3: ("3", "3 - Low")}
CAT = {"sec": ("ot_security", "OT security"), "net": ("network", "Network"), "hw": ("hardware", "Hardware"),
       "sw": ("software", "Software"), "inq": ("inquiry", "Inquiry / Help")}
INC_STATE = {1: "New", 2: "In Progress", 3: "On Hold", 6: "Resolved", 7: "Closed"}
INC_TEMPLATES = [  # short, category, prio, severity, group, business service, ci, assignee pool
    ("Claroty CTD: S7 Unauthorized Read/Scan from KPP-ENG-WS02", "sec", 3, 2, "OT SOC", "Turbine Control", "KPP-ENG-WS02", ["j.koskinen", "s.laine"]),
    ("Defender: ransomware behavior on KPP-FILE-01", "sec", 1, 1, "IT Security", "Backup & Recovery", "KPP-FILE-01", ["t.berg", "n.aaltonen"]),
    ("FortiGate FGT-KPP-OT01: SSL VPN brute force from external hosts", "net", 2, 2, "Network Operations", "Remote Maintenance Access", "FGT-KPP-OT01", ["n.aaltonen", "r.lund"]),
    ("KPP-HMI-01: WinCC runtime crash on alarm page", "sw", 2, 2, "Plant IT", "SCADA Visualization", "KPP-HMI-01", ["l.heikkinen", "m.haas"]),
    ("Historian disk usage above 85 percent on KPP-HIST-01", "hw", 3, 3, "Plant IT", "Process Historian", "KPP-HIST-01", ["l.heikkinen", "e.voss"]),
    ("Turbine 2 governor setpoint drift reported by operators", "sec", 2, 1, "OT Security", "Turbine Control", "KPP-PLC-T2", ["j.koskinen", "a.lindqvist"]),
    ("Meta Data Kiosk: file blocked, policy violation", "sec", 3, 3, "OT SOC", "USB Media Scanning", "KPP-USB-KIOSK01", ["s.laine"]),
    ("Patch window request for KPP-ENG-WS01", "sw", 4, 3, "Service Desk", "Engineering Workstation Services", "KPP-ENG-WS01", ["m.haas", "e.voss"]),
    ("Remote access request for vendor Siemens", "inq", 4, 3, "Service Desk", "Remote Maintenance Access", "KPP-JUMP01", ["e.voss"]),
    ("RTU KPP-RTU-SS1 DNP3 poll timeouts", "net", 2, 2, "Substation Automation", "Substation Telemetry", "KPP-RTU-SS1", ["p.salo", "n.aaltonen"]),
    ("Claroty CTD: new unmanaged asset on control network", "sec", 3, 2, "OT Security", "OT Network Segmentation", "FGT-KPP-OT01", ["s.laine", "j.koskinen"]),
    ("FortiGate: interface port1 flapping", "net", 3, 2, "Network Operations", "OT Network Segmentation", "FGT-KPP-OT01", ["r.lund", "n.aaltonen"]),
    ("TIA Portal license server unreachable from engineering workstation", "sw", 3, 3, "Control Systems Engineering", "Engineering Workstation Services", "KPP-ENG-WS01", ["a.lindqvist"]),
    ("Time sync drift on KPP-ENG-WS02", "sw", 4, 3, "Plant IT", "Engineering Workstation Services", "KPP-ENG-WS02", ["l.heikkinen"]),
    ("Backup job failed on KPP-FILE-01", "hw", 3, 3, "Plant IT", "Backup & Recovery", "KPP-FILE-01", ["l.heikkinen", "m.haas"]),
    ("USB kiosk signature update failed", "sw", 3, 3, "OT Security", "USB Media Scanning", "KPP-USB-KIOSK01", ["s.laine"]),
    ("Operator account locked out in control room", "inq", 4, 3, "Service Desk", "SCADA Visualization", "KPP-HMI-01", ["e.voss", "m.haas"]),
    ("Defender: PUA on engineering workstation", "sec", 3, 2, "IT Security", "Engineering Workstation Services", "KPP-ENG-WS01", ["t.berg"]),
    ("Claroty CTD: firmware change detected on KPP-PLC-T2", "sec", 2, 1, "OT Security", "Turbine Control", "KPP-PLC-T2", ["j.koskinen", "s.laine"]),
    ("Switch KPP-SW-L2-01 port error rate high", "net", 3, 2, "Network Operations", "OT Network Segmentation", "KPP-SW-L2-01", ["r.lund"]),
]
INC_KINDS = ["in_progress", "closed", "resolved", "new", "closed", "on_hold", "reopened", "closed", "in_progress", "resolved"]
NOTES = ["Resolved after investigation, no further action.", "Confirmed benign, tuned the detection.",
         "Remediated and verified with the owner.", "Vendor fix applied.", "Duplicate of an existing incident.",
         "False positive: scheduled maintenance, known-good workstation."]
RECENT_H = [0.4, 1.1, 2.0, 3.4, 5.0, 6.5, 8.0, 10.0, 12.5, 14.0, 17.0, 19.5, 21.0, 23.0]


def steps_for(opened_h, kind):
    """Returns [(hours ago, state)] and the reopen flag for an incident/problem style lifecycle."""
    f = lambda x: max(opened_h * (1 - x), 0.05)  # noqa: E731
    if kind == "new":
        return [(opened_h, 1)], False
    if kind == "in_progress":
        return [(opened_h, 1), (f(0.2), 2)], False
    if kind == "on_hold":
        return [(opened_h, 1), (f(0.15), 2), (f(0.45), 3)], False
    if kind == "resolved":
        return [(opened_h, 1), (f(0.15), 2), (f(0.6), 6)], False
    if kind == "reopened":
        return [(opened_h, 1), (f(0.15), 2), (f(0.45), 6), (f(0.7), 2)], True
    return [(opened_h, 1), (f(0.15), 2), (f(0.5), 6), (f(0.8), 7)], False


def incidents():
    tags = ["incident"]
    rnd = random.Random(1001)
    older = sorted(rnd.uniform(26, 700) for _ in range(26))
    opened = RECENT_H + older
    for i, oh in enumerate(opened):
        short, c, prio, sev, grp, svc, ci, pool = INC_TEMPLATES[i % len(INC_TEMPLATES)]
        number = "INC%07d" % (11001 + i)
        kind = INC_KINDS[(i * 3) % len(INC_KINDS)]
        who = FULL[pool[i % len(pool)]]
        caller = FULL[OPS[(i * 5) % len(OPS)]] if c != "sec" else "Claroty CTD"
        steps, reopened = steps_for(oh, kind)
        opened_t = T(oh)
        for si, (h, st) in enumerate(steps):
            f = {"number": number, "short_description": short, "description": short, "category": CAT[c], "subcategory": "OT",
                 "state": (str(st), INC_STATE[st]), "incident_state": (str(st), INC_STATE[st]), "priority": PRIO[prio],
                 "urgency": IMPACT[min(prio, 3)], "impact": IMPACT[min(prio, 3)], "severity": SEV[sev],
                 "active": st not in (6, 7), "assignment_group": R(grp), "assigned_to": R(who) if st >= 2 else ("", ""),
                 "caller_id": R(caller), "opened_by": R(caller), "opened_at": opened_t, "business_service": R(svc),
                 "cmdb_ci": R(ci), "company": R(SITE), "location": R(SITE), "contact_type": "integration" if c == "sec" else "phone",
                 "sys_created_on": opened_t, "sys_updated_by": dv(who if st >= 2 else "admin"), "escalation": ("0", "Normal"),
                 "approval": "not requested", "made_sla": True, "sys_mod_count": dv(si + 1), "source": "Karins ITSM",
                 "reopen_count": 1 if (reopened and si == len(steps) - 1) else 0,
                 "close_code": "", "close_notes": ""}
            if st in (6, 7):
                note = NOTES[(i + si) % len(NOTES)]
                f.update(close_code="Solved (Permanently)" if i % 3 else "False positive", close_notes=note,
                         resolved_at=T(h), resolved_by=R(who))
            if st == 7:
                f["closed_at"] = T(h)
            emit("incident", number, NOW - h * 3600.0, f, tags)


PRB_STATE = {101: "New", 102: "Assess", 103: "Root Cause Analysis", 104: "Fix in Progress", 106: "Resolved", 107: "Closed"}
PRB = [  # short, category, prio, group, escalation, major, known_error, workaround, ci, service, kind, related, opened_h
    ("Turbine 2 governor setpoint deviation after TurbineGovernor_v14 download (KPP-PLC-T2)", "sec", 1, "Turbine Controls", 3, True, False, True,
     "KPP-PLC-T2", "Turbine Control", "rca", 4, 20),
    ("FortiGate FGT-KPP-OT01 port1 intermittent flapping", "net", 3, "Network Operations", 1, False, True, True, "FGT-KPP-OT01",
     "OT Network Segmentation", "fix", 5, 240),
    ("KPP-HMI-01 slow response after WinCC patch", "sw", 2, "Plant IT", 2, False, False, False, "KPP-HMI-01", "SCADA Visualization", "rca", 3, 110),
    ("Historian disk growth on KPP-HIST-01 exceeds forecast", "hw", 3, "Plant IT", 1, False, True, True, "KPP-HIST-01",
     "Process Historian", "resolved", 4, 400),
    ("Repeated Claroty false positives in Monday maintenance window", "sec", 4, "OT Security", 0, False, False, True, "KPP-ENG-WS01",
     "Engineering Workstation Services", "closed", 7, 650),
    ("Meta Data Kiosk scan engine signature update failures", "sw", 3, "OT Security", 1, False, True, False, "KPP-USB-KIOSK01",
     "USB Media Scanning", "fix", 3, 320),
    ("SSL VPN failed login spikes from external addresses", "net", 2, "Network Operations", 2, False, False, True, "FGT-KPP-OT01",
     "Remote Maintenance Access", "assess", 6, 60),
    ("Time sync drift on engineering workstations", "sw", 4, "Plant IT", 0, False, False, True, "KPP-ENG-WS02",
     "Engineering Workstation Services", "resolved", 2, 500),
    ("RTU560 DNP3 poll timeouts on substation 1 link", "net", 2, "Substation Automation", 2, False, False, False, "KPP-RTU-SS1",
     "Substation Telemetry", "rca", 3, 180),
    ("Nightly backup failures on KPP-FILE-01", "hw", 3, "Plant IT", 1, False, True, True, "KPP-FILE-01", "Backup & Recovery", "closed", 5, 690),
    ("Unmanaged devices appearing on Level 2 switch ports", "sec", 3, "OT Security", 1, False, False, False, "KPP-SW-L2-01",
     "OT Network Segmentation", "new", 2, 12),
    ("Engineering workstation TIA Portal license timeouts", "sw", 3, "Control Systems Engineering", 1, False, True, True, "KPP-ENG-WS01",
     "Engineering Workstation Services", "fix", 2, 36),
]
PRB_PATH = {"new": [101], "assess": [101, 102], "rca": [101, 102, 103], "fix": [101, 102, 103, 104],
            "resolved": [101, 102, 103, 104, 106], "closed": [101, 102, 103, 104, 106, 107]}
ESC = {0: ("0", "Normal"), 1: ("1", "Moderate"), 2: ("2", "High"), 3: ("3", "Overdue")}


def problems():
    tags = ["problem"]
    for i, (short, c, prio, grp, esc, major, known, wa, ci, svc, kind, rel, oh) in enumerate(PRB):
        number = "PRB%07d" % (40001 + i)
        path = PRB_PATH[kind]
        n = len(path)
        for si, st in enumerate(path):
            h = max(oh * (1 - si / float(n)), 0.1 + si * 0.01) if n > 1 else oh
            if si == 0:
                h = oh
            who = FULL[OPS[(i + 2) % len(OPS)]]
            f = {"number": number, "short_description": short,
                 "description": short + ". Raised from related incidents; tracked by %s." % grp, "category": CAT[c],
                 "state": (str(st), PRB_STATE[st]), "problem_state": (str(st), PRB_STATE[st]), "priority": PRIO[prio],
                 "urgency": IMPACT[min(prio, 3)], "impact": IMPACT[min(prio, 3)], "escalation": ESC[esc if st < 106 else 0],
                 "active": st < 107, "assignment_group": R(grp), "assigned_to": R(who) if st > 101 else ("", ""),
                 "opened_at": T(oh), "opened_by": R(who), "major_problem": major, "known_error": known and st >= 104,
                 "workaround_applied": wa and st >= 103, "related_incidents": rel, "cmdb_ci": R(ci),
                 "business_service": R(svc), "approval": "not requested", "reopen_count": 1 if (i % 5 == 2 and st >= 103) else 0,
                 "upon_reject": ("cancel", "Cancel all future Tasks"), "company": R(SITE), "sys_created_on": T(oh),
                 "sys_updated_by": dv(who), "sys_mod_count": dv(si + 1), "resolution_code": "", "close_notes": ""}
            if st >= 103:
                f["cause_notes"] = "Investigation points to %s. Evidence collected in Claroty CTD and Elastic." % short.split(" (")[0].lower()
            if st >= 106:
                f.update(resolution_code=("fix_applied", "Fix applied"), close_notes="Fix applied and validated by %s." % who,
                         fix_notes="Corrective change implemented under change control.", resolved_at=T(h), resolved_by=R(who))
            if st == 107:
                f["closed_at"] = T(h)
            emit("problem", number, NOW - h * 3600.0, f, tags)


CHG_STATE = {-5: "New", -4: "Assess", -3: "Authorize", -2: "Scheduled", -1: "Implement", 0: "Review", 3: "Closed", 4: "Canceled"}
SCOPE = {2: ("2", "Large"), 3: ("3", "Medium"), 4: ("4", "Small"), 5: ("5", "Tiny")}
RISK = {2: ("2", "High"), 3: ("3", "Moderate"), 4: ("4", "Low")}
CHANGES = [  # short, type, category, risk, scope, prio, group, requester, ci, service, final state path, opened_h, tasks
    ("Turbine 2 governor update TurbineGovernor_v14 on KPP-PLC-T2", "Normal", "Software", 2, 3, 2, "Control Systems Engineering", "h.makela",
     "KPP-PLC-T2", "Turbine Control", [-5, -4, -3, -2], 36, ["Prepare and verify program backup", "Download TurbineGovernor_v14 to KPP-PLC-T2", "Post-change validation of governor response"]),
    ("Firewall rule update on FGT-KPP-OT01 for historian replication", "Normal", "Network", 3, 4, 3, "Network Operations", "n.aaltonen",
     "FGT-KPP-OT01", "OT Network Segmentation", [-5, -4, -3, -2, -1, 0, 3], 300, ["Review rule set", "Apply policy change"]),
    ("Windows security patching of KPP-ENG-WS01 and KPP-ENG-WS02", "Standard", "Software", 4, 4, 3, "Plant IT", "l.heikkinen",
     "KPP-ENG-WS01", "Engineering Workstation Services", [-5, -3, -2, -1, 3], 210, ["Snapshot workstations", "Install patches", "Verify TIA Portal"]),
    ("WinCC screen update for turbine hall overview (KPP-HMI-01)", "Normal", "Software", 3, 4, 3, "Control Systems Engineering", "a.lindqvist",
     "KPP-HMI-01", "SCADA Visualization", [-5, -4, -3, -2, -1, 0, 3], 520, ["Export HMI project", "Deploy screens"]),
    ("PI historian upgrade on KPP-HIST-01", "Normal", "Software", 3, 3, 3, "Plant IT", "l.heikkinen", "KPP-HIST-01",
     "Process Historian", [-5, -4, -3], 90, ["Backup PI archives", "Upgrade PI server"]),
    ("Meta Data Kiosk scan engine signature update", "Standard", "Software", 4, 5, 4, "OT Security", "s.laine", "KPP-USB-KIOSK01",
     "USB Media Scanning", [-5, -2, -1, 3], 150, ["Apply signature package"]),
    ("Emergency: RTU560 firmware hotfix for DNP3 timeouts", "Emergency", "Hardware", 2, 4, 1, "Substation Automation", "p.salo", "KPP-RTU-SS1",
     "Substation Telemetry", [-5, -3, -1, 0, 3], 100, ["Stage firmware", "Flash RTU", "Verify telemetry"]),
    ("Replace turbine 2 vibration sensor", "Normal", "Hardware", 3, 4, 3, "Turbine Controls", "h.makela", "KPP-PLC-T2",
     "Turbine Control", [-5, -4, 4], 380, ["Order spare sensor"]),
    ("Level 3 jump host OS upgrade (KPP-JUMP01)", "Normal", "Software", 3, 4, 3, "Network Operations", "r.lund", "KPP-JUMP01",
     "Remote Maintenance Access", [-5, -4, -3, -2, -1, 0, 3], 600, ["Build new image", "Cutover"]),
    ("Domain controller certificate renewal", "Standard", "Software", 4, 4, 4, "Plant IT", "l.heikkinen", "KPP-DC01", "Patch Management",
     [-5, -2, -1, 3], 450, ["Renew and deploy certificate"]),
    ("Level 2 switch KPP-SW-L2-01 configuration backup and port security", "Normal", "Network", 3, 3, 3, "Network Operations", "n.aaltonen",
     "KPP-SW-L2-01", "OT Network Segmentation", [-5, -4, -3, -2, -1], 14, ["Back up running config", "Enable port security"]),
    ("UPS battery maintenance, server room", "Standard", "Hardware", 4, 5, 4, "Plant IT", "m.haas", "KPP-HIST-01", "Backup & Recovery",
     [-5, -2, 3], 680, ["Swap battery module"]),
    ("Enable MFA on remote access gateway", "Normal", "Other", 3, 2, 2, "IT Security", "t.berg", "FGT-KPP-OT01", "Remote Maintenance Access",
     [-5, -4, -3, -2, -1, 0, 3], 280, ["Enrol vendor accounts", "Switch on enforcement"]),
]
TASK_STATE = {1: "Open", 2: "Work in Progress", 3: "Closed Complete", 4: "Closed Incomplete"}


def changes():
    for i, (short, typ, cat, risk, scope, prio, grp, req, ci, svc, path, oh, tasks) in enumerate(CHANGES):
        number = "CHG%07d" % (30001 + i)
        n = len(path)
        who = FULL[OPS[(i * 3 + 1) % len(OPS)]]
        for si, st in enumerate(path):
            h = oh if si == 0 else max(oh * (1 - si / float(n)), 0.2 + si * 0.01)
            cl = st in (3, 4)
            f = {"number": number, "short_description": short, "description": short + ". Planned under the Karins change process.",
                 "state": (str(st), CHG_STATE[st]), "phase": ("requested" if st < -2 else "implementation", "Requested" if st < -2 else "Implementation"),
                 "phase_state": ("closed", "Closed") if cl else ("open", "Open"), "type": typ, "category": cat, "risk": RISK[risk],
                 "scope": SCOPE[scope], "priority": PRIO[prio], "impact": IMPACT[min(prio, 3)], "active": not cl,
                 "requested_by": R(FULL[req]), "assigned_to": R(who), "assignment_group": R(grp), "cmdb_ci": R(ci),
                 "business_service": R(svc), "conflict_status": "Conflict" if i == 10 else "No Conflict",
                 "cab_required": typ != "Standard", "production_system": True, "unauthorized": False,
                 "outside_maintenance_schedule": typ == "Emergency", "approval": "approved" if st >= -2 else "requested",
                 "start_date": T(oh - 24 if st < 3 else h + 4), "end_date": T(oh - 26 if st < 3 else h + 2),
                 "reason": "Planned maintenance" if typ != "Emergency" else "Restore telemetry", "opened_at": T(oh),
                 "opened_by": R(FULL[req]), "company": R(SITE), "sys_created_on": T(oh), "sys_updated_by": dv(who),
                 "sys_mod_count": dv(si + 1), "review_status": ("3", "Complete") if st in (0, 3) else ("1", "Not reviewed")}
            if cl:
                f.update(closed_at=T(h), close_code="successful" if st == 3 else "unsuccessful",
                         close_notes="Implemented and validated." if st == 3 else "Cancelled, superseded by vendor advisory.")
            emit("change_request", number, NOW - h * 3600.0, f, ["change_request"])
        for k, tshort in enumerate(tasks):
            tnum = "CTASK%07d" % (50001 + i * 4 + k)
            done = 3 in path or (-1 in path and k == 0)
            tpath = [1, 2, 3] if done else ([1, 2] if -1 in path else [1])
            if path[-1] == 4:
                tpath = [1, 4]
            tt = ("planning" if k == 0 else "implementation" if k < len(tasks) - 1 or len(tasks) == 1 else "review",
                  "Planning" if k == 0 else "Implementation" if k < len(tasks) - 1 or len(tasks) == 1 else "Review")
            tw = FULL[OPS[(i + k * 2) % len(OPS)]]
            for ti, ts in enumerate(tpath):
                th = max(oh * (1 - (k + ti + 1) / float(len(tasks) + len(tpath) + 1)) * 0.9, 0.15 + ti * 0.02)
                if ts == 1 and ti == 0:
                    th = max(oh * 0.95 - k * 0.5, 0.3)
                tf = {"number": tnum, "short_description": tshort, "description": tshort + " (" + number + ")",
                      "change_request": R(number), "change_task_type": tt, "state": (str(ts), TASK_STATE[ts]), "priority": PRIO[prio],
                      "contact_type": "email" if k % 2 else "phone", "assigned_to": R(tw), "assignment_group": R(grp),
                      "active": ts in (1, 2), "made_sla": not (i % 6 == 5 and k == 0), "opened_by": R(FULL[req]),
                      "opened_at": T(oh * 0.95 - k * 0.5 if oh > 2 else oh), "cmdb_ci": R(ci), "company": R(SITE),
                      "sys_created_on": T(oh * 0.95), "sys_updated_by": dv(tw), "sys_mod_count": dv(ti + 1)}
                if ts in (3, 4):
                    tf["closed_at"] = T(th)
                emit("change_task", tnum, NOW - th * 3600.0, tf, ["change_task"])


# --------------------------------------------------------------------------------------------------------------
# Knowledge
# --------------------------------------------------------------------------------------------------------------
KB = [  # title, topic, author, state, rating, base views
    ("S7-1500 PLC maintenance: pre-flight checklist before a program download", "Siemens S7 Maintenance", "a.lindqvist", "published", "4.8", 410),
    ("S7-1500 PLC maintenance: backing up and comparing project versions", "Siemens S7 Maintenance", "a.lindqvist", "published", "4.6", 330),
    ("Turbine 2 governor update procedure for TurbineGovernor_v14", "Turbine Controls", "h.makela", "published", "4.9", 280),
    ("Scanning USB media at the Meta Data Kiosk before it enters Level 2", "USB Media Scanning", "s.laine", "published", "4.7", 520),
    ("What to do when the kiosk blocks a file", "USB Media Scanning", "s.laine", "published", "4.2", 360),
    ("Handling Claroty CTD alerts during the Monday maintenance window", "OT Security Operations", "j.koskinen", "published", "4.5", 240),
    ("Triage guide: PLC program download detected", "OT Security Operations", "j.koskinen", "review", "4.4", 190),
    ("Requesting vendor remote access through the Level 3 jump host", "Remote Access", "n.aaltonen", "published", "3.9", 300),
    ("FortiGate FGT-KPP-OT01 SSL VPN troubleshooting", "Network Security", "r.lund", "published", "4.1", 215),
    ("Restoring the PI historian from backup", "Backup and Recovery", "l.heikkinen", "published", "4.3", 120),
    ("WinCC HMI restart and alarm acknowledgement guide for operators", "Control Room Operations", "o.rantanen", "published", "4.6", 450),
    ("Legacy RTU firmware upgrade notes (superseded)", "Substation Automation", "p.salo", "outdated", "2.9", 60),
    ("Draft: Level 3 DMZ jump host hardening baseline", "Network Security", "t.berg", "draft", "0", 5),
]


def knowledge():
    tags = ["kb_knowledge"]
    for i, (title, topic, author, state, rating, views) in enumerate(KB):
        number = "KB%07d" % (10001 + i)
        hrs = [24 * 26 - i * 9, 24 * 14 - i * 6, 24 * 5 + i, 3 + i * 1.7] if state != "draft" else [30 + i]
        n = len(hrs)

        def per(si, n, views=views):
            return {"sys_view_count": int(views * (si + 1) / float(n)) if state != "draft" else 3,
                    "use_count": int(views * (si + 1) / (6.0 * n))}
        base = {"number": number, "short_description": title, "topic": topic, "workflow_state": state, "article_type": ("html", "HTML"),
                "author": R(FULL[author]), "rating": rating, "kb_knowledge_base": R("OT Operations Knowledge Base"),
                "kb_category": R(topic), "active": state != "outdated", "published": T(hrs[-1] + 2) if state == "published" else "",
                "valid_to": T(-24 * 300), "text": "<p>%s. Maintained by %s for %s.</p><ul><li>Verify the change window</li><li>Record the outcome in ServiceNow</li></ul>"
                % (title, FULL[author], SITE), "flagged": False, "disable_commenting": False, "disable_suggesting": False,
                "display_attachments": True, "direct": False, "view_as_allowed": True, "generated_with_now_assist": False,
                "sys_created_on": T(24 * 120 + i), "sys_updated_by": dv(author)}
        snaps("kb_knowledge", number, hrs, base, tags, per, extra={"user": {"full": FULL[author]}})


# --------------------------------------------------------------------------------------------------------------
# CMDB: services, servers, computers, hardware, ALM, DB instances, relations
# --------------------------------------------------------------------------------------------------------------
def ci_common(name, ip, vendor, mfr, model, serial, tag, cost, loc, support, assigned, op="Operational", inst="Installed", i=0,
              unverified=False, disc="Claroty CTD", used="Production"):
    return {"name": name, "short_description": name, "host_name": name, "ip_address": ip, "vendor": R(vendor),
            "manufacturer": R(mfr), "model_id": R(model), "serial_number": serial, "asset_tag": tag,
            "cost": (str(cost), "%s.00" % format(cost, ",")), "cost_cc": "EUR", "location": R(loc), "company": R(SITE),
            "support_group": R(support), "assigned_to": R(FULL[assigned]), "managed_by": R(FULL[assigned]),
            "owned_by": R(FULL[assigned]), "operational_status": op, "install_status": inst, "unverified": unverified,
            "discovery_source": disc, "used_for": used, "warranty_expiration": T(-24 * (200 + i * 53) + 0),
            "first_discovered": T(24 * 120 + i), "last_discovered": T(5 + i), "po_number": "PO-%05d" % (7100 + i),
            "sys_created_on": T(24 * 130 + i)}


SERVERS = [  # table, class, name, ip, os, os version, vendor/mfr, model, os subcategory, loc, support, assigned, fw, used, unverified, maint
    ("cmdb_ci_win_server", "Windows Server", "KPP-HIST-01", "10.20.3.40", "Windows Server 2019 Standard", "10.0.17763", "HPE", "ProLiant DL360 Gen11",
     "Windows", "Level 2 Process Network", "Plant IT", "l.heikkinen", "Intranet", "Production", False),
    ("cmdb_ci_win_server", "Windows Server", "KPP-SCADA-SRV01", "10.20.3.30", "Windows Server 2022 Standard", "10.0.20348", "Dell", "PowerEdge R660",
     "Windows", "Level 2 Process Network", "Control Systems Engineering", "a.lindqvist", "Intranet", "Production", False),
    ("cmdb_ci_win_server", "Windows Server", "KPP-DC01", "10.20.5.10", "Windows Server 2022 Standard", "10.0.20348", "Dell", "PowerEdge R660",
     "Windows", "Server Room", "Plant IT", "l.heikkinen", "Intranet", "Production", False),
    ("cmdb_ci_server", "Server", "KPP-FILE-01", "10.20.5.20", "Windows Server 2019 Standard", "10.0.17763", "HPE", "ProLiant DL380 Gen10",
     "Windows", "Server Room", "Plant IT", "l.heikkinen", "Intranet", "Production", False),
    ("cmdb_ci_linux_server", "Linux Server", "KPP-JUMP01", "10.20.0.60", "Red Hat Enterprise Linux 9", "9.3", "Dell", "PowerEdge R250",
     "Linux", "Level 3 Control DMZ", "Network Operations", "n.aaltonen", "DMZ", "Production", False),
    ("cmdb_ci_linux_server", "Linux Server", "KPP-SYSLOG01", "10.20.0.61", "Ubuntu Server 22.04", "22.04.4", "Dell", "PowerEdge R250",
     "Linux", "Level 3 Control DMZ", "OT Security", "s.laine", "DMZ", "Production", False),
    ("cmdb_ci_app_server", "Application Server", "KPP-PIWEB-01", "10.20.3.41", "Windows Server 2019 Standard", "10.0.17763", "Microsoft", "PI Web API",
     "Windows", "Level 2 Process Network", "Plant IT", "l.heikkinen", "Intranet", "Production", True),
    ("cmdb_ci_vm", "Virtual Machine", "KPP-VM-HMI-BKP", "10.20.3.11", "Windows 10 IoT Enterprise LTSC", "10.0.19044", "VMware", "VMware Virtual Platform",
     "Virtual", "Level 2 Process Network", "Control Systems Engineering", "a.lindqvist", "Intranet", "Staging", True),
    ("cmdb_ci_vm", "Virtual Machine", "KPP-VM-TEST01", "10.20.3.90", "Windows Server 2022 Standard", "10.0.20348", "VMware", "VMware Virtual Platform",
     "Virtual", "Server Room", "Plant IT", "m.haas", "Not Protected", "Test", True),
]
MAINT = ["Mon 08:00-10:00 Europe/Helsinki", "Sun 02:00-04:00 Europe/Helsinki", "Wed 22:00-23:00 Europe/Helsinki"]


def servers():
    for i, (table, cls, name, ip, os_, osv, mfr, model, sub, loc, sup, who, fw, used, unv) in enumerate(SERVERS):
        c = ci_common(name, ip, mfr, mfr, model, "SN-%s-%04d" % (name[-4:].replace("-", ""), 4400 + i), "KPP-A%04d" % (200 + i),
                      9000 + i * 1700, SITE + " / " + loc if False else SITE, sup, who, i=i, unverified=unv,
                      disc="ServiceNow Discovery" if i % 2 else "Claroty CTD", used=used)
        c.update({"sys_class_name": cls, "os": os_, "os_version": osv, "subcategory": sub, "firewall_status": fw,
                  "maintenance_schedule": R(MAINT[i % 3]), "dns_domain": "kpp.example", "cpu_count": 2 + i % 3, "ram": 32768 + 16384 * (i % 3),
                  "location": R(SITE + " / " + ("Server Room" if "Server" in loc or "DMZ" in loc else loc)), "category": "Server",
                  "operational_status": "Non-Operational" if i == 8 else "Operational"})
        hrs = [24 * 24 + i * 5, 24 * 9 + i * 3, 30 + i * 2, 1.5 + i * 0.9]
        snaps(table, name, hrs, c, [table, "cmdb_ci", "cmdb"],
              lambda si, n: {"last_discovered": T(hrs[si] + 0.2), "sys_mod_count": dv(si + 1)})


COMPUTERS = [  # name, ip, os, mfr/vendor, model, cpu, hw status, unverified, assigned, loc, cost center
    ("KPP-ENG-WS01", "10.20.3.21", "Windows 11 Enterprise", "Dell", "Precision 5860 Tower", "Intel Xeon w5-2455X", "Installed", False, "a.lindqvist", "Level 2 Process Network", "CC-4200 Control Systems"),
    ("KPP-ENG-WS02", "10.20.3.22", "Windows 11 Enterprise", "Dell", "Precision 5860 Tower", "Intel Xeon w5-2455X", "Installed", False, "a.lindqvist", "Level 2 Process Network", "CC-4200 Control Systems"),
    ("KPP-HMI-01", "10.20.3.10", "Windows 10 IoT Enterprise LTSC", "Siemens", "SIMATIC IPC477E", "Intel Core i7-8700T", "Installed", False, "o.rantanen", "Control Room", "CC-4100 Plant Operations"),
    ("KPP-HMI-02", "10.20.3.11", "Windows 10 IoT Enterprise LTSC", "Siemens", "SIMATIC IPC477E", "Intel Core i7-8700T", "Installed", False, "o.rantanen", "Control Room", "CC-4100 Plant Operations"),
    ("KPP-USB-KIOSK01", "10.20.0.50", "Windows 10 Enterprise LTSC", "OPSWAT", "MetaDefender Kiosk K1000", "Intel Core i5-10500", "Installed", False, "s.laine", "USB Kiosk Lobby", "CC-4300 OT Security"),
    ("KPP-OPS-WS01", "10.20.3.51", "Windows 10 Enterprise", "HP", "Z2 G9 Tower", "Intel Core i7-12700", "Installed", True, "m.virtanen", "Control Room", "CC-4100 Plant Operations"),
    ("KPP-OPS-WS02", "10.20.3.52", "Windows 10 Enterprise", "HP", "Z2 G9 Tower", "Intel Core i7-12700", "In stock", True, "o.rantanen", "Spares Store", "CC-4100 Plant Operations"),
    ("KPP-OFF-LT01", "10.20.5.101", "Windows 11 Pro", "Lenovo", "ThinkPad T14", "Intel Core i5-1335U", "Installed", False, "e.voss", "Server Room", "CC-4500 Plant IT"),
    ("KPP-OFF-LT02", "10.20.5.102", "Windows 11 Pro", "Lenovo", "ThinkPad T14", "Intel Core i5-1335U", "In maintenance", True, "m.haas", "Server Room", "CC-4500 Plant IT"),
    ("KPP-ENG-LT09", "10.20.3.29", "Windows 10 Enterprise", "Dell", "Latitude 5540", "Intel Core i7-1355U", "Retired", False, "a.lindqvist", "Spares Store", "CC-4200 Control Systems"),
]


def computers():
    for i, (name, ip, os_, mfr, model, cpu, hw, unv, who, loc, cc) in enumerate(COMPUTERS):
        c = ci_common(name, ip, mfr, mfr, model, "SN-%s-%04d" % (name[-4:].replace("-", ""), 5500 + i), "KPP-C%04d" % (300 + i),
                      2400 + i * 650, SITE, "Control Systems Engineering" if "ENG" in name else "Service Desk", who, i=i,
                      unverified=unv, disc="Claroty CTD" if i < 5 else "ServiceNow Discovery")
        c.update({"sys_class_name": "Computer", "os": os_, "os_version": "10.0.%d" % (19044 + i), "cpu_name": cpu, "cpu_count": 1,
                  "cpu_speed": 3200 + i * 50, "ram": 16384 * (1 + i % 3), "disk_space": 512, "hardware_status": hw,
                  "cost_center": R(cc), "location": R(SITE + " / " + loc), "subcategory": "Workstation" if "WS" in name else "Computer",
                  "operational_status": "Non-Operational" if hw == "Retired" else "Operational",
                  "install_status": "Retired" if hw == "Retired" else "Installed"})
        hrs = [24 * 22 + i * 7, 24 * 6 + i * 2, 18 + i * 0.7] if i % 2 else [24 * 15 + i, 2.5 + i * 0.8]
        snaps("cmdb_ci_computer", name, hrs, c, ["cmdb_ci_computer", "cmdb_ci", "cmdb"],
              lambda si, n, hrs=hrs: {"last_discovered": T(hrs[si] + 0.2)})


HARDWARE = [  # name, ip, mfr, model, class, hw status, loc, assigned, cost
    ("KPP-PLC-T2", "10.20.4.12", "Siemens", "SIMATIC S7-1500 CPU 1516-3 PN/DP", "Hardware", "Installed", "Turbine Hall T2", "h.makela", 18500),
    ("KPP-RTU-SS1", "10.20.4.30", "ABB", "RTU560", "Hardware", "Installed", "Substation 1", "p.salo", 14200),
    ("FGT-KPP-OT01", "10.20.0.1", "Fortinet", "FortiGate 100F", "Network Gear", "Installed", "Level 3 Control DMZ", "n.aaltonen", 6200),
    ("KPP-SW-L2-01", "10.20.3.2", "Hirschmann", "GRS1042 Industrial Switch", "Network Gear", "Installed", "Level 2 Process Network", "r.lund", 3100),
    ("KPP-SW-L1-01", "10.20.4.2", "Siemens", "SCALANCE XC208", "Network Gear", "Installed", "Level 1 Control Network (Turbine Hall)", "r.lund", 1250),
    ("KPP-SW-L1-02", "10.20.4.3", "Siemens", "SCALANCE XC208", "Network Gear", "In stock", "Spares Store", "r.lund", 1250),
    ("KPP-UPS-SR1", "10.20.5.200", "APC", "Smart-UPS SRT 5000", "Hardware", "Installed", "Server Room", "m.haas", 4900),
    ("KPP-ET200-T2A", "10.20.4.21", "Siemens", "SIMATIC ET 200SP", "Hardware", "Installed", "Turbine Hall T2", "h.makela", 2300),
    ("KPP-PLC-SPARE1", "", "Siemens", "SIMATIC S7-1500 CPU 1516-3 PN/DP", "Hardware", "In stock", "Spares Store", "h.makela", 18500),
]


def hardware():
    for i, (name, ip, mfr, model, cls, hw, loc, who, cost) in enumerate(HARDWARE):
        c = ci_common(name, ip, mfr, mfr, model, "SN-%s-%04d" % (name[-4:].replace("-", ""), 6600 + i), "KPP-H%04d" % (400 + i), cost,
                      SITE, "Turbine Controls" if "PLC" in name or "ET200" in name else "Network Operations", who, i=i,
                      unverified=i == 8, disc="Claroty CTD", op="Non-Operational" if hw == "In stock" else "Operational")
        if not ip:
            c.pop("ip_address")
        c.update({"sys_class_name": cls, "hardware_status": hw, "cost_center": R("CC-4200 Control Systems" if "PLC" in name else "CC-4500 Plant IT"),
                  "location": R(SITE + " / " + loc), "install_status": "In stock" if hw == "In stock" else "Installed",
                  "subcategory": cls})
        hrs = [24 * 20 + i * 11, 24 * 7 + i * 4, 10 + i * 2.1]
        snaps("cmdb_ci_hardware", name, hrs, c, ["cmdb_ci_hardware", "cmdb_ci", "cmdb"],
              lambda si, n, hrs=hrs: {"last_discovered": T(hrs[si] + 0.2)})


MODEL_CAT = ["Computer", "Server", "Network Gear", "PLC / Controller", "Computer", "Network Gear", "Peripheral", "PLC / Controller"]


def alm():
    items = [("KPP-ENG-WS01", "Dell Precision 5860 Tower", "Computer", "CC-4200 Control Systems", "Dell", "a.lindqvist"),
             ("KPP-ENG-WS02", "Dell Precision 5860 Tower", "Computer", "CC-4200 Control Systems", "Dell", "a.lindqvist"),
             ("KPP-HMI-01", "Siemens SIMATIC IPC477E", "Computer", "CC-4100 Plant Operations", "Siemens", "o.rantanen"),
             ("KPP-HIST-01", "HPE ProLiant DL360 Gen11", "Server", "CC-4500 Plant IT", "HPE", "l.heikkinen"),
             ("KPP-SCADA-SRV01", "Dell PowerEdge R660", "Server", "CC-4200 Control Systems", "Dell", "a.lindqvist"),
             ("KPP-PLC-T2", "Siemens SIMATIC S7-1500 CPU 1516-3 PN/DP", "PLC / Controller", "CC-4200 Control Systems", "Siemens", "h.makela"),
             ("KPP-RTU-SS1", "ABB RTU560", "PLC / Controller", "CC-4600 Substation Automation", "ABB", "p.salo"),
             ("FGT-KPP-OT01", "Fortinet FortiGate 100F", "Network Gear", "CC-4300 OT Security", "Fortinet", "n.aaltonen"),
             ("KPP-SW-L2-01", "Hirschmann GRS1042", "Network Gear", "CC-4500 Plant IT", "Hirschmann", "r.lund"),
             ("KPP-USB-KIOSK01", "OPSWAT MetaDefender Kiosk K1000", "Peripheral", "CC-4300 OT Security", "OPSWAT", "s.laine"),
             ("KPP-UPS-SR1", "APC Smart-UPS SRT 5000", "Peripheral", "CC-4500 Plant IT", "APC", "m.haas"),
             ("KPP-PLC-SPARE1", "Siemens SIMATIC S7-1500 CPU 1516-3 PN/DP", "PLC / Controller", "CC-4200 Control Systems", "Siemens", "h.makela")]
    for i, (ci, model, cat, cc, vendor, who) in enumerate(items):
        tag = "KPP-ALM%04d" % (100 + i)
        base = {"display_name": "%s - %s" % (tag, ci), "asset_tag": tag, "model": R(model), "model_category": R(cat), "ci": R(ci),
                "cost_center": R(cc), "vendor": R(vendor), "manufacturer": R(vendor), "assigned_to": R(FULL[who]), "company": R(SITE),
                "serial_number": "SN-ALM-%04d" % (3300 + i), "install_status": "In stock" if "SPARE" in ci else "In use",
                "location": R(SITE), "cost": (str(3000 + i * 1400), "%s.00" % format(3000 + i * 1400, ",")),
                "purchase_date": T(24 * (500 + i * 40)), "warranty_expiration": T(-24 * (150 + i * 30)), "residual": 1500.0 + i * 100,
                "salvage_value": 300.0, "depreciated_amount": 900.0 + i * 50, "eligible_for_refresh": i % 4 == 0, "pre_allocated": False,
                "substatus": "", "state": ("6", "In stock") if "SPARE" in ci else ("1", "In use"), "sys_created_on": T(24 * 130 + i)}
        snaps("alm_hardware", tag, [24 * 18 + i * 6, 8 + i * 1.6], base, ["alm_hardware"])


SERVICES = [  # name, category, business unit, support group, op status, used for, unverified, discovery
    ("Turbine Control", "Business Service", "Generation", "Turbine Controls", "Operational", "Production", False, "Manual Entry"),
    ("Process Historian", "Technical Service", "Operations", "Plant IT", "Operational", "Production", False, "ServiceNow Discovery"),
    ("SCADA Visualization", "Business Service", "Operations", "Control Systems Engineering", "Operational", "Production", False, "ServiceNow Discovery"),
    ("OT Network Segmentation", "Technical Service", "Operations", "Network Operations", "Operational", "Production", False, "Claroty CTD"),
    ("USB Media Scanning", "Technical Service", "Operations", "OT Security", "Operational", "Production", False, "Claroty CTD"),
    ("Remote Maintenance Access", "Technical Service", "Operations", "Network Operations", "Repair in Progress", "Production", False, "Manual Entry"),
    ("Substation Telemetry", "Business Service", "Grid", "Substation Automation", "Operational", "Production", False, "Claroty CTD"),
    ("Engineering Workstation Services", "Technical Service", "Generation", "Control Systems Engineering", "Operational", "Production", True, "ServiceNow Discovery"),
    ("Patch Management", "Technical Service", "IT", "Plant IT", "Operational", "Staging", True, "Manual Entry"),
    ("Backup & Recovery", "Technical Service", "IT", "Plant IT", "Non-Operational", "Production", True, "ServiceNow Discovery"),
    ("Training Simulator", "Business Service", "Generation", "Control Systems Engineering", "Operational", "Test", True, "Manual Entry"),
]


def services():
    for i, (name, cat, bu, sup, op, used, unv, disc) in enumerate(SERVICES):
        base = {"name": name, "short_description": name + " at " + SITE, "category": cat, "business_unit": R(bu), "support_group": R(sup),
                "operational_status": op, "used_for": used, "unverified": unv, "discovery_source": disc, "install_status": "Installed" if i != 9 else "Installed",
                "company": R(SITE), "managed_by": R(FULL[OPS[i % len(OPS)]]), "owned_by": R(FULL[OPS[(i + 3) % len(OPS)]]),
                "sys_class_name": "Business Service" if cat.startswith("Business") else "Technical Service", "location": R(SITE),
                "service_classification": cat, "sys_created_on": T(24 * 300), "sys_updated_by": dv("admin")}
        snaps("cmdb_ci_service", name, [24 * 19 + i * 8, 24 * 5 + i * 3, 4 + i * 1.3], base, ["cmdb_ci_service", "cmdb"],
              lambda si, n: {"operational_status": "Operational" if (si == 0 and i == 5) else op})


DBS = [  # name, model, ip, port, host, used
    ("PI_Archive", "Microsoft SQL Server 2019 Standard", "10.20.3.40", "1433", "KPP-HIST-01", "Production"),
    ("PI_AF_Config", "Microsoft SQL Server 2019 Standard", "10.20.3.41", "1433", "KPP-PIWEB-01", "Production"),
    ("SCADA_Config", "PostgreSQL 14", "10.20.3.30", "5432", "KPP-SCADA-SRV01", "Production"),
    ("CMMS_Maintenance", "Oracle Database 19c", "10.20.5.30", "1521", "KPP-FILE-01", "Production"),
    ("Kiosk_Audit", "SQLite 3", "10.20.0.50", "0", "KPP-USB-KIOSK01", "Production"),
    ("PI_Archive_Test", "Microsoft SQL Server 2019 Express", "10.20.3.90", "1433", "KPP-VM-TEST01", "Test"),
]


def db_instances():
    for i, (name, model, ip, port, host, used) in enumerate(DBS):
        c = ci_common(name, ip, model.split()[0], model.split()[0], model, "SN-DB-%04d" % (8800 + i), "KPP-D%04d" % (500 + i),
                      4000 + i * 900, SITE, "Plant IT", "l.heikkinen", i=i, used=used, unverified=i == 5)
        c.update({"cl_port": port, "sys_class_name": "Database Instance", "type": model.split()[0].lower(), "version": model.split()[-1],
                  "instance_name": name, "category": "Database", "short_description": "%s on %s" % (name, host)})
        snaps("cmdb_ci_db_instance", name, [24 * 17 + i * 9, 6 + i * 2.3], c, ["cmdb_ci_db_instance", "cmdb_ci", "cmdb"])


RELS = [  # parent, child, type, strength
    ("Turbine Control", "KPP-PLC-T2", "Depends on::Used by", "Always"),
    ("Turbine Control", "KPP-ENG-WS01", "Depends on::Used by", "Occasionally"),
    ("Turbine Control", "KPP-ENG-WS02", "Depends on::Used by", "Occasionally"),
    ("Process Historian", "KPP-HIST-01", "Runs on::Runs", "Always"),
    ("Process Historian", "PI_Archive", "Depends on::Used by", "Always"),
    ("SCADA Visualization", "KPP-HMI-01", "Runs on::Runs", "Always"),
    ("SCADA Visualization", "KPP-HMI-02", "Runs on::Runs", "Always"),
    ("SCADA Visualization", "KPP-SCADA-SRV01", "Depends on::Used by", "Always"),
    ("OT Network Segmentation", "FGT-KPP-OT01", "Runs on::Runs", "Always"),
    ("OT Network Segmentation", "KPP-SW-L2-01", "Depends on::Used by", "Always"),
    ("USB Media Scanning", "KPP-USB-KIOSK01", "Runs on::Runs", "Always"),
    ("Remote Maintenance Access", "KPP-JUMP01", "Runs on::Runs", "Always"),
    ("Remote Maintenance Access", "FGT-KPP-OT01", "Depends on::Used by", "Always"),
    ("Substation Telemetry", "KPP-RTU-SS1", "Depends on::Used by", "Always"),
    ("Engineering Workstation Services", "KPP-ENG-WS01", "Runs on::Runs", "Always"),
    ("Engineering Workstation Services", "KPP-ENG-WS02", "Runs on::Runs", "Always"),
    ("Backup & Recovery", "KPP-FILE-01", "Runs on::Runs", "Often"),
    ("KPP-HIST-01", "KPP-SW-L2-01", "Connects to::Connects to", "Always"),
    ("KPP-HMI-01", "KPP-SW-L2-01", "Connects to::Connects to", "Always"),
    ("KPP-ENG-WS01", "KPP-SW-L2-01", "Connects to::Connects to", "Always"),
    ("KPP-ENG-WS02", "KPP-SW-L2-01", "Connects to::Connects to", "Always"),
    ("KPP-PLC-T2", "KPP-SW-L1-01", "Connects to::Connects to", "Always"),
    ("KPP-RTU-SS1", "KPP-SW-L1-01", "Connects to::Connects to", "Always"),
    ("KPP-SW-L2-01", "FGT-KPP-OT01", "Connects to::Connects to", "Always"),
    ("KPP-PIWEB-01", "KPP-HIST-01", "Depends on::Used by", "Often"),
    ("KPP-VM-HMI-BKP", "KPP-HMI-01", "Hosted on::Hosts", "Occasionally"),
    ("PI_AF_Config", "KPP-PIWEB-01", "Hosted on::Hosts", "Always"),
    ("SCADA_Config", "KPP-SCADA-SRV01", "Hosted on::Hosts", "Always"),
    ("KPP-DC01", "KPP-FILE-01", "Depends on::Used by", "Often"),
    ("KPP-SYSLOG01", "FGT-KPP-OT01", "Depends on::Used by", "Always"),
]


def relations():
    for i, (p, c, t, s) in enumerate(RELS):
        h = 6 + (i * 53) % 680 if i % 3 else 2 + i * 0.7
        emit("cmdb_rel_ci", "%s:%s" % (p, c), NOW - h * 3600.0,
             {"parent": R(p), "child": R(c), "type": R(t), "connection_strength": s, "sys_created_by": dv(OPS[i % len(OPS)]),
              "sys_updated_by": dv(OPS[i % len(OPS)]), "sys_created_on": T(h + 24)}, ["cmdb_rel_ci"])


# --------------------------------------------------------------------------------------------------------------
# Not requested by the brief but cheap: Service Catalog, Business Application, ESX and Hyper-V dashboards
# --------------------------------------------------------------------------------------------------------------
CATALOG = ["Request remote access for vendor", "New engineering workstation", "USB media scan exemption", "Privileged access to PLC engineering project",
           "Additional HMI operator account", "Firewall change request", "Historian trend report access", "Software install: TIA Portal V19"]
RITM_STATE = {1: "Open", 2: "Work in Progress", 3: "Closed Complete", 4: "Closed Incomplete"}


def catalog():
    rnd = random.Random(2002)
    for i in range(24):
        item = CATALOG[i % len(CATALOG)]
        number = "RITM%07d" % (60001 + i)
        oh = RECENT_H[i] if i < 8 else rnd.uniform(26, 690)
        path = [[1], [1, 2], [1, 2, 3], [1, 2, 3], [1, 2], [1, 4]][i % 6]
        who = FULL[OPS[(i * 2) % len(OPS)]]
        req = FULL[OPS[(i * 3 + 1) % len(OPS)]]
        for si, st in enumerate(path):
            h = max(oh * (1 - si / float(len(path) + 0.5)), 0.1 + si * 0.01)
            f = {"number": number, "short_description": item, "cat_item": R(item), "state": (str(st), RITM_STATE[st]),
                 "stage": ("fulfillment" if st == 2 else "request_approved", "Fulfillment" if st == 2 else "Request Approved"),
                 "approval": "approved" if st > 1 or i % 4 else "requested", "priority": PRIO[3 + (i % 2)], "opened_by": R(req),
                 "opened_at": T(oh), "assigned_to": R(who) if st > 1 else ("", ""), "assignment_group": R(["Service Desk", "Network Operations", "OT Security"][i % 3]),
                 "quantity": 1, "price": 0.0 if i % 3 else 450.0, "active": st in (1, 2), "company": R(SITE), "sys_created_on": T(oh),
                 "sys_updated_by": dv(who), "request": R("REQ%07d" % (20001 + i))}
            if st in (3, 4):
                f["closed_at"] = T(h)
            emit("sc_req_item", number, NOW - h * 3600.0, f, ["sc_req_item"])


BAPPS = [  # name, vendor, stack, tier, classification, users, certified, unverified, owner
    ("WinCC SCADA", "Siemens", "Windows / SQL Server", "Tier 1", "Confidential", 14, True, False, "a.lindqvist"),
    ("TIA Portal", "Siemens", "Windows / .NET", "Tier 2", "Confidential", 6, True, False, "a.lindqvist"),
    ("PI System Historian", "AVEVA", "Windows / SQL Server", "Tier 2", "Internal", 22, True, False, "l.heikkinen"),
    ("Claroty CTD", "Claroty", "Linux / Elasticsearch", "Tier 2", "Confidential", 5, True, False, "j.koskinen"),
    ("MetaDefender Kiosk", "OPSWAT", "Windows", "Tier 3", "Internal", 40, False, True, "s.laine"),
    ("CMMS Maintenance Manager", "Oracle", "Oracle / Java", "Tier 3", "Internal", 18, False, True, "p.salo"),
    ("FortiManager", "Fortinet", "Linux", "Tier 2", "Confidential", 3, True, False, "n.aaltonen"),
    ("Turbine Governor Engineering", "Siemens", "Windows / S7-1500 firmware", "Tier 1", "Restricted", 4, True, False, "h.makela"),
]


def business_apps():
    for i, (name, vendor, stack, tier, cls, users_, cert, unv, owner) in enumerate(BAPPS):
        base = {"name": name, "number": "APP%07d" % (70001 + i), "short_description": "%s at %s" % (name, SITE), "vendor": R(vendor),
                "technology_stack": stack, "emergency_tier": tier, "data_classification": cls, "active_user_count": users_,
                "certified": cert, "unverified": unv, "application_type": "Packaged software" if vendor != "Karins" else "Custom",
                "attestation_status": "Attested" if cert else "Not yet reviewed", "install_type": "On-premise",
                "business_criticality": CRIT[1 if tier == "Tier 1" else 2 if tier == "Tier 2" else 3],
                "department": R("Control Systems Engineering" if i < 2 else "Plant IT"), "discovery_source": "ServiceNow Discovery" if i % 2 else "Manual Entry",
                "it_application_owner": R(FULL[owner]), "ip_address": "10.20.3.%d" % (10 + i * 5),
                "url": "https://%s.kpp.example/" % name.lower().replace(" ", "-"), "company": R(SITE), "sys_created_on": T(24 * 200)}
        snaps("cmdb_ci_business_app", name, [24 * 21 + i * 5, 10 + i * 2], base, ["cmdb_ci_business_app"])


def virtualization():
    for i, name in enumerate(["KPP-ESX-01", "KPP-ESX-02", "KPP-ESX-03"]):
        c = ci_common(name, "10.20.5.%d" % (40 + i), "VMware", "VMware", "ESXi 8.0", "SN-ESX-%04d" % (9100 + i), "KPP-V%04d" % (600 + i),
                      16000, SITE, "Plant IT", "l.heikkinen", i=i)
        c.update({"sys_class_name": "ESX Server", "power_state": "on" if i < 2 else "off", "hardware_status": "Installed",
                  "connection_state": "connected" if i < 2 else "disconnected", "attestation_status": "Attested" if i != 1 else "Not yet reviewed",
                  "firewall_status": "Intranet", "os": "VMware ESXi", "os_version": "8.0.2"})
        snaps("cmdb_ci_esx_server", name, [24 * 12 + i * 4, 5 + i], c, ["cmdb_ci_esx_server"])
    for i, name in enumerate(["KPP-HV-01", "KPP-HV-02"]):
        c = ci_common(name, "10.20.5.%d" % (50 + i), "Microsoft", "Dell", "PowerEdge R660", "SN-HV-%04d" % (9200 + i), "KPP-V%04d" % (610 + i),
                      12000, SITE, "Plant IT", "l.heikkinen", i=i)
        c.update({"sys_class_name": "Hyper-V Server", "windows_host": "KPP-HV-HOST%02d" % (i + 1), "pool_name": ["OT-Pool", "Test-Pool"][i],
                  "firewall_status": "Intranet" if i == 0 else "Not Protected", "os": "Windows Server 2022 Datacenter", "os_version": "10.0.20348"})
        snaps("cmdb_ci_hyper_v_server", name, [24 * 10 + i * 4, 6 + i], c, ["cmdb_ci_hyper_v_server"])


def main():
    global NOW
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--now", type=int, default=None, help="epoch seconds (default: current time rounded down to the hour)")
    a = ap.parse_args()
    NOW = float(a.now if a.now is not None else int(time.time()) // 3600 * 3600)
    users()
    groups()
    memberships()
    locations()
    incidents()
    problems()
    changes()
    knowledge()
    servers()
    computers()
    hardware()
    alm()
    services()
    db_instances()
    relations()
    catalog()
    business_apps()
    virtualization()
    sys.stdout.write("\n".join(OUT) + "\n")
    sys.stderr.write("servicenow.py: now=%d, %d documents\n" % (NOW, len(OUT) // 2))


if __name__ == "__main__":
    main()
