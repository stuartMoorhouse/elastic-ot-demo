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
ENDPOINT_FILE = "/var/log/ot-demo/endpoint.ndjson"


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


class Sink:
    """Handles TCP (reconnecting), UDP and file output, or stdout in dry-run."""

    def __init__(self, a):
        self.a, self.tcp, self.udp, self.f = a, None, None, None
        self.samples = {}
        if not a.dry_run:
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            d = os.path.dirname(a.endpoint_file)
            os.makedirs(d, exist_ok=True)
            self.f = open(a.endpoint_file, "a", buffering=1)

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


def noise_alert(sink, ts):
    sid, name, sev = random.choice(NOISE_ALERTS)
    sink.claroty(claroty_line(ts, sid, name, sev, ENG, PLC))


def run_noise(a, sink):
    print("noise mode: ~%.1f alerts/min, ~%.1f events/s" % (a.alert_rate, a.event_rate), file=sys.stderr)
    nxt_alert = time.time()
    n = 0
    while True:
        now = time.time()
        normal_tick(sink, now)
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
    ts, nxt_alert, count = start, start, 0
    alert_gap = 60.0 / max(a.alert_rate, 0.01)
    while ts < end:
        normal_tick(sink, ts)
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


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", required=True, choices=["noise", "backfill", "scenario"])
    p.add_argument("--hours", type=float, default=24, help="backfill window")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, dest="claroty_port", default=9100, help="Claroty CEF TCP port")
    p.add_argument("--claroty-port", type=int, dest="claroty_port", help=argparse.SUPPRESS)
    p.add_argument("--fortigate-port", type=int, default=9004)
    p.add_argument("--endpoint-file", default=ENDPOINT_FILE)
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
        {"noise": run_noise, "backfill": run_backfill, "scenario": run_scenario}[a.mode](a, sink)
    except KeyboardInterrupt:
        pass
    if a.dry_run:
        print("dry-run counts: %s" % json.dumps(sink.samples), file=sys.stderr)


if __name__ == "__main__":
    main()
