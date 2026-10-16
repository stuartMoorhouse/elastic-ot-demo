#!/usr/bin/env python3
"""Historical fill for the Fortinet FortiGate and Claroty CTD integration dashboards (stdlib only).

Prints Elasticsearch bulk NDJSON to stdout covering the last ~14 days (up to two hours before "now", the live
generator covers the rest). Records are RAW messages (FortiGate key=value syslog, Claroty CEF syslog, Claroty asset
and baseline API JSON) bulk-loaded into the integrations' own data streams, so each integration's default ingest
pipeline does the parsing, GeoIP and ECS mapping. Lines are built by importing scripts/generator/ot_generator.py.

Idempotent: _ids and record content are derived from a UTC-day anchor and the slot index, so re-running on the
same day (or with the same --now day) never duplicates: data streams only accept op_type create, so already loaded
documents come back as 409 version conflicts (expected, harmless) and only missing ones are added.

  python3 scripts/fill/fortinet_claroty.py [--now EPOCH] [--days 14] > fill.ndjson
  curl -X POST $ES/_bulk -H 'Content-Type: application/x-ndjson' --data-binary @fill.ndjson
"""
import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ot_generator", os.path.join(HERE, "..", "generator", "ot_generator.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

FGT_DS = "fortinet_fortigate.log"
CEF_DS = "claroty_ctd.event"
ASSET_DS = "claroty_ctd.asset"
BASE_DS = "claroty_ctd.baseline"
WAN_IP = "81.2.69.142"  # public address of FGT-KPP-OT01 port1 (resolves to a UK location in GeoIP)
LIVE_GAP = 2 * 3600  # leave the most recent hours to the live generator


class Collector:
    """Stands in for the generator's Sink: captures lines instead of sending them."""

    def __init__(self):
        self.out = []  # (kind, line)

    def claroty(self, line):
        self.out.append(("cef", line))

    def fgt(self, line):
        self.out.append(("fgt", line))

    def cassets(self, line, ts):
        self.out.append(("asset", line))

    def cbaseline(self, line, ts):
        self.out.append(("baseline", line))

    def __getattr__(self, name):  # endpoint, kiosk, defender, ... are not part of this fill
        return lambda *a, **k: None


EXT_KEY = re.compile(r"(?:^| )([A-Za-z0-9_]+)=")


def decode_cef(line):
    """Python stand-in for Filebeat's decode_cef processor, which the real input runs before the ingest pipeline
    (the Claroty CTD pipeline reads the cef.* object, not the raw line). Returns (cef dict, raw CEF text)."""
    raw = line[line.index("CEF:"):]
    head = raw.split("|", 7)
    ext_text = head[7]
    keys = list(EXT_KEY.finditer(ext_text))
    ext = {}
    for i, m in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(ext_text)
        ext[m.group(1)] = ext_text[m.end():end].replace("\\=", "=").replace("\\\\", "\\")
    return {"version": head[0][4:], "device": {"vendor": head[1], "product": head[2], "version": head[3],
                                               "event_class_id": head[4]},
            "name": head[5], "severity": head[6], "extensions": ext}


def emit(docs, kind, line, ts, key):
    ds, itype, tags = {
        "fgt": (FGT_DS, "udp", ["fortinet-fortigate", "fortinet-firewall", "forwarded", "sample-data"]),
        "cef": (CEF_DS, "tcp", ["forwarded", "claroty_ctd-event", "sample-data"]),
        "asset": (ASSET_DS, None, ["sample-data"]),
        "baseline": (BASE_DS, None, ["sample-data"]),
    }[kind]
    _id = hashlib.sha1(key.encode()).hexdigest()[:20]
    doc = {"@timestamp": g._ts(ts), "message": line,
           "data_stream": {"type": "logs", "dataset": ds, "namespace": "default"},
           "event": {"dataset": ds}, "tags": tags}
    if kind == "cef":  # as the real tcp input + decode_cef deliver it: event.original (raw) plus parsed cef.*
        doc["event"]["original"] = doc.pop("message")
        doc["cef"] = decode_cef(line)
    if itype:
        doc["input"] = {"type": itype}
        doc["log"] = {"source": {"address": "127.0.0.1:%d" % (9004 if kind == "fgt" else 9100)}}
    docs.append(json.dumps({"create": {"_index": "logs-%s-default" % ds, "_id": _id}}))
    docs.append(json.dumps(doc))


def slot(docs, tag, idx, ts, fn, count=1):
    """Run generator function fn(sink, ts) for a deterministic slot and emit whatever it produced."""
    random.seed("%s-%s" % (tag, idx))
    for i in range(count):
        c = Collector()
        t = ts + random.uniform(0, 3599) if count > 1 else ts
        t = int(t)
        fn(c, t)
        for n, (kind, line) in enumerate(c.out):
            emit(docs, kind, line, t, "%s-%s-%d-%d" % (tag, idx, i, n))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--now", type=float, default=time.time(), help="epoch seconds treated as now")
    p.add_argument("--days", type=int, default=14)
    a = p.parse_args()
    now = int(a.now)
    end = now - LIVE_GAP
    anchor = (now // 86400) * 86400  # UTC midnight: keeps ids stable across re-runs on the same day
    first_hour = anchor - a.days * 86400
    docs = []

    def fgt_traffic(sink, ts):
        for _ in range(random.randint(8, 16)):  # internal OT flows
            t = ts + random.randint(0, 3599)
            sink.fgt(g.fgt_line(t, random.choice(g.FLOWS)))

    def fgt_ext(sink, ts):
        for _ in range(random.randint(30, 60)):  # internet-facing traffic plus ips/webfilter/virus/app-ctrl/vpn/system
            sink.fgt(g.fgt_external(ts + random.randint(0, 3599)))

    def fgt_wan(sink, ts):
        """Internet scanners hitting the FortiGate WAN address (local-in deny). Both ends are public addresses, so the
        pipeline GeoIP fills source and destination geo and the overview's source-to-destination map has lines."""
        for _ in range(random.randint(6, 14)):
            t = ts + random.randint(0, 3599)
            atk, atk_c = random.choice(g.ATTACKERS)
            svc, dport = random.choice(g.PROBE_PORTS)
            sink.fgt(g.fgt_event(t, "0001000014", "traffic", "local", "notice", g._fgt_flow(
                atk, random.randint(1024, 65000), "port1", "wan", WAN_IP, "root", "unknown-0", dport, 6, svc, atk_c) + [
                ("sessionid", random.randint(1000000, 9999999)), ("proto", 6), ("action", "deny"), ("policyid", 0),
                ("policytype", "local-in-policy"), ("service", svc), ("trandisp", "noop"), ("duration", 0),
                ("sentbyte", 0), ("rcvdbyte", 0), ("sentpkt", 1), ("rcvdpkt", 0), ("dstcountry", "United Kingdom")]))

    h = first_hour
    idx = 0
    while h < end:
        hour_of_day = (h // 3600) % 24
        # a working-day shape: busier 06:00-18:00 UTC
        busy = 1.0 if 6 <= hour_of_day < 18 else 0.6
        if h + 3599 < end:
            slot(docs, "fgt-flow", idx, h, fgt_traffic)
            slot(docs, "fgt-ext", idx, h, fgt_ext)
            slot(docs, "fgt-wan", idx, h, fgt_wan)
            # claroty alerts (noise signatures), events, health, activity, insight
            slot(docs, "ctd-alert", idx, h, g.noise_alert, count=int(12 * busy) + 3)
            slot(docs, "ctd-event", idx, h, g.claroty_event, count=random.randint(1, 3))
            for q in range(4):  # health check every 15 minutes
                slot(docs, "ctd-health", "%d-%d" % (idx, q), h + q * 900, g.claroty_health)
            slot(docs, "ctd-act", idx, h, g.claroty_activity, count=1 if random.random() < 0.7 else 2)
            slot(docs, "ctd-ins", idx, h, g.claroty_insight, count=1 if hour_of_day % 2 == 0 else 0)
            # asset and baseline API snapshots every 6 hours
            if hour_of_day % 6 == 0:
                slot(docs, "ctd-asset", idx, h + 120, g.asset_snapshot)
                slot(docs, "ctd-base", idx, h + 180, g.baseline_snapshot)
        h += 3600
        idx += 1

    sys.stdout.write("\n".join(docs) + "\n")
    print("fill: %d documents, window %s .. %s" % (len(docs) // 2, g.utc(first_hour).isoformat(), g.utc(end).isoformat()),
          file=sys.stderr)


if __name__ == "__main__":
    main()
