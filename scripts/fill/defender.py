#!/usr/bin/env python3
"""Raw Microsoft Defender for Endpoint API-shaped records for the Karins Power Plant demo, as ES bulk NDJSON.

Fills the data streams that the live demo does not otherwise populate (baseline, configuration, information_gathering,
machine, machine_action, vulnerability) so every panel of the integration dashboards has data, plus a few extra
alerts for the .log stream (user and IP evidence panels). The raw API JSON goes in `message`; the installed
integration ingest pipelines parse it (same convention as scripts/generator/ot_generator.py).

Usage: python3 scripts/fill/defender.py [--now EPOCH] | curl -XPOST .../_bulk -H 'Content-Type: application/x-ndjson' --data-binary @-

Idempotency: all timestamps hang off an anchor (--now, default the current time floored to 6 hours) and every document
has a deterministic _id, so re-running with the same anchor yields the same ids. Data streams only accept `create`,
so a re-load answers 409 version_conflict for documents that already exist, which is harmless.
Stdlib only.
"""
import argparse
import hashlib
import json
import random
import time
import uuid
from datetime import datetime, timezone

TENANT = "7c1d0a3e-d66c-4c7e-9e30-40034eb7c6f3"
NS = uuid.UUID("5d2c1a52-3a45-4d9a-8d6e-0b7a8c1d9e11")

# name: (ip, mac, os platform, os version/build, osversion label, group, risk, exposure, health, external ip)
HOSTS = {
    "KPP-ENG-WS01": ("10.20.3.21", "00-50-56-A1-03-21", "Windows10", "10.0.19045.3693", "22H2", "OT Engineering", "Medium", "Medium", "Active", "85.23.14.70"),
    "KPP-ENG-WS02": ("10.20.3.22", "00-50-56-A1-03-22", "Windows10", "10.0.19045.3693", "22H2", "OT Engineering", "High", "High", "Active", "85.23.14.70"),
    "KPP-HMI-01": ("10.20.3.10", "00-50-56-A1-03-10", "Windows10", "10.0.19044.3086", "21H2", "OT Operations", "Low", "Low", "Active", "85.23.14.71"),
    "KPP-HIST-01": ("10.20.3.40", "00-50-56-A1-03-40", "WindowsServer2016", "10.0.14393.6614", "1607", "OT Operations", "Medium", "Medium", "Active", "85.23.14.71"),
    "KPP-USB-KIOSK01": ("10.20.0.50", "00-50-56-A1-00-50", "Windows10", "10.0.19045.3570", "22H2", "OT DMZ", "Low", "Low", "Inactive", "85.23.14.72"),
    "KPP-OFFICE-PC07": ("10.10.5.17", "00-50-56-A1-05-17", "Windows11", "10.0.22631.2861", "23H2", "Corporate IT", "High", "Medium", "Active", "85.23.14.73"),
}
GROUP_ID = {"OT Engineering": 11, "OT Operations": 12, "OT DMZ": 13, "Corporate IT": 14}
USERS = {"KPP-ENG-WS01": "a.lindqvist", "KPP-ENG-WS02": "a.lindqvist", "KPP-HMI-01": "operator1",
         "KPP-HIST-01": "svc_scada", "KPP-USB-KIOSK01": "j.koskinen", "KPP-OFFICE-PC07": "s.laine"}


def mid(host):
    return hashlib.sha1(host.encode()).hexdigest()  # same machineId the generator uses for the alert docs


def aad(host):
    return str(uuid.uuid5(NS, "aad-" + host))


def iso(ts, digits=7):
    t = datetime.fromtimestamp(ts, timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + ("%07d" % int((ts % 1) * 10**7))[:digits] + "Z"


def plain(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def zsec(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def age(rng, recent=0.45):
    """Seconds back from the anchor: a good share within the last 24 h, the rest over 14 days."""
    if rng.random() < recent:
        return rng.randint(300, 86400)
    return rng.randint(86400, 14 * 86400)


class Out:
    def __init__(self):
        self.lines = []

    def add(self, dataset, ts, raw, key):
        _id = hashlib.sha1(("%s|%s" % (dataset, key)).encode()).hexdigest()[:20]
        self.lines.append(json.dumps({"create": {"_index": "logs-%s-default" % dataset, "_id": _id}}))
        self.lines.append(json.dumps({
            "@timestamp": iso(ts, 3), "message": json.dumps(raw),
            "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
            "event": {"dataset": dataset}, "tags": ["sample-data"]}))


def machines(out, now):
    rng = random.Random(101)
    ages = [3600, 8 * 3600, 14 * 3600, 21 * 3600, 2 * 86400, 4 * 86400, 6 * 86400, 9 * 86400, 12 * 86400]
    for h, (ip, mac, plat, build, ver, grp, risk, expo, health, ext) in HOSTS.items():
        for i, a in enumerate(ages):
            ts = now - a - rng.randint(0, 1800)
            hs = health
            if h == "KPP-OFFICE-PC07" and a > 5 * 86400:
                hs = "Inactive"
            ips = [{"ipAddress": ip, "macAddress": mac, "type": "Ethernet", "operationalStatus": "Up"}]
            if h == "KPP-ENG-WS02":
                ips.append({"ipAddress": "10.20.9.22", "macAddress": "00-50-56-A1-09-22", "type": "Ethernet", "operationalStatus": "Up"})
            out.add("microsoft_defender_endpoint.machine", ts, {
                "id": mid(h), "computerDnsName": h, "firstSeen": iso(now - 120 * 86400), "lastSeen": iso(ts - 60),
                "osPlatform": plat, "osVersion": None, "osProcessor": "x64", "version": ver, "lastIpAddress": ip,
                "lastExternalIpAddress": ext, "agentVersion": "10.8210.19045.3693", "osBuild": int(build.split(".")[2]),
                "healthStatus": hs, "deviceValue": "High" if grp.startswith("OT") else "Normal",
                "rbacGroupId": GROUP_ID[grp], "rbacGroupName": grp, "riskScore": risk, "exposureLevel": expo,
                "isAadJoined": h.startswith("KPP-OFFICE"), "aadDeviceId": aad(h) if h.startswith("KPP-OFFICE") else None,
                "machineTags": ["OT", "KPP"] if grp.startswith("OT") else ["KPP"], "ipAddresses": ips,
                "osArchitecture": "64-bit", "managedBy": "MicrosoftDefenderForEndpoint", "managedByStatus": "Success",
                "onboardingStatus": "Onboarded", "isExcluded": False, "exclusionReason": None,
                "isPotentialDuplication": False, "mergedIntoMachineId": None}, "%s|%d" % (h, i))


def machine_actions(out, now):
    rng = random.Random(202)
    soc = ["n.aaltonen@karinspower.example", "t.berg@karinspower.example", "j.koskinen@karinspower.example"]
    plan = [  # type, title, comment, scope, weight
        ("RunAntiVirusScan", "Quick scan after engineering session", "Scheduled after TIA Portal project upload", None, 9),
        ("CollectInvestigationPackage", "Collect investigation package", "Evidence for open Defender alert", None, 6),
        ("Isolate", "Isolate device from network", "Suspected credential theft, contain pending investigation", "Selective", 4),
        ("Isolate", "Isolate device from network", "Ransomware behavior alert, full isolation", "Full", 3),
        ("Unisolate", "Release device from isolation", "Investigation closed, no malicious activity", None, 5),
        ("LiveResponse", "Live response session", "Verify scheduled task and unsigned driver", None, 3),
        ("RestrictCodeExecution", "Restrict app execution", "Allow only Microsoft-signed binaries during triage", None, 2),
        ("UnrestrictCodeExecution", "Remove app execution restriction", "Triage complete", None, 2),
        ("StopAndQuarantineFile", "Stop and quarantine file", "Trojan found on removable media", None, 3),
    ]
    pool = [p for p in plan for _ in range(p[4])]
    statuses = ["Succeeded"] * 8 + ["Pending", "InProgress", "Failed", "Cancelled"]
    hosts = list(HOSTS)
    for i in range(48):
        t, title, comment, scope, _ = rng.choice(pool)
        h = rng.choice(hosts)
        if h == "KPP-ENG-WS02":  # leave the live EWS storyline host alone
            h = "KPP-ENG-WS01"
        created = now - age(rng, 0.5)
        status = rng.choice(statuses)
        updated = min(now, created + rng.randint(30, 900))
        raw = {"id": str(uuid.uuid5(NS, "action-%d" % i)), "type": t, "title": title, "requestor": rng.choice(soc),
               "requestorComment": comment, "status": status, "machineId": mid(h), "computerDnsName": h,
               "creationDateTimeUtc": iso(created), "lastUpdateDateTimeUtc": iso(updated),
               "externalID": None, "requestSource": rng.choice(["PublicApi", "Portal", "AutomatedInvestigation"]),
               "commands": ["RunScript", "GetFile"] if t == "LiveResponse" else [], "troubleshootInfo": None,
               "scope": scope, "cancellationRequestor": None, "cancellationComment": None,
               "cancellationDateTimeUtc": None, "errorHResult": 0}
        if t == "StopAndQuarantineFile":
            raw["relatedFileInfo"] = {"fileIdentifier": hashlib.sha1(("f%d" % i).encode()).hexdigest(), "fileIdentifierType": "Sha1"}
        if status == "Cancelled":
            raw.update(cancellationRequestor=raw["requestor"], cancellationComment="Duplicate request",
                       cancellationDateTimeUtc=iso(min(now, created + 120)))
        if status == "Failed":
            raw["errorHResult"] = -2147024891
            raw["troubleshootInfo"] = "Device was offline for the whole request window"
        out.add("microsoft_defender_endpoint.machine_action", updated, raw, str(i))


CVES = [  # cve, score, severity, exploit, software, vendor, version, update, title
    ("CVE-2024-38063", 9.8, "Critical", "ExploitIsPublic", "windows_10", "microsoft", "10.0.19045.3693", "KB5041580", "Windows TCP/IP remote code execution"),
    ("CVE-2020-1472", 10.0, "Critical", "ExploitIsVerified", "windows_server_2016", "microsoft", "10.0.14393.6614", "KB4571694", "Netlogon elevation of privilege (Zerologon)"),
    ("CVE-2021-34527", 8.8, "High", "ExploitIsVerified", "windows_server_2016", "microsoft", "10.0.14393.6614", "KB5004238", "Windows Print Spooler remote code execution"),
    ("CVE-2023-4863", 8.8, "High", "ExploitIsVerified", "chrome", "google", "116.0.5845.97", "Chrome 116.0.5845.187", "libwebp heap buffer overflow"),
    ("CVE-2023-38831", 7.8, "High", "ExploitIsPublic", "winrar", "rarlab", "6.22.0.0", "WinRAR 6.23", "WinRAR code execution on archive open"),
    ("CVE-2024-11477", 7.8, "High", "ExploitIsPublic", "7-zip", "7-zip", "23.01.0.0", "7-Zip 24.07", "7-Zip Zstandard decompression code execution"),
    ("CVE-2023-48795", 5.9, "Medium", "NoExploit", "putty", "simon_tatham", "0.79.0.0", "PuTTY 0.80", "SSH Terrapin prefix truncation"),
    ("CVE-2023-38545", 9.8, "Critical", "ExploitIsPublic", "curl", "haxx", "8.3.0.0", "curl 8.4.0", "SOCKS5 heap buffer overflow"),
    ("CVE-2023-26369", 7.8, "High", "NoExploit", "acrobat_reader_dc", "adobe", "23.001.20093", "Acrobat Reader 23.003", "Out-of-bounds write on crafted PDF"),
    ("CVE-2023-44487", 7.5, "High", "ExploitIsPublic", ".net_framework", "microsoft", "4.8.4515.0", "KB5031224", "HTTP/2 rapid reset denial of service"),
    ("CVE-2023-36025", 8.8, "High", "ExploitIsVerified", "windows_11", "microsoft", "10.0.22631.2861", "KB5032288", "Windows SmartScreen security feature bypass"),
    ("CVE-2023-23397", 9.8, "Critical", "ExploitIsInKit", "outlook", "microsoft", "16.0.16327.20264", "Microsoft 365 Apps update", "Outlook elevation of privilege"),
    ("CVE-2022-41099", 7.8, "High", "NoExploit", "windows_10", "microsoft", "10.0.19044.3086", "KB5022282", "BitLocker security feature bypass"),
    ("CVE-2019-0708", 9.8, "Critical", "ExploitIsInKit", "windows_server_2016", "microsoft", "10.0.14393.6614", "KB4499177", "Remote Desktop Services remote code execution"),
]


def vulnerabilities(out, now):
    rng = random.Random(303)
    by_host = {
        "KPP-ENG-WS01": [0, 3, 4, 5, 6, 7],
        "KPP-ENG-WS02": [0, 3, 4, 5, 8, 9, 12],
        "KPP-HMI-01": [12, 9, 6, 7],
        "KPP-HIST-01": [1, 2, 13, 9, 7],
        "KPP-USB-KIOSK01": [0, 4, 5, 3],
        "KPP-OFFICE-PC07": [10, 11, 3, 8, 4],
    }
    for h, idx in by_host.items():
        ip, mac, plat, build, ver, grp, *_ = HOSTS[h]
        for ci in idx:
            cve, score, sev, exp, sw, vendor, swver, upd, title = CVES[ci]
            first = now - rng.randint(2, 13) * 86400 - rng.randint(0, 80000)
            states = [("New", first)]
            if rng.random() < 0.6:
                states.append(("Updated", now - age(rng, 0.7)))
            if rng.random() < 0.15:
                states.append(("Fixed", now - rng.randint(600, 40000)))
            for st, ts in states:
                last = max(ts, first)
                if st == "Fixed":
                    last = ts
                out.add("microsoft_defender_endpoint.vulnerability", ts, {
                    "id": hashlib.md5(("%s|%s|%s" % (h, cve, st)).encode()).hexdigest(),
                    "cveId": cve, "cvssScore": score, "vulnerabilitySeverityLevel": sev, "exploitabilityLevel": exp,
                    "deviceId": mid(h), "deviceName": h, "diskPaths": ["C:\\Program Files\\%s" % sw] if not sw.startswith("windows") else [],
                    "registryPaths": [], "eventTimestamp": plain(ts), "firstSeenTimestamp": plain(first),
                    "lastSeenTimestamp": plain(last), "osPlatform": plat, "osVersion": build, "osArchitecture": "x64",
                    "rbacGroupId": GROUP_ID[grp], "rbacGroupName": grp, "isOnboarded": True,
                    "softwareName": sw, "softwareVendor": vendor, "softwareVersion": swver,
                    "recommendedSecurityUpdate": upd, "recommendedSecurityUpdateId": upd.split()[0] if upd.startswith("KB") else None,
                    "recommendationReference": "va-_%s_%s" % (vendor, sw), "status": st,
                    "cveBatchTitle": title, "cveBatchUrl": "https://msrc.microsoft.com/update-guide/vulnerability/" + cve}, "%s|%s|%s" % (h, cve, st))


def info_gathering(out, now):
    rng = random.Random(404)
    ages = [2 * 3600, 9 * 3600, 17 * 3600, 23 * 3600, 2 * 86400, 4 * 86400, 7 * 86400, 11 * 86400]
    for h, (ip, mac, plat, build, ver, grp, risk, expo, health, ext) in HOSTS.items():
        lag = h in ("KPP-HMI-01", "KPP-HIST-01", "KPP-USB-KIOSK01")  # segmented hosts update signatures late
        for i, a in enumerate(ages):
            ts = now - a - rng.randint(0, 3000)
            stale = lag and (i % 3 != 0)
            sig_age = (3 if stale else 0) * 86400 + rng.randint(3600, 40000)
            info = {
                "AvEngineVersion": "1.1.23100.2009", "AvPlatformVersion": "4.18.23100.2009",
                "AvSignatureVersion": "1.403.%d.0" % (1800 + i), "AvMode": "Normal", "AvScanResults": "Success",
                "AvIsEngineUptodate": not (stale and i % 2 == 0), "AvIsPlatformUptodate": True,
                "AvIsSignatureUptoDate": not stale, "IsAvEngineLoaded": True,
                "AvSignatureUpdateTime": plain(ts - sig_age), "AvSignaturePublishTime": plain(ts - sig_age - 3600),
                "AvEngineUpdateTime": plain(ts - 6 * 86400), "AvPlatformUpdateTime": plain(ts - 20 * 86400),
                "AvModeDataRefreshTime": plain(ts - 600), "AvSignatureDataRefreshTime": plain(ts - 600),
                "AvEnginePublishTime": plain(ts - 7 * 86400), "AvPlatformPublishTime": plain(ts - 21 * 86400),
                "AvPlatformExpirationTime": plain(ts + 150 * 86400), "AvSignatureRing": "Production",
                "AvEngineRing": "Production", "AvPlatformRing": "Production", "CloudProtectionState": "Enabled",
                "QuickScanResult": "Success", "FullScanResult": "Success", "LocalCveScannerExecuted": "True",
                "Log4j_CVE_2021_44228": "NotVulnerable", "Log4jLocalScanVulnerable": "False",
                "Log4jEnvironmentVariableMitigation": "NotApplicable"}
            out.add("microsoft_defender_endpoint.information_gathering", ts, {
                "DeviceId": mid(h), "DeviceName": h, "OsPlatform": plat, "OsVersion": build,
                "LastSeenTime": iso(ts - 30, 3), "Timestamp": iso(ts, 3), "RbacGroupId": GROUP_ID[grp],
                "RbacGroupName": grp, "DeviceGatheredInfo": json.dumps(info)}, "%s|%d" % (h, i))


CONFIGS = [  # scid, name, category, subcategory, impact, os-agnostic
    ("scid-2000", "Turn on real-time protection", "Antivirus", "Real-time protection", 9),
    ("scid-2010", "Turn on cloud-delivered protection", "Antivirus", "Cloud protection", 7),
    ("scid-91", "Turn on Microsoft Defender Firewall for all profiles", "Network", "Firewall", 8),
    ("scid-42", "Disable SMBv1 client driver", "Network", "SMB", 6),
    ("scid-80", "Require NLA for Remote Desktop", "Network", "Remote Desktop", 5),
    ("scid-70", "Enable BitLocker on the OS drive", "Security controls", "Encryption", 7),
    ("scid-90", "Enable Credential Guard", "Security controls", "Credential protection", 8),
    ("scid-93", "Block credential stealing from LSASS (ASR)", "Security controls", "Attack surface reduction", 6),
    ("scid-94", "Block executable content from email client (ASR)", "Security controls", "Attack surface reduction", 4),
    ("scid-95", "Block USB mass storage for standard users", "Security controls", "Device control", 5),
    ("scid-60", "Install the latest Windows cumulative update", "OS", "Update", 10),
    ("scid-62", "Turn on automatic updates for engineering software", "Application", "Update", 3),
]


def configurations(out, now):
    rng = random.Random(505)
    for h, (ip, mac, plat, build, ver, grp, *_r) in HOSTS.items():
        for j, (scid, name, cat, sub, impact) in enumerate(CONFIGS):
            ts = now - age(rng, 0.5)
            if plat == "Windows11" and scid == "scid-62":
                continue
            comp = rng.random() < (0.45 if h in ("KPP-ENG-WS02", "KPP-OFFICE-PC07") else 0.7)
            out.add("microsoft_defender_endpoint.configuration", ts, {
                "id": hashlib.sha1((h + scid).encode()).hexdigest(), "deviceId": mid(h), "deviceName": h,
                "osPlatform": plat, "osVersion": build, "rbacGroupName": grp, "configurationId": scid,
                "configurationCategory": cat, "configurationSubcategory": sub, "configurationName": name,
                "configurationImpact": impact, "isCompliant": comp, "isApplicable": True,
                "isExpectedUserImpact": rng.random() < 0.3, "recommendationReference": "sca-_" + scid,
                "timestamp": iso(ts, 3)}, "%s|%s" % (h, scid))


BASE = [  # config id, source, recommended value, bad current value
    ("scid-2000", "Registry", "0", "1"), ("scid-91", "Registry", "1", "0"), ("scid-42", "Registry", "4", "1"),
    ("scid-70", "Registry", "1", "0"), ("scid-80", "Registry", "1", "0"), ("scid-90", "Registry", "1", "0"),
    ("scid-93", "Registry", "1", "0"), ("scid-95", "Registry", "3", "0"),
]
PROFILES = {"Windows10": ("cis_microsoft_windows_10_enterprise_v3.0.0_l1", "CIS Microsoft Windows 10 Enterprise Level 1"),
            "Windows11": ("cis_microsoft_windows_11_enterprise_v3.0.0_l1", "CIS Microsoft Windows 11 Enterprise Level 1"),
            "WindowsServer2016": ("cis_microsoft_windows_server_2016_v3.0.0_l1", "CIS Microsoft Windows Server 2016 Level 1")}


def baselines(out, now):
    rng = random.Random(606)
    for h, (ip, mac, plat, build, ver, grp, *_r) in HOSTS.items():
        prof = PROFILES[plat][0]
        for j, (cid, src, rec, bad) in enumerate(BASE[:7]):
            for k, a in enumerate([4 * 3600, 3 * 86400]):
                if k and rng.random() < 0.3:
                    continue
                ts = now - a - rng.randint(0, 3000)
                comp = rng.random() < (0.45 if h in ("KPP-ENG-WS02", "KPP-OFFICE-PC07", "KPP-USB-KIOSK01") else 0.75)
                out.add("microsoft_defender_endpoint.baseline", ts, {
                    "id": hashlib.sha1(("%s|%s|%s" % (h, prof, cid)).encode()).hexdigest()[:32],
                    "deviceId": mid(h), "deviceName": h, "osPlatform": plat, "osVersion": build,
                    "rbacGroupId": GROUP_ID[grp], "rbacGroupName": grp, "configurationId": cid, "profileId": prof,
                    "isApplicable": True, "isCompliant": comp, "source": src, "recommendedValue": rec,
                    "currentValue": rec if comp else bad, "complianceCalculationTimeOffset": zsec(ts),
                    "dataCollectionTimeOffset": zsec(ts - 900)}, "%s|%s|%d" % (h, cid, k))


ALERTS = [  # title, description, severity, category, classification, host, ip evidence
    ("Suspicious PowerShell command line", "PowerShell ran an encoded command from an Office process.", "Medium", "Execution", None, "KPP-OFFICE-PC07", None),
    ("Sensitive credential memory read", "A process attempted to read LSASS memory.", "High", "CredentialAccess", None, "KPP-HIST-01", None),
    ("Suspicious RDP connection to engineering workstation", "An interactive RDP logon came from an unusual source address.", "High", "LateralMovement", None, "KPP-ENG-WS02", "10.20.3.21"),
    ("Network scan from internal host", "The host probed ports on the control network segment.", "Medium", "Discovery", None, "KPP-ENG-WS01", "10.20.4.12"),
    ("Outbound connection to rare external host", "A connection to a rarely seen external address was observed.", "Low", "CommandAndControl", None, "KPP-OFFICE-PC07", "198.51.100.23"),
    ("Engineering software communicated with an industrial controller", "Siemens TIA Portal connected to a PLC. Matches an allowed engineering workflow.", "Informational", "Discovery", "FalsePositive", "KPP-ENG-WS01", "10.20.4.12"),
    ("Malware detected on removable media", "A file copied from a USB device matched a trojan signature and was quarantined.", "High", "Malware", "TruePositive", "KPP-USB-KIOSK01", None),
    ("Unsigned driver loaded", "A driver without a valid signature was loaded.", "Low", "SuspiciousActivity", None, "KPP-HMI-01", None),
]


def alerts(out, now):
    rng = random.Random(707)
    for i in range(16):
        title, desc, sev, cat, cls, h, ip = ALERTS[i % len(ALERTS)]
        user = USERS[h]
        ts = now - age(rng, 0.5)
        resolved = cls is not None
        inc = 450000 + i
        raw = {"id": "da637%015d_%d" % (int(hashlib.sha1(("a%d" % i).encode()).hexdigest()[:12], 16) % 10**15, 920000000 + i),
               "incidentId": inc, "investigationId": inc - 440000,
               "assignedTo": rng.choice(["n.aaltonen@karinspower.example", "t.berg@karinspower.example", "Automated investigation"]),
               "severity": sev, "status": "Resolved" if resolved else rng.choice(["New", "InProgress"]),
               "classification": cls, "determination": "Other" if resolved else None,
               "investigationState": "Benign" if resolved else "PendingApproval", "detectionSource": "WindowsDefenderAtp",
               "category": cat, "threatFamilyName": None, "title": title, "description": desc,
               "alertCreationTime": iso(ts), "firstEventTime": iso(ts - 30), "lastEventTime": iso(ts - 5),
               "lastUpdateTime": iso(ts + 2), "resolvedTime": iso(ts + 2) if resolved else None,
               "machineId": mid(h), "computerDnsName": h, "rbacGroupName": None, "aadTenantId": TENANT,
               "relatedUser": {"userName": user, "domainName": "KPP"}, "comments": [],
               "evidence": ({"entityType": "Ip", "ipAddress": ip, "accountName": user, "domainName": "KPP"} if ip else
                            {"entityType": "User", "accountName": user, "domainName": "KPP"})}
        out.add("microsoft_defender_endpoint.log", ts, raw, "alert|%d" % i)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--now", type=float, default=None, help="anchor epoch seconds (default: now floored to 6h)")
    a = ap.parse_args()
    now = a.now if a.now is not None else (int(time.time()) // 21600) * 21600
    out = Out()
    for fn in (machines, machine_actions, vulnerabilities, info_gathering, configurations, baselines, alerts):
        fn(out, now)
    print("\n".join(out.lines))


if __name__ == "__main__":
    main()
