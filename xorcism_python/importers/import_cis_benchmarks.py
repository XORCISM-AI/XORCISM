"""
import_cis_benchmarks.py - CIS Benchmarks support for XORCISM Configuration Management.

Two modes:
  1) Catalogue seed (default): seeds a catalogue of the most widely used CIS Benchmarks (with their
     L1/L2 recommendation structure) into XOVAL.CISBENCHMARK / CISBENCHMARKRECOMMENDATION. The full CIS
     recommendation content is membership-gated, so we ship a representative structure; the per-control
     pass/fail comes from CIS-CAT scans (mode 2).
  2) CIS-CAT result import (--cis-cat FILE [--asset NAME]): parses a CIS-CAT result (XCCDF XML or
     CIS-CAT JSON) into XOVAL.CISBENCHMARKRESULT — one pass/fail/error per recommendation, linked to an
     ASSET (by name). Idempotent by (Source, ExternalID).

Usage:
    python import_cis_benchmarks.py                          # seed the catalogue
    python import_cis_benchmarks.py --cis-cat report.xml --asset web-01
"""

import argparse
import os
import sqlite3
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from xorcism_python.config import DB_DIR
except Exception:  # noqa: BLE001
    DB_DIR = os.getenv("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

MODULE = "ImportCISBenchmarks"
XOVAL = os.path.join(DB_DIR, "XOVAL.db")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"{_now()} : {MODULE} : {msg}")


# A representative catalogue: (Name, Version, Platform, Category, [(number, title, level, section), ...])
CATALOGUE = [
    ("CIS Ubuntu Linux 22.04 LTS Benchmark", "2.0.0", "Ubuntu 22.04", "Operating System", [
        ("1.1.1.1", "Ensure cramfs kernel module is not available", "L1", "Initial Setup"),
        ("1.4.1", "Ensure bootloader password is set", "L1", "Initial Setup"),
        ("5.2.1", "Ensure permissions on /etc/ssh/sshd_config are configured", "L1", "Access Control"),
        ("5.3.1", "Ensure sudo is installed", "L1", "Access Control"),
        ("4.1.1.1", "Ensure auditd is installed", "L2", "Logging and Auditing"),
    ]),
    ("CIS Red Hat Enterprise Linux 9 Benchmark", "2.0.0", "RHEL 9", "Operating System", [
        ("1.2.1", "Ensure GPG keys are configured", "L1", "Initial Setup"),
        ("5.2.4", "Ensure SSH access is limited", "L1", "Access Control"),
        ("3.4.1", "Ensure firewalld is installed", "L1", "Network Configuration"),
        ("4.2.3", "Ensure logging is configured", "L1", "Logging and Auditing"),
    ]),
    ("CIS Microsoft Windows Server 2022 Benchmark", "3.0.0", "Windows Server 2022", "Operating System", [
        ("1.1.1", "Ensure 'Enforce password history' is set to '24 or more password(s)'", "L1", "Account Policies"),
        ("2.3.1.1", "Ensure 'Accounts: Administrator account status' is set to 'Disabled'", "L1", "Local Policies"),
        ("18.9.4.1", "Ensure 'Configure SMB v1 client driver' is set", "L1", "Administrative Templates"),
        ("9.1.1", "Ensure 'Windows Firewall: Domain: Firewall state' is 'On'", "L1", "Windows Firewall"),
    ]),
    ("CIS Microsoft Windows 11 Enterprise Benchmark", "3.0.0", "Windows 11", "Operating System", [
        ("1.1.2", "Ensure 'Maximum password age' is set to '365 or fewer days'", "L1", "Account Policies"),
        ("2.3.7.1", "Ensure interactive logon does not display last user", "L1", "Local Policies"),
        ("18.9.47.5.1", "Ensure BitLocker is enabled", "L1", "Administrative Templates"),
    ]),
    ("CIS Docker Benchmark", "1.6.0", "Docker", "Containerization", [
        ("2.1", "Ensure network traffic is restricted between containers", "L1", "Docker daemon configuration"),
        ("4.1", "Ensure a user for the container has been created", "L1", "Container Images"),
        ("5.4", "Ensure privileged containers are not used", "L1", "Container Runtime"),
    ]),
    ("CIS Kubernetes Benchmark", "1.9.0", "Kubernetes", "Containerization", [
        ("1.2.1", "Ensure that the --anonymous-auth argument is set to false", "L1", "Control Plane"),
        ("4.2.1", "Ensure that the --anonymous-auth argument is set to false (kubelet)", "L1", "Worker Nodes"),
        ("5.2.2", "Minimize the admission of privileged containers", "L2", "Policies"),
    ]),
    ("CIS Amazon Web Services Foundations Benchmark", "3.0.0", "AWS", "Cloud", [
        ("1.4", "Ensure no 'root' user account access key exists", "L1", "Identity and Access Management"),
        ("1.5", "Ensure MFA is enabled for the 'root' user account", "L1", "Identity and Access Management"),
        ("3.1", "Ensure CloudTrail is enabled in all regions", "L1", "Logging"),
        ("2.1.1", "Ensure S3 Bucket Policy denies HTTP requests", "L2", "Storage"),
    ]),
    ("CIS Microsoft Azure Foundations Benchmark", "2.1.0", "Azure", "Cloud", [
        ("1.1.1", "Ensure Security Defaults is enabled on Azure Active Directory", "L1", "Identity and Access Management"),
        ("3.1", "Ensure that 'Secure transfer required' is enabled for storage accounts", "L1", "Storage Accounts"),
        ("5.1.1", "Ensure that a diagnostic setting exists", "L1", "Logging and Monitoring"),
    ]),
    ("CIS Microsoft 365 Foundations Benchmark", "3.1.0", "Microsoft 365", "SaaS", [
        ("1.1.1", "Ensure Administrative accounts are separate and cloud-only", "L1", "Account / Authentication"),
        ("5.2.2.1", "Ensure multifactor authentication is enabled for all users", "L1", "Conditional Access"),
        ("2.1.1", "Ensure Safe Links for Office Applications is enabled", "L2", "Defender"),
    ]),
    ("CIS Apache HTTP Server 2.4 Benchmark", "2.1.0", "Apache HTTP Server 2.4", "Application", [
        ("2.3", "Ensure the autoindex module is disabled", "L1", "Minimize Modules"),
        ("5.6", "Ensure TLSv1.0 and TLSv1.1 are disabled", "L1", "SSL/TLS Configuration"),
        ("9.1", "Ensure ServerTokens is set to Prod", "L1", "Information Leakage"),
    ]),
]


def seed_catalogue(con):
    cur = con.cursor()
    created = updated = recs = 0
    for name, version, platform, category, recommendations in CATALOGUE:
        row = cur.execute("SELECT BenchmarkID FROM CISBENCHMARK WHERE Name=? AND Version=?", (name, version)).fetchone()
        if row:
            bid = row[0]
            updated += 1
        else:
            bid = (cur.execute("SELECT COALESCE(MAX(BenchmarkID),0)+1 FROM CISBENCHMARK").fetchone()[0])
            cur.execute(
                "INSERT INTO CISBENCHMARK (BenchmarkID, BenchmarkGUID, Name, Version, Platform, Category, Source, RecommendationCount, CreatedDate) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (bid, str(uuid.uuid4()), name, version, platform, category, "CIS", len(recommendations), _now()),
            )
            created += 1
        for number, title, level, section in recommendations:
            ext = f"{name} {version} {number}"
            if cur.execute("SELECT 1 FROM CISBENCHMARKRECOMMENDATION WHERE BenchmarkID=? AND Number=?", (bid, number)).fetchone():
                continue
            rid = cur.execute("SELECT COALESCE(MAX(RecommendationID),0)+1 FROM CISBENCHMARKRECOMMENDATION").fetchone()[0]
            cur.execute(
                "INSERT INTO CISBENCHMARKRECOMMENDATION (RecommendationID, RecommendationGUID, BenchmarkID, Number, Title, Level, Section, AssessmentType, ExternalID, CreatedDate) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (rid, str(uuid.uuid4()), bid, number, title, level, section, "Automated", ext, _now()),
            )
            recs += 1
    con.commit()
    log(f"Catalogue: {created} benchmarks created, {updated} present; {recs} new recommendations.")


# ── CIS-CAT result import (XCCDF XML or CIS-CAT JSON) ─────────────────────────
def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_ciscat(path):
    """Returns (benchmark_title, [(number, result, severity)])."""
    if path.lower().endswith(".json"):
        import json
        doc = json.load(open(path, encoding="utf-8"))
        title = doc.get("benchmark-title") or doc.get("title") or "CIS-CAT scan"
        out = []
        for r in doc.get("rules", []) or doc.get("results", []):
            num = r.get("number") or r.get("rule-id") or r.get("id") or ""
            out.append((str(num), str(r.get("result") or "").lower(), r.get("severity") or ""))
        return title, out
    # XCCDF XML
    tree = ET.parse(path)
    root = tree.getroot()
    title = "CIS-CAT scan"
    results = []
    for el in root.iter():
        tag = _strip_ns(el.tag)
        if tag == "title" and not results:
            title = (el.text or title).strip()
        if tag == "rule-result":
            idref = el.get("idref", "")
            # extract a recommendation number like 1.1.1 from the idref
            import re
            m = re.search(r"(\d+(?:\.\d+)+)", idref)
            num = m.group(1) if m else idref
            sev = el.get("severity") or ""
            res = ""
            for c in el:
                if _strip_ns(c.tag) == "result":
                    res = (c.text or "").strip().lower()
                    break
            results.append((num, res, sev))
    return title, results


def import_ciscat(con, path, asset_name):
    cur = con.cursor()
    title, rules = parse_ciscat(path)
    log(f"CIS-CAT '{title}': {len(rules)} rule results")
    # resolve asset id (from XORCISM.ASSET) — best-effort
    asset_id = None
    if asset_name:
        try:
            xo = sqlite3.connect(os.path.join(DB_DIR, "XORCISM.db"))
            r = xo.execute("SELECT AssetID FROM ASSET WHERE AssetName=? LIMIT 1", (asset_name,)).fetchone()
            asset_id = r[0] if r else None
            xo.close()
        except Exception:  # noqa: BLE001
            pass
    # best-effort benchmark match by title prefix
    brow = cur.execute("SELECT BenchmarkID FROM CISBENCHMARK WHERE ? LIKE Name || '%' OR Name LIKE ? LIMIT 1",
                       (title, f"%{title.split(' v')[0]}%")).fetchone()
    bid = brow[0] if brow else None
    rec_by_num = {}
    if bid:
        for rid, num in cur.execute("SELECT RecommendationID, Number FROM CISBENCHMARKRECOMMENDATION WHERE BenchmarkID=?", (bid,)).fetchall():
            rec_by_num[num] = rid
    src = f"CIS-CAT:{asset_name or 'scan'}"
    ins = upd = 0
    for num, result, sev in rules:
        ext = f"{src}:{num}"
        row = cur.execute("SELECT ResultID FROM CISBENCHMARKRESULT WHERE Source=? AND ExternalID=?", (src, ext)).fetchone()
        vals = (bid, rec_by_num.get(num), num, asset_id, result, sev, _now(), src, ext)
        if row:
            cur.execute("UPDATE CISBENCHMARKRESULT SET BenchmarkID=?, RecommendationID=?, RecommendationNumber=?, AssetID=?, Result=?, Severity=?, CheckedAt=?, Source=?, ExternalID=? WHERE ResultID=?", (*vals, row[0]))
            upd += 1
        else:
            nid = cur.execute("SELECT COALESCE(MAX(ResultID),0)+1 FROM CISBENCHMARKRESULT").fetchone()[0]
            cur.execute("INSERT INTO CISBENCHMARKRESULT (ResultID, ResultGUID, BenchmarkID, RecommendationID, RecommendationNumber, AssetID, Result, Severity, CheckedAt, Source, ExternalID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (nid, str(uuid.uuid4()), *vals, _now()))
            ins += 1
    con.commit()
    passed = sum(1 for _, r, _ in rules if r == "pass")
    log(f"Done. {ins} new, {upd} updated; {passed}/{len(rules)} pass (asset={asset_name or '—'}, benchmark={'matched' if bid else 'unmatched'}).")


def ensure_tables(con):
    con.executescript("""
      CREATE TABLE IF NOT EXISTS CISBENCHMARK (BenchmarkID INTEGER PRIMARY KEY, BenchmarkGUID TEXT, Name TEXT, Version TEXT, Platform TEXT, Category TEXT, Source TEXT, ExternalID TEXT, RecommendationCount INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS CISBENCHMARKRECOMMENDATION (RecommendationID INTEGER PRIMARY KEY, RecommendationGUID TEXT, BenchmarkID INTEGER, Number TEXT, Title TEXT, Level TEXT, Section TEXT, Description TEXT, Remediation TEXT, AssessmentType TEXT, ExternalID TEXT, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS CISBENCHMARKRESULT (ResultID INTEGER PRIMARY KEY, ResultGUID TEXT, BenchmarkID INTEGER, RecommendationID INTEGER, RecommendationNumber TEXT, AssetID INTEGER, Result TEXT, Severity TEXT, CheckedAt TEXT, Source TEXT, ExternalID TEXT, CreatedDate TEXT, TenantID INTEGER);
    """)
    con.commit()


def main():
    ap = argparse.ArgumentParser(description="Seed CIS Benchmark catalogue / import CIS-CAT results into XOVAL")
    ap.add_argument("--cis-cat", help="Import a CIS-CAT result (XCCDF XML or CIS-CAT JSON)")
    ap.add_argument("--asset", default="", help="Asset name to link CIS-CAT results to")
    args = ap.parse_args()
    con = sqlite3.connect(XOVAL, timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    ensure_tables(con)
    if args.cis_cat:
        if not os.path.exists(args.cis_cat):
            raise SystemExit(f"CIS-CAT file not found: {args.cis_cat}")
        import_ciscat(con, args.cis_cat, args.asset)
    else:
        seed_catalogue(con)
    con.close()


if __name__ == "__main__":
    main()
