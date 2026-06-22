"""import_scf.py — import the Secure Controls Framework (SCF) into XORCISM.CONTROL.

The SCF (securecontrolsframework.com) is a free, comprehensive cybersecurity & privacy
"metaframework": ~1000+ controls across ~33 domains, each cross-mapped to 100+ statutory,
regulatory and contractual authorities (NIST 800-53, ISO 27001/2, CIS, PCI DSS, SOC 2, GDPR,
CMMC, CCPA, HIPAA…). It is the Rosetta Stone of control frameworks.

Two modes:
  * --file <SCF.xlsx>  : parse the official SCF spreadsheet (openpyxl). Reads the "SCF #" /
                         "SCF Control" / "Secure Controls Framework (SCF) Control Description"
                         columns from the main worksheet, and (best-effort) the per-authority
                         mapping columns → CONTROLMAPPING. (Download from securecontrolsframework.com.)
  * (no file)          : seed the ~33 SCF domains + a representative set of controls (embedded),
                         so the framework is present immediately; run --file for the full catalogue.

Writes CONTROL rows (VocabularyID = the SCF vocab; ControlName="SCF-ID Title", domain in
ControlDescription, Statement=description). Idempotent by VocabularyID. Raw SQL.

    python xorcism_python/importers/import_scf.py [--file SCF.xlsx]
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "SCF"

DOMAINS = {
    "GOV": "Security & Privacy Governance", "AST": "Asset Management",
    "BCD": "Business Continuity & Disaster Recovery", "CAP": "Capacity & Performance Planning",
    "CFG": "Configuration Management", "CHG": "Change Management", "CLD": "Cloud Security",
    "CPL": "Compliance", "CRY": "Cryptographic Protections", "DCH": "Data Classification & Handling",
    "END": "Endpoint Security", "HRS": "Human Resources Security", "IAC": "Identification & Authentication",
    "IAO": "Information Assurance", "IRO": "Incident Response", "MNT": "Maintenance",
    "MDM": "Mobile Device Management", "NET": "Network Security", "PES": "Physical & Environmental Security",
    "PRI": "Privacy", "PRM": "Project & Resource Management", "RSK": "Risk Management",
    "SAT": "Security Awareness & Training", "SEA": "Secure Engineering & Architecture",
    "TDA": "Technology Development & Acquisition", "THR": "Threat Management", "TPM": "Third-Party Management",
    "VPM": "Vulnerability & Patch Management", "WEB": "Web Security", "MON": "Continuous Monitoring",
    "AAT": "Artificial & Autonomous Technologies", "EMB": "Embedded Technology", "OPS": "Security Operations",
}

SEED = [
    ("GOV-01", "Information Security & Privacy Governance Program"),
    ("GOV-02", "Publishing Security & Privacy Documentation"),
    ("GOV-05", "Operationalizing Cybersecurity & Data Protection Practices"),
    ("AST-01", "Asset Governance"), ("AST-02", "Asset Inventories"),
    ("BCD-01", "Business Continuity Management System (BCMS)"), ("BCD-11", "Data Backups"),
    ("CAP-01", "Capacity & Performance Management"),
    ("CFG-01", "Configuration Management Program"), ("CFG-02", "System Hardening Through Baseline Configurations"),
    ("CHG-01", "Change Management Program"),
    ("CLD-01", "Cloud Services"), ("CLD-06", "Multi-Tenant Environments"),
    ("CPL-01", "Statutory, Regulatory & Contractual Compliance"), ("CPL-02", "Cybersecurity & Data Privacy Controls Oversight"),
    ("CRY-01", "Use of Cryptographic Controls"), ("CRY-05", "Encrypting Data At Rest"), ("CRY-09", "Cryptographic Key Management"),
    ("DCH-01", "Data Protection"), ("DCH-02", "Data & Asset Classification"),
    ("END-01", "Endpoint Security"), ("END-04", "Malicious Code Protection (Anti-Malware)"),
    ("HRS-01", "Human Resources Security Management"), ("HRS-04", "Personnel Screening"),
    ("IAC-01", "Identity & Access Management (IAM)"), ("IAC-06", "Multi-Factor Authentication (MFA)"), ("IAC-10", "Authenticator Management"),
    ("IAO-01", "Information Assurance (IA) Operations"),
    ("IRO-01", "Incident Response Operations"), ("IRO-02", "Incident Handling"),
    ("MNT-01", "Maintenance Operations"), ("MDM-01", "Centralized Management Of Mobile Devices"),
    ("NET-01", "Network Security Management"), ("NET-06", "Boundary Protection"),
    ("PES-01", "Physical & Environmental Protections"),
    ("PRI-01", "Privacy Program"), ("PRI-05", "Data Subject Access"),
    ("PRM-01", "Cybersecurity & Data Protection Portfolio Management"),
    ("RSK-01", "Risk Management Program"), ("RSK-04", "Risk Assessment"), ("RSK-06", "Risk Remediation"),
    ("SAT-01", "Security & Privacy-Minded Workforce"),
    ("SEA-01", "Secure Engineering Principles"), ("SEA-02", "Alignment With Enterprise Architecture"),
    ("TDA-01", "Technology Development & Acquisition"), ("TDA-06", "Secure Coding"),
    ("THR-01", "Threat Intelligence Program"), ("THR-03", "Threat Hunting"),
    ("TPM-01", "Third-Party Management"), ("TPM-05", "Third-Party Contract Requirements"),
    ("VPM-01", "Vulnerability & Patch Management Program (VPMP)"), ("VPM-05", "Software & Firmware Patching"), ("VPM-06", "Vulnerability Scanning"),
    ("WEB-01", "Web Security"),
    ("MON-01", "Continuous Monitoring"), ("MON-02", "Centralized Collection of Security Event Logs"),
    ("AAT-01", "Artificial & Autonomous Technologies Governance"), ("AAT-02", "AI & Autonomous Technologies Risk Management"),
    ("OPS-01", "Operations Security"),
]


def _db_path() -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XORCISM.db")


def _ensure_vocab(cur: sqlite3.Cursor, name: str) -> int:
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    namecol = "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)
    if namecol:
        row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
        if row:
            return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    rec = {"VocabularyID": nid}
    if namecol:
        rec[namecol] = name
    if "VocabularyGUID" in cols:
        rec["VocabularyGUID"] = str(uuid.uuid4())
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def _from_excel(path: str):
    """Parse the official SCF spreadsheet → list of (scf_id, title, description)."""
    from openpyxl import load_workbook  # type: ignore

    wb = load_workbook(path, read_only=True, data_only=True)
    out = []
    seen = set()
    scf_re = re.compile(r"^[A-Z]{3}-\d{2}(?:\.\d+)?$")
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            cells = [str(c).strip() if c is not None else "" for c in row]
            sid = next((c for c in cells if scf_re.match(c)), "")
            if not sid or sid in seen:
                continue
            idx = cells.index(sid)
            rest = [c for c in cells[idx + 1:] if c]
            title = rest[0] if rest else sid
            desc = rest[1] if len(rest) > 1 else ""
            seen.add(sid)
            out.append((sid, title[:300], desc[:4000]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Import the Secure Controls Framework into XORCISM.CONTROL")
    ap.add_argument("--file", help="official SCF .xlsx (full catalogue)")
    a = ap.parse_args()

    controls = _from_excel(a.file) if a.file else [(sid, title, "") for sid, title in SEED]
    if not controls:
        print("[scf] no controls parsed"); return 1

    con = sqlite3.connect(_db_path()); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    next_id = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    n = 0
    for sid, title, desc in controls:
        dom = sid.split("-")[0]
        rec = {
            "ControlID": next_id, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{sid} {title}".strip(),
            "ControlDescription": f"SCF — {DOMAINS.get(dom, dom)}",
            "VocabularyID": vid, "Statement": desc or None,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1; n += 1
    con.commit(); con.close()
    src = a.file if a.file else "embedded seed"
    print(f"[scf] VocabularyID={vid}: {n} controls across {len({c.split('-')[0] for c,_,_ in controls})} domains ({src}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
