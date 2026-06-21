"""
import_iec62443.py — seed the OT security control catalogues into XCOMPLIANCE.
Jerome Athias - XORCISM

Seeds two frameworks and their requirement catalogues used by the OT Security module
(/ot-security), the same way the GRC frameworks (ISO 27001, NIST CSF) are referenced:

  • IEC 62443-3-3:2013 — System security requirements & security levels: the 7 foundational
    requirements (FR1-7) and their 51 system requirements (SR x.y).
  • NIST SP 800-82 Rev 3 — Guide to Operational Technology (OT) Security: the OT control overlay,
    seeded at the SP 800-53 control-family level with OT context.

Targets XCOMPLIANCE.db → FRAMEWORK (idempotent by Name) + REFERENCECONTROL (idempotent by
Provider+Ref). The tables are self-sufficient (CREATE IF NOT EXISTS + additive ALTER), so it runs
against any database version. Re-running updates names/descriptions, never duplicates.

Usage:
    python import_iec62443.py
    python import_iec62443.py --db-dir C:\\Users\\me\\XORCISM_databases
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid4

# ── IEC 62443-3-3 system requirements (FR -> [(SR ref, title)]) ───────────────────
IEC_62443_3_3 = {
    "FR1 - Identification and authentication control": [
        ("SR 1.1", "Human user identification and authentication"),
        ("SR 1.2", "Software process and device identification and authentication"),
        ("SR 1.3", "Account management"),
        ("SR 1.4", "Identifier management"),
        ("SR 1.5", "Authenticator management"),
        ("SR 1.6", "Wireless access management"),
        ("SR 1.7", "Strength of password-based authentication"),
        ("SR 1.8", "Public key infrastructure (PKI) certificates"),
        ("SR 1.9", "Strength of public key authentication"),
        ("SR 1.10", "Authenticator feedback"),
        ("SR 1.11", "Unsuccessful login attempts"),
        ("SR 1.12", "System use notification"),
        ("SR 1.13", "Access via untrusted networks"),
    ],
    "FR2 - Use control": [
        ("SR 2.1", "Authorization enforcement"),
        ("SR 2.2", "Wireless use control"),
        ("SR 2.3", "Use control for portable and mobile devices"),
        ("SR 2.4", "Mobile code"),
        ("SR 2.5", "Session lock"),
        ("SR 2.6", "Remote session termination"),
        ("SR 2.7", "Concurrent session control"),
        ("SR 2.8", "Auditable events"),
        ("SR 2.9", "Audit storage capacity"),
        ("SR 2.10", "Response to audit processing failures"),
        ("SR 2.11", "Timestamps"),
        ("SR 2.12", "Non-repudiation"),
    ],
    "FR3 - System integrity": [
        ("SR 3.1", "Communication integrity"),
        ("SR 3.2", "Malicious code protection"),
        ("SR 3.3", "Security functionality verification"),
        ("SR 3.4", "Software and information integrity"),
        ("SR 3.5", "Input validation"),
        ("SR 3.6", "Deterministic output"),
        ("SR 3.7", "Error handling"),
        ("SR 3.8", "Session integrity"),
        ("SR 3.9", "Protection of audit information"),
    ],
    "FR4 - Data confidentiality": [
        ("SR 4.1", "Information confidentiality"),
        ("SR 4.2", "Information persistence"),
        ("SR 4.3", "Use of cryptography"),
    ],
    "FR5 - Restricted data flow": [
        ("SR 5.1", "Network segmentation"),
        ("SR 5.2", "Zone boundary protection"),
        ("SR 5.3", "General purpose person-to-person communication restrictions"),
        ("SR 5.4", "Application partitioning"),
    ],
    "FR6 - Timely response to events": [
        ("SR 6.1", "Audit log accessibility"),
        ("SR 6.2", "Continuous monitoring"),
    ],
    "FR7 - Resource availability": [
        ("SR 7.1", "Denial of service protection"),
        ("SR 7.2", "Resource management"),
        ("SR 7.3", "Control system backup"),
        ("SR 7.4", "Control system recovery and reconstitution"),
        ("SR 7.5", "Emergency power"),
        ("SR 7.6", "Network and security configuration settings"),
        ("SR 7.7", "Least functionality"),
        ("SR 7.8", "Control system component inventory"),
    ],
}

# ── NIST SP 800-82 Rev 3 OT control overlay (SP 800-53 families, OT context) ───────
NIST_800_82 = [
    ("AC", "Access Control", "Least privilege & segmentation for control systems; remote-access restrictions to OT."),
    ("AT", "Awareness and Training", "OT-specific security awareness for operators, engineers and ICS vendors."),
    ("AU", "Audit and Accountability", "Logging tuned for OT constraints (limited resources, real-time)."),
    ("CA", "Assessment, Authorization and Monitoring", "OT-aware assessment that avoids disrupting live processes."),
    ("CM", "Configuration Management", "Baseline & change control for PLCs/RTUs/HMIs; firmware integrity."),
    ("CP", "Contingency Planning", "OT recovery, safe-state fallback, backup of control logic & configs."),
    ("IA", "Identification and Authentication", "Device & process identity for OT; shared-account compensations."),
    ("IR", "Incident Response", "OT incident handling integrated with safety and physical response."),
    ("MA", "Maintenance", "Controlled (often vendor) maintenance of OT assets; remote-maintenance security."),
    ("MP", "Media Protection", "Removable-media controls for engineering workstations and field devices."),
    ("PE", "Physical and Environmental Protection", "Physical access to field sites, cabinets and control rooms."),
    ("PL", "Planning", "OT security plan, system boundaries, zones & conduits architecture."),
    ("PM", "Program Management", "OT security governance and risk-management program."),
    ("PS", "Personnel Security", "Vetting for OT operators, integrators and third-party engineers."),
    ("PT", "PII Processing and Transparency", "Handling of any personal data processed by OT/IoT."),
    ("RA", "Risk Assessment", "OT risk assessment including safety/consequence and process impact."),
    ("SA", "System and Services Acquisition", "Secure procurement of ICS components (align with IEC 62443-4-1/-4-2)."),
    ("SC", "System and Communications Protection", "OT network segmentation, protocol/DMZ controls, boundary protection."),
    ("SI", "System and Information Integrity", "OT malware protection, monitoring and integrity of control logic."),
    ("SR", "Supply Chain Risk Management", "ICS supply-chain risk, component provenance and integrity."),
]

_FRAMEWORK_COLS = {
    "FrameworkID": "INTEGER PRIMARY KEY", "FrameworkGUID": "TEXT", "Name": "TEXT", "Description": "TEXT",
    "Provider": "TEXT", "Version": "TEXT", "URN": "TEXT", "Ref": "TEXT", "Locale": "TEXT",
    "CreatedDate": "TEXT", "TenantID": "INTEGER",
}
_REFCTRL_COLS = {
    "ReferenceControlID": "INTEGER PRIMARY KEY", "ReferenceControlGUID": "TEXT", "Name": "TEXT",
    "Description": "TEXT", "Category": "TEXT", "Function": "TEXT", "Provider": "TEXT",
    "URN": "TEXT", "Ref": "TEXT", "CreatedDate": "TEXT", "TenantID": "INTEGER",
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _ensure(cur, table, cols):
    cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(f'{n} {t}' for n, t in cols.items())})")
    have = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, typ in cols.items():
        if name not in have:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")


def _framework(cur, name, description, provider, version):
    row = cur.execute("SELECT FrameworkID FROM FRAMEWORK WHERE Name=?", (name,)).fetchone()
    if row:
        cur.execute("UPDATE FRAMEWORK SET Description=?, Provider=?, Version=? WHERE FrameworkID=?",
                    (description, provider, version, row[0]))
        return row[0]
    nid = cur.execute("SELECT COALESCE(MAX(FrameworkID),0)+1 FROM FRAMEWORK").fetchone()[0]
    cur.execute(
        "INSERT INTO FRAMEWORK (FrameworkID, FrameworkGUID, Name, Description, Provider, Version, Locale, CreatedDate, TenantID) "
        "VALUES (?,?,?,?,?,?,?,?,NULL)", (nid, str(uuid4()), name, description, provider, version, "EN", _now()))
    return nid


def _refctrl(cur, provider, category, ref, name, description, function="OT"):
    row = cur.execute("SELECT ReferenceControlID FROM REFERENCECONTROL WHERE Provider=? AND Ref=?", (provider, ref)).fetchone()
    if row:
        cur.execute("UPDATE REFERENCECONTROL SET Name=?, Description=?, Category=?, Function=? WHERE ReferenceControlID=?",
                    (name, description, category, function, row[0]))
        return 0
    nid = cur.execute("SELECT COALESCE(MAX(ReferenceControlID),0)+1 FROM REFERENCECONTROL").fetchone()[0]
    cur.execute(
        "INSERT INTO REFERENCECONTROL (ReferenceControlID, ReferenceControlGUID, Name, Description, Category, Function, Provider, Ref, CreatedDate, TenantID) "
        "VALUES (?,?,?,?,?,?,?,?,?,NULL)", (nid, str(uuid4()), name, description, category, function, provider, ref, _now()))
    return 1


def main():
    ap = argparse.ArgumentParser(description="Seed IEC 62443 + NIST SP 800-82 catalogues into XCOMPLIANCE")
    ap.add_argument("--db-dir", default=os.getenv("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases"))
    a = ap.parse_args()
    db = os.path.join(a.db_dir, "XCOMPLIANCE.db")
    if not os.path.exists(db):
        print(f"[iec62443] XCOMPLIANCE.db not found at {db}", file=sys.stderr)
        sys.exit(1)
    con = sqlite3.connect(db, timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    _ensure(cur, "FRAMEWORK", _FRAMEWORK_COLS)
    _ensure(cur, "REFERENCECONTROL", _REFCTRL_COLS)

    created = 0
    _framework(cur, "IEC 62443-3-3", "System security requirements and security levels (IACS)", "IEC 62443-3-3", "2013")
    for fr, srs in IEC_62443_3_3.items():
        for ref, title in srs:
            created += _refctrl(cur, "IEC 62443-3-3", fr, ref, f"{ref} — {title}", title)

    _framework(cur, "NIST SP 800-82 Rev 3", "Guide to Operational Technology (OT) Security", "NIST SP 800-82 Rev 3", "Rev 3")
    for code, fam, ctx in NIST_800_82:
        created += _refctrl(cur, "NIST SP 800-82 Rev 3", "OT control overlay", code, f"{code} — {fam}", ctx)

    con.commit()
    total = cur.execute("SELECT COUNT(*) FROM REFERENCECONTROL WHERE Provider LIKE 'IEC 62443%' OR Provider LIKE 'NIST SP 800-82%'").fetchone()[0]
    con.close()
    iec = sum(len(v) for v in IEC_62443_3_3.values())
    print(f"[iec62443] seeded/updated {iec} IEC 62443-3-3 SRs + {len(NIST_800_82)} NIST SP 800-82 families "
          f"({created} newly inserted); {total} OT reference controls total.")


if __name__ == "__main__":
    main()
