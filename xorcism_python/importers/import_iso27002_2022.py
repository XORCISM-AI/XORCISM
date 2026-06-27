"""import_iso27002_2022.py - import the ISO/IEC 27002:2022 control set into XORCISM.

ISO/IEC 27002:2022 ("Information security, cybersecurity and privacy protection - Information
security controls") restructured the former 114 controls into **93 controls** under four themes:
Organizational (5.x, 37), People (6.x, 8), Physical (7.x, 14) and Technological (8.x, 34). Each
control also carries attributes (control type, security property CIA, cybersecurity concept ...).

This loads the 93 controls (numbers + official titles only - the standard text itself is
copyrighted by ISO/IEC and is NOT reproduced) into:

  XORCISM.CONTROL  -> VOCABULARY "ISO 27002" (version 2022)
                      one CONTROL per control; CIS = the control number (e.g. "8.8"),
                      Statement = the control title, ControlDescription = the theme.

Reuses the existing empty "ISO 27002" vocabulary stub if present. Idempotent (delete-then-insert
by VocabularyID). Raw SQL; DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_iso27002_2022.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "ISO 27002"
VERSION = "2022"
REF = "ISO/IEC 27002:2022"
DESC = "ISO/IEC 27002:2022 - Information security controls (93 controls across 4 themes). Titles only; standard text is copyrighted by ISO/IEC."

# theme -> [ (control number, official title), ... ].  Titles only (copyrighted standard).
THEMES = [
    ("Organizational controls", [
        ("5.1", "Policies for information security"),
        ("5.2", "Information security roles and responsibilities"),
        ("5.3", "Segregation of duties"),
        ("5.4", "Management responsibilities"),
        ("5.5", "Contact with authorities"),
        ("5.6", "Contact with special interest groups"),
        ("5.7", "Threat intelligence"),
        ("5.8", "Information security in project management"),
        ("5.9", "Inventory of information and other associated assets"),
        ("5.10", "Acceptable use of information and other associated assets"),
        ("5.11", "Return of assets"),
        ("5.12", "Classification of information"),
        ("5.13", "Labelling of information"),
        ("5.14", "Information transfer"),
        ("5.15", "Access control"),
        ("5.16", "Identity management"),
        ("5.17", "Authentication information"),
        ("5.18", "Access rights"),
        ("5.19", "Information security in supplier relationships"),
        ("5.20", "Addressing information security within supplier agreements"),
        ("5.21", "Managing information security in the ICT supply chain"),
        ("5.22", "Monitoring, review and change management of supplier services"),
        ("5.23", "Information security for use of cloud services"),
        ("5.24", "Information security incident management planning and preparation"),
        ("5.25", "Assessment and decision on information security events"),
        ("5.26", "Response to information security incidents"),
        ("5.27", "Learning from information security incidents"),
        ("5.28", "Collection of evidence"),
        ("5.29", "Information security during disruption"),
        ("5.30", "ICT readiness for business continuity"),
        ("5.31", "Legal, statutory, regulatory and contractual requirements"),
        ("5.32", "Intellectual property rights"),
        ("5.33", "Protection of records"),
        ("5.34", "Privacy and protection of personal identifiable information (PII)"),
        ("5.35", "Independent review of information security"),
        ("5.36", "Compliance with policies, rules and standards for information security"),
        ("5.37", "Documented operating procedures"),
    ]),
    ("People controls", [
        ("6.1", "Screening"),
        ("6.2", "Terms and conditions of employment"),
        ("6.3", "Information security awareness, education and training"),
        ("6.4", "Disciplinary process"),
        ("6.5", "Responsibilities after termination or change of employment"),
        ("6.6", "Confidentiality or non-disclosure agreements"),
        ("6.7", "Remote working"),
        ("6.8", "Information security event reporting"),
    ]),
    ("Physical controls", [
        ("7.1", "Physical security perimeters"),
        ("7.2", "Physical entry"),
        ("7.3", "Securing offices, rooms and facilities"),
        ("7.4", "Physical security monitoring"),
        ("7.5", "Protecting against physical and environmental threats"),
        ("7.6", "Working in secure areas"),
        ("7.7", "Clear desk and clear screen"),
        ("7.8", "Equipment siting and protection"),
        ("7.9", "Security of assets off-premises"),
        ("7.10", "Storage media"),
        ("7.11", "Supporting utilities"),
        ("7.12", "Cabling security"),
        ("7.13", "Equipment maintenance"),
        ("7.14", "Secure disposal or re-use of equipment"),
    ]),
    ("Technological controls", [
        ("8.1", "User end point devices"),
        ("8.2", "Privileged access rights"),
        ("8.3", "Information access restriction"),
        ("8.4", "Access to source code"),
        ("8.5", "Secure authentication"),
        ("8.6", "Capacity management"),
        ("8.7", "Protection against malware"),
        ("8.8", "Management of technical vulnerabilities"),
        ("8.9", "Configuration management"),
        ("8.10", "Information deletion"),
        ("8.11", "Data masking"),
        ("8.12", "Data leakage prevention"),
        ("8.13", "Information backup"),
        ("8.14", "Redundancy of information processing facilities"),
        ("8.15", "Logging"),
        ("8.16", "Monitoring activities"),
        ("8.17", "Clock synchronization"),
        ("8.18", "Use of privileged utility programs"),
        ("8.19", "Installation of software on operational systems"),
        ("8.20", "Networks security"),
        ("8.21", "Security of network services"),
        ("8.22", "Segregation of networks"),
        ("8.23", "Web filtering"),
        ("8.24", "Use of cryptography"),
        ("8.25", "Secure development life cycle"),
        ("8.26", "Application security requirements"),
        ("8.27", "Secure system architecture and engineering principles"),
        ("8.28", "Secure coding"),
        ("8.29", "Security testing in development and acceptance"),
        ("8.30", "Outsourced development"),
        ("8.31", "Separation of development, test and production environments"),
        ("8.32", "Change management"),
        ("8.33", "Test information"),
        ("8.34", "Protection of information systems during audit testing"),
    ]),
]


def _db(n: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{n}.db")


def _cols(cur: sqlite3.Cursor, t: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{t}")').fetchall()}


def _ins(cur: sqlite3.Cursor, t: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {t} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str, version: str = "", ref: str = "", desc: str = "") -> int:
    cols = _cols(cur, "VOCABULARY")
    nc = "VocabularyName" if "VocabularyName" in cols else "Name"
    now = datetime.now(timezone.utc).isoformat()
    row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {nc}=?", (name,)).fetchone()
    if row:
        vid = int(row[0])
        for col, val in (("VocabularyVersion", version), ("VocabularyReference", ref), ("VocabularyDescription", desc)):
            if val and col in cols:
                cur.execute(f"UPDATE VOCABULARY SET {col}=? WHERE VocabularyID=?", (val, vid))
        return vid
    vid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    _ins(cur, "VOCABULARY", {"VocabularyID": vid, "VocabularyGUID": str(uuid.uuid4()), "CreatedDate": now,
                             nc: name, "VocabularyVersion": version, "VocabularyReference": ref,
                             "VocabularyDescription": desc}, cols)
    return vid


def main() -> int:
    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, VERSION, REF, DESC)
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    n = 0
    for theme, controls in THEMES:
        for cid, title in controls:
            _ins(cur, "CONTROL", {
                "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
                "ControlName": f"{cid}: {title}"[:300],
                "ControlDescription": f"ISO/IEC 27002:2022 / {theme}"[:600],
                "VocabularyID": vid, "CIS": cid, "Statement": title,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            }, ccols)
            nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[iso27002:2022] VocabularyID={vid}: {n} controls (37 organizational / 8 people / 14 physical / 34 technological).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
