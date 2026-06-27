"""import_soc2.py - import the SOC 2 (2017) Trust Services Criteria into XORCISM.

The AICPA Trust Services Criteria (TSC 2017, points of focus revised 2022) underpin SOC 2
examinations. They comprise the Common Criteria CC1-CC9 (the Security category, always in scope)
plus four additional categories: Availability (A1), Confidentiality (C1), Processing Integrity
(PI1) and Privacy (P1-P8). The Common Criteria are aligned with the COSO 2013 framework's 17
principles (CC1-CC5) plus supplemental criteria (CC6-CC9).

This creates the **Vocabulary "SOC2"** and loads the criteria into:

  XORCISM.CONTROL  -> VOCABULARY "SOC2"
                      one CONTROL per criterion; CIS = the criterion id (e.g. "CC6.1"),
                      Statement = a short criterion descriptor, ControlDescription = the category.

The criterion descriptors here are short, factual summaries / COSO principle names - the full
AICPA TSC criterion text and points of focus are copyrighted and are NOT reproduced. Idempotent
(delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_soc2.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "SOC2"
VERSION = "2017 TSC (rev. 2022 PoF)"
REF = "AICPA Trust Services Criteria (2017)"
DESC = "SOC 2 - AICPA Trust Services Criteria 2017: Common Criteria CC1-CC9 (Security) + Availability, Confidentiality, Processing Integrity, Privacy. Short descriptors only; AICPA TSC text is copyrighted."

# category -> [ (criterion id, short descriptor), ... ]
CATEGORIES = [
    ("Common Criteria (Security)", [
        ("CC1.1", "COSO P1 - Demonstrates commitment to integrity and ethical values"),
        ("CC1.2", "COSO P2 - Board of directors exercises oversight responsibility"),
        ("CC1.3", "COSO P3 - Management establishes structure, authority and responsibility"),
        ("CC1.4", "COSO P4 - Demonstrates commitment to competence"),
        ("CC1.5", "COSO P5 - Enforces accountability"),
        ("CC2.1", "COSO P13 - Uses relevant, quality information"),
        ("CC2.2", "COSO P14 - Communicates information internally"),
        ("CC2.3", "COSO P15 - Communicates information externally"),
        ("CC3.1", "COSO P6 - Specifies suitable objectives"),
        ("CC3.2", "COSO P7 - Identifies and analyzes risk"),
        ("CC3.3", "COSO P8 - Assesses fraud risk"),
        ("CC3.4", "COSO P9 - Identifies and analyzes significant change"),
        ("CC4.1", "COSO P16 - Conducts ongoing and/or separate evaluations"),
        ("CC4.2", "COSO P17 - Evaluates and communicates deficiencies"),
        ("CC5.1", "COSO P10 - Selects and develops control activities"),
        ("CC5.2", "COSO P11 - Selects and develops general controls over technology"),
        ("CC5.3", "COSO P12 - Deploys control activities through policies and procedures"),
        ("CC6.1", "Logical access security software, infrastructure and architectures"),
        ("CC6.2", "Registration and authorization of new internal/external users"),
        ("CC6.3", "Role-based access and least privilege; modification/removal of access"),
        ("CC6.4", "Restricts physical access to facilities and protected information assets"),
        ("CC6.5", "Discontinues logical/physical protections when assets are disposed"),
        ("CC6.6", "Implements logical access security measures against external threats"),
        ("CC6.7", "Restricts transmission, movement and removal of information"),
        ("CC6.8", "Prevents or detects unauthorized or malicious software"),
        ("CC7.1", "Detection/monitoring to identify config changes and vulnerabilities"),
        ("CC7.2", "Monitors system components for anomalies and malicious acts"),
        ("CC7.3", "Evaluates security events to determine impact"),
        ("CC7.4", "Responds to identified security incidents"),
        ("CC7.5", "Recovers from identified security incidents"),
        ("CC8.1", "Authorizes, designs, tests, approves and implements changes"),
        ("CC9.1", "Identifies and develops mitigation for business disruption risks"),
        ("CC9.2", "Assesses and manages vendor and business-partner risks"),
    ]),
    ("Availability", [
        ("A1.1", "Maintains, monitors and evaluates current processing capacity"),
        ("A1.2", "Environmental protections, backup, recovery infrastructure"),
        ("A1.3", "Tests recovery plan procedures"),
    ]),
    ("Confidentiality", [
        ("C1.1", "Identifies and maintains confidential information"),
        ("C1.2", "Disposes of confidential information"),
    ]),
    ("Processing Integrity", [
        ("PI1.1", "Quality information about processing objectives"),
        ("PI1.2", "Policies and procedures over system inputs"),
        ("PI1.3", "Policies and procedures over system processing"),
        ("PI1.4", "Makes output available to meet objectives"),
        ("PI1.5", "Stores inputs and outputs completely, accurately and timely"),
    ]),
    ("Privacy", [
        ("P1.1", "Notice - communicates privacy practices to data subjects"),
        ("P2.1", "Choice and consent for collection, use and disclosure"),
        ("P3.1", "Collection consistent with stated objectives"),
        ("P3.2", "Explicit consent for sensitive personal information"),
        ("P4.1", "Use limited to purposes identified in the notice"),
        ("P4.2", "Retention of personal information"),
        ("P4.3", "Secure disposal of personal information"),
        ("P5.1", "Provides data subjects access to their personal information"),
        ("P5.2", "Correction, amendment or deletion of personal information"),
        ("P6.1", "Discloses personal information only with consent"),
        ("P6.2", "Records authorized disclosures of personal information"),
        ("P6.3", "Records unauthorized disclosures of personal information"),
        ("P6.4", "Obtains commitments from third parties to protect data"),
        ("P6.5", "Obtains commitments from third parties to notify of breaches"),
        ("P6.6", "Notifies data subjects/authorities of unauthorized disclosure"),
        ("P6.7", "Provides an accounting of personal information held/disclosed"),
        ("P7.1", "Quality - maintains accurate, complete and relevant data"),
        ("P8.1", "Monitoring and enforcement - handles complaints and disputes"),
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
    for cat, crits in CATEGORIES:
        for cid, descr in crits:
            _ins(cur, "CONTROL", {
                "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
                "ControlName": f"{cid}: {descr}"[:300],
                "ControlDescription": f"SOC 2 (2017 TSC) / {cat}"[:600],
                "VocabularyID": vid, "CIS": cid, "Statement": descr,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            }, ccols)
            nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[soc2] VocabularyID={vid}: {n} Trust Services Criteria (CC1-CC9 + Availability/Confidentiality/Processing Integrity/Privacy).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
