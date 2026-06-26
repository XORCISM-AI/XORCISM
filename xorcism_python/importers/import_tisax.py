"""import_tisax.py - import the TISAX / VDA-ISA information-security catalogue into XORCISM.

TISAX (Trusted Information Security Assessment Exchange, run by ENX) is the automotive-industry
information-security assessment, based on the VDA-ISA control catalogue (VDA = German Association of
the Automotive Industry). The catalogue has three modules: Information Security (7 chapters), Prototype
Protection, and Data Protection. Assessments are performed at assessment levels AL1/AL2/AL3 and lead to
shareable TISAX labels.

This loads the VDA-ISA control areas into XORCISM.CONTROL under VOCABULARY "TISAX (VDA-ISA)" with a
maturity-model flavour (the ISA uses a 0-5 maturity scale per control), plus an ISO/IEC 27001 crosswalk
(the ISA aligns to Annex A). Faithful chapter/control-area titles only (the VDA-ISA catalogue is
copyrighted by VDA/ENX). Idempotent. Raw SQL; DB dir = XORCISM_DB_DIR env or default. No schema change.

    python xorcism_python/importers/import_tisax.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "TISAX (VDA-ISA)"
MAP_SOURCE = "TISAX VDA-ISA crosswalk"

# (ref, title, module/chapter). VDA-ISA control areas.
ITEMS = [
    # Module: Information Security (7 chapters)
    ("ISA-1", "IS policies and organization", "Information Security"),
    ("ISA-1.1", "Information security policies and responsibilities", "Information Security"),
    ("ISA-1.2", "Organization of information security and project management", "Information Security"),
    ("ISA-1.3", "Asset management and information classification", "Information Security"),
    ("ISA-1.4", "IS risk management", "Information Security"),
    ("ISA-1.5", "Assessments, audits and IS incident management", "Information Security"),
    ("ISA-2", "Human resources security and awareness", "Information Security"),
    ("ISA-2.1", "Qualification, training and awareness of employees", "Information Security"),
    ("ISA-3", "Physical security and business continuity", "Information Security"),
    ("ISA-3.1", "Security zones and protection against external threats", "Information Security"),
    ("ISA-4", "Identity and access management", "Information Security"),
    ("ISA-4.1", "Identity management (users, accounts, service accounts)", "Information Security"),
    ("ISA-4.2", "Access management and authentication (incl. MFA, privileged access)", "Information Security"),
    ("ISA-5", "IT security / cyber security (IT operations)", "Information Security"),
    ("ISA-5.1", "Cryptography and key management", "Information Security"),
    ("ISA-5.2", "Operations security, logging and monitoring", "Information Security"),
    ("ISA-5.3", "Network security and segmentation", "Information Security"),
    ("ISA-5.4", "Protection against malware and vulnerability management", "Information Security"),
    ("ISA-5.5", "Secure software development and change management", "Information Security"),
    ("ISA-6", "Supplier relationships and information security in the supply chain", "Information Security"),
    ("ISA-7", "Compliance, legal and data-protection alignment", "Information Security"),
    # Module: Prototype Protection
    ("ISA-8.1", "Physical and environmental security for prototypes", "Prototype Protection"),
    ("ISA-8.2", "Organizational requirements for handling prototypes and parts", "Prototype Protection"),
    ("ISA-8.3", "Handling of vehicles, components and parts", "Prototype Protection"),
    ("ISA-8.4", "Requirements for trial vehicles, test drives and events/film/photo shoots", "Prototype Protection"),
    # Module: Data Protection (GDPR Art. 28 processing on behalf)
    ("ISA-9.1", "Data protection / processing on behalf (GDPR Art. 28)", "Data Protection"),
    ("ISA-9.2", "Special categories of personal data", "Data Protection"),
]

LEVELS = [
    ("TISAX-AL1", "Assessment Level 1 - self-assessment", "Assessment level"),
    ("TISAX-AL2", "Assessment Level 2 - plausibility check (remote/evidence)", "Assessment level"),
    ("TISAX-AL3", "Assessment Level 3 - on-site audit (highest assurance)", "Assessment level"),
]


def _db(name: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _cols(cur: sqlite3.Cursor, table: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _ins(cur: sqlite3.Cursor, table: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str) -> int:
    cols = _cols(cur, "VOCABULARY")
    namecol = "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)
    if namecol:
        row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
        if row:
            return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    rec = {"VocabularyID": nid, "VocabularyGUID": str(uuid.uuid4()), "CreatedDate": datetime.now(timezone.utc).isoformat()}
    if namecol:
        rec[namecol] = name
    _ins(cur, "VOCABULARY", rec, cols)
    return nid


def main() -> int:
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(_db("XORCISM")); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    iso_refs = []
    for ref, title, module in ITEMS + LEVELS:
        _ins(cur, "CONTROL", {
            "ControlID": cid, "ControlGUID": str(uuid.uuid4()), "ControlName": f"{ref} {title}"[:300],
            "ControlDescription": f"TISAX / VDA-ISA - {module}", "VocabularyID": vid, "CIS": ref,
            "Statement": title, "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        if module == "Information Security":
            iso_refs.append(cid)
        cid += 1
    # crosswalk: the ISA Information-Security module aligns to ISO/IEC 27001 Annex A
    n_map = 0
    if cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone():
        mcols = _cols(cur, "CONTROLMAPPING")
        cur.execute("DELETE FROM CONTROLMAPPING WHERE Source=?", (MAP_SOURCE,))
        mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1
        for cidx in iso_refs:
            _ins(cur, "CONTROLMAPPING", {
                "MappingID": mid, "MappingGUID": str(uuid.uuid4()), "ControlID": cidx,
                "Framework": "ISO/IEC 27001", "ExternalID": "ISO/IEC 27001:2022 Annex A", "Relationship": "aligns-to",
                "Source": MAP_SOURCE, "CreatedDate": now,
            }, mcols)
            mid += 1; n_map += 1
    con.commit(); con.close()
    print(f"[tisax] VocabularyID={vid}: {len(ITEMS) + len(LEVELS)} controls "
          f"(VDA-ISA: Information Security / Prototype Protection / Data Protection + assessment levels), {n_map} ISO 27001 crosswalk rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
