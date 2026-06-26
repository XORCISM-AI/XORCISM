"""import_hds.py - import the HDS (Hebergeur de Donnees de Sante) certification framework into XORCISM.

HDS is the French mandatory certification for hosting personal health data (referentiel de
certification HDS v1.1, ANS / French Ministry of Health, under Art. L.1111-8 CSP). It builds on
ISO/IEC 27001 + ISO/IEC 20000-1 and adds health-data-specific requirements, scoped to 6 hosting
activities. This loads the framework into XORCISM.CONTROL under VOCABULARY "HDS (Hebergeur de Donnees
de Sante)": the 6 certified activities + the HDS-specific requirements that go beyond ISO 27001, with a
CONTROLMAPPING crosswalk noting the ISO/IEC 27001 + 20000-1 foundation.

Faithful titles / requirement themes only (the ANS referentiel text is copyrighted). Idempotent
(delete-then-insert by VocabularyID). Raw SQL; DB dir = XORCISM_DB_DIR env or default. No schema change.

    python xorcism_python/importers/import_hds.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "HDS (Hébergeur de Données de Santé)"  # matches the DOC_FRAMEWORKS picker label (not printed; ASCII-print rule unaffected)
MAP_SOURCE = "HDS v1.1 foundation"

# (ref, title, group). Activities = the 6 certified hosting scopes; the rest are HDS-specific exigences.
ITEMS = [
    ("HDS-A1", "Provision and operational maintenance of physical hosting sites", "Certified activity"),
    ("HDS-A2", "Provision and operational maintenance of the physical infrastructure", "Certified activity"),
    ("HDS-A3", "Provision and operational maintenance of the virtual infrastructure", "Certified activity"),
    ("HDS-A4", "Provision and operational maintenance of the application hosting platform", "Certified activity"),
    ("HDS-A5", "Administration and operation of the information system holding health data", "Certified activity"),
    ("HDS-A6", "Backup of health data", "Certified activity"),
    ("HDS-1", "ISO/IEC 27001 certified ISMS covering the health-data hosting scope", "Foundation"),
    ("HDS-2", "ISO/IEC 20000-1 IT service management for the hosting service", "Foundation"),
    ("HDS-3", "Health data localised within the EU/EEA (no transfer outside without safeguards)", "Health-data requirement"),
    ("HDS-4", "Medical confidentiality / secret protection and need-to-know access to health data", "Health-data requirement"),
    ("HDS-5", "GDPR compliance and a data processing agreement with the data controller (Art. 28)", "Health-data requirement"),
    ("HDS-6", "Designated personal-data protection officer (DPO) and privacy governance", "Health-data requirement"),
    ("HDS-7", "Reversibility: documented conditions for return and migration of health data", "Health-data requirement"),
    ("HDS-8", "Secure restitution and certified destruction of health data at end of contract", "Health-data requirement"),
    ("HDS-9", "Transparency on subcontractors hosting health data and flow-down of HDS obligations", "Health-data requirement"),
    ("HDS-10", "Hosting contract clauses required by the HDS framework (Art. L.1111-8 CSP)", "Health-data requirement"),
    ("HDS-11", "Traceability and logging of access to health data", "Health-data requirement"),
    ("HDS-12", "Availability, integrity and recovery commitments for health data (RTO/RPO, backups)", "Health-data requirement"),
    ("HDS-13", "Incident notification to the controller and the competent health authority", "Health-data requirement"),
    ("HDS-14", "Identification/authentication of health professionals consistent with national rules", "Health-data requirement"),
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
    id2cid: dict[str, int] = {}
    for ref, title, group in ITEMS:
        id2cid[ref] = cid
        _ins(cur, "CONTROL", {
            "ControlID": cid, "ControlGUID": str(uuid.uuid4()), "ControlName": f"{ref} {title}"[:300],
            "ControlDescription": f"HDS v1.1 - {group}", "VocabularyID": vid, "CIS": ref, "Statement": title,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        cid += 1
    # crosswalk: HDS is founded on ISO 27001 + 20000-1
    n_map = 0
    if cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone():
        mcols = _cols(cur, "CONTROLMAPPING")
        cur.execute("DELETE FROM CONTROLMAPPING WHERE Source=?", (MAP_SOURCE,))
        mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1
        for ref, fw, ext in [("HDS-1", "ISO/IEC 27001", "ISO/IEC 27001:2022"), ("HDS-2", "ISO/IEC 20000-1", "ISO/IEC 20000-1"),
                             ("HDS-5", "GDPR", "GDPR Art. 28"), ("HDS-3", "GDPR", "GDPR Chap. V")]:
            if ref in id2cid:
                _ins(cur, "CONTROLMAPPING", {
                    "MappingID": mid, "MappingGUID": str(uuid.uuid4()), "ControlID": id2cid[ref],
                    "Framework": fw, "ExternalID": ext, "Relationship": "based-on", "Source": MAP_SOURCE, "CreatedDate": now,
                }, mcols)
                mid += 1; n_map += 1
    con.commit(); con.close()
    print(f"[hds] VocabularyID={vid}: {len(ITEMS)} controls (6 activities + HDS requirements), {n_map} crosswalk rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
