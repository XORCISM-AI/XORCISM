"""import_iso27701.py - import ISO/IEC 27701:2019 (PIMS) into XORCISM.CONTROL.

ISO/IEC 27701:2019 is the Privacy Information Management System (PIMS) extension of
ISO/IEC 27001/27002. Beyond the clause 5 (PIMS-specific ISMS requirements) and clause 6
(privacy overlay of the ISO/IEC 27002 controls) refinements - which simply qualify the
already-imported 27001/27002 catalogues - its distinctive content is the two sets of
*additional* privacy controls:

  * Annex A - 31 additional controls for PII controllers   (clauses 7.2-7.5)
  * Annex B - 18 additional controls for PII processors    (clauses 8.2-8.5)

This importer registers the VOCABULARY "ISO/IEC 27701:2019" and writes those 49 controls as
CONTROL rows. Only the clause REFERENCE and the short factual TITLE are stored - the normative
ISO text is copyright-protected and is NOT reproduced (same treatment as import_iso27001.py).

It also writes CONTROLMAPPING rows (Framework="GDPR") crosswalking each control to the relevant
EU GDPR (Regulation (EU) 2016/679) article(s), per the ISO/IEC 27701 Annex D correspondence -
mirroring the ReCyF -> NIS2 crosswalk in import_recyf.py.

Idempotent: re-running deletes the 27701 controls + their GDPR mappings and re-inserts. Raw SQL;
DB path = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_iso27701.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "ISO/IEC 27701:2019"

# Annex A - additional controls for PII CONTROLLERS. (clause heading, [(ref, title), ...]).
CONTROLLER = [
    ("A.7.2 Conditions for collection and processing", [
        ("A.7.2.1", "Identify and document purpose"),
        ("A.7.2.2", "Identify lawful basis"),
        ("A.7.2.3", "Determine when and how consent is to be obtained"),
        ("A.7.2.4", "Obtain and record consent"),
        ("A.7.2.5", "Privacy impact assessment"),
        ("A.7.2.6", "Contracts with PII processors"),
        ("A.7.2.7", "Joint PII controller"),
        ("A.7.2.8", "Records related to processing PII"),
    ]),
    ("A.7.3 Obligations to PII principals", [
        ("A.7.3.1", "Determining and fulfilling obligations to PII principals"),
        ("A.7.3.2", "Determining information for PII principals"),
        ("A.7.3.3", "Providing information to PII principals"),
        ("A.7.3.4", "Providing mechanism to modify or withdraw consent"),
        ("A.7.3.5", "Providing mechanism to object to PII processing"),
        ("A.7.3.6", "Access, correction and/or erasure"),
        ("A.7.3.7", "PII controllers' obligations to inform third parties"),
        ("A.7.3.8", "Providing copy of PII processed"),
        ("A.7.3.9", "Handling requests"),
        ("A.7.3.10", "Automated decision making"),
    ]),
    ("A.7.4 Privacy by design and privacy by default", [
        ("A.7.4.1", "Limit collection"),
        ("A.7.4.2", "Limit processing"),
        ("A.7.4.3", "Accuracy and quality"),
        ("A.7.4.4", "PII minimization objectives"),
        ("A.7.4.5", "PII de-identification and deletion at the end of processing"),
        ("A.7.4.6", "Temporary files"),
        ("A.7.4.7", "Retention"),
        ("A.7.4.8", "Disposal"),
        ("A.7.4.9", "PII transmission controls"),
    ]),
    ("A.7.5 PII sharing, transfer, and disclosure", [
        ("A.7.5.1", "Identify basis for PII transfer between jurisdictions"),
        ("A.7.5.2", "Countries and international organizations to which PII can be transferred"),
        ("A.7.5.3", "Records of transfer of PII"),
        ("A.7.5.4", "Records of PII disclosure to third parties"),
    ]),
]

# Annex B - additional controls for PII PROCESSORS.
PROCESSOR = [
    ("B.8.2 Conditions for collection and processing", [
        ("B.8.2.1", "Customer agreement"),
        ("B.8.2.2", "Organization's purposes"),
        ("B.8.2.3", "Marketing and advertising use"),
        ("B.8.2.4", "Infringing instruction"),
        ("B.8.2.5", "Customer obligations"),
        ("B.8.2.6", "Records related to processing PII"),
    ]),
    ("B.8.3 Obligations to PII principals", [
        ("B.8.3.1", "Obligations to PII principals"),
    ]),
    ("B.8.4 Privacy by design and privacy by default", [
        ("B.8.4.1", "Temporary files"),
        ("B.8.4.2", "Return, transfer or disposal of PII"),
        ("B.8.4.3", "PII transmission controls"),
    ]),
    ("B.8.5 PII sharing, transfer, and disclosure", [
        ("B.8.5.1", "Basis for PII transfer between jurisdictions"),
        ("B.8.5.2", "Countries and international organizations to which PII can be transferred"),
        ("B.8.5.3", "Records of PII disclosure to third parties"),
        ("B.8.5.4", "Notification of PII disclosure requests"),
        ("B.8.5.5", "Legally binding PII disclosures"),
        ("B.8.5.6", "Disclosure of subcontractors used to process PII"),
        ("B.8.5.7", "Engagement of a subcontractor to process PII"),
        ("B.8.5.8", "Change of subcontractor to process PII"),
    ]),
]

# EU GDPR (Regulation (EU) 2016/679) article -> short title (for CONTROLMAPPING.ExternalName).
GDPR_TITLES = {
    "Art.5": "Principles relating to processing of personal data",
    "Art.6": "Lawfulness of processing",
    "Art.7": "Conditions for consent",
    "Art.12": "Transparent information, communication and modalities",
    "Art.13": "Information to be provided where PII collected from the data subject",
    "Art.14": "Information to be provided where PII not obtained from the data subject",
    "Art.15": "Right of access by the data subject",
    "Art.16": "Right to rectification",
    "Art.17": "Right to erasure (right to be forgotten)",
    "Art.19": "Notification obligation regarding rectification or erasure",
    "Art.20": "Right to data portability",
    "Art.21": "Right to object",
    "Art.22": "Automated individual decision-making, including profiling",
    "Art.25": "Data protection by design and by default",
    "Art.26": "Joint controllers",
    "Art.28": "Processor",
    "Art.29": "Processing under the authority of the controller or processor",
    "Art.30": "Records of processing activities",
    "Art.32": "Security of processing",
    "Art.35": "Data protection impact assessment",
    "Art.44": "General principle for transfers",
    "Art.45": "Transfers on the basis of an adequacy decision",
    "Art.46": "Transfers subject to appropriate safeguards",
    "Art.48": "Transfers or disclosures not authorised by Union law",
    "Art.49": "Derogations for specific situations",
}

# Curated ISO/IEC 27701 Annex D -> EU GDPR crosswalk (control ref -> [articles]).
GDPR = {
    "A.7.2.1": ["Art.5", "Art.30"], "A.7.2.2": ["Art.6"], "A.7.2.3": ["Art.6", "Art.7"],
    "A.7.2.4": ["Art.7"], "A.7.2.5": ["Art.35"], "A.7.2.6": ["Art.28"], "A.7.2.7": ["Art.26"],
    "A.7.2.8": ["Art.30"],
    "A.7.3.1": ["Art.12"], "A.7.3.2": ["Art.13", "Art.14"], "A.7.3.3": ["Art.13", "Art.14"],
    "A.7.3.4": ["Art.7"], "A.7.3.5": ["Art.21"], "A.7.3.6": ["Art.15", "Art.16", "Art.17"],
    "A.7.3.7": ["Art.19"], "A.7.3.8": ["Art.15", "Art.20"], "A.7.3.9": ["Art.12"],
    "A.7.3.10": ["Art.22"],
    "A.7.4.1": ["Art.5"], "A.7.4.2": ["Art.5"], "A.7.4.3": ["Art.5"], "A.7.4.4": ["Art.5", "Art.25"],
    "A.7.4.5": ["Art.5", "Art.25"], "A.7.4.6": ["Art.5"], "A.7.4.7": ["Art.5"], "A.7.4.8": ["Art.5"],
    "A.7.4.9": ["Art.32"],
    "A.7.5.1": ["Art.44", "Art.45", "Art.46"], "A.7.5.2": ["Art.45", "Art.46", "Art.49"],
    "A.7.5.3": ["Art.30"], "A.7.5.4": ["Art.30"],
    "B.8.2.1": ["Art.28"], "B.8.2.2": ["Art.28", "Art.29"], "B.8.2.3": ["Art.28"],
    "B.8.2.4": ["Art.28"], "B.8.2.5": ["Art.28"], "B.8.2.6": ["Art.30"],
    "B.8.3.1": ["Art.28"],
    "B.8.4.1": ["Art.5"], "B.8.4.2": ["Art.28"], "B.8.4.3": ["Art.32"],
    "B.8.5.1": ["Art.44", "Art.46"], "B.8.5.2": ["Art.45", "Art.46"], "B.8.5.3": ["Art.30"],
    "B.8.5.4": ["Art.48"], "B.8.5.5": ["Art.48"], "B.8.5.6": ["Art.28"], "B.8.5.7": ["Art.28"],
    "B.8.5.8": ["Art.28"],
}


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
    if "CreatedDate" in cols:
        rec["CreatedDate"] = datetime.now(timezone.utc).isoformat()
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def main() -> int:
    con = sqlite3.connect(_db_path())
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()

    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    has_map = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone() is not None

    # idempotent: drop previous 27701 controls + their GDPR mappings
    old_ids = [r[0] for r in cur.execute("SELECT ControlID FROM CONTROL WHERE VocabularyID=?", (vid,)).fetchall()]
    if old_ids and has_map:
        cur.execute(f"DELETE FROM CONTROLMAPPING WHERE Framework='GDPR' AND ControlID IN ({','.join('?'*len(old_ids))})", old_ids)
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))

    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    next_mid = 1
    if has_map:
        next_mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1

    def insert_control(rec: dict) -> None:
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])

    n_ctrl = n_map = 0
    sections = [("PII controller (Annex A)", CONTROLLER), ("PII processor (Annex B)", PROCESSOR)]
    for role, blocks in sections:
        for clause, items in blocks:
            for ref, title in items:
                cid = next_cid
                next_cid += 1
                insert_control({
                    "ControlID": cid, "ControlGUID": str(uuid.uuid4()),
                    "ControlName": f"{ref} {title}"[:300],
                    "ISO": ref, "CIS": ref,
                    "ControlDescription": f"ISO/IEC 27701:2019 - {clause}",
                    "Guidance": f"Additional PIMS control - {role}.",
                    "VocabularyID": vid,
                    "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
                })
                n_ctrl += 1
                if has_map:
                    for art in GDPR.get(ref, []):
                        cur.execute(
                            "INSERT INTO CONTROLMAPPING (MappingID, MappingGUID, ControlID, Framework, ExternalID, ExternalName, Relationship, Source, CreatedDate) "
                            "VALUES (?,?,?,?,?,?,?,?,?)",
                            (next_mid, str(uuid.uuid4()), cid, "GDPR", art, GDPR_TITLES.get(art, art), "supports",
                             "ISO/IEC 27701:2019 Annex D <-> EU GDPR (Regulation (EU) 2016/679) correspondence", now))
                        next_mid += 1
                        n_map += 1

    con.commit()
    con.close()
    print(f"[iso27701] VocabularyID={vid}: {n_ctrl} additional controls "
          f"(31 controller + 18 processor), {n_map} GDPR mappings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
