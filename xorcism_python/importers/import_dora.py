"""import_dora.py - import the Digital Operational Resilience Act (DORA) into XORCISM.

Regulation (EU) 2022/2554 (DORA) sets uniform requirements for the security of network and
information systems of financial entities and their critical ICT third-party providers. It has
64 articles across 9 chapters (ICT risk management, incident reporting, resilience testing /
TLPT, ICT third-party risk and the Oversight Framework, information sharing).

Loads the article structure (numbers + official titles - EU law, public) into:

  XORCISM.CONTROL  -> VOCABULARY "DORA" (Regulation (EU) 2022/2554)
                      one CONTROL per article; CIS = "Art. N", Statement = the article title,
                      ControlDescription = the chapter.

Reuses the existing empty "DORA" vocabulary stub if present. Idempotent (delete-then-insert by
VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_dora.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "DORA"
VERSION = "Regulation (EU) 2022/2554"
REF = "EUR-Lex 32022R2554"
DESC = "DORA - Digital Operational Resilience Act, Regulation (EU) 2022/2554. 64 articles / 9 chapters (ICT risk management, incident reporting, resilience testing/TLPT, ICT third-party risk & Oversight Framework, information sharing)."

CHAPTERS = [
    ("I - General provisions", [
        ("1", "Subject matter"), ("2", "Scope"), ("3", "Definitions"), ("4", "Proportionality principle"),
    ]),
    ("II - ICT risk management", [
        ("5", "Governance and organisation"),
        ("6", "ICT risk management framework"),
        ("7", "ICT systems, protocols and tools"),
        ("8", "Identification"),
        ("9", "Protection and prevention"),
        ("10", "Detection"),
        ("11", "Response and recovery"),
        ("12", "Backup policies and procedures, restoration and recovery procedures and methods"),
        ("13", "Learning and evolving"),
        ("14", "Communication"),
        ("15", "Further harmonisation of ICT risk management tools, methods, processes and policies"),
        ("16", "Simplified ICT risk management framework"),
    ]),
    ("III - ICT-related incident management, classification and reporting", [
        ("17", "ICT-related incident management process"),
        ("18", "Classification of ICT-related incidents and cyber threats"),
        ("19", "Reporting of major ICT-related incidents and voluntary notification of significant cyber threats"),
        ("20", "Harmonisation of reporting content and templates"),
        ("21", "Centralisation of reporting of major ICT-related incidents"),
        ("22", "Supervisory feedback"),
        ("23", "Operational or security payment-related incidents concerning credit institutions, payment institutions, account information service providers, and electronic money institutions"),
    ]),
    ("IV - Digital operational resilience testing", [
        ("24", "General requirements for the performance of digital operational resilience testing"),
        ("25", "Testing of ICT tools and systems"),
        ("26", "Advanced testing of ICT tools, systems and processes based on TLPT"),
        ("27", "Requirements for testers for the carrying out of TLPT"),
    ]),
    ("V - Managing of ICT third-party risk", [
        ("28", "General principles"),
        ("29", "Preliminary assessment of ICT concentration risk at entity level"),
        ("30", "Key contractual provisions"),
        ("31", "Designation of critical ICT third-party service providers"),
        ("32", "Structure of the Oversight Framework"),
        ("33", "Tasks of the Lead Overseer"),
        ("34", "Operational coordination between Lead Overseers"),
        ("35", "Powers of the Lead Overseer"),
        ("36", "Exercise of the powers of the Lead Overseer outside the Union"),
        ("37", "Request for information"),
        ("38", "General investigations"),
        ("39", "Inspections"),
        ("40", "Ongoing oversight"),
        ("41", "Harmonisation of conditions enabling the conduct of the oversight activities"),
        ("42", "Follow-up by competent authorities"),
        ("43", "Oversight fees"),
        ("44", "International cooperation"),
    ]),
    ("VI - Information-sharing arrangements", [
        ("45", "Information-sharing arrangements on cyber threat information and intelligence"),
    ]),
    ("VII - Competent authorities", [
        ("46", "Competent authorities"),
        ("47", "Cooperation with structures and authorities established by Union law"),
        ("48", "Cooperation between authorities"),
        ("49", "Financial cross-sector exercises, communication and cooperation"),
        ("50", "Administrative penalties and remedial measures"),
        ("51", "Exercise of the power to impose administrative penalties and remedial measures"),
        ("52", "Criminal penalties"),
        ("53", "Notification duties"),
        ("54", "Publication of administrative penalties"),
        ("55", "Professional secrecy"),
        ("56", "Data protection"),
    ]),
    ("VIII - Delegated acts", [
        ("57", "Exercise of the delegation"),
    ]),
    ("IX - Transitional and final provisions", [
        ("58", "Review clause"),
        ("59", "Amendments to Regulation (EC) No 1060/2009"),
        ("60", "Amendments to Regulation (EU) No 648/2012"),
        ("61", "Amendments to Regulation (EU) No 600/2014"),
        ("62", "Amendments to Regulation (EU) No 909/2014"),
        ("63", "Amendment to Regulation (EU) 2016/1011"),
        ("64", "Entry into force and application"),
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
    for chapter, arts in CHAPTERS:
        for num, title in arts:
            _ins(cur, "CONTROL", {
                "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
                "ControlName": f"DORA Art. {num}: {title}"[:300],
                "ControlDescription": f"DORA (Regulation (EU) 2022/2554) / Chapter {chapter}"[:600],
                "VocabularyID": vid, "CIS": f"Art. {num}", "Statement": title,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            }, ccols)
            nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[dora] VocabularyID={vid}: {n} articles (Regulation (EU) 2022/2554, 9 chapters).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
