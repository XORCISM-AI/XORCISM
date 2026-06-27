"""import_nis2.py - import the NIS2 Directive into XORCISM.

Directive (EU) 2022/2555 (NIS2) is the EU-wide legislation on measures for a high common level of
cybersecurity across the Union. It repeals the original NIS Directive (EU) 2016/1148 and has 46
articles across its chapters (coordinated frameworks, CSIRTs & cooperation, risk-management
measures and reporting obligations Art. 20-23, jurisdiction & registration, supervision &
enforcement).

Loads the European text article structure (numbers + official titles - EU law, public) into:

  XORCISM.CONTROL  -> VOCABULARY "NIS2" (Directive (EU) 2022/2555)
                      one CONTROL per article; CIS = "Art. N", Statement = the article title.

Reuses the existing empty "NIS2" vocabulary stub if present. Idempotent (delete-then-insert by
VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_nis2.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "NIS2"
VERSION = "Directive (EU) 2022/2555"
REF = "EUR-Lex 32022L2555"
DESC = "NIS2 - Directive (EU) 2022/2555 on measures for a high common level of cybersecurity across the Union. 46 articles; repeals Directive (EU) 2016/1148. Includes the cybersecurity risk-management measures (Art. 21) and reporting obligations (Art. 23)."

CHAPTERS = [
    ("I - General provisions", [
        ("1", "Subject matter"),
        ("2", "Scope"),
        ("3", "Essential and important entities"),
        ("4", "Sector-specific Union legal acts"),
        ("5", "Minimum harmonisation"),
        ("6", "Definitions"),
    ]),
    ("II - Coordinated cybersecurity frameworks", [
        ("7", "National cybersecurity strategy"),
        ("8", "Competent authorities and single points of contact"),
        ("9", "National cyber crisis management frameworks"),
        ("10", "Computer security incident response teams (CSIRTs)"),
        ("11", "Requirements, technical capabilities and tasks of CSIRTs"),
        ("12", "Coordinated vulnerability disclosure and a European vulnerability database"),
        ("13", "Cooperation at national level"),
    ]),
    ("III - Cooperation at Union and international level", [
        ("14", "Cooperation Group"),
        ("15", "CSIRTs network"),
        ("16", "European cyber crisis liaison organisation network (EU-CyCLONe)"),
        ("17", "International cooperation"),
        ("18", "Report on the state of cybersecurity in the Union"),
        ("19", "Peer reviews"),
    ]),
    ("IV - Cybersecurity risk-management measures and reporting obligations", [
        ("20", "Governance"),
        ("21", "Cybersecurity risk-management measures"),
        ("22", "Union level coordinated security risk assessments of critical supply chains"),
        ("23", "Reporting obligations"),
        ("24", "Use of European cybersecurity certification schemes"),
        ("25", "Standardisation"),
    ]),
    ("V - Jurisdiction and registration", [
        ("26", "Jurisdiction and territoriality"),
        ("27", "Registry of entities"),
        ("28", "Database of domain name registration data"),
    ]),
    ("VI - Information sharing", [
        ("29", "Cybersecurity information-sharing arrangements"),
        ("30", "Voluntary notification of relevant information"),
    ]),
    ("VII - Supervision and enforcement", [
        ("31", "General aspects concerning supervision and enforcement"),
        ("32", "Supervisory and enforcement measures in relation to essential entities"),
        ("33", "Supervisory and enforcement measures in relation to important entities"),
        ("34", "General conditions for imposing administrative fines on essential and important entities"),
        ("35", "Infringements entailing a personal data breach"),
        ("36", "Penalties"),
        ("37", "Mutual assistance"),
    ]),
    ("VIII - Delegated and implementing acts", [
        ("38", "Exercise of the delegation"),
        ("39", "Committee procedure"),
    ]),
    ("IX - Final provisions", [
        ("40", "Review"),
        ("41", "Transposition"),
        ("42", "Amendment to Regulation (EU) No 910/2014"),
        ("43", "Amendment to Directive (EU) 2018/1972"),
        ("44", "Repeal (Directive (EU) 2016/1148)"),
        ("45", "Entry into force"),
        ("46", "Addressees"),
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
                "ControlName": f"NIS2 Art. {num}: {title}"[:300],
                "ControlDescription": f"NIS2 (Directive (EU) 2022/2555) / Chapter {chapter}"[:600],
                "VocabularyID": vid, "CIS": f"Art. {num}", "Statement": title,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            }, ccols)
            nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[nis2] VocabularyID={vid}: {n} articles (Directive (EU) 2022/2555).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
