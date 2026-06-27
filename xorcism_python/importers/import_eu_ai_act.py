"""import_eu_ai_act.py - import the EU Artificial Intelligence Act into XORCISM.

Regulation (EU) 2024/1689 (the AI Act) lays down harmonised rules on artificial intelligence. It
is risk-based: prohibited practices (Art. 5), high-risk AI systems and their requirements
(Art. 8-15) and obligations (Art. 16-27), transparency obligations (Art. 50), general-purpose AI
(GPAI) models (Art. 51-56), governance, market surveillance and penalties (Art. 99-101).

Loads the compliance-relevant article structure (numbers + official titles - EU law, public)
into:

  XORCISM.CONTROL  -> VOCABULARY "EU AI Act" (Regulation (EU) 2024/1689)
                      one CONTROL per article; CIS = "Art. N", Statement = the article title,
                      ControlDescription = the chapter.

Reuses the existing empty "EU AI Act" vocabulary stub if present. The set covers the substantive
compliance articles (a curated subset of the 113 articles - procedural / institutional articles
are summarised). Idempotent (delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR env.

    python xorcism_python/importers/import_eu_ai_act.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "EU AI Act"
VERSION = "Regulation (EU) 2024/1689"
REF = "EUR-Lex 32024R1689"
DESC = "EU AI Act - Regulation (EU) 2024/1689 laying down harmonised rules on artificial intelligence. Risk-based: prohibited practices (Art. 5), high-risk requirements (Art. 8-15) & obligations (Art. 16-27), transparency (Art. 50), GPAI models (Art. 51-56), governance & penalties."

CHAPTERS = [
    ("I - General provisions", [
        ("1", "Subject matter"),
        ("2", "Scope"),
        ("3", "Definitions"),
        ("4", "AI literacy"),
    ]),
    ("II - Prohibited AI practices", [
        ("5", "Prohibited AI practices"),
    ]),
    ("III - High-risk AI systems (Classification)", [
        ("6", "Classification rules for high-risk AI systems"),
        ("7", "Amendments to Annex III"),
    ]),
    ("III - High-risk AI systems (Requirements)", [
        ("8", "Compliance with the requirements"),
        ("9", "Risk management system"),
        ("10", "Data and data governance"),
        ("11", "Technical documentation"),
        ("12", "Record-keeping"),
        ("13", "Transparency and provision of information to deployers"),
        ("14", "Human oversight"),
        ("15", "Accuracy, robustness and cybersecurity"),
    ]),
    ("III - High-risk AI systems (Obligations)", [
        ("16", "Obligations of providers of high-risk AI systems"),
        ("17", "Quality management system"),
        ("18", "Documentation keeping"),
        ("19", "Automatically generated logs"),
        ("20", "Corrective actions and duty of information"),
        ("21", "Cooperation with competent authorities"),
        ("22", "Authorised representatives of providers of high-risk AI systems"),
        ("23", "Obligations of importers"),
        ("24", "Obligations of distributors"),
        ("25", "Responsibilities along the AI value chain"),
        ("26", "Obligations of deployers of high-risk AI systems"),
        ("27", "Fundamental rights impact assessment for high-risk AI systems"),
    ]),
    ("III - High-risk AI systems (Conformity)", [
        ("40", "Harmonised standards and standardisation deliverables"),
        ("41", "Common specifications"),
        ("43", "Conformity assessment"),
        ("47", "EU declaration of conformity"),
        ("48", "CE marking"),
        ("49", "Registration"),
    ]),
    ("IV - Transparency obligations", [
        ("50", "Transparency obligations for providers and deployers of certain AI systems"),
    ]),
    ("V - General-purpose AI models", [
        ("51", "Classification of general-purpose AI models as general-purpose AI models with systemic risk"),
        ("52", "Procedure"),
        ("53", "Obligations for providers of general-purpose AI models"),
        ("54", "Authorised representatives of providers of general-purpose AI models"),
        ("55", "Obligations for providers of general-purpose AI models with systemic risk"),
        ("56", "Codes of practice"),
    ]),
    ("VI - Measures in support of innovation", [
        ("57", "AI regulatory sandboxes"),
        ("60", "Testing of high-risk AI systems in real world conditions outside AI regulatory sandboxes"),
        ("61", "Informed consent to participate in testing in real world conditions"),
        ("62", "Measures for providers and deployers, in particular SMEs, including start-ups"),
    ]),
    ("VII - Governance", [
        ("64", "AI Office"),
        ("65", "Establishment and structure of the European Artificial Intelligence Board"),
        ("66", "Tasks of the Board"),
        ("70", "Designation of national competent authorities and single points of contact"),
    ]),
    ("VIII - EU database", [
        ("71", "EU database for high-risk AI systems listed in Annex III"),
    ]),
    ("IX - Post-market monitoring, information sharing and market surveillance", [
        ("72", "Post-market monitoring by providers and post-market monitoring plan for high-risk AI systems"),
        ("73", "Reporting of serious incidents"),
        ("74", "Market surveillance and control of AI systems in the Union market"),
        ("79", "Procedure at national level for dealing with AI systems presenting a risk"),
    ]),
    ("X - Codes of conduct", [
        ("95", "Codes of conduct for voluntary application of specific requirements"),
    ]),
    ("XII - Penalties", [
        ("99", "Penalties"),
        ("100", "Administrative fines on Union institutions, bodies, offices and agencies"),
        ("101", "Fines for providers of general-purpose AI models"),
    ]),
    ("XIII - Final provisions", [
        ("111", "AI systems already placed on the market or put into service and general-purpose AI models already placed on the market"),
        ("112", "Evaluation and review"),
        ("113", "Entry into force and application"),
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
                "ControlName": f"AI Act Art. {num}: {title}"[:300],
                "ControlDescription": f"EU AI Act (Regulation (EU) 2024/1689) / Chapter {chapter}"[:600],
                "VocabularyID": vid, "CIS": f"Art. {num}", "Statement": title,
                "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            }, ccols)
            nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[eu-ai-act] VocabularyID={vid}: {n} articles (Regulation (EU) 2024/1689, compliance-relevant subset).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
