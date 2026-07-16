"""import_cc.py - import Common Criteria (ISO/IEC 15408 / CC:2022) into XORCISM.
Jerome Athias - XORCISM

Common Criteria for Information Technology Security Evaluation (CC:2022 Revision 1, = ISO/IEC
15408) is the international standard for IT security evaluation. Its requirement catalogue is
split across the published parts:

  Part 2 (CCMB-2022-11-002) Security functional components  -> SFR classes / families / components
                                                               (FAU, FCO, FCS, FDP, FIA, FMT,
                                                                FPR, FPT, FRU, FTA, FTP)
  Part 3 (CCMB-2022-11-003) Security assurance components   -> SAR classes / families / components
                                                               (ADV, AGD, ALC, ATE, AVA, ASE, APE,
                                                                ACE, ACO)
  Part 5 (CCMB-2022-11-005) Pre-defined packages            -> EAL1..EAL7 and their component sets
                              NOTE: in CC:2022 the EAL packages moved OUT of Part 3 into Part 5.

Target:
  XORCISM.CONTROL -> VOCABULARY "Common Criteria (ISO/IEC 15408)"
      one CONTROL per class (CIS = FAU / ADV), family (CIS = FAU_GEN / ADV_FSP), component
      (CIS = FAU_GEN.1 / ADV_FSP.4) and EAL package (CIS = EAL4). Statement = the official title;
      ControlDescription carries the part / kind (SFR|SAR) / level / class / family, and for an
      EAL the full list of assurance components it requires.

The catalogue is a committed snapshot `importers/data/cc_catalogue.json`, mined from the official
CC:2022 R1 PDFs (commoncriteriaportal.org) - the PDFs are not redistributed here. Idempotent
(delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

Usage:
    python import_cc.py
    python import_cc.py --data other_catalogue.json
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

VOCAB = "Common Criteria (ISO/IEC 15408)"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cc_catalogue.json")


def _db(n: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{n}.db")


def _cols(cur: sqlite3.Cursor, t: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{t}")').fetchall()}


def _ins(cur: sqlite3.Cursor, t: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {t} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str, version: str, ref: str, desc: str) -> int:
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


def log(msg: str) -> None:
    print(f"[ImportCC] {msg}", flush=True)


PART_OF = {"SFR": "Part 2 (security functional components)", "SAR": "Part 3 (security assurance components)"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Import Common Criteria (ISO/IEC 15408) into XORCISM.CONTROL")
    ap.add_argument("--data", default=DATA, help="catalogue JSON snapshot")
    args = ap.parse_args()

    if not os.path.isfile(args.data):
        log(f"catalogue not found: {args.data}")
        return 2
    with open(args.data, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    rows, eals = data.get("rows", []), data.get("eals", [])
    if not rows:
        log("empty catalogue")
        return 2

    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM"))
    xo.execute("PRAGMA busy_timeout=20000")
    cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, data.get("version", "CC:2022 R1"), data.get("url", ""),
                        "Common Criteria for Information Technology Security Evaluation (ISO/IEC 15408): "
                        "security functional components (Part 2), security assurance components (Part 3) "
                        "and the pre-defined EAL packages (Part 5).")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    n = {"class": 0, "family": 0, "component": 0, "eal": 0}
    for r in rows:
        kind, level = r["kind"], r["level"]
        bits = [f"Common Criteria {PART_OF.get(kind, '')}", f"{kind} {level}", f"class {r['class']}"]
        if r.get("family") and level != "family":
            bits.append(f"family {r['family']}")
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{r['id']}: {r['name']}"[:300],
            "ControlDescription": " - ".join(bits)[:600],
            "VocabularyID": vid, "CIS": r["id"], "Statement": r["name"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1
        n[level] += 1

    for e in eals:
        comps = e.get("components") or []
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{e['id']}: {e['name']}"[:300],
            "ControlDescription": (f"Common Criteria Part 5 (pre-defined packages) - assurance package - "
                                   f"{len(comps)} assurance components: {', '.join(comps)}")[:600],
            "VocabularyID": vid, "CIS": e["id"], "Statement": f"{e['id']} - {e['name']}"[:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1
        n["eal"] += 1

    xo.commit()
    total = cur.execute("SELECT COUNT(*) FROM CONTROL WHERE VocabularyID=?", (vid,)).fetchone()[0]
    xo.close()
    log(f"Vocabulary '{VOCAB}' (id {vid}) - {data.get('version')}")
    log(f"  classes {n['class']} / families {n['family']} / components {n['component']} / EAL packages {n['eal']}")
    log(f"Done - {total} CONTROL rows in XORCISM.CONTROL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
