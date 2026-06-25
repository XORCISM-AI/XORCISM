"""import_cri_profile.py - import the CRI Profile v2.2 (Cyber Risk Institute) into XORCISM.

The CRI Profile is the financial sector's cybersecurity benchmark: NIST CSF 2.0 structure
(Govern / Identify / Protect / Detect / Respond / Recover) plus CRI's "Extend (EX)" supply-chain
function, broken into testable "Diagnostic Statements" with impact-tier (Tier-1..4) applicability and
a NIST CSF v2 crosswalk. Loads the whole catalogue (bundled cri_profile_v2.2.json, parsed by
gen_cri_profile.py from the official v2.2 xlsx) into:

  1. Controls -> XORCISM.CONTROL          (VOCABULARY "CRI Profile v2.2"; CIS = Diagnostic-Statement id,
                                           Statement = the control text; 318 statements / 7 functions)
  2. Mappings -> XORCISM.CONTROLMAPPING   (Framework "NIST CSF 2.0" crosswalk + "Financial Services
                                           Regulations" reference; Source = "CRI Profile v2.2 mapping")

Idempotent (delete-then-insert by VocabularyID / Source). Raw SQL; no schema change (CONTROL /
CONTROLMAPPING / VOCABULARY already exist). DB dir = XORCISM_DB_DIR env or the default. ASCII output.

    python xorcism_python/importers/import_cri_profile.py
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "CRI Profile v2.2"
MAP_SOURCE = "CRI Profile v2.2 mapping"
BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cri_profile_v2.2.json")
FUNC_NAMES = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect",
              "RS": "Respond", "RC": "Recover", "EX": "Extend (supply chain)"}


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
    if "Description" in cols:
        rec["Description"] = "Cyber Risk Institute (CRI) Profile v2.2 - financial-sector cybersecurity benchmark (NIST CSF 2.0 + Extend)."
    _ins(cur, "VOCABULARY", rec, cols)
    return nid


def main() -> int:
    with open(BUNDLE, encoding="utf-8") as fh:
        cat = json.load(fh)
    controls = cat["controls"]
    now = datetime.now(timezone.utc).isoformat()

    xo = sqlite3.connect(_db("XORCISM"))
    xo.execute("PRAGMA busy_timeout=15000")
    cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    id2cid: dict[str, int] = {}
    for c in controls:
        cid = str(c.get("id") or "").strip()
        if not cid:
            continue
        func = str(c.get("function") or "").strip()
        fn = func.split("(")[0].strip() or FUNC_NAMES.get(cid.split(".")[0], "")
        tiers = c.get("tiers") or []
        tier_note = f" - Tiers {','.join(str(t) for t in tiers)}" if tiers else ""
        name = (c.get("name") or "").strip()
        id2cid[cid] = next_cid
        _ins(cur, "CONTROL", {
            "ControlID": next_cid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{cid}{(' ' + name) if name else ''}".strip()[:300],
            "ControlDescription": f"CRI Profile v2.2 - {fn}{tier_note}"[:500],
            "VocabularyID": vid, "CIS": cid, "Statement": (c.get("statement") or None),
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        next_cid += 1

    # NIST CSF 2.0 crosswalk + Financial-Services regulatory reference mappings.
    n_map = 0
    has_map = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone() is not None
    if has_map:
        mcols = _cols(cur, "CONTROLMAPPING")
        cur.execute("DELETE FROM CONTROLMAPPING WHERE Source=?", (MAP_SOURCE,))
        next_mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1
        for c in controls:
            cid = id2cid.get(str(c.get("id") or "").strip())
            if cid is None:
                continue
            nist = str(c.get("nist") or "").strip()
            if nist:
                _ins(cur, "CONTROLMAPPING", {
                    "MappingID": next_mid, "MappingGUID": str(uuid.uuid4()), "ControlID": cid,
                    "Framework": "NIST CSF 2.0", "ExternalID": nist[:1000],
                    "Relationship": "derived-from", "Source": MAP_SOURCE, "CreatedDate": now,
                }, mcols)
                next_mid += 1
                n_map += 1
            fsmap = str(c.get("fsMapping") or "").strip()
            if fsmap:
                _ins(cur, "CONTROLMAPPING", {
                    "MappingID": next_mid, "MappingGUID": str(uuid.uuid4()), "ControlID": cid,
                    "Framework": "Financial Services Regulations", "ExternalID": fsmap[:1000],
                    "ExternalName": "CRI regulatory mapping reference", "Relationship": "maps-to",
                    "Source": MAP_SOURCE, "CreatedDate": now,
                }, mcols)
                next_mid += 1
                n_map += 1
    xo.commit()
    xo.close()
    print(f"OK: VOCABULARY '{VOCAB}' (VocabID {vid}) - {len(id2cid)} controls, {n_map} mappings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
