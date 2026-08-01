"""import_nist_800171r3.py — import NIST SP 800-171 Revision 3 into XORCISM as a control framework.

NIST SP 800-171 Rev 3 (May 2024) — "Protecting Controlled Unclassified Information (CUI) in Nonfederal
Systems and Organizations" — is the U.S. requirement referenced by **DFARS 252.204-7012** (safeguarding
CUI for DoD contractors) and used as the basis for **CMMC Level 2**. Rev 3 restructures the catalogue to
**97 security requirements across 17 families** (Rev 2 had 110 across 14; Rev 3 adds Planning, System &
Services Acquisition and Supply Chain Risk Management, and withdraws/consolidates others).

This importer loads the 17 families + 97 requirements into XORCISM.CONTROL under VOCABULARY
"NIST SP 800-171 Rev 3": one CONTROL per family (header) and per requirement. CIS = the requirement id
(e.g. "03.01.01"), ControlName = "<id> <title>", ControlDescription = "NIST SP 800-171 Rev 3 — <family>".
Flows into /frameworks + /compliance-management (assessment scoring). Complements the existing CMMC 2.0
vocab and the /sprs (Rev 2) SPRS score.

NIST SP 800-171 is a U.S. Government work (public domain). Catalogue mined from the NIST OSCAL content
(usnistgov/oscal-content) and committed to importers/data/nist_800171r3.json. Idempotent (delete-then-
insert by VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_nist_800171r3.py
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "NIST SP 800-171 Rev 3"
_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "nist_800171r3.json")


def _db_path(db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
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
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def _key(ref: str) -> list[int]:
    return [int(x) for x in ref.split(".") if x.isdigit()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Import NIST SP 800-171 Rev 3 into XORCISM.CONTROL")
    ap.add_argument("--file", default=_DATA, help="bundled nist_800171r3.json (default: data/nist_800171r3.json)")
    ap.add_argument("--db-dir", help="directory holding XORCISM.db (default: $XORCISM_DB_DIR)")
    a = ap.parse_args()

    doc = json.load(open(a.file, encoding="utf-8"))
    famname = {f["code"]: f["name"] for f in doc["families"]}

    # Ordered rows: family headers then requirements. (ref, title, statement, desc)
    rows: list[tuple[str, str, str, str]] = []
    for f in sorted(doc["families"], key=lambda x: _key(x["code"])):
        rows.append((f["code"], f["name"], f"NIST SP 800-171 Rev 3 family {f['code']} ({f['count']} requirements).",
                     f"NIST SP 800-171 Rev 3 — Family {f['code']} {f['name']}"))
    for r in sorted(doc["requirements"], key=lambda x: _key(x["id"])):
        fam = ".".join(r["id"].split(".")[:2])
        rows.append((r["id"], r["title"], r["title"],
                     f"NIST SP 800-171 Rev 3 — {fam} {famname.get(fam, r.get('familyName', ''))}"))

    con = sqlite3.connect(_db_path(a.db_dir)); con.execute("PRAGMA busy_timeout=15000"); cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    vid = _ensure_vocab(cur, VOCAB)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))  # idempotent refresh
    next_id = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1

    n_fam = n_req = 0
    for ref, title, statement, desc in rows:
        is_family = ref.count(".") == 1
        rec = {
            "ControlID": next_id, "ControlGUID": f"n171r3-{ref}",
            "ControlName": f"{ref} {title}".strip()[:300], "ControlDescription": desc,
            "VocabularyID": vid, "CIS": ref, "Statement": statement or None,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        next_id += 1
        if is_family:
            n_fam += 1
        else:
            n_req += 1

    try:  # register/refresh a FRAMEWORK row if the table exists
        cur.execute("UPDATE FRAMEWORK SET FrameworkVersion=? WHERE FrameworkName LIKE '%800-171%'", ("Rev 3",))
    except Exception:  # noqa: BLE001
        pass
    con.commit(); con.close()
    print(f"[800-171r3] VocabularyID={vid}: {n_fam + n_req} rows ({n_fam} families + {n_req} requirements) "
          f"— NIST SP 800-171 Rev 3 (DFARS 252.204-7012 / CMMC L2).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
