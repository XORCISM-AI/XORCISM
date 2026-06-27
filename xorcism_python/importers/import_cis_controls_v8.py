"""import_cis_controls_v8.py - import the CIS Critical Security Controls v8 into XORCISM.

The CIS Critical Security Controls v8 (Center for Internet Security) are 18 prioritized,
prescriptive controls (153 underlying Safeguards, organized into Implementation Groups IG1/IG2/IG3)
that defend against the most common cyber attacks. NB: distinct from CIS *Benchmarks* (hardening
guides) which XORCISM imports separately (import_cis_benchmarks.py).

This loads the 18 Controls (number + official title + safeguard count) into:

  XORCISM.CONTROL  -> VOCABULARY "CIS Controls v8"
                      one CONTROL per Control; CIS = the control number ("1".."18"),
                      Statement = the control title, ControlDescription = safeguards / IG context.

CIS Controls titles are factual identifiers (the detailed Safeguard text is CIS-licensed and is
NOT reproduced here). Idempotent (delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR
env or the default.

    python xorcism_python/importers/import_cis_controls_v8.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB = "CIS Controls v8"
VERSION = "8.0"
REF = "CIS Critical Security Controls v8 (center for internet security)"
DESC = "CIS Critical Security Controls v8 - 18 prioritized controls / 153 safeguards (IG1/IG2/IG3). Titles only; Safeguard text is CIS-licensed."

# (number, official title, number of Safeguards).  Safeguard counts sum to 153.
CONTROLS = [
    ("1", "Inventory and Control of Enterprise Assets", 5),
    ("2", "Inventory and Control of Software Assets", 7),
    ("3", "Data Protection", 14),
    ("4", "Secure Configuration of Enterprise Assets and Software", 12),
    ("5", "Account Management", 6),
    ("6", "Access Control Management", 8),
    ("7", "Continuous Vulnerability Management", 7),
    ("8", "Audit Log Management", 12),
    ("9", "Email and Web Browser Protections", 7),
    ("10", "Malware Defenses", 7),
    ("11", "Data Recovery", 5),
    ("12", "Network Infrastructure Management", 8),
    ("13", "Network Monitoring and Defense", 11),
    ("14", "Security Awareness and Skills Training", 9),
    ("15", "Service Provider Management", 7),
    ("16", "Application Software Security", 14),
    ("17", "Incident Response Management", 9),
    ("18", "Penetration Testing", 5),
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
    n = sg = 0
    for cid, title, safeguards in CONTROLS:
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"CIS Control {cid}: {title}"[:300],
            "ControlDescription": f"CIS Critical Security Controls v8 - {safeguards} Safeguards (Implementation Groups IG1/IG2/IG3)."[:600],
            "VocabularyID": vid, "CIS": cid, "Statement": title,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1; n += 1; sg += safeguards
    xo.commit(); xo.close()
    print(f"[cis-controls-v8] VocabularyID={vid}: {n} controls covering {sg} safeguards.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
