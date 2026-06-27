"""import_spvs.py - import the OWASP SPVS (Secure Pipeline Verification Standard) into XORCISM.

OWASP SPVS (owasp.org/www-project-spvs) is a security-maturity verification standard for the
end-to-end software delivery pipeline across five stages - Plan, Develop, Integrate, Release,
Operate - with L1/L2/L3 maturity levels and mappings to NIST 800-53, the OWASP Top 10 CI/CD
Security Risks (CICD-SEC-*) and CWE. The project ships two requirement sets:

  * SPVS 1.0      - the general secure-pipeline requirements (with NIST / CICD-SEC / CWE mappings).
  * SPVS 1.5-AI   - the AI-pipeline security extension (AI/ML delivery pipelines).

Each is loaded as its own selectable control framework:

  XORCISM.CONTROL  -> VOCABULARY "OWASP SPVS 1.0"     (one CONTROL per requirement; CIS = V1.1.1 ...)
                   -> VOCABULARY "OWASP SPVS 1.5-AI"
  Statement = the requirement text; ControlDescription = stage / sub-category / level / mappings.

Data: a committed snapshot at importers/data/spvs.json (parsed from the SPVS CSVs). Pass
`--repo <path>` to re-parse a fresh clone of github.com/OWASP/www-project-spvs and refresh it.
OWASP SPVS is open (community). Idempotent (delete-then-insert per VocabularyID). DB dir =
XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_spvs.py
    python xorcism_python/importers/import_spvs.py --repo /path/to/www-project-spvs
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "spvs.json")
SOURCE = "https://owasp.org/www-project-spvs/"
REQ = re.compile(r"^V\d+(?:\.\d+){1,2}$")
RELEASES = [("OWASP SPVS 1.0", "1.0", "OWASP_SPVS_1.0_-en_Requirements.csv"),
            ("OWASP SPVS 1.5-AI", "1.5-AI", "OWASP_SPVS_1.5-AI_-en_Requirements.csv")]


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


def _parse_repo(repo: str) -> dict:
    clean = lambda s: re.sub(r"\s+", " ", (s or "")).strip()
    base = repo
    if os.path.isdir(os.path.join(repo, "1.5")):
        base = os.path.join(repo, "1.5")
    out = {"meta": {"title": "OWASP Secure Pipeline Verification Standard (SPVS)", "source": SOURCE,
                    "repo": "https://github.com/OWASP/www-project-spvs"}, "releases": []}
    for vocab, ver, fn in RELEASES:
        reqs = []
        for r in csv.DictReader(open(os.path.join(base, fn), encoding="utf-8-sig")):
            rid = clean(r.get("req_id"))
            if not REQ.match(rid):
                continue
            reqs.append({"id": rid, "category": clean(r.get("category_name")), "subcategory": clean(r.get("sub-category_name")),
                         "description": clean(r.get("req_description")),
                         "levels": [f"L{n}" for n in (1, 2, 3) if clean(r.get(f"level {n}", "")).upper() == "X"],
                         "nist": clean(r.get("NIST", "")), "cicd": clean(r.get("OWASP_CICD_Risk", "")), "cwe": clean(r.get("cwe_mapping", ""))})
        out["releases"].append({"vocab": vocab, "version": ver, "requirements": reqs})
    return out


def main() -> int:
    if "--repo" in sys.argv:
        data = _parse_repo(sys.argv[sys.argv.index("--repo") + 1])
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        json.dump(data, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("[spvs] re-parsed: " + ", ".join(f"{r['vocab']}={len(r['requirements'])}" for r in data["releases"]))
    data = json.load(open(DATA, encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    ccols = _cols(cur, "CONTROL")
    summary = []
    for rel in data["releases"]:
        vid = _ensure_vocab(cur, rel["vocab"], rel.get("version", ""), SOURCE,
                            f"OWASP Secure Pipeline Verification Standard ({rel.get('version','')}) - secure software-delivery-pipeline requirements across Plan/Develop/Integrate/Release/Operate; L1/L2/L3 maturity, mapped to NIST 800-53, OWASP CI/CD Top 10 (CICD-SEC) and CWE.")
        cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
        nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
        n = 0
        for q in rel["requirements"]:
            parts = [q.get("category", ""), q.get("subcategory", "")]
            meta = []
            if q.get("levels"):
                meta.append("Level " + "/".join(q["levels"]))
            if q.get("cicd"):
                meta.append(q["cicd"])
            if q.get("nist"):
                meta.append("NIST: " + q["nist"])
            if q.get("cwe"):
                meta.append(q["cwe"])
            desc = f"{rel['vocab']} / " + " / ".join(p for p in parts if p) + ((" - " + " - ".join(meta)) if meta else "")
            _ins(cur, "CONTROL", {
                "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
                "ControlName": f"{q['id']}: {q['description'][:90]}"[:300],
                "ControlDescription": desc[:600], "VocabularyID": vid, "CIS": q["id"],
                "Statement": q["description"][:2000], "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
            }, ccols)
            nid += 1; n += 1
        summary.append(f"{rel['vocab']} (VocabID={vid}): {n}")
    xo.commit(); xo.close()
    print("[spvs] imported -> " + "; ".join(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
