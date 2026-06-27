"""import_mlasvs.py - import the MLASVS verification standard (from MLASTG) into XORCISM.

MLASTG (github.com/bb1nfosec/MLASTG, "MLSec Application Security Testing Guide") is the ML/AI
analogue of the OWASP MASVS/MASTG. Its verification standard, **MLASVS**, defines security controls
for machine-learning systems (classic ML, deep nets, LLMs) across seven categories - Data Security
& Privacy, Model Security, LLM Security, Supply Chain, Pipeline & MLOps, Runtime & Infrastructure,
Governance & Compliance - each at L1 (baseline) / L2 (defense-grade), mapped to MITRE ATLAS, NIST AI
RMF and OWASP, with a companion MLASTG test case (MLASTG-TEST-*).

This loads the MLASVS controls into:

  XORCISM.CONTROL  -> VOCABULARY "MLASVS (MLASTG)"
                      one CONTROL per requirement; CIS = the control id (e.g. "DATA-001"),
                      Statement = the requirement, ControlDescription = category + level + ATLAS +
                      test reference.

Data: a committed snapshot at importers/data/mlasvs.json (parsed from the repo's docs/MLASVS/*.md).
Pass `--repo <path>` to re-parse a freshly cloned MLASTG checkout and refresh the snapshot. MIT.
Idempotent (delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_mlasvs.py
    python xorcism_python/importers/import_mlasvs.py --repo /path/to/MLASTG
"""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

VOCAB = "MLASVS (MLASTG)"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mlasvs.json")
SOURCE = "https://github.com/bb1nfosec/MLASTG"
CATMAP = {"DATA": "MLASVS-DATA: Data Security & Privacy", "MODEL": "MLASVS-MODEL: Model Security",
          "LLM": "MLASVS-LLM: LLM Security", "SUPPLY": "MLASVS-SUPPLY: Supply Chain Security",
          "PIPELINE": "MLASVS-PIPELINE: Pipeline & MLOps", "INFRA": "MLASVS-INFRA: Runtime & Infrastructure",
          "GOV": "MLASVS-GOV: Governance & Compliance"}


def _db(n: str) -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{n}.db")


def _cols(cur: sqlite3.Cursor, t: str) -> set:
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{t}")').fetchall()}


def _ins(cur: sqlite3.Cursor, t: str, rec: dict, present: set) -> None:
    keys = [k for k in rec if k in present]
    cur.execute(f"INSERT INTO {t} ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])


def _ensure_vocab(cur: sqlite3.Cursor, name: str, ref: str, desc: str) -> int:
    cols = _cols(cur, "VOCABULARY")
    nc = "VocabularyName" if "VocabularyName" in cols else "Name"
    now = datetime.now(timezone.utc).isoformat()
    row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {nc}=?", (name,)).fetchone()
    if row:
        vid = int(row[0])
        for col, val in (("VocabularyReference", ref), ("VocabularyDescription", desc)):
            if val and col in cols:
                cur.execute(f"UPDATE VOCABULARY SET {col}=? WHERE VocabularyID=?", (val, vid))
        return vid
    vid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    _ins(cur, "VOCABULARY", {"VocabularyID": vid, "VocabularyGUID": str(uuid.uuid4()), "CreatedDate": now,
                             nc: name, "VocabularyReference": ref, "VocabularyDescription": desc}, cols)
    return vid


def _parse_repo(repo: str) -> dict:
    head = re.compile(r"^###\s+([A-Z]+-\d+):\s*(.+?)\s*\((L[12])\)\s*$")
    field = re.compile(r"^\*\*([A-Za-z ]+):\*\*\s*(.*)$")
    clean = lambda s: re.sub(r"\s+", " ", (s or "")).strip()
    controls, seen = [], set()
    for f in sorted(glob.glob(os.path.join(repo, "docs", "MLASVS", "V*", "*.md"))):
        lines = open(f, encoding="utf-8").read().split("\n")
        category = ""
        for i, ln in enumerate(lines):
            if ln.strip() == "## Category":
                for j in range(i + 1, min(i + 4, len(lines))):
                    if lines[j].strip():
                        category = clean(lines[j]); break
                break
        i = 0
        while i < len(lines):
            m = head.match(lines[i].strip())
            if not m:
                i += 1; continue
            cid, title, level = m.group(1), clean(m.group(2)), m.group(3)
            block, j = [], i + 1
            while j < len(lines) and not lines[j].startswith("### ") and lines[j].strip() != "---":
                block.append(lines[j]); j += 1
            fld = {}
            for b in block:
                fm = field.match(b.strip())
                if fm:
                    fld[fm.group(1).strip()] = clean(fm.group(2))
            if cid not in seen:
                seen.add(cid)
                controls.append({"id": cid, "title": title, "level": level,
                                 "category": category or CATMAP.get(cid.split("-")[0], "MLASVS"),
                                 "description": fld.get("Description", ""), "atlas": fld.get("MITRE ATLAS", ""),
                                 "nist": fld.get("NIST AI RMF", ""), "testRef": fld.get("Test Reference", ""),
                                 "remediation": fld.get("Remediation", "")})
            i = j
    return {"meta": {"title": "MLASVS - ML Security Application Verification Standard (MLASTG)",
                     "publisher": "bb1nfosec / MLASTG", "source": SOURCE, "controls": len(controls)},
            "controls": controls}


def main() -> int:
    if "--repo" in sys.argv:
        data = _parse_repo(sys.argv[sys.argv.index("--repo") + 1])
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        json.dump(data, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"[mlasvs] re-parsed: {data['meta']['controls']} controls -> {DATA}")
    data = json.load(open(DATA, encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, SOURCE,
                        "MLASVS (from MLASTG, bb1nfosec) - ML/AI security verification standard, the OWASP-MASVS analogue: L1/L2 controls across Data, Model, LLM, Supply Chain, Pipeline, Infrastructure and Governance, mapped to MITRE ATLAS / NIST AI RMF / OWASP.")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    n = 0
    for c in data["controls"]:
        parts = [c.get("category", "").split(":")[0] or "MLASVS", c["level"]]
        if c.get("atlas"):
            parts.append("ATLAS: " + c["atlas"])
        if c.get("testRef"):
            parts.append("Test: " + c["testRef"])
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{c['id']}: {c['title']}"[:300],
            "ControlDescription": ("MLASVS (MLASTG) / " + " - ".join(parts))[:600],
            "VocabularyID": vid, "CIS": c["id"], "Statement": (c.get("description") or c["title"])[:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[mlasvs] VocabularyID={vid}: {n} MLASVS controls imported under '{VOCAB}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
