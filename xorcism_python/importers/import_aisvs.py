"""import_aisvs.py - import the OWASP AISVS (AI Security Verification Standard) into XORCISM.

OWASP AISVS (github.com/OWASP/AISVS) is the "Artificial Intelligence Security Verification Standard"
- the AI counterpart of the OWASP ASVS. Version 1.0 (June 2026) defines security verification
requirements for AI/ML applications across twelve chapters (C1 Training Data Integrity, C2 Input
Validation, C3 Model Lifecycle, C4 Infrastructure, C5 Access Control & Identity, C6 Supply Chain,
C7 Model Behavior & Safety, C8 Memory/Embeddings/Vector DB, C9 Orchestration & Agentic Security,
C10 Model Context Protocol (MCP) Security, C11 Adversarial Robustness, C12 Monitoring & Logging),
each requirement graded at Level 1 / 2 / 3.

This loads the AISVS requirements into:

  XORCISM.CONTROL  -> VOCABULARY "OWASP AISVS 1.0"
                      one CONTROL per requirement; CIS = the requirement id (e.g. "2.1.1"),
                      Statement = the "Verify that ..." requirement text, ControlName = id + text,
                      ControlDescription = chapter / sub-category / level.

Data: a committed snapshot at importers/data/aisvs.json (parsed from the repo's 1.0/en/*.md). Pass
`--repo <path>` to re-parse a freshly cloned AISVS checkout and refresh the snapshot. AISVS is open
(OWASP, CC BY-SA). Idempotent (delete-then-insert by VocabularyID). DB dir = XORCISM_DB_DIR or default.

    python xorcism_python/importers/import_aisvs.py
    python xorcism_python/importers/import_aisvs.py --repo /path/to/AISVS
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

VOCAB = "OWASP AISVS 1.0"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "aisvs.json")
SOURCE = "https://github.com/OWASP/AISVS"

CHAP = re.compile(r"^#\s+C(\d+)\b\s*(.*)$")                       # "# C2 Input Validation"
SUBC = re.compile(r"^##\s+C(\d+)\.(\d+)\b\s*(.*)$")              # "## C2.1 Prompt Injection Defenses"
ROW = re.compile(r"^\|\s*\*{0,2}\s*(\d+\.\d+\.\d+)\s*\*{0,2}\s*\|\s*(.+?)\s*\|\s*([123])\s*\|\s*$")


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


def _clean(s: str) -> str:
    s = re.sub(r"\s+", " ", (s or "")).strip()
    s = s.replace("**", "")                       # bold markers
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)  # [text](url) -> text
    return s.strip()


def _chapter_dir(repo: str) -> str:
    for cand in (os.path.join(repo, "1.0", "en"), os.path.join(repo, "en"), repo):
        if glob.glob(os.path.join(cand, "0x10-C*.md")):
            return cand
    hits = glob.glob(os.path.join(repo, "**", "0x10-C*.md"), recursive=True)
    return os.path.dirname(hits[0]) if hits else os.path.join(repo, "1.0", "en")


def _parse_repo(repo: str) -> dict:
    base = _chapter_dir(repo)
    controls, chapters, seen = [], [], set()
    for f in sorted(glob.glob(os.path.join(base, "0x10-C*.md"))):
        lines = open(f, encoding="utf-8").read().split("\n")
        ch_id = ch_title = cat_id = cat_title = ""
        for ln in lines:
            mc = CHAP.match(ln)
            if mc:
                ch_id, ch_title = "C" + mc.group(1), _clean(mc.group(2))
                chapters.append({"id": ch_id, "title": ch_title})
                continue
            ms = SUBC.match(ln)
            if ms:
                cat_id, cat_title = f"C{ms.group(1)}.{ms.group(2)}", _clean(ms.group(3))
                continue
            mr = ROW.match(ln)
            if mr and ch_id:
                rid, desc, lvl = mr.group(1), _clean(mr.group(2)), "L" + mr.group(3)
                if rid in seen or not desc:
                    continue
                seen.add(rid)
                controls.append({"id": rid, "level": lvl, "chapter": ch_id, "chapterTitle": ch_title,
                                 "category": cat_id, "categoryTitle": cat_title, "description": desc})
    return {"meta": {"title": "Artificial Intelligence Security Verification Standard (AISVS)",
                     "version": "1.0", "publisher": "OWASP", "source": SOURCE,
                     "repo": SOURCE, "chapters": chapters, "controls": len(controls)},
            "controls": controls}


def main() -> int:
    if "--repo" in sys.argv:
        data = _parse_repo(sys.argv[sys.argv.index("--repo") + 1])
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        json.dump(data, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        by_lvl = {}
        for c in data["controls"]:
            by_lvl[c["level"]] = by_lvl.get(c["level"], 0) + 1
        print(f"[aisvs] re-parsed: {data['meta']['controls']} requirements "
              f"({', '.join(f'{k}={v}' for k, v in sorted(by_lvl.items()))}) across "
              f"{len(data['meta']['chapters'])} chapters -> {DATA}")
    data = json.load(open(DATA, encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, "1.0", SOURCE,
                        "OWASP AISVS 1.0 (Artificial Intelligence Security Verification Standard) - the AI "
                        "counterpart of the OWASP ASVS: verification requirements for AI/ML applications across "
                        "12 chapters (training-data integrity, input validation, model lifecycle, infrastructure, "
                        "access control, supply chain, model behavior & safety, memory/embeddings/vector DB, "
                        "orchestration & agentic security, MCP security, adversarial robustness, monitoring), each "
                        "graded Level 1/2/3.")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    n = 0
    for c in data["controls"]:
        ctx = f"{c['chapter']} {c['chapterTitle']}"
        if c.get("category"):
            ctx += f" / {c['category']} {c['categoryTitle']}".rstrip()
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{c['id']}: {c['description']}"[:300],
            "ControlDescription": (f"OWASP AISVS 1.0 / {ctx} - Level {c['level'][1:]}")[:600],
            "VocabularyID": vid, "CIS": c["id"], "Statement": c["description"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1; n += 1
    xo.commit(); xo.close()
    print(f"[aisvs] VocabularyID={vid}: {n} AISVS 1.0 requirements imported under '{VOCAB}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
