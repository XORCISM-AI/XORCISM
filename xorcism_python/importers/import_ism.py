"""import_ism.py - import the ACSC Information Security Manual (ISM) into XORCISM.

The Information Security Manual (Australian Signals Directorate / ACSC) is a cyber security framework
of ~1100 prescriptive security controls organised under "Guidelines for ..." chapters, plus 49
strategic cyber security principles grouped by the NIST-CSF-2.0-aligned functions GOVern / IDEntify /
PROtect / DETect / RESpond / RECover. Each control carries an identifier (ISM-NNNN), a revision, an
applicability across security classifications (NC / OS / P / S / TS) and, where relevant, an
Essential Eight maturity-level mapping (ML1 / ML2 / ML3).

This loads the catalogue into:

  XORCISM.CONTROL  -> VOCABULARY "ACSC ISM"
                      one CONTROL per principle (CIS = GOV-01 ...) and per control (CIS = ISM-NNNN),
                      Statement = the control / principle text, ControlDescription = chapter +
                      applicability + Essential 8 mapping + revision.

Data: a committed snapshot at importers/data/ism_controls.json (parsed from the published PDF). Pass
`--pdf <path>` to re-parse a newer ISM edition (needs `pypdf`) and refresh the snapshot before import.
ISM is published by ASD/ACSC for public use. Idempotent (delete-then-insert by VocabularyID).
DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_ism.py
    python xorcism_python/importers/import_ism.py --pdf "C:/path/Information Security Manual.pdf"
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

VOCAB = "ACSC ISM"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ism_controls.json")


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


def _parse_pdf(pdf: str) -> dict:
    """Re-parse an ISM PDF into the snapshot shape (needs pypdf)."""
    import re
    from pypdf import PdfReader
    chapters = [
        "Guidelines for cyber security roles", "Guidelines for cyber security incidents",
        "Guidelines for procurement and outsourcing", "Guidelines for cyber security documentation",
        "Guidelines for physical security", "Guidelines for personnel security",
        "Guidelines for communications infrastructure", "Guidelines for communications systems",
        "Guidelines for enterprise mobility", "Guidelines for evaluated products",
        "Guidelines for information technology equipment", "Guidelines for media",
        "Guidelines for system hardening", "Guidelines for system management",
        "Guidelines for security assurance", "Guidelines for software development",
        "Guidelines for database systems", "Guidelines for email", "Guidelines for networking",
        "Guidelines for cryptography", "Guidelines for gateways", "Guidelines for data transfers",
    ]
    chapset = set(chapters)
    func = {"GOV": "Govern", "IDE": "Identify", "PRO": "Protect", "DET": "Detect", "RES": "Respond", "REC": "Recover"}
    ctrl_re = re.compile(r"^Control:\s*(ISM-\d+);\s*Revision:\s*(\d+);\s*Updated:\s*([^;]+);\s*Applicable:\s*([^;\n]+?)(?:;\s*Essential 8:\s*(.+))?$")
    prin_re = re.compile(r"^(GOV|IDE|PRO|DET|RES|REC)-(\d+)\s*[^0-9A-Za-z]{1,3}\s*(.+)$")
    foot_re = re.compile(r"^Information security manual\s*\d*\s*$|^\d+\s*$|^\s*$")
    lead = re.compile(r"^[^0-9A-Za-z]+")

    def head(ln: str) -> bool:
        s = ln.strip()
        if not s or len(s) > 90 or s.endswith((".", ":", ";", ",")):
            return s.startswith(("Control:", "Further information"))
        return s[0].isupper() and len(s.split()) <= 10 and not s.endswith(")")

    lines = [ln.rstrip() for p in PdfReader(pdf).pages for ln in (p.extract_text() or "").split("\n")]
    cs = [k for k, l in enumerate(lines) if l.strip() == "Cyber security principles"]
    i, n = (cs[1] if len(cs) > 1 else 0), len(lines)
    chapter, inp, prins, ctrls, seen = "General", False, [], [], set()
    while i < n:
        s = lines[i].strip()
        if s in ("Cyber security principles", "The cyber security principles"):
            inp, chapter, i = True, "Cyber security principles", i + 1; continue
        if s in chapset:
            inp, chapter, i = False, s, i + 1; continue
        if inp:
            m = prin_re.match(lead.sub("", lines[i]).strip())
            if m:
                fn, num, rest = m.groups(); buf = [rest]; j = i + 1
                while j < n:
                    t = lines[j].strip()
                    if not t or foot_re.match(t) or prin_re.match(lead.sub("", lines[j]).strip()) or t in chapset or (t.startswith("The ") and t.endswith("principles are:")):
                        break
                    buf.append(t); j += 1
                full = re.sub(r"\s+", " ", " ".join(buf)).strip(); title, _, desc = full.partition(":")
                pid = f"{fn}-{int(num):02d}"
                if pid not in seen:
                    seen.add(pid); prins.append({"id": pid, "function": func[fn], "title": title.strip(), "text": desc.strip() or title.strip()})
                i = j; continue
        m = ctrl_re.match(s)
        if m:
            cid, rev, upd, appl, e8 = m.groups()
            e8 = (e8 or "").strip(); buf = []; j = i + 1
            while j < n:
                t = lines[j].strip()
                if foot_re.match(t):
                    j += 1; continue
                if t.startswith("Control:") or t in chapset or t.startswith("Further information") or head(t):
                    break
                buf.append(t); j += 1
            ctrls.append({"id": cid, "chapter": chapter, "revision": int(rev), "updated": upd.strip(),
                          "applicable": [x for x in appl.replace(" ", "").split(",") if x],
                          "essential8": ([] if e8.upper() in ("", "N/A") else [x.strip() for x in e8.split(",") if x.strip()]),
                          "text": re.sub(r"\s+", " ", " ".join(buf)).strip()})
            i = j; continue
        i += 1
    return {"meta": {"title": "ACSC Information Security Manual", "publisher": "ASD/ACSC",
                     "source": "https://www.cyber.gov.au/ism", "principles": len(prins), "controls": len(ctrls)},
            "principles": prins, "controls": ctrls}


def main() -> int:
    if "--pdf" in sys.argv:
        pdf = sys.argv[sys.argv.index("--pdf") + 1]
        data = _parse_pdf(pdf)
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        json.dump(data, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"[ism] re-parsed {pdf}: {len(data['principles'])} principles, {len(data['controls'])} controls -> {DATA}")
    data = json.load(open(DATA, encoding="utf-8"))
    edition = data.get("meta", {}).get("edition") or data.get("meta", {}).get("source", "")
    now = datetime.now(timezone.utc).isoformat()
    xo = sqlite3.connect(_db("XORCISM")); xo.execute("PRAGMA busy_timeout=20000"); cur = xo.cursor()
    vid = _ensure_vocab(cur, VOCAB, str(data.get("meta", {}).get("edition", "")),
                        "https://www.cyber.gov.au/ism",
                        "ACSC Information Security Manual (ASD) - ~1100 security controls across 22 guideline chapters + 49 cyber security principles (GOV/IDE/PRO/DET/RES/REC), with security-classification applicability (NC/OS/P/S/TS) and Essential Eight maturity mapping.")
    ccols = _cols(cur, "CONTROL")
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vid,))
    nid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    npr = nc = 0
    for p in data.get("principles", []):
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{p['id']}: {p['title']}"[:300],
            "ControlDescription": f"ACSC ISM cyber security principle / {p['function']}"[:600],
            "VocabularyID": vid, "CIS": p["id"], "Statement": p["text"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1; npr += 1
    for c in data.get("controls", []):
        e8 = ", ".join(c.get("essential8") or []) or "N/A"
        appl = ", ".join(c.get("applicable") or [])
        _ins(cur, "CONTROL", {
            "ControlID": nid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{c['id']}: {c['text'][:90]}"[:300],
            "ControlDescription": f"ACSC ISM / {c['chapter']} - Applicable: {appl} - Essential 8: {e8} - Rev {c['revision']} ({c['updated']})"[:600],
            "VocabularyID": vid, "CIS": c["id"], "Statement": c["text"][:2000],
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }, ccols)
        nid += 1; nc += 1
    xo.commit(); xo.close()
    print(f"[ism] VocabularyID={vid}: {npr} principles + {nc} controls imported under '{VOCAB}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
