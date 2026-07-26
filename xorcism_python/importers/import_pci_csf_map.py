"""import_pci_csf_map.py — import the PCI DSS v4.0.1 ↔ NIST CSF 2.0 crosswalk into XORCISM.

Source: "Mapping PCI DSS v4.0.1 to the NIST Cybersecurity Framework (CSF) 2.0", produced by the
PCI SSC Board of Advisors (BoA), July 2026. The document maps each of the 106 NIST CSF 2.0
Subcategory outcomes to the PCI DSS v4.0.1 requirements that support it (many-to-many).

What this importer does (all raw SQL, idempotent by ControlGUID prefix + CONTROLMAPPING.Source):

  1. Populates the NIST CSF 2.0 CONTROL vocabulary with the 106 Subcategories as CONTROL rows
     (the PDF gives their full outcome text; the vocab was otherwise empty). Each control is
     ControlName="GV.OC-01 <outcome>", ControlDescription="<FUNCTION> › <Category>",
     Statement=<outcome>, ControlGUID="csf2-GV.OC-01".

  2. Forward crosswalk (CSF → PCI): for every Subcategory, one CONTROLMAPPING row per mapped PCI
     requirement (Framework="PCI DSS v4.0.1", ExternalID="12.1.1", ExternalName=<official PCI
     title if that requirement already exists as a control, else "PCI DSS Requirement 12.1.1">).

  3. Reverse crosswalk (PCI → CSF): so the mapping is navigable from the PCI DSS side too, every
     EXISTING PCI DSS control (VocabularyID of the "PCI DSS" vocab) whose requirement number
     appears in the mapping gets CONTROLMAPPING rows to the NIST CSF 2.0 Subcategories it supports
     (Framework="NIST CSF 2.0", ExternalID="GV.OC-01", ExternalName=<outcome>).

The mapping data is baked in data/pci_csf_map.json (mined from the PDF). Pass --pdf <file> to
re-mine straight from the source PDF instead (requires pdfplumber).

    python xorcism_python/importers/import_pci_csf_map.py [--pdf "PCI DSS-NIST CSF mapping.pdf"]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone

CSF_VOCAB = "NIST CSF 2.0"
PCI_FW = "PCI DSS v4.0.1"
CSF_FW = "NIST CSF 2.0"
SRC = "PCI-DSS-NIST-CSF-Map 2026"          # CONTROLMAPPING.Source — idempotency key for the crosswalk
GUID_PREFIX = "csf2-"                       # marks the CONTROL rows this importer owns
REL = "mapped-to"

_DATA = os.path.join(os.path.dirname(__file__), "data", "pci_csf_map.json")
# Leading requirement id in a PCI DSS control name, e.g. "1.2.1 …", "12.10.1 …", "A1.1 …".
_LEAD_REQ = re.compile(r"^([A-Z]?\d+(?:\.\d+){0,4})\b")


# ── PDF mining (optional, --pdf) ────────────────────────────────────────────────
def _from_pdf(path: str) -> dict:
    """Re-mine the crosswalk from the PCI SSC BoA PDF. Returns the same shape as the baked JSON."""
    import pdfplumber  # type: ignore

    def clean(s):
        return re.sub(r"\s+", " ", (s or "").replace("\n", " ")).strip()

    re_func = re.compile(r"^([A-Z][A-Za-z]+)\s+\(([A-Z]{2})\):\s*(.*)$")
    re_cat = re.compile(r"^(.*?)\(([A-Z]{2}\.[A-Z]{2})\):\s*(.*)$")
    re_sub = re.compile(r"^([A-Z]{2}\.[A-Z]{2}-\d{2}):\s*(.*)$")
    re_reqtok = re.compile(r"^[A-Z]?\d+(?:\.\d+){0,4}$")

    def parse_reqs(cell):
        c = clean(cell)
        out = []
        for t in re.split(r"[,\s]+", c):
            t = t.strip().rstrip(".").strip()
            if t and re_reqtok.match(t):
                out.append(t)
        return out

    pdf = pdfplumber.open(path)
    cur_func = cur_cat = None
    recs, seen = [], set()
    funcs, cats = {}, {}
    for pi in range(len(pdf.pages)):
        for t in pdf.pages[pi].extract_tables() or []:
            for row in t:
                cells = [clean(c) for c in row]
                if not any(cells):
                    continue
                if any(c.startswith("NIST CSF 2.0") or c.startswith("PCI DSS v4.0.1 Requirement") for c in cells):
                    continue
                for c in cells:
                    m = re_func.match(c)
                    if m:
                        cur_func = (m.group(2), m.group(1).upper() + " (" + m.group(2) + ")")
                        funcs[cur_func[0]] = cur_func[1]
                        break
                for c in cells:
                    m = re_cat.match(c)
                    if m and "." in m.group(2):
                        cur_cat = (m.group(2), clean(m.group(1)))
                        cats[cur_cat[0]] = cur_cat[1]
                        break
                sub = None
                for c in cells:
                    m = re_sub.match(c)
                    if m:
                        sub = (m.group(1), clean(m.group(2)))
                        break
                if not sub:
                    continue
                reqs = parse_reqs(cells[7]) if len(cells) > 7 else []
                if not reqs:
                    for c in cells:
                        if re_sub.match(c):
                            continue
                        r = parse_reqs(c)
                        if r:
                            reqs = r
                            break
                if sub[0] in seen:
                    for rec in recs:
                        if rec["subcategory"] == sub[0]:
                            for rq in reqs:
                                if rq not in rec["pci_reqs"]:
                                    rec["pci_reqs"].append(rq)
                            break
                    continue
                seen.add(sub[0])
                recs.append({
                    "function": cur_func[0] if cur_func else "",
                    "function_name": cur_func[1] if cur_func else "",
                    "category": cur_cat[0] if cur_cat else "",
                    "category_name": cats.get(cur_cat[0], "") if cur_cat else "",
                    "subcategory": sub[0], "subcategory_desc": sub[1], "pci_reqs": reqs,
                })
    return {"source": "mined from " + os.path.basename(path), "pci_version": "4.0.1",
            "csf_version": "2.0", "functions": funcs, "categories": cats, "subcategories": recs}


# ── DB helpers ──────────────────────────────────────────────────────────────────
def _db_path(db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XORCISM.db")


def _vocab_namecol(cur):
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    return "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)


def _find_csf_vocab(cur, namecol):
    """Reuse an existing NIST CSF vocabulary (rename the empty generic one to 'NIST CSF 2.0'),
    else create it. Returns the VocabularyID."""
    rows = cur.execute(f"SELECT VocabularyID,{namecol} FROM VOCABULARY").fetchall()
    exact = [r for r in rows if (r[1] or "").strip().lower() == CSF_VOCAB.lower()]
    if exact:
        return int(exact[0][0])
    csfish = [r for r in rows if "csf" in (r[1] or "").lower()
              or "cyber security framework" in (r[1] or "").lower()
              or "cybersecurity framework" in (r[1] or "").lower()]
    for vid, nm in csfish:
        n = cur.execute("SELECT COUNT(*) FROM CONTROL WHERE VocabularyID=?", (vid,)).fetchone()[0]
        if n == 0:                                    # empty → safe to reuse + align its name to CSF 2.0
            cur.execute(f"UPDATE VOCABULARY SET {namecol}=? WHERE VocabularyID=?", (CSF_VOCAB, vid))
            return int(vid)
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    rec = {"VocabularyID": nid, namecol: CSF_VOCAB}
    if "VocabularyGUID" in cols:
        rec["VocabularyGUID"] = str(uuid.uuid4())
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})",
                [rec[k] for k in keys])
    return nid


def _find_pci_vocab(cur, namecol):
    rows = cur.execute(f"SELECT VocabularyID,{namecol} FROM VOCABULARY WHERE {namecol} LIKE 'PCI DSS%'").fetchall()
    return int(rows[0][0]) if rows else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Import the PCI DSS v4.0.1 ↔ NIST CSF 2.0 crosswalk")
    ap.add_argument("--pdf", help="re-mine the crosswalk from the source PDF (needs pdfplumber)")
    ap.add_argument("--data", default=_DATA, help="baked mapping JSON (default: data/pci_csf_map.json)")
    ap.add_argument("--db-dir", help="directory holding XORCISM.db (default: $XORCISM_DB_DIR)")
    a = ap.parse_args()

    doc = _from_pdf(a.pdf) if a.pdf else json.load(open(a.data, encoding="utf-8"))
    recs = doc["subcategories"]
    if not recs:
        print("[pci-csf] no subcategories parsed"); return 1

    con = sqlite3.connect(_db_path(a.db_dir)); con.execute("PRAGMA busy_timeout=30000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()
    namecol = _vocab_namecol(cur)
    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    have_map = bool(cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone())
    if not have_map:
        print("[pci-csf] CONTROLMAPPING table missing"); return 1

    csf_vid = _find_csf_vocab(cur, namecol)
    pci_vid = _find_pci_vocab(cur, namecol)

    # Existing PCI DSS controls, keyed by their leading requirement id → (ControlID, short title).
    pci_ctrls = {}
    if pci_vid is not None:
        for cid, nm in cur.execute("SELECT ControlID,ControlName FROM CONTROL WHERE VocabularyID=?", (pci_vid,)).fetchall():
            m = _LEAD_REQ.match((nm or "").strip())
            if m:
                title = (nm or "").strip()[len(m.group(1)):].strip()
                pci_ctrls[m.group(1)] = (int(cid), title)

    # ── idempotent refresh ──────────────────────────────────────────────────────
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=? AND ControlGUID LIKE ?", (csf_vid, GUID_PREFIX + "%"))
    cur.execute("DELETE FROM CONTROLMAPPING WHERE Source=?", (SRC,))
    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    next_map = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1

    # ── 1) populate the 106 NIST CSF 2.0 subcategory controls ───────────────────
    sub_cid = {}
    for r in recs:
        ctx = " › ".join(x for x in (r.get("function_name"), r.get("category_name")) if x)
        rec = {
            "ControlID": next_cid, "ControlGUID": GUID_PREFIX + r["subcategory"],
            "ControlName": f"{r['subcategory']} {r['subcategory_desc']}".strip()[:400],
            "ControlDescription": ctx or "NIST CSF 2.0",
            "VocabularyID": csf_vid, "Statement": r["subcategory_desc"] or None,
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})",
                    [rec[k] for k in keys])
        sub_cid[r["subcategory"]] = next_cid
        next_cid += 1

    # ── 2) forward crosswalk (CSF subcategory → PCI DSS requirement) ─────────────
    fwd = []
    for r in recs:
        cid = sub_cid[r["subcategory"]]
        for req in r["pci_reqs"]:
            title = pci_ctrls[req][1] if req in pci_ctrls and pci_ctrls[req][1] else f"PCI DSS Requirement {req}"
            fwd.append((next_map, str(uuid.uuid4()), cid, PCI_FW, req, title[:200], REL, SRC, now))
            next_map += 1

    # ── 3) reverse crosswalk (existing PCI DSS control → CSF subcategory) ────────
    rev = []
    for r in recs:
        for req in r["pci_reqs"]:
            hit = pci_ctrls.get(req)
            if not hit:
                continue
            ext_name = f"{r['subcategory']}: {r['subcategory_desc']}"
            rev.append((next_map, str(uuid.uuid4()), hit[0], CSF_FW, r["subcategory"], ext_name[:200], REL, SRC, now))
            next_map += 1

    cur.executemany(
        "INSERT INTO CONTROLMAPPING (MappingID, MappingGUID, ControlID, Framework, ExternalID, "
        "ExternalName, Relationship, Source, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?)", fwd + rev)

    # keep the NIST CSF FRAMEWORK row linked to the vocab we just populated
    try:
        cur.execute("UPDATE FRAMEWORK SET VocabularyID=? WHERE FrameworkName LIKE '%CSF 2.0%' "
                    "AND (VocabularyID IS NULL OR VocabularyID=0)", (csf_vid,))
    except Exception:  # noqa: BLE001
        pass

    con.commit(); con.close()
    src = ("PDF " + os.path.basename(a.pdf)) if a.pdf else "baked JSON"
    matched = sum(1 for r in recs for q in r["pci_reqs"] if q in pci_ctrls)
    print(f"[pci-csf] NIST CSF vocab={csf_vid} ({len(recs)} subcategories) | PCI vocab={pci_vid} "
          f"({len(pci_ctrls)} existing controls matched {matched} refs).")
    print(f"[pci-csf] CONTROLMAPPING: {len(fwd)} forward (CSF->PCI) + {len(rev)} reverse (PCI->CSF) "
          f"= {len(fwd)+len(rev)} rows | Source='{SRC}' ({src}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
