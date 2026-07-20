"""run.py — XORCISM connector for the Forensix DFIR mission workbook.

Forensix is a digital-forensics / incident-response mission workbook (Excel): an 85-control,
6-phase investigation-conformity checklist (methodology & legal framework, disk acquisition,
network PCAP, memory & live forensics, correlation & report, logs & SIEM), each control carrying a
status and a normative reference (ISO/IEC 27037, RFC 3227, French CPP, GDPR/RGPD, Code penal, NIS2,
ANSSI, MITRE ATT&CK). XORCISM replicates this natively in the /cert-ops forensic-case checklist;
this connector imports a filled-in Forensix .xlsx into a forensic case.

It reads each phase sheet's control rows in order, maps the French status column
(Conforme / Non conforme / En cours / A verifier) to the XORCISM vocabulary, positions them onto the
bundled English control catalogue (catalogue.json) by phase + order, and emits a `forensic_checklist`
for runner.import_forensic_checklist -> XINCIDENT.FORENSICCASE + FORENSICCHECK.

Modes: file (params["file"] = the Forensix .xlsx, parsed with a stdlib-only reader) or demo (sample).
Worker-safe: stdlib only (zipfile + xml.etree parse the .xlsx, no openpyxl), no secrets.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List

SOURCE = "Forensix"
_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_RNS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
# French status -> XORCISM forensic-check status
_STATUS = {
    "conforme": "compliant", "non conforme": "non-compliant", "non-conforme": "non-compliant",
    "en cours": "in-progress", "a verifier": "to-verify", "à vérifier": "to-verify",
    "a verifier ": "to-verify", "compliant": "compliant", "non-compliant": "non-compliant",
    "in-progress": "in-progress", "to-verify": "to-verify",
}
# workbook phase-sheet name (lowercased, accent-insensitive substring) -> catalogue phase key
_PHASE_SHEETS = [
    ("phase1", "P1"), ("phase 1", "P1"), ("methodolog", "P1"),
    ("phase2", "P2"), ("phase 2", "P2"), ("acquisition", "P2"),
    ("phase3", "P3"), ("phase 3", "P3"), ("reseau", "P3"),
    ("phase4", "P4"), ("phase 4", "P4"), ("memoire", "P4"),
    ("phase5", "P5"), ("phase 5", "P5"), ("rapport", "P5"),
    ("logs", "P6"), ("siem", "P6"),
]


def _deaccent(s: str) -> str:
    return (s.lower().replace("é", "e").replace("è", "e").replace("ê", "e").replace("à", "a")
            .replace("â", "a").replace("î", "i").replace("ô", "o").replace("û", "u").replace("ç", "c"))


def _col(a1: str) -> str:
    return "".join(ch for ch in a1 if ch.isalpha())


def _read_sheet_rows(z: zipfile.ZipFile, shared: List[str], target: str) -> List[Dict[str, str]]:
    sheet = ET.fromstring(z.read(target))
    rows: List[Dict[str, str]] = []
    for row in sheet.iter(f"{_NS}row"):
        cells: Dict[str, str] = {}
        for c in row.findall(f"{_NS}c"):
            ref = c.get("r") or ""
            v = c.find(f"{_NS}v")
            txt = ""
            if c.get("t") == "s" and v is not None:
                try:
                    txt = shared[int(v.text)]
                except (ValueError, IndexError):
                    txt = ""
            elif c.get("t") == "inlineStr":
                isv = c.find(f"{_NS}is")
                txt = "".join(t.text or "" for t in isv.iter(f"{_NS}t")) if isv is not None else ""
            elif v is not None:
                txt = v.text or ""
            if ref:
                cells[_col(ref)] = (txt or "").strip()
        rows.append(cells)
    return rows


def _parse_xlsx(path: str) -> Dict[str, List[Dict[str, str]]]:
    """Return {phaseKey: [row cells...]} for each recognised phase sheet."""
    out: Dict[str, List[Dict[str, str]]] = {}
    with zipfile.ZipFile(path) as z:
        shared: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(f"{_NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{_NS}t")))
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rid_target = {r.get("Id"): r.get("Target") for r in rels}
        for s in wb.find(f"{_NS}sheets") or []:
            name = _deaccent(s.get("name") or "")
            pk = next((k for sub, k in _PHASE_SHEETS if sub in name), None)
            if not pk or pk in out:
                continue
            tgt = rid_target.get(s.get(f"{_RNS}id"))
            if not tgt:
                continue
            tgt = tgt if tgt.startswith("xl/") else "xl/" + tgt.lstrip("/")
            out[pk] = _read_sheet_rows(z, shared, tgt)
    return out


def _catalogue() -> Dict[str, List[Dict[str, Any]]]:
    cat = json.load(open(os.path.join(os.path.dirname(__file__), "catalogue.json"), encoding="utf-8"))
    by_phase: Dict[str, List[Dict[str, Any]]] = {}
    for c in cat["controls"]:
        by_phase.setdefault(c["phase"], []).append(c)
    return by_phase


def _status_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """The control rows of a phase sheet, in order: a row whose column A is a non-header control name.
    The Forensix layout is: col A = control, col C = status, col D = evidence. The header row has
    'Controle' in A; the title row is above it."""
    out: List[Dict[str, str]] = []
    started = False
    for cells in rows:
        a = cells.get("A", "")
        if not started:
            if _deaccent(a).startswith("controle"):
                started = True
            continue
        if not a:
            continue
        out.append({"status": cells.get("C", ""), "evidence": cells.get("D", "")})
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    by_phase = _catalogue()
    case = {"title": str(params.get("name") or "Forensix DFIR mission"),
            "examiner": str(params.get("examiner") or ""), "severity": str(params.get("severity") or "High")}

    path = params.get("file")
    checks: List[Dict[str, Any]] = []
    if path and str(path).lower().endswith(".xlsx"):
        sheets = _parse_xlsx(path)
        for pk, ctrls in by_phase.items():
            rows = _status_rows(sheets.get(pk, []))
            for i, c in enumerate(ctrls):
                st = _STATUS.get(_deaccent(rows[i]["status"]).strip(), "to-verify") if i < len(rows) else "to-verify"
                ev = rows[i]["evidence"] if i < len(rows) else ""
                if _deaccent(ev).startswith("a joindre"):
                    ev = ""
                checks.append({"phase": pk, "ref": c["ref"], "title": c["title"], "norm": c["norm"],
                               "description": c["description"], "status": st, "evidence": ev})
    else:
        # demo / JSON: a saved export {case, checks:[{ref,status,evidence}]} or the bundled sample
        p = path or os.path.join(os.path.dirname(__file__), "sample.json")
        data = json.load(open(p, encoding="utf-8"))
        case.update(data.get("case") or {})
        cat_by_ref = {c["ref"]: c for cl in by_phase.values() for c in cl}
        for ch in (data.get("checks") or []):
            meta = cat_by_ref.get(str(ch.get("ref")))
            if not meta:
                continue
            checks.append({"phase": meta["phase"], "ref": meta["ref"], "title": meta["title"], "norm": meta["norm"],
                           "description": meta["description"], "status": str(ch.get("status") or "to-verify"),
                           "evidence": str(ch.get("evidence") or "")})

    return {"source": SOURCE, "forensic_checklist": {"case": case, "checks": checks}}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    fc = r["forensic_checklist"]
    from collections import Counter
    print(json.dumps({"source": r["source"], "case": fc["case"]["title"], "checks": len(fc["checks"]),
                      "by_status": dict(Counter(c["status"] for c in fc["checks"]))}))
