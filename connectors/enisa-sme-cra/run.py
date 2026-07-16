"""run.py — XORCISM connector for ENISA's SME Cyber Resilience Maturity Assessment tool.

Imports a filled-in copy of ENISA's official self-check tool ("CRA_Maturity_Model_TOOL.xlsx", from
enisa.europa.eu/publications/sme-cyber-resilience-maturity-assessment-model) into XORCISM's native
/cra-maturity cockpit. The 25 question scores (5 domains x 5 questions, 1-5) become an
SMEMATURITYASSESSMENT + its SMEMATURITYANSWER rows (runner.import_sme_maturity), where XORCISM
recomputes the domain averages, the overall maturity band and the Annex B improvement roadmap.

Modes (in order):
    file  : params["file"] -> the ENISA xlsx (parsed with a stdlib-only reader), OR a JSON export
            ({"assessments":[...]} / {"scores":{"1.1":3,...}} / [{"ref","score"}]).
    demo  : no file -> the bundled sample.json (ENISA's own worked example, overall 3.0).

No API/secrets: the ENISA tool is an offline spreadsheet. Worker-safe: stdlib only (zipfile +
xml.etree parse the .xlsx — no openpyxl), ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List, Optional

SOURCE = "ENISA SME CRA Maturity"
_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_RNS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_REF_RE = re.compile(r"^(\d)\.(\d)\.?$")            # question refs like "1.1." / "3.5"
_LEAD_INT = re.compile(r"^\s*([1-5])\b")            # a level cell begins with its number


# ── minimal stdlib .xlsx reader (only what we need: one sheet, cells by A1 ref) ──
def _col_letters(a1: str) -> str:
    return "".join(ch for ch in a1 if ch.isalpha())


def _read_xlsx_rows(path: str, sheet_name: str) -> List[Dict[str, str]]:
    """Return the target sheet as a list of {colLetter: text} dicts, one per row (1-based order)."""
    with zipfile.ZipFile(path) as z:
        # shared strings
        shared: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(f"{_NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{_NS}t")))
        # sheet name -> rId -> target path
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rid = None
        for s in wb.find(f"{_NS}sheets") or []:
            if (s.get("name") or "").strip().lower() == sheet_name.lower():
                rid = s.get(f"{_RNS}id")
                break
        if rid is None:
            return []
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        target = None
        for r in rels:
            if r.get("Id") == rid:
                target = r.get("Target")
                break
        if not target:
            return []
        target = target if target.startswith("xl/") else "xl/" + target.lstrip("/")
        sheet = ET.fromstring(z.read(target))
        rows: List[Dict[str, str]] = []
        for row in sheet.iter(f"{_NS}row"):
            cells: Dict[str, str] = {}
            for c in row.findall(f"{_NS}c"):
                ref = c.get("r") or ""
                v = c.find(f"{_NS}v")
                txt = ""
                if c.get("t") == "s" and v is not None:              # shared string
                    try:
                        txt = shared[int(v.text)]
                    except (ValueError, IndexError):
                        txt = ""
                elif c.get("t") == "inlineStr":
                    isv = c.find(f"{_NS}is")
                    txt = "".join(t.text or "" for t in isv.iter(f"{_NS}t")) if isv is not None else ""
                elif v is not None:                                   # number / cached formula value
                    txt = v.text or ""
                if ref:
                    cells[_col_letters(ref)] = (txt or "").strip()
            rows.append(cells)
        return rows


def _answers_from_xlsx(path: str) -> List[Dict[str, Any]]:
    """Extract {ref, score} from the ENISA Questionnaire sheet (col B = ref, col E = score, or the
    level text in col D as a fallback)."""
    rows = _read_xlsx_rows(path, "Questionnaire")
    out: List[Dict[str, Any]] = []
    for cells in rows:
        ref = cells.get("B", "")
        m = _REF_RE.match(ref)
        if not m:
            continue
        canon = f"{m.group(1)}.{m.group(2)}"
        score: Optional[int] = None
        raw = cells.get("E", "")                                     # the Score column (formula value)
        if raw:
            try:
                score = int(round(float(raw)))
            except ValueError:
                score = None
        if score is None:                                            # fallback: leading digit of col D
            dm = _LEAD_INT.match(cells.get("D", ""))
            if dm:
                score = int(dm.group(1))
        if score is not None and 1 <= score <= 5:
            out.append({"ref": canon, "score": score})
    return out


def _answers_from_json(data: Any) -> List[Dict[str, Any]]:
    def norm(ref: str, score: Any) -> Optional[Dict[str, Any]]:
        m = _REF_RE.match(str(ref))
        try:
            s = int(round(float(score)))
        except (TypeError, ValueError):
            return None
        return {"ref": f"{m.group(1)}.{m.group(2)}", "score": s} if m and 1 <= s <= 5 else None

    out: List[Dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("scores"), dict):
        for k, v in data["scores"].items():
            n = norm(k, v)
            if n:
                out.append(n)
    elif isinstance(data, list):
        for x in data:
            if isinstance(x, dict):
                n = norm(x.get("ref"), x.get("score"))
                if n:
                    out.append(n)
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    name = str(params.get("name") or "").strip()

    if str(path).lower().endswith(".xlsx"):
        answers = _answers_from_xlsx(path)
        assessment = {
            "name": name or "ENISA SME CRA maturity self-check (imported)",
            "org": str(params.get("org") or ""), "product_scope": str(params.get("product_scope") or ""),
            "assessor": str(params.get("assessor") or ""), "answers": answers,
        }
        return {"source": SOURCE, "sme_maturity": [assessment]}

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    # a full export ({"assessments":[{name, answers:[...]}]}) passes through; a bare scores map/list is wrapped
    if isinstance(data, dict) and isinstance(data.get("assessments"), list):
        assessments = []
        for a in data["assessments"]:
            if not isinstance(a, dict):
                continue
            ans = a.get("answers") if isinstance(a.get("answers"), list) else _answers_from_json(a.get("scores") or {})
            assessments.append({
                "name": (name or a.get("name") or "ENISA SME CRA maturity self-check"),
                "org": a.get("org", ""), "product_scope": a.get("product_scope", ""),
                "assessor": a.get("assessor", ""),
                "answers": [x for x in (ans or []) if isinstance(x, dict) and "ref" in x and "score" in x],
            })
        return {"source": SOURCE, "sme_maturity": assessments}

    return {"source": SOURCE, "sme_maturity": [{
        "name": name or "ENISA SME CRA maturity self-check",
        "org": "", "product_scope": "", "assessor": "",
        "answers": _answers_from_json(data),
    }]}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    a = r["sme_maturity"][0]
    print(json.dumps({"source": r["source"], "name": a["name"], "answers": len(a["answers"])}))
    print(json.dumps(a["answers"]))
