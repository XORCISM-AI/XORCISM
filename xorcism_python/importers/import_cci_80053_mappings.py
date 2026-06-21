"""
import_cci_80053_mappings.py - Imports the authoritative DISA Control Correlation Identifier (CCI)
<-> NIST SP 800-53 Rev 5 mappings into XORCISM.CONTROLMAPPING.

A CCI is the granular, assessable statement DISA/DoD RMF uses to tie STIG checks and assessment
objectives back to 800-53 controls. The official list maps each CCI to NIST 800-53 references; we keep
the Revision 5 ones.

Source: DISA "U_CCI_List" (public, public-domain US government work):
  https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip  (contains U_CCI_List.xml)
Cached extracted to resources/U_CCI_List.xml.

Mapping: CONTROLMAPPING(Framework='DISA CCI', ControlID = the 800-53 control, ExternalID = CCI-xxxxxx,
ExternalName = the CCI definition, Relationship='assessed-by'). Idempotent: clears Framework='DISA CCI'
then re-inserts. Matches on CONTROL.NIST (VocabularyID=7); CCI index "AC-2 (1)" -> "AC-2(1)".

Usage:
    python import_cci_80053_mappings.py [--file U_CCI_List.xml] [--no-download]
"""

import argparse
import io
import os
import re
import sys
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone

from sqlalchemy import text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportCCI80053"
VOCAB_ID = 7
FRAMEWORK = "DISA CCI"
URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip"
RES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "resources")
CCI_XML = os.path.join(RES_DIR, "U_CCI_List.xml")
ITEM_RE = re.compile(r'<cci_item id="(CCI-\d+)">(.*?)</cci_item>', re.S)
DEF_RE = re.compile(r"<definition>(.*?)</definition>", re.S)
REF5_RE = re.compile(r'<reference [^>]*version="5"[^>]*index="([^"]+)"')


def norm_ctrl(idx: str) -> str:
    """ 'AC-1 a' -> 'AC-1'; 'AC-2 (1)' / 'AC-2 (1)(a)' -> 'AC-2(1)'. """
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\s*\((\d+)\))?", idx.strip())
    if not m:
        return ""
    return f"{m.group(1)}-{int(m.group(2))}({int(m.group(3))})" if m.group(3) else f"{m.group(1)}-{int(m.group(2))}"


def ensure_cci_xml(src_file: str, download: bool) -> str:
    if src_file:
        if not os.path.exists(src_file):
            raise SystemExit(f"CCI list not found: {src_file}")
        return src_file
    if os.path.exists(CCI_XML):
        return CCI_XML
    if not download:
        raise SystemExit(f"Missing {CCI_XML} (run without --no-download to fetch it)")
    os.makedirs(RES_DIR, exist_ok=True)
    log(MODULE, f"Downloading {URL}")
    req = urllib.request.Request(URL, headers={"User-Agent": "XORCISM-importer"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (fixed DISA URL)
        blob = resp.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        name = next(n for n in z.namelist() if n.lower().endswith("u_cci_list.xml"))
        with open(CCI_XML, "wb") as fh:
            fh.write(z.read(name))
    return CCI_XML


def parse_cci(xml_path: str):
    """ -> list of (cci_id, definition, set(control_refs)) for CCIs that reference an 800-53 Rev 5 control. """
    with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
        xml = fh.read()
    out = []
    for m in ITEM_RE.finditer(xml):
        cid, body = m.group(1), m.group(2)
        refs = {norm_ctrl(i) for i in REF5_RE.findall(body)}
        refs.discard("")
        if not refs:
            continue
        d = DEF_RE.search(body)
        definition = re.sub(r"\s+", " ", (d.group(1) if d else "")).strip()
        out.append((cid, definition, refs))
    return out


def run(src_file: str, download: bool) -> None:
    path = ensure_cci_xml(src_file, download)
    items = parse_cci(path)
    log(MODULE, f"{len(items)} CCIs reference an 800-53 Rev 5 control")

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    with session_scope("XORCISM") as session:
        session.execute(text(
            'CREATE TABLE IF NOT EXISTS "CONTROLMAPPING" ('
            '"MappingID" INTEGER PRIMARY KEY, "MappingGUID" TEXT, "ControlID" INTEGER, "Framework" TEXT, '
            '"ExternalID" TEXT, "ExternalName" TEXT, "Relationship" TEXT, "Source" TEXT, "CreatedDate" TEXT)'
        ))
        ctrl = {r[0]: r[1] for r in session.execute(
            text('SELECT "NIST","ControlID" FROM "CONTROL" WHERE "VocabularyID" = :v AND "NIST" IS NOT NULL'),
            {"v": VOCAB_ID}).fetchall()}
        session.execute(text('DELETE FROM "CONTROLMAPPING" WHERE "Framework" = :f'), {"f": FRAMEWORK})
        nxt = (session.execute(text('SELECT COALESCE(MAX("MappingID"),0) FROM "CONTROLMAPPING"')).scalar() or 0) + 1

        inserted = unmatched = 0
        unmatched_refs = set()
        ctrl_hit = set()
        for cid, definition, refs in items:
            for ref in refs:
                c = ctrl.get(ref)
                if c is None:
                    unmatched += 1
                    unmatched_refs.add(ref)
                    continue
                ctrl_hit.add(c)
                session.execute(
                    text('INSERT INTO "CONTROLMAPPING" ("MappingID","MappingGUID","ControlID","Framework",'
                         '"ExternalID","ExternalName","Relationship","Source","CreatedDate") '
                         'VALUES (:id,:guid,:cid,:fw,:eid,:enm,:rel,:src,:cd)'),
                    {"id": nxt, "guid": str(uuid.uuid4()), "cid": c, "fw": FRAMEWORK, "eid": cid,
                     "enm": (definition or "")[:300], "rel": "assessed-by", "src": "DISA U_CCI_List", "cd": now},
                )
                nxt += 1
                inserted += 1
        session.commit()

    log(MODULE, f"Done. Inserted {inserted} DISA CCI mappings "
                f"({len(ctrl_hit)} controls, {len(items)} CCIs); "
                f"{unmatched} references to controls not in the catalogue.")
    if unmatched_refs:
        log(MODULE, "Unmatched refs sample: " + ", ".join(sorted(unmatched_refs)[:10]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Import DISA CCI<->NIST 800-53 Rev5 mappings into XORCISM.CONTROLMAPPING")
    ap.add_argument("--file", default="", help="Use a local U_CCI_List.xml instead of downloading")
    ap.add_argument("--no-download", action="store_true", help="Do not fetch the CCI list from DISA")
    args = ap.parse_args()
    run(args.file, download=not args.no_download)


if __name__ == "__main__":
    main()
