"""
import_cis_80053_mappings.py - Imports CIS Controls v8.1 <-> NIST SP 800-53 Rev 5 mappings into
XORCISM.CONTROLMAPPING, composed through the DISA CCI as the bridge:
    CIS safeguard --(CIS->CCI)--> CCI --(DISA CCI->800-53 Rev5)--> 800-53 control

This is more control-specific than the CSF-bridged CIS crosswalk and REPLACES it. Provenance, honestly:
  - CCI -> 800-53 Rev 5 : DISA U_CCI_List (authoritative) -- see import_cci_80053_mappings.py
  - CIS v8.1 -> CCI      : github.com/mitre/cis-cci-mappings (community-maintained, confidence-scored)
So the 800-53 half is authoritative; the CIS->CCI half is community data. Relationship='via CCI',
Source notes both. Idempotent: clears Framework='CIS v8' (incl. any earlier CSF-bridged rows) then inserts.

Usage:
    python import_cis_80053_mappings.py [--cis-file file.json] [--no-download]
"""

import argparse
import json
import os
import sys
import urllib.request
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.dirname(__file__))  # to import the sibling CCI module
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log
import import_cci_80053_mappings as cci  # reuse the CCI download/parse

MODULE = "ImportCIS80053"
VOCAB_ID = 7
FRAMEWORK = "CIS v8"
CIS_URL = "https://raw.githubusercontent.com/mitre/cis-cci-mappings/main/mappings/cis-cci-mapping-v8.1.json"
RES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "resources")
CIS_JSON = os.path.join(RES_DIR, "cis-cci-mapping-v8.1.json")


def _ensure_cis(src_file: str, download: bool) -> str:
    if src_file:
        if not os.path.exists(src_file):
            raise SystemExit(f"CIS mapping not found: {src_file}")
        return src_file
    if os.path.exists(CIS_JSON):
        return CIS_JSON
    if not download:
        raise SystemExit(f"Missing {CIS_JSON} (run without --no-download to fetch it)")
    os.makedirs(RES_DIR, exist_ok=True)
    log(MODULE, f"Downloading {CIS_URL}")
    req = urllib.request.Request(CIS_URL, headers={"User-Agent": "XORCISM-importer"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed GitHub raw URL)
        data = resp.read()
    with open(CIS_JSON, "wb") as fh:
        fh.write(data)
    return CIS_JSON


def run(cis_file: str, download: bool) -> None:
    # CCI -> {800-53 refs} (authoritative DISA half)
    cci_xml = cci.ensure_cci_xml("", download)
    cci2ctrl = {cid: refs for cid, _def, refs in cci.parse_cci(cci_xml)}
    log(MODULE, f"{len(cci2ctrl)} CCIs carry an 800-53 Rev 5 control")

    # CIS safeguard -> {CCIs} (community half)
    with open(_ensure_cis(cis_file, download), "r", encoding="utf-8") as fh:
        cisdoc = json.load(fh)
    rows = cisdoc.get("mappings", [])
    log(MODULE, f"{len(rows)} CIS v8.1 safeguards")

    # compose CIS -> 800-53 ref
    pairs = []  # (cis_id, cis_title, control_ref)
    for m in rows:
        cis_id = m.get("cis_id")
        title = m.get("cis_title") or ""
        ccis = set()
        if m.get("primary_cci"):
            ccis.add(m["primary_cci"].get("cci"))
        for s in m.get("supporting_ccis", []) or []:
            ccis.add(s.get("cci"))
        refs = set()
        for c in ccis:
            refs |= cci2ctrl.get(c, set())
        for ref in refs:
            pairs.append((cis_id, title, ref))

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

        seen = set()
        inserted = unmatched = 0
        for cis_id, title, ref in pairs:
            c = ctrl.get(ref)
            if c is None:
                unmatched += 1
                continue
            key = (c, cis_id)
            if key in seen:
                continue
            seen.add(key)
            session.execute(
                text('INSERT INTO "CONTROLMAPPING" ("MappingID","MappingGUID","ControlID","Framework",'
                     '"ExternalID","ExternalName","Relationship","Source","CreatedDate") '
                     'VALUES (:id,:guid,:cid,:fw,:eid,:enm,:rel,:src,:cd)'),
                {"id": nxt, "guid": str(uuid.uuid4()), "cid": c, "fw": FRAMEWORK, "eid": cis_id,
                 "enm": (title or "")[:300], "rel": "via CCI",
                 "src": "mitre cis-cci-mappings v8.1 + DISA CCI->800-53", "cd": now},
            )
            nxt += 1
            inserted += 1
        session.commit()

    log(MODULE, f"Done. Inserted {inserted} CIS v8 mappings "
                f"({len({k[0] for k in seen})} controls, {len({k[1] for k in seen})} safeguards) "
                f"[replaced any CSF-bridged CIS rows].")


def main() -> None:
    ap = argparse.ArgumentParser(description="Import CIS v8.1<->NIST 800-53 Rev5 (composed via DISA CCI) into XORCISM.CONTROLMAPPING")
    ap.add_argument("--cis-file", default="", help="Use a local CIS->CCI JSON instead of downloading")
    ap.add_argument("--no-download", action="store_true", help="Do not fetch sources")
    args = ap.parse_args()
    run(args.cis_file, download=not args.no_download)


if __name__ == "__main__":
    main()
