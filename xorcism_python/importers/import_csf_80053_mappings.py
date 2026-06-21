"""
import_csf_80053_mappings.py - Imports the NIST CSF 2.0 <-> SP 800-53 Rev 5 mappings (which CSF 2.0
subcategories each 800-53 control informs) into XORCISM.CONTROLMAPPING.

Source: the NIST Cybersecurity & Privacy Reference Tool (CPRT) JSON API (public):
  base https://csrc.nist.gov/extensions/nudp/services/json/nudp/
  - list CSF 2.0 subcategories:  framework/version/CSF_2_0_0/type/subcategory/elements
  - per subcategory graph:        framework/version/CSF_2_0_0/element/{subcat}/graph
Each subcategory carries `externalRelationships`; the items whose shortName is "SP 800-53 Rev 5.x"
(relationIdentifier "olir_focal", elementTypeIdentifier "control") give the mapped 800-53 controls.

Mapping: CONTROLMAPPING(Framework='CSF', ControlID = the 800-53 control, ExternalID = CSF subcategory
id e.g. "PR.AA-01", ExternalName = subcategory text, Relationship='informative-reference'). Idempotent:
clears Framework='CSF' rows then re-inserts. Matches on CONTROL.NIST (VocabularyID=7); CPRT control ids
are zero-padded ("AC-01") and normalised to our notation ("AC-1").

Usage:
    python import_csf_80053_mappings.py [--csf-version CSF_2_0_0]
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportCSF80053"
VOCAB_ID = 7
FRAMEWORK = "CSF"
BASE = "https://csrc.nist.gov/extensions/nudp/services/json/nudp"
SUBCAT_RE = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d+$")          # CSF 2.0 subcategory id, e.g. PR.AA-01
IS_80053 = re.compile(r"SP\s*800-53\s*Rev\s*5", re.I)         # the 800-53 Rev 5 OLIRs


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "XORCISM-importer"})
    with urllib.request.urlopen(req, timeout=45) as resp:  # noqa: S310 (fixed NIST CPRT URL)
        return json.load(resp)


def norm_ctrl(eid: str) -> str:
    """ 'AC-01' -> 'AC-1'; 'AC-02(01)' / 'AC-2.1' -> 'AC-2(1)'. """
    m = re.match(r"^([A-Z]{2})-0*(\d+)(?:[.\(]0*(\d+)\)?)?", str(eid).strip().upper())
    if not m:
        return str(eid).strip().upper()
    fam, base, enh = m.group(1), m.group(2), m.group(3)
    return f"{fam}-{int(base)}({int(enh)})" if enh else f"{fam}-{int(base)}"


def _find_node(o, subcat):
    """Locate the subcategory node (with its externalRelationships) in an element-graph response."""
    if isinstance(o, dict):
        if o.get("elementIdentifier") == subcat and o.get("externalRelationships") is not None:
            return o
        for v in o.values():
            r = _find_node(v, subcat)
            if r:
                return r
    elif isinstance(o, list):
        for v in o:
            r = _find_node(v, subcat)
            if r:
                return r
    return None


def run(csf_version: str) -> None:
    # 1) enumerate CSF subcategories (id -> descriptive text)
    log(MODULE, f"Listing {csf_version} subcategories")
    doc = _get(f"{BASE}/framework/version/{csf_version}/type/subcategory/elements")
    subs: dict[str, str] = {}

    def collect(o):
        if isinstance(o, dict):
            sid = o.get("elementIdentifier")
            if o.get("elementTypeIdentifier") == "subcategory" and sid and SUBCAT_RE.match(sid):
                subs.setdefault(sid, (o.get("title") or o.get("text") or "").strip())
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)

    collect(doc)
    log(MODULE, f"{len(subs)} CSF subcategories; fetching 800-53 references per subcategory")

    # 2) per subcategory, pull its SP 800-53 Rev 5 informative references
    pairs = []  # (control_ref, subcat_id, subcat_text)
    errors = 0
    for i, sid in enumerate(sorted(subs), 1):
        try:
            g = _get(f"{BASE}/framework/version/{csf_version}/element/{sid}/graph")
        except Exception as e:  # noqa: BLE001
            errors += 1
            if errors <= 5:
                log(MODULE, f"  skip {sid}: {e}")
            continue
        node = _find_node(g, sid)
        for rel in (node or {}).get("externalRelationships", []) or []:
            if rel.get("elementTypeIdentifier") == "control" and IS_80053.search(str(rel.get("shortName") or "")):
                ctrl_ref = norm_ctrl(rel.get("elementIdentifier"))
                if ctrl_ref:
                    pairs.append((ctrl_ref, sid, subs[sid]))
        if i % 25 == 0:
            log(MODULE, f"  …{i}/{len(subs)} subcategories")
        time.sleep(0.05)

    # 3) write CONTROLMAPPING
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
        unmatched_refs = set()
        for ctrl_ref, sid, stext in pairs:
            cid = ctrl.get(ctrl_ref)
            if cid is None:
                unmatched += 1
                unmatched_refs.add(ctrl_ref)
                continue
            key = (cid, sid)
            if key in seen:
                continue
            seen.add(key)
            session.execute(
                text('INSERT INTO "CONTROLMAPPING" ("MappingID","MappingGUID","ControlID","Framework",'
                     '"ExternalID","ExternalName","Relationship","Source","CreatedDate") '
                     'VALUES (:id,:guid,:cid,:fw,:eid,:enm,:rel,:src,:cd)'),
                {"id": nxt, "guid": str(uuid.uuid4()), "cid": cid, "fw": FRAMEWORK,
                 "eid": sid, "enm": (stext or "")[:300], "rel": "informative-reference",
                 "src": "NIST CPRT CSF 2.0 OLIR", "cd": now},
            )
            nxt += 1
            inserted += 1
        session.commit()

    log(MODULE, f"Done. Inserted {inserted} CSF mappings "
                f"({len({k[0] for k in seen})} controls, {len({k[1] for k in seen})} subcategories); "
                f"{unmatched} unmatched control refs, {errors} subcategory fetch errors.")
    if unmatched_refs:
        log(MODULE, "Unmatched refs sample: " + ", ".join(sorted(unmatched_refs)[:10]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Import CSF 2.0<->NIST 800-53 Rev5 mappings into XORCISM.CONTROLMAPPING")
    ap.add_argument("--csf-version", default="CSF_2_0_0", help="CPRT CSF framework version id (default CSF_2_0_0)")
    args = ap.parse_args()
    run(args.csf_version)


if __name__ == "__main__":
    main()
