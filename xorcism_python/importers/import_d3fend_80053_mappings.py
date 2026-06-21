"""
import_d3fend_80053_mappings.py - Imports the MITRE D3FEND <-> NIST SP 800-53 Rev 5 control
mappings (which D3FEND defensive techniques relate to each control) into XORCISM.CONTROLMAPPING.

Source: the MITRE D3FEND ontology (JSON-LD, public):
  https://d3fend.mitre.org/ontologies/d3fend.json
The @graph contains `d3f:NISTControl` individuals (rdfs:label = the control ref, e.g. "AC-2(1)")
that link to D3FEND techniques via d3f:related / d3f:narrower / d3f:broader / d3f:exactly. Each link
target resolves to a D3FEND technique node (d3f:d3fend-id = "D3-XXX", rdfs:label = its name).

Mapping: CONTROLMAPPING(Framework='D3FEND', ControlID = the 800-53 control, ExternalID = D3-XXX,
ExternalName = technique name, Relationship = related|narrower|broader|exactly). Idempotent: clears
Framework='D3FEND' rows then re-inserts. Matches on CONTROL.NIST (VocabularyID=7).

Usage:
    python import_d3fend_80053_mappings.py [--file d3fend.json] [--no-download]
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
from xorcism_python.models.base import session_scope
from xorcism_python.utils import log

MODULE = "ImportD3fend80053"
VOCAB_ID = 7
FRAMEWORK = "D3FEND"
URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
RES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "resources")
REL_PROPS = ("d3f:related", "d3f:narrower", "d3f:broader", "d3f:exactly")


def _resolve(src_file: str, download: bool) -> str:
    if src_file:
        if not os.path.exists(src_file):
            raise SystemExit(f"Ontology not found: {src_file}")
        return src_file
    dest = os.path.join(RES_DIR, "d3fend.json")
    if os.path.exists(dest):
        return dest
    if not download:
        raise SystemExit(f"Missing {dest} (run without --no-download to fetch it)")
    os.makedirs(RES_DIR, exist_ok=True)
    log(MODULE, f"Downloading {URL}")
    with urllib.request.urlopen(URL, timeout=120) as resp:  # noqa: S310 (fixed MITRE URL)
        data = resp.read()
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest


def _ids(v):
    if v is None:
        return []
    if isinstance(v, dict):
        return [v.get("@id")]
    if isinstance(v, list):
        return [x.get("@id") if isinstance(x, dict) else x for x in v]
    return [v]


def run(src_file: str, download: bool) -> None:
    path = _resolve(src_file, download)
    with open(path, "r", encoding="utf-8") as fh:
        graph = json.load(fh).get("@graph", [])
    # technique node @id -> (D3-XXX, name)
    tech = {n["@id"]: (n["d3f:d3fend-id"], n.get("rdfs:label"))
            for n in graph if isinstance(n, dict) and n.get("d3f:d3fend-id") and n.get("@id")}
    ctrl_nodes = [n for n in graph if isinstance(n, dict) and "d3f:NISTControl" in (n.get("@type") or [])]
    log(MODULE, f"{len(tech)} D3FEND techniques, {len(ctrl_nodes)} NIST control nodes")

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
        for n in ctrl_nodes:
            ref = (n.get("rdfs:label") or "").strip()
            cid = ctrl.get(ref)
            if cid is None:
                unmatched += 1
                unmatched_refs.add(ref)
                continue
            for prop in REL_PROPS:
                rel = prop.split(":", 1)[1]
                for tid in _ids(n.get(prop)):
                    if not tid:
                        continue
                    d3id, name = tech.get(tid, (None, None))
                    if not d3id:  # link to a non-technique concept -> use the local @id name
                        d3id = str(tid).split(":")[-1]
                        name = d3id
                    key = (cid, d3id)
                    if key in seen:
                        continue
                    seen.add(key)
                    session.execute(
                        text('INSERT INTO "CONTROLMAPPING" ("MappingID","MappingGUID","ControlID","Framework",'
                             '"ExternalID","ExternalName","Relationship","Source","CreatedDate") '
                             'VALUES (:id,:guid,:cid,:fw,:eid,:enm,:rel,:src,:cd)'),
                        {"id": nxt, "guid": str(uuid.uuid4()), "cid": cid, "fw": FRAMEWORK,
                         "eid": d3id, "enm": name, "rel": rel, "src": "MITRE D3FEND ontology", "cd": now},
                    )
                    nxt += 1
                    inserted += 1
        session.commit()

    log(MODULE, f"Done. Inserted {inserted} D3FEND mappings "
                f"({len({k[0] for k in seen})} controls, {len({k[1] for k in seen})} techniques); "
                f"{unmatched} control nodes had no matching catalogue ref.")
    if unmatched_refs:
        log(MODULE, "Unmatched refs sample: " + ", ".join(sorted(r for r in unmatched_refs if r)[:10]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Import D3FEND<->NIST 800-53 Rev5 mappings into XORCISM.CONTROLMAPPING")
    ap.add_argument("--file", default="", help="Use a local d3fend.json instead of downloading")
    ap.add_argument("--no-download", action="store_true", help="Do not fetch the ontology from MITRE")
    args = ap.parse_args()
    run(args.file, download=not args.no_download)


if __name__ == "__main__":
    main()
