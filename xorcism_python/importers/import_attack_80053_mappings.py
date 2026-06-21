"""
import_attack_80053_mappings.py - Imports the MITRE ATT&CK <-> NIST SP 800-53 Rev 5 control
mappings (which ATT&CK techniques each control mitigates) into XORCISM.CONTROLMAPPING.

Source: Center for Threat-Informed Defense - Mappings Explorer (public, Apache-2.0):
  .../mappings/nist_800_53/attack-<ver>/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-<ver>-enterprise.json
Downloaded into resources/ (unless already present or --file is given). The file lists
"mapping_objects" {capability_id, attack_object_id, attack_object_name, mapping_type, status}.

Mapping: for each *mappable* row we resolve capability_id (e.g. "AC-02") to CONTROL.NIST ("AC-2",
VocabularyID=7) and insert CONTROLMAPPING(Framework='ATT&CK', ExternalID=Txxxx, ExternalName=...,
Relationship=mapping_type). Idempotent: clears Framework='ATT&CK' rows then re-inserts.

Usage:
    python import_attack_80053_mappings.py [--attack-version 16.1] [--file path.json] [--no-download]
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

MODULE = "ImportAttack80053"
VOCAB_ID = 7
FRAMEWORK = "ATT&CK"
DEFAULT_VER = "16.1"
RES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "resources")
URL_TMPL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/"
    "mappings/nist_800_53/attack-{v}/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-{v}-enterprise.json"
)


def norm_ref(cap: str) -> str:
    """ 'AC-02' -> 'AC-2'; 'AC-02.01' -> 'AC-2(1)'. Strips zero-padding to match CONTROL.NIST. """
    cap = str(cap or "").strip().upper()
    fam, _, rest = cap.partition("-")
    if not rest:
        return cap
    try:
        if "." in rest:
            base, enh = rest.split(".", 1)
            return f"{fam}-{int(base)}({int(enh)})"
        return f"{fam}-{int(rest)}"
    except ValueError:
        return cap


def _resolve_file(ver: str, src_file: str, download: bool) -> str:
    if src_file:
        if not os.path.exists(src_file):
            raise SystemExit(f"Mapping file not found: {src_file}")
        return src_file
    fname = f"nist_800_53-rev5_attack-{ver}-enterprise.json"
    dest = os.path.join(RES_DIR, fname)
    if os.path.exists(dest):
        return dest
    if not download:
        raise SystemExit(f"Missing {dest} (run without --no-download to fetch it)")
    os.makedirs(RES_DIR, exist_ok=True)
    url = URL_TMPL.format(v=ver)
    log(MODULE, f"Downloading {url}")
    with urllib.request.urlopen(url, timeout=90) as resp:  # noqa: S310 (fixed CTID URL)
        data = resp.read()
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest


def run(ver: str, src_file: str, download: bool) -> None:
    path = _resolve_file(ver, src_file, download)
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    objs = doc.get("mapping_objects", [])
    log(MODULE, f"{len(objs)} mapping rows in {os.path.basename(path)}")

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    with session_scope("XORCISM") as session:
        # Self-sufficient: create the crosswalk table if the server hasn't booted the migration yet.
        session.execute(text(
            'CREATE TABLE IF NOT EXISTS "CONTROLMAPPING" ('
            '"MappingID" INTEGER PRIMARY KEY, "MappingGUID" TEXT, "ControlID" INTEGER, "Framework" TEXT, '
            '"ExternalID" TEXT, "ExternalName" TEXT, "Relationship" TEXT, "Source" TEXT, "CreatedDate" TEXT)'
        ))
        # ref -> ControlID for the 800-53 catalogue
        ctrl = {
            r[0]: r[1] for r in session.execute(
                text('SELECT "NIST", "ControlID" FROM "CONTROL" WHERE "VocabularyID" = :v AND "NIST" IS NOT NULL'),
                {"v": VOCAB_ID},
            ).fetchall()
        }
        # Clear previous ATT&CK mappings (idempotent).
        session.execute(text('DELETE FROM "CONTROLMAPPING" WHERE "Framework" = :f'), {"f": FRAMEWORK})
        nxt = (session.execute(text('SELECT COALESCE(MAX("MappingID"),0) FROM "CONTROLMAPPING"')).scalar() or 0) + 1

        seen = set()  # (ControlID, ExternalID)
        inserted = unmatched = 0
        unmatched_refs = set()
        for m in objs:
            cap = m.get("capability_id")
            if not cap or m.get("status") == "non_mappable":
                continue
            tech = m.get("attack_object_id")
            if not tech:
                continue
            ref = norm_ref(cap)
            cid = ctrl.get(ref)
            if cid is None:
                unmatched += 1
                unmatched_refs.add(ref)
                continue
            key = (cid, tech)
            if key in seen:
                continue
            seen.add(key)
            session.execute(
                text('INSERT INTO "CONTROLMAPPING" ("MappingID","MappingGUID","ControlID","Framework",'
                     '"ExternalID","ExternalName","Relationship","Source","CreatedDate") '
                     'VALUES (:id,:guid,:cid,:fw,:eid,:enm,:rel,:src,:cd)'),
                {"id": nxt, "guid": str(uuid.uuid4()), "cid": cid, "fw": FRAMEWORK,
                 "eid": tech, "enm": m.get("attack_object_name"), "rel": m.get("mapping_type") or "mitigates",
                 "src": f"CTID mappings-explorer attack-{ver}", "cd": now},
            )
            nxt += 1
            inserted += 1
        session.commit()

    log(MODULE, f"Done. Inserted {inserted} ATT&CK mappings "
                f"({len({k[0] for k in seen})} controls, {len({k[1] for k in seen})} techniques); "
                f"{unmatched} rows had an unmatched control ref.")
    if unmatched_refs:
        log(MODULE, "Unmatched refs sample: " + ", ".join(sorted(unmatched_refs)[:10]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Import ATT&CK<->NIST 800-53 Rev5 mappings into XORCISM.CONTROLMAPPING")
    ap.add_argument("--attack-version", default=DEFAULT_VER, help="ATT&CK version of the mapping (default 16.1)")
    ap.add_argument("--file", default="", help="Use a local mapping JSON instead of downloading")
    ap.add_argument("--no-download", action="store_true", help="Do not fetch the mapping from CTID")
    args = ap.parse_args()
    run(args.attack_version, args.file, download=not args.no_download)


if __name__ == "__main__":
    main()
