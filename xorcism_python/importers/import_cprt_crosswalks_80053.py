"""
import_cprt_crosswalks_80053.py - Adds *CSF-bridged* crosswalks from NIST SP 800-53 Rev 5 to other
frameworks (ISO/IEC 27001, CIS Controls v8, PCI DSS, NICE, CCM) into XORCISM.CONTROLMAPPING.

HOW (and the caveat): NIST CSF 2.0 acts as a Rosetta Stone — each CSF subcategory has informative
references to many frameworks at once (incl. SP 800-53). For every CSF subcategory we take its set of
SP 800-53 Rev 5 controls (the bridge) and its set of target-framework items, and co-map them:
"800-53 control X <-> framework item Y" when both inform the same CSF subcategory. These are therefore
INDIRECT (transitive via CSF), unlike the direct ATT&CK / D3FEND / CSF mappings — stored with
Relationship='via CSF' and Source='NIST CPRT (bridged via CSF 2.0)'.

Source: NIST CPRT API (same as import_csf_80053_mappings.py):
  base https://csrc.nist.gov/extensions/nudp/services/json/nudp/
  per subcategory: framework/version/CSF_2_0_0/element/{subcat}/graph -> externalRelationships.

Idempotent: clears the target Framework labels then re-inserts. Matches on CONTROL.NIST (VocabularyID=7).

Usage:
    python import_cprt_crosswalks_80053.py                 # all default frameworks
    python import_cprt_crosswalks_80053.py --frameworks "ISO 27001,CIS v8"
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

MODULE = "ImportCPRTCrosswalks"
VOCAB_ID = 7
BASE = "https://csrc.nist.gov/extensions/nudp/services/json/nudp"
SUBCAT_RE = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d+$")
IS_80053 = re.compile(r"SP\s*800-53\s*Rev\s*5", re.I)
ISO_NOISE = re.compile(r"mandatory clause|^\s*none\s*$|:\s*none", re.I)

# clean framework label -> (shortName matcher, externalId cleaner)
FRAMEWORKS = {
    "ISO 27001": (re.compile(r"ISO/?IEC\s*27001", re.I), lambda x: re.sub(r"^Control\s+", "", x).strip()),
    "CIS v8": (re.compile(r"CIS\s*Controls\s*v8", re.I), lambda x: x.strip()),
    "PCI DSS": (re.compile(r"PCI\s*DSS", re.I), lambda x: x.strip()),
    "NICE": (re.compile(r"NICE\s*Framework", re.I), lambda x: x.strip()),
    "CCM v4": (re.compile(r"CCM", re.I), lambda x: x.strip()),
}
# CCM v4 + PCI DSS are the noisiest transitive bridges (50-90 items/control) and CIS v8 now comes from
# the more specific CCI composition (import_cis_80053_mappings.py) — so the default bridged set is just
# ISO 27001 + NICE. Pass --frameworks to include the others explicitly.
DEFAULT_FRAMEWORKS = ("ISO 27001", "NICE")


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "XORCISM-importer"})
    with urllib.request.urlopen(req, timeout=45) as resp:  # noqa: S310 (fixed NIST CPRT URL)
        return json.load(resp)


def norm_ctrl(eid: str) -> str:
    m = re.match(r"^([A-Z]{2})-0*(\d+)(?:[.\(]0*(\d+)\)?)?", str(eid).strip().upper())
    if not m:
        return str(eid).strip().upper()
    fam, base, enh = m.group(1), m.group(2), m.group(3)
    return f"{fam}-{int(base)}({int(enh)})" if enh else f"{fam}-{int(base)}"


def _find_node(o, subcat):
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


def run(active: dict, csf_version: str) -> None:
    log(MODULE, f"Bridged frameworks: {', '.join(active)}")
    doc = _get(f"{BASE}/framework/version/{csf_version}/type/subcategory/elements")
    subs = set()

    def collect(o):
        if isinstance(o, dict):
            sid = o.get("elementIdentifier")
            if o.get("elementTypeIdentifier") == "subcategory" and sid and SUBCAT_RE.match(sid):
                subs.add(sid)
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)

    collect(doc)
    log(MODULE, f"{len(subs)} CSF subcategories; bridging 800-53 <-> targets")

    # (control_ref, framework_label, ext_id, ext_name)
    pairs = []
    errors = 0
    for i, sid in enumerate(sorted(subs), 1):
        try:
            g = _get(f"{BASE}/framework/version/{csf_version}/element/{sid}/graph")
        except Exception as e:  # noqa: BLE001
            errors += 1
            continue
        rels = (_find_node(g, sid) or {}).get("externalRelationships", []) or []
        # bridge: this subcategory's 800-53 controls
        bridge = {norm_ctrl(r.get("elementIdentifier")) for r in rels
                  if r.get("elementTypeIdentifier") == "control" and IS_80053.search(str(r.get("shortName") or ""))}
        if not bridge:
            continue
        for label, (matcher, clean) in active.items():
            items = {}
            for r in rels:
                sn = str(r.get("shortName") or "")
                if not matcher.search(sn) or IS_80053.search(sn):
                    continue
                eid = clean(str(r.get("elementIdentifier") or ""))
                if not eid or ISO_NOISE.search(eid):
                    continue
                items[eid] = (r.get("text") or r.get("title") or "").strip()
            for ctrl_ref in bridge:
                for eid, name in items.items():
                    pairs.append((ctrl_ref, label, eid, name))
        if i % 30 == 0:
            log(MODULE, f"  …{i}/{len(subs)} subcategories")
        time.sleep(0.05)

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
        for label in active:
            session.execute(text('DELETE FROM "CONTROLMAPPING" WHERE "Framework" = :f'), {"f": label})
        nxt = (session.execute(text('SELECT COALESCE(MAX("MappingID"),0) FROM "CONTROLMAPPING"')).scalar() or 0) + 1

        seen = set()
        per = {}
        inserted = unmatched = 0
        for ctrl_ref, label, eid, name in pairs:
            cid = ctrl.get(ctrl_ref)
            if cid is None:
                unmatched += 1
                continue
            key = (cid, label, eid)
            if key in seen:
                continue
            seen.add(key)
            per[label] = per.get(label, 0) + 1
            session.execute(
                text('INSERT INTO "CONTROLMAPPING" ("MappingID","MappingGUID","ControlID","Framework",'
                     '"ExternalID","ExternalName","Relationship","Source","CreatedDate") '
                     'VALUES (:id,:guid,:cid,:fw,:eid,:enm,:rel,:src,:cd)'),
                {"id": nxt, "guid": str(uuid.uuid4()), "cid": cid, "fw": label, "eid": eid,
                 "enm": (name or "")[:300], "rel": "via CSF", "src": "NIST CPRT (bridged via CSF 2.0)", "cd": now},
            )
            nxt += 1
            inserted += 1
        session.commit()

    summary = " | ".join(f"{k}={v}" for k, v in sorted(per.items()))
    log(MODULE, f"Done. Inserted {inserted} bridged mappings -> {summary} ; {errors} subcategory fetch errors.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Add CSF-bridged 800-53 crosswalks (ISO/CIS/PCI/NICE/CCM) to CONTROLMAPPING")
    ap.add_argument("--frameworks", default="", help="Comma-separated subset of: " + ", ".join(FRAMEWORKS))
    ap.add_argument("--csf-version", default="CSF_2_0_0")
    args = ap.parse_args()
    if args.frameworks.strip():
        want = {f.strip() for f in args.frameworks.split(",")}
        active = {k: v for k, v in FRAMEWORKS.items() if k in want}
        if not active:
            raise SystemExit(f"No known frameworks in {want}; choose from {list(FRAMEWORKS)}")
    else:
        active = {k: v for k, v in FRAMEWORKS.items() if k in DEFAULT_FRAMEWORKS}
    run(active, args.csf_version)


if __name__ == "__main__":
    main()
