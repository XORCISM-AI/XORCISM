"""run.py — XORCISM connector: OpenCTI → XTHREAT.INTELEXCHANGE.

Pulls Reports from an OpenCTI platform (open cyber-threat-intelligence platform built on
STIX 2.1, https://www.opencti.io) and maps each report to a normalized XORCISM intel item.
The runner imports them into XTHREAT.INTELEXCHANGE (idempotent by report reference) and
cross-links the report's MITRE ATT&CK techniques into INTELEXCHANGEATTACK so they count
toward the ATT&CK matrix coverage.

This module performs NO database access (so it also runs on a remote worker): it returns
{"intel": [ ... ], "source": "OpenCTI"}.

Python stdlib only (urllib + json) — the pycti SDK is NOT required.

Live mode (worker environment variables):
    OPENCTI_URL       base URL of the OpenCTI platform, e.g. https://opencti.example.org
    OPENCTI_TOKEN     an API token (Bearer auth)

Offline / air-gapped / test mode:
    params["file"] = path to either a STIX 2.1 bundle (JSON with {"objects": [...]}, e.g.
                     an OpenCTI export) or a saved OpenCTI GraphQL response.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List
from uuid import uuid4

SOURCE = "OpenCTI"
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_GQL = """query Reports($n: Int!) {
  reports(first: $n, orderBy: published, orderMode: desc) {
    edges { node {
      id name description published
      createdBy { ... on Identity { name } }
      objectLabel { value }
      objects { edges { node {
        entity_type
        ... on AttackPattern { x_mitre_id name }
        ... on IntrusionSet { name }
        ... on ThreatActorGroup { name }
        ... on Malware { name }
        ... on Tool { name }
        ... on Vulnerability { name }
      } } }
    } }
  }
}"""


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    max_items = int(params.get("max_items") or 60)
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        payload = _fetch_live(max_items)
    if isinstance(payload, dict) and (payload.get("type") == "bundle" or "objects" in payload):
        intel = _from_stix_bundle(payload, max_items)
    else:
        intel = _from_graphql(payload, max_items)
    return {"intel": intel, "source": SOURCE}


def _fetch_live(n: int) -> Any:
    base = (os.getenv("OPENCTI_URL") or "").rstrip("/")
    token = os.getenv("OPENCTI_TOKEN") or ""
    if not base or not token:
        raise RuntimeError("OpenCTI live mode needs OPENCTI_URL and OPENCTI_TOKEN (or pass a saved file=...).")
    body = json.dumps({"query": _GQL, "variables": {"n": n}}).encode()
    req = urllib.request.Request(
        f"{base}/graphql", data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310 (configured instance)
        return json.loads(r.read().decode("utf-8", "replace"))


def _csv(values) -> str:
    return ", ".join(sorted({str(v).strip() for v in values if str(v or "").strip()}))


def _clean_actor(name: str) -> str:
    return re.sub(r"\s|-", "", name).upper() if name.upper().startswith(("APT", "UTA")) else name


# ── OpenCTI GraphQL response → intel ─────────────────────────────────────────
def _from_graphql(payload: Any, n: int) -> List[Dict[str, Any]]:
    try:
        edges = payload["data"]["reports"]["edges"]
    except (KeyError, TypeError):
        return []
    base = (os.getenv("OPENCTI_URL") or "").rstrip("/")
    out: List[Dict[str, Any]] = []
    for e in edges[:n]:
        node = e.get("node") or {}
        attack, actors, malware, cves = set(), set(), set(), set()
        for oe in ((node.get("objects") or {}).get("edges") or []):
            on = oe.get("node") or {}
            et = (on.get("entity_type") or "").lower()
            nm = on.get("name") or ""
            if on.get("x_mitre_id"):
                attack.add(str(on["x_mitre_id"]).upper())
            elif et in ("intrusion-set", "threat-actor", "threat-actor-group"):
                actors.add(_clean_actor(nm))
            elif et in ("malware", "tool"):
                malware.add(nm)
            elif et == "vulnerability" and _CVE_RE.match(nm):
                cves.add(nm.upper())
        out.append(_item(
            rid=node.get("id"), name=node.get("name"), desc=node.get("description"),
            date=(node.get("published") or "")[:10],
            author=(node.get("createdBy") or {}).get("name"),
            labels=[l.get("value") for l in (node.get("objectLabel") or [])],
            attack=attack, actors=actors, malware=malware, cves=cves,
            ref=(f"{base}/dashboard/analyses/reports/{node.get('id')}" if base and node.get("id") else node.get("id")),
        ))
    return out


# ── STIX 2.1 bundle → intel (resolve object_refs against the bundle) ─────────
def _from_stix_bundle(bundle: Dict[str, Any], n: int) -> List[Dict[str, Any]]:
    objs = bundle.get("objects") or []
    by_id = {o.get("id"): o for o in objs if isinstance(o, dict) and o.get("id")}

    def mitre_id(o: Dict[str, Any]) -> str:
        for ref in o.get("external_references") or []:
            if (ref.get("source_name") or "").lower() in ("mitre-attack", "mitre attack") and ref.get("external_id"):
                return str(ref["external_id"]).upper()
        return ""

    def first_url(o: Dict[str, Any]) -> str:
        for ref in o.get("external_references") or []:
            if ref.get("url"):
                return ref["url"]
        return ""

    out: List[Dict[str, Any]] = []
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "report":
            continue
        attack, actors, malware, cves = set(), set(), set(), set()
        for rid in o.get("object_refs") or []:
            ro = by_id.get(rid)
            if not ro:
                if isinstance(rid, str) and rid.startswith("attack-pattern"):
                    pass
                continue
            rt = ro.get("type")
            nm = ro.get("name") or ""
            if rt == "attack-pattern":
                attack.add(mitre_id(ro) or "")
                attack.discard("")
                for m in _ATTACK_RE.findall(nm):
                    attack.add(m.upper())
            elif rt in ("intrusion-set", "threat-actor"):
                actors.add(_clean_actor(nm))
            elif rt in ("malware", "tool"):
                malware.add(nm)
            elif rt == "vulnerability":
                if _CVE_RE.match(nm):
                    cves.add(nm.upper())
        author = ""
        cb = by_id.get(o.get("created_by_ref"))
        if cb:
            author = cb.get("name") or ""
        out.append(_item(
            rid=o.get("id"), name=o.get("name"), desc=o.get("description"),
            date=(o.get("published") or o.get("created") or "")[:10], author=author,
            labels=o.get("labels") or [], attack=attack, actors=actors, malware=malware, cves=cves,
            ref=first_url(o) or o.get("id"),
        ))
        if len(out) >= n:
            break
    return out


def _item(rid, name, desc, date, author, labels, attack, actors, malware, cves, ref) -> Dict[str, Any]:
    return {
        "name": (name or "OpenCTI report")[:500],
        "description": (desc or "")[:8000],
        "reference": ref or f"opencti:report:{rid or uuid4()}",
        "external_id": rid,
        "author": author or "OpenCTI",
        "date": date or "",
        "attack_tags": _csv(attack),
        "actor_tags": _csv(actors),
        "malware_tags": _csv(malware),
        "cve_tags": _csv(cves),
        "tags": _csv(["OpenCTI"] + list(labels or []))[:1000],
        "views": None,
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="OpenCTI → INTELEXCHANGE import (dry run)")
    ap.add_argument("--file", help="STIX 2.1 bundle JSON or a saved OpenCTI GraphQL response")
    ap.add_argument("--max-items", type=int, default=60)
    a = ap.parse_args()
    res = run({"file": a.file, "max_items": a.max_items}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[opencti] {len(res['intel'])} report(s) from {res['source']}", flush=True)
