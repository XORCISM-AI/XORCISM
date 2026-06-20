"""run.py — XORCISM connector: MISP → XTHREAT.INTELEXCHANGE.

Pulls events from a MISP instance (open-source threat-intelligence sharing platform,
https://www.misp-project.org) and maps each event to a normalized XORCISM intel item.
The runner imports them into XTHREAT.INTELEXCHANGE (idempotent by event reference) and
cross-links any MITRE ATT&CK techniques into INTELEXCHANGEATTACK so they contribute to
the ATT&CK matrix coverage.

This module performs NO database access (so it also runs on a remote worker): it returns
{"intel": [ ... ], "source": "MISP"}.

Python stdlib only (urllib + json). PyMISP is NOT required.

Live mode (worker environment variables):
    MISP_URL          base URL of the MISP instance, e.g. https://misp.example.org
    MISP_KEY          the automation/API key (Authorization header)
    MISP_VERIFY_SSL   "0" to skip TLS verification (self-signed MISP) — default verify
    MISP_DAYS         look-back window for published events (default 30)

Offline / air-gapped / test mode:
    params["file"] = path to a saved MISP JSON (a /events/restSearch response, a single
                     /events/view export {"Event": {...}}, or a JSON list of events).
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.request
from typing import Any, Dict, List
from uuid import uuid4

SOURCE = "MISP"
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IOC_TYPES = {  # MISP attribute type → coarse IOC class for the tag summary
    "ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "domain",
    "url": "url", "md5": "hash", "sha1": "hash", "sha256": "hash", "filename|md5": "hash",
    "filename|sha256": "hash", "email-src": "email", "email": "email",
}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    max_items = int(params.get("max_items") or 100)
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        payload = _fetch_live(int(params.get("days") or os.getenv("MISP_DAYS") or 30), max_items)
    events = _events(payload)
    base = (os.getenv("MISP_URL") or "").rstrip("/")
    return {"intel": [_map_event(e, base) for e in events[:max_items] if e], "source": SOURCE}


def _fetch_live(days: int, limit: int) -> Any:
    base = (os.getenv("MISP_URL") or "").rstrip("/")
    key = os.getenv("MISP_KEY") or ""
    if not base or not key:
        raise RuntimeError("MISP live mode needs MISP_URL and MISP_KEY (or pass a saved file=...).")
    body = json.dumps({
        "returnFormat": "json", "published": True, "limit": limit, "page": 1,
        "last": f"{days}d", "enforceWarninglist": False,
    }).encode()
    req = urllib.request.Request(
        f"{base}/events/restSearch", data=body, method="POST",
        headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
    )
    ctx = None
    if (os.getenv("MISP_VERIFY_SSL") or "1") in ("0", "false", "no"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=90, context=ctx) as r:  # noqa: S310 (configured instance)
        return json.loads(r.read().decode("utf-8", "replace"))


def _events(payload: Any) -> List[Dict[str, Any]]:
    """Normalize the various MISP shapes to a list of Event dicts."""
    if isinstance(payload, dict):
        if "response" in payload:        # restSearch: {"response": [{"Event": {...}}, ...]}
            payload = payload["response"]
        elif "Event" in payload:          # single /events/view export
            return [payload["Event"]]
    out: List[Dict[str, Any]] = []
    for it in (payload if isinstance(payload, list) else []):
        if isinstance(it, dict):
            out.append(it.get("Event", it))
    return out


def _csv(values) -> str:
    return ", ".join(sorted({str(v).strip() for v in values if str(v or "").strip()}))


def _clean_actor(name: str) -> str:
    return re.sub(r"\s|-", "", name).upper() if name.upper().startswith(("APT", "UTA")) else name


def _map_event(ev: Dict[str, Any], base: str) -> Dict[str, Any]:
    attrs = list(ev.get("Attribute") or [])
    for obj in ev.get("Object") or []:          # attributes inside object containers too
        attrs += obj.get("Attribute") or []
    tags = [t.get("name", "") for t in (ev.get("Tag") or [])]
    galaxies = ev.get("Galaxy") or []

    attack, actors, malware = set(), set(), set()
    for g in galaxies:
        gtype = (g.get("type") or "").lower()
        for cl in g.get("GalaxyCluster") or []:
            val = cl.get("value") or ""
            meta = cl.get("meta") or {}
            ext = meta.get("external_id") or []
            for x in (ext if isinstance(ext, list) else [ext]):
                if _ATTACK_RE.fullmatch(str(x or "")):
                    attack.add(str(x).upper())
            for m in _ATTACK_RE.findall(val):
                attack.add(m.upper())
            if "threat-actor" in gtype or "intrusion-set" in gtype:
                actors.add(_clean_actor(val.split(" - ")[0]))
            elif gtype in ("malware", "tool", "ransomware") or "malware" in gtype:
                malware.add(val.split(" - ")[0])
    blob = f"{ev.get('info','')} " + " ".join(tags)
    for m in _ATTACK_RE.findall(" ".join(tags)):
        attack.add(m.upper())
    cves = {m.upper() for m in _CVE_RE.findall(blob)}

    ioc_count: Dict[str, int] = {}
    for a in attrs:
        t = (a.get("type") or "").lower()
        if t == "vulnerability" and _CVE_RE.match(str(a.get("value", ""))):
            cves.add(str(a["value"]).upper())
        cls = _IOC_TYPES.get(t)
        if cls:
            ioc_count[cls] = ioc_count.get(cls, 0) + 1

    eid = ev.get("id") or ev.get("uuid")
    ref = f"{base}/events/view/{eid}" if base and eid else f"misp:event:{ev.get('uuid') or uuid4()}"
    org = (ev.get("Orgc") or {}).get("name") or ev.get("org_id") or "MISP"
    level = {"1": "high", "2": "medium", "3": "low", "4": "undefined"}.get(str(ev.get("threat_level_id", "")), "")
    ioc_summary = ", ".join(f"{v} {k}" for k, v in ioc_count.items())
    clean_tags = [re.sub(r'^(tlp:|type:)', '', t).strip('"') for t in tags
                  if t and not t.startswith("misp-galaxy:")]
    desc = f"MISP event #{eid}: {ev.get('info','')}." \
        + (f" Threat level: {level}." if level else "") \
        + (f" Indicators: {ioc_summary}." if ioc_summary else "") \
        + f" {len(attrs)} attribute(s)."

    return {
        "name": (ev.get("info") or f"MISP event {eid}")[:500],
        "description": desc[:8000],
        "reference": ref,
        "external_id": ev.get("uuid"),
        "author": org,
        "date": (ev.get("date") or "")[:10],
        "attack_tags": _csv(attack),
        "actor_tags": _csv(actors),
        "malware_tags": _csv(malware),
        "cve_tags": _csv(cves),
        "tags": _csv(["MISP"] + clean_tags)[:1000],
        "views": None,
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="MISP → INTELEXCHANGE import (dry run)")
    ap.add_argument("--file", help="Saved MISP JSON (restSearch response / event export / list)")
    ap.add_argument("--max-items", type=int, default=100)
    ap.add_argument("--days", type=int, default=30)
    a = ap.parse_args()
    res = run({"file": a.file, "max_items": a.max_items, "days": a.days}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[misp] {len(res['intel'])} event(s) from {res['source']}", flush=True)
