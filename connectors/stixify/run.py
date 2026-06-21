"""Stixify connector — import extracted threat-intel reports into XTHREAT.INTELEXCHANGE.

Offline: a Stixify reports JSON or a STIX bundle via the `file` param. Live: STIXIFY_API_KEY (API-KEY
header) + optional STIXIFY_BASE. Returns {"intel": [...], "source": "Stixify"} for runner.import_threat_intel.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402  (reuse http_json / rows)

ATT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _intel_from_report(r):
    rid = r.get("id") or r.get("report_id")
    name = r.get("name") or r.get("title") or "Stixify report"
    desc = r.get("description") or r.get("summary") or ""
    labels = r.get("labels") or r.get("tags") or []
    if isinstance(labels, str):
        labels = [labels]
    blob = f"{name} {desc} {' '.join(labels)}"
    attack = ", ".join(sorted({m.upper() for m in ATT.findall(blob)}))
    return {
        "name": name, "description": desc,
        "reference": r.get("url") or (f"https://app.stixify.com/reports/{rid}" if rid else None) or name,
        "external_id": str(rid) if rid else None,
        "author": r.get("created_by") or r.get("identity") or "Stixify",
        "date": (r.get("created") or r.get("created_at") or "")[:10] or None,
        "tags": ", ".join(str(x) for x in labels) if labels else None,
        "attack_tags": attack or None,
    }


def run(params, workdir):
    items = g.from_file(params)
    if items is not None:
        intel = []
        for x in items:
            if isinstance(x, dict) and (x.get("type") == "report" or x.get("name") or x.get("title")):
                intel.append(_intel_from_report(x))
        return {"intel": [i for i in intel if i.get("reference")], "source": "Stixify"}

    key = os.getenv("STIXIFY_API_KEY")
    base = (params.get("base") or os.getenv("STIXIFY_BASE") or "https://api.stixify.com").rstrip("/")
    if not key:
        raise RuntimeError("Stixify: provide a `file` param (offline export) or set STIXIFY_API_KEY in the worker env.")
    hdr = {"API-KEY": key, "Accept": "application/json"}
    cap = int(params.get("max_items") or 200)
    intel = []
    page = 1
    while len(intel) < cap and page <= 25:
        try:
            data = g.http_json(f"{base}/v1/reports/?page={page}", hdr)
        except Exception:  # noqa: BLE001
            break
        rows = g.rows(data) or data.get("reports", []) if isinstance(data, dict) else []
        if not rows:
            break
        for r in rows:
            intel.append(_intel_from_report(r))
        if isinstance(data, dict) and not data.get("next"):
            break
        page += 1
    return {"intel": [i for i in intel[:cap] if i.get("reference")], "source": "Stixify"}
