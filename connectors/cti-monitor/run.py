"""CTI Monitor connector — import open-source threat-intelligence records into XTHREAT.INTELEXCHANGE.

Offline: a JSON export via the `file` param. Live: CTI_MONITOR_URL (+ optional CTI_MONITOR_TOKEN).
Returns {"intel": [...], "source": "CTI Monitor"} for runner.import_threat_intel.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import grc_common as g  # noqa: E402

ATT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _intel(x):
    name = x.get("title") or x.get("name") or x.get("headline") or "CTI Monitor record"
    desc = x.get("summary") or x.get("description") or x.get("content") or ""
    ref = x.get("url") or x.get("link") or x.get("source_url") or x.get("id")
    blob = f"{name} {desc}"
    return {
        "name": name, "description": desc[:4000], "reference": str(ref) if ref else None,
        "external_id": str(x.get("id") or ref or ""), "author": x.get("source") or x.get("feed") or "CTI Monitor",
        "date": (str(x.get("published") or x.get("date") or x.get("created_at") or ""))[:10] or None,
        "actor_tags": (", ".join(x.get("actors", [])) if isinstance(x.get("actors"), list) else x.get("actor")) or None,
        "attack_tags": ", ".join(sorted({m.upper() for m in ATT.findall(blob)})) or None,
        "cve_tags": ", ".join(sorted({m.upper() for m in CVE.findall(blob)})) or None,
        "tags": (", ".join(x.get("tags", [])) if isinstance(x.get("tags"), list) else x.get("category")) or None,
    }


def _from_file(params):
    f = params.get("file")
    if not f or not os.path.exists(f):
        return None
    with open(f, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("threats") or data.get("records") or data.get("intel") or data.get("items") or g.rows(data)
    return []


def run(params, workdir):
    items = _from_file(params)
    if items is None:
        base = (params.get("base") or os.getenv("CTI_MONITOR_URL") or "").rstrip("/")
        if not base:
            raise RuntimeError("CTI Monitor: provide a `file` param or set CTI_MONITOR_URL in the worker env.")
        token = os.getenv("CTI_MONITOR_TOKEN")
        hdr = {"Accept": "application/json"}
        if token:
            hdr["Authorization"] = f"Bearer {token}"
        path = params.get("path") or "/api/threats"
        try:
            items = g.rows(g.http_json(base + path, hdr))
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"CTI Monitor: API call failed ({e}). Check CTI_MONITOR_URL / path.")
    cap = int(params.get("max_items") or 1000)
    intel = [_intel(x) for x in items if isinstance(x, dict)]
    return {"intel": [i for i in intel[:cap] if i.get("reference")], "source": "CTI Monitor"}
