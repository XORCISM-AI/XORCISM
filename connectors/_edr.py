"""
_edr.py — shared EDR/XDR detection normalizer for XORCISM connectors.

The major endpoint platforms (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne,
Palo Alto Cortex XDR, VMware Carbon Black, …) all export "detections / alerts" with the same shape:
an id, a name, the affected host, a severity, a status, and (usually) an ATT&CK tactic/technique.
This module maps any of them to the XORCISM normalized ALERT result `{source, alerts:[...]}` consumed
by the runner's import_incidents (XINCIDENT.ALERT, idempotent by DetectionSource+ExternalID, with the
impacted host linked as an ASSET). Each EDR connector is then ~12 lines: a list-locator + a field map.

Stdlib only; defensive against vendor schema differences (tolerant key lists + dotted paths).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

# severity words across vendors (incl. EDR verdicts) -> XORCISM band
_SEV_WORDS = {
    "critical": "critical", "crit": "critical", "high": "high", "medium": "medium", "moderate": "medium",
    "med": "medium", "low": "low", "informational": "info", "info": "info", "none": "info", "unknown": "info",
    "malicious": "high", "suspicious": "medium", "benign": "info",
}


def sev_band(v: Any) -> str:
    """Normalize a vendor severity (number on a 0-100 or 0-10 scale, or a word) to crit/high/medium/low/info."""
    if v is None:
        return "medium"
    if isinstance(v, bool):
        return "medium"
    if isinstance(v, (int, float)):
        n = float(v)
        if n > 10:  # 0-100 scale (CrowdStrike, …)
            return "critical" if n >= 90 else "high" if n >= 70 else "medium" if n >= 40 else "low" if n > 0 else "info"
        return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low" if n > 0 else "info"  # 0-10 (Carbon Black, …)
    return _SEV_WORDS.get(str(v).strip().lower(), "medium")


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _pick(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for k in keys:
        v = _get(d, k)
        if v not in (None, "", [], {}):
            return v
    return default


def _flat(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(_flat(x) for x in v if x not in (None, ""))
    if isinstance(v, dict):
        return ", ".join(str(x) for x in v.values() if x not in (None, ""))
    return str(v)


def find_items(data: Any, keys: List[str]) -> List[Dict[str, Any]]:
    """Locate the detections list in a vendor document (tries dotted key paths, then any list-of-dicts)."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in keys:
            cur = _get(data, k)
            if isinstance(cur, list):
                return [x for x in cur if isinstance(x, dict)]
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return v
            if isinstance(v, dict):  # one level deeper (e.g. reply.alerts.data)
                got = find_items(v, keys)
                if got:
                    return got
    return []


def to_alerts(source: str, items: List[Dict[str, Any]], M: Dict[str, List[str]]) -> Dict[str, Any]:
    alerts: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ext = _pick(it, M.get("id", []))
        host = _pick(it, M.get("host", []))
        tactic = _pick(it, M.get("tactic", []))
        tech = _pick(it, M.get("technique", []))
        cls = " / ".join(_flat(x) for x in (tactic, tech) if x) or None
        alerts.append({
            "external_id": str(ext) if ext is not None else None,
            "name": _flat(_pick(it, M.get("name", []), "EDR detection"))[:300],
            "description": _flat(_pick(it, M.get("desc", []), ""))[:1500],
            "severity": sev_band(_pick(it, M.get("sev", []))),
            "status": str(_pick(it, M.get("status", []), "new"))[:60],
            "category": "EDR detection",
            "classification": cls,
            "asset": _flat(host) if host else None,
            "created": str(_pick(it, M.get("time", []), "")) or None,
        })
    return {"source": source, "alerts": alerts}


def run_edr(params: Dict[str, Any], here: str, sample: str, source: str, list_keys: List[str], M: Dict[str, List[str]]) -> Dict[str, Any]:
    """Connector entry point: read the vendor JSON (file param or bundled sample) and normalize it."""
    path = params.get("file") or os.path.join(here, sample)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return to_alerts(source, find_items(data, list_keys), M)


def smoke(run_fn, source: str) -> None:
    """Shared __main__ smoke test for the EDR connectors."""
    import tempfile
    r = run_fn({}, tempfile.mkdtemp())
    a = r["alerts"]
    bands: Dict[str, int] = {}
    for x in a:
        bands[x["severity"]] = bands.get(x["severity"], 0) + 1
    print("%s: %d alerts %s" % (source, len(a), bands))
    for x in a[:6]:
        print("  %-8s %-24s %s" % (x["severity"], (x["asset"] or "-")[:24], x["name"][:46]))
