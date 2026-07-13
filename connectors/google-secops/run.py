"""run.py — XORCISM connector for Google SecOps (Chronicle SIEM).

Imports Google Security Operations (formerly Chronicle) rule detections / curated
alerts into XORCISM as security alerts (XINCIDENT.ALERT via runner.import_incidents).
Google SecOps is Google Cloud's cloud-native SIEM; this brings its rule-engine
detections into XORCISM's incident layer so the SOC has one pane of glass.

Modes (in order):
    live    : GOOGLE_SECOPS_TOKEN + region/instance -> Chronicle v1alpha legacy alerts API.
    offline : params["file"] -> parse a saved detections / alerts export.
    demo    : neither -> import the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    GOOGLE_SECOPS_TOKEN     OAuth2 Bearer access token (gcloud auth print-access-token
                            or a service-account token; scope cloud-platform)      (live)
    GOOGLE_SECOPS_REGION    regional host prefix, e.g. "us", "europe", "asia-southeast1"
                            (default "us")                                         (live)
    GOOGLE_SECOPS_PROJECT   Google Cloud project id / number                       (live)
    GOOGLE_SECOPS_LOCATION  instance location, e.g. "us" (default = region)        (optional)
    GOOGLE_SECOPS_INSTANCE  Chronicle instance (customer) id (a UUID)              (live)
    GOOGLE_SECOPS_ENDPOINT  full URL override; if set, used verbatim (advanced)    (optional)

Chronicle alert/detection responses are deeply nested and vary by endpoint, so parsing
is tolerant: it walks several known shapes ({detections|alerts|rulesAlerts:[...]}, a bare
list, the legacy backstory shape) and extracts sensible defaults.

Normalized result: {"source": "Google SecOps", "alerts": [...]}. Worker-safe: stdlib only,
secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "Google SecOps"
# Chronicle rule / UDM severity -> XORCISM severity
_SEV = {
    "CRITICAL": "critical", "FATAL": "critical",
    "HIGH": "high", "ERROR": "high",
    "MEDIUM": "medium", "WARNING": "medium",
    "LOW": "low", "INFORMATIONAL": "info", "INFO": "info", "DEFAULT": "info",
}


def _first(d: Any, *keys: str) -> Any:
    """Return the first present, non-empty value among keys of a dict."""
    if not isinstance(d, dict):
        return None
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _severity(*vals: Any) -> str:
    for v in vals:
        if v:
            s = _SEV.get(str(v).strip().upper())
            if s:
                return s
    return "medium"


def _asset_from_events(collection: Any) -> Optional[str]:
    """Pull a host/asset label out of Chronicle collectionElements (matched UDM events).

    Prefer a hostname (a better ASSET key) over a bare IP across all matched events.
    """
    if not isinstance(collection, list):
        return None
    fallback_ip: Optional[str] = None
    for elem in collection:
        refs = (elem or {}).get("references") if isinstance(elem, dict) else None
        for ref in refs or []:
            ev = (ref or {}).get("event") if isinstance(ref, dict) else None
            if not isinstance(ev, dict):
                continue
            for node in ("principal", "target", "src", "observer"):
                n = ev.get(node)
                if not isinstance(n, dict):
                    continue
                host = _first(n, "hostname", "assetId")
                if host:
                    return str(host)
                if fallback_ip is None:
                    ips = n.get("ip")
                    if isinstance(ips, list) and ips:
                        fallback_ip = str(ips[0])
                    elif isinstance(ips, str) and ips:
                        fallback_ip = ips
    return fallback_ip


def _attack(det: Dict[str, Any]) -> Optional[str]:
    """Collect MITRE ATT&CK technique ids attached to a Chronicle detection."""
    ids: List[str] = []
    for key in ("mitreAttack", "mitre", "mitreTechniques", "techniques"):
        v = det.get(key)
        if isinstance(v, list):
            for t in v:
                if isinstance(t, str):
                    ids.append(t)
                elif isinstance(t, dict):
                    tid = _first(t, "id", "techniqueId", "technique")
                    if tid:
                        ids.append(str(tid))
        elif isinstance(v, str):
            ids.append(v)
    # de-dup, preserve order
    seen, uniq = set(), []
    for t in ids:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return ",".join(uniq) or None


def _normalize(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        # A Chronicle detection wraps its rule facts in a detection[] list; curated/legacy
        # alerts put them at the top level. Merge both so field lookups are uniform.
        det_list = r.get("detection")
        det = det_list[0] if isinstance(det_list, list) and det_list and isinstance(det_list[0], dict) else {}
        merged: Dict[str, Any] = {**r, **det}

        name = _first(merged, "ruleName", "name", "title", "displayName", "detectionType")
        ext = _first(r, "id", "detectionId", "name") or _first(merged, "ruleId", "alertId")
        if not ext and not name:
            continue
        state = str(_first(merged, "alertState", "status", "state") or "").upper()
        status = "Open" if state in ("ALERTING", "OPEN", "ACTIVE", "NEW") else (state.title() or None)
        url = _first(merged, "urlBackToProduct", "url", "alertUrl")
        asset = _asset_from_events(r.get("collectionElements")) or _first(merged, "hostname", "asset")
        created = _first(r, "detectionTime", "createdTime", "timestamp") or _first(merged, "detectionTime", "createTime")
        out.append({
            "external_id": str(ext or name)[:200],
            "name": str(name or ext)[:300],
            "description": str(_first(merged, "description", "summary", "commentary", "ruleText") or "")[:4000],
            "severity": _severity(_first(merged, "severity", "priority"), r.get("severity")),
            "status": status,
            "category": "Detection",
            "assignee": _first(merged, "assignee", "assignedTo"),
            "tags": _first(merged, "ruleType", "detectionType", "type"),
            "url": str(url) if url else None,
            "asset": str(asset) if asset else None,
            "created": created,
            "attack": _attack(merged),
        })
    return out


def _extract_rows(data: Any) -> List[Dict[str, Any]]:
    """Find the alert/detection array inside a tolerant set of Chronicle response shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("detections", "alerts", "rulesAlerts", "ruleAlerts",
                    "curatedRuleDetections", "results", "result"):
            v = data.get(key)
            if isinstance(v, list):
                return v
        # legacyFetchAlertsView groups under "alertGroups" -> [{alertInfos:[...]}]
        groups = data.get("alertGroups")
        if isinstance(groups, list):
            rows: List[Dict[str, Any]] = []
            for g in groups:
                infos = (g or {}).get("alertInfos") if isinstance(g, dict) else None
                if isinstance(infos, list):
                    rows.extend(infos)
            if rows:
                return rows
    return []


def _live(token: str, region: str, project: str, location: str, instance: str,
          endpoint: str, limit: int) -> List[Dict[str, Any]]:
    if endpoint:
        url = endpoint
    else:
        region = (region or "us").strip().strip("/")
        host = f"https://{region}-chronicle.googleapis.com"
        parent = f"projects/{project}/locations/{location or region}/instances/{instance}"
        qs = urllib.parse.urlencode({"pageSize": str(limit)})
        url = f"{host}/v1alpha/{parent}/legacy:legacyFetchAlertsView?{qs}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8", "replace") or "null")
    return _normalize(_extract_rows(data))


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 200) or 200)
    token = (os.environ.get("GOOGLE_SECOPS_TOKEN") or "").strip()
    region = (os.environ.get("GOOGLE_SECOPS_REGION") or "us").strip()
    project = (os.environ.get("GOOGLE_SECOPS_PROJECT") or "").strip()
    location = (os.environ.get("GOOGLE_SECOPS_LOCATION") or "").strip()
    instance = (os.environ.get("GOOGLE_SECOPS_INSTANCE") or "").strip()
    endpoint = (os.environ.get("GOOGLE_SECOPS_ENDPOINT") or "").strip()

    if token and (endpoint or (project and instance)):
        alerts = _live(token, region, project, location, instance, endpoint, limit)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        alerts = _normalize(_extract_rows(data))
    return {"source": SOURCE, "alerts": alerts[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
