"""run.py — Import AiSOC outputs into XORCISM (multi-cockpit).

AiSOC (https://github.com/beenuar/AiSOC, MIT) is an open-source, self-hostable AI Security Operations
Center: alert fusion, four LangGraph agents (Detect / Triage / Hunt / Respond), OCSF-normalized alerts,
cases, MITRE ATT&CK investigation, risk-based alerting, detection-as-code (Sigma) and a replayable
investigation ledger.

This connector is **import-type, read-only, worker-safe**: it parses an exported AiSOC JSON (or pulls
read-only from the AiSOC API when AISOC_URL/AISOC_API_KEY are set) and normalizes it so the existing
XORCISM importers fan it out to three cockpits in one run:

  * AiSOC cases & alerts            -> `alerts`     -> XINCIDENT.ALERT          (Incident / SOC)
  * AiSOC IOCs + threat-actor attr. -> `intel`      -> XTHREAT.INTELEXCHANGE    (CTI; MITRE tags -> ATT&CK matrix)
  * AiSOC detection rules (Sigma)   -> `detections` -> XTHREAT.SIGMARULE        (purple-team / TID)

No actions are ever sent back to AiSOC. The live pull (if configured) is best-effort GET-only.

Config (worker / params):
    params["file"]          an AiSOC export JSON (object with cases/alerts/iocs/detections/actors, or an array)
    params["kind"]          all | cases | alerts | iocs | detections (default all)
    params["limit"]         max items per category (default 500)
    params["min_severity"]  info|low|medium|high|critical — minimum severity for alerts/IOCs (default info)
    AISOC_URL / AISOC_API_KEY   optional read-only API pull (Bearer)
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/beenuar/AiSOC"
SOURCE = "AiSOC"
_SEV_RANK = {"info": 0, "informational": 0, "none": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4, "severe": 4}
_NUM_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical", 5: "critical"}
_MITRE_RX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _sev(v: Any) -> str:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return _NUM_SEV.get(int(v), "medium")
    s = str(v or "").strip().lower()
    s = {"informational": "info", "moderate": "medium", "severe": "critical", "warning": "medium"}.get(s, s)
    return s if s in _SEV_RANK else "medium"


def _mitre(obj: Any) -> List[str]:
    """All MITRE technique ids referenced anywhere in the item (mitre/techniques fields or free text)."""
    try:
        blob = json.dumps(obj, default=str)
    except Exception:
        blob = str(obj)
    return sorted({m.upper() for m in _MITRE_RX.findall(blob)})


def _cves(obj: Any) -> List[str]:
    try:
        blob = json.dumps(obj, default=str)
    except Exception:
        blob = str(obj)
    return sorted({m.upper() for m in _CVE_RX.findall(blob)})


def _asset_of(it: Dict[str, Any]) -> Optional[str]:
    """First host-like entity (OCSF device/host, or an entities[] node)."""
    for k in ("hostname", "host", "device", "asset", "src_host", "dst_host"):
        v = it.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            n = _first(v, "name", "hostname", "fqdn", "ip")
            if n:
                return str(n)
    for ent in it.get("entities") or it.get("entity_links") or []:
        if isinstance(ent, dict):
            t = str(ent.get("type") or ent.get("kind") or "").lower()
            val = _first(ent, "value", "name", "id")
            if val and t in ("host", "device", "hostname", "asset", "endpoint"):
                return str(val)
    return None


# ── normalizers ────────────────────────────────────────────────────────────
def _to_alert(it: Dict[str, Any], category: str) -> Optional[Dict[str, Any]]:
    ext = _first(it, "id", "_id", "case_id", "alert_id", "uid", "external_id")
    if not ext:
        return None
    name = str(_first(it, "title", "name", "finding", "summary", "rule_name") or ext)[:300]
    sev = _sev(_first(it, "severity", "risk", "level", "priority"))
    mitre = _mitre(it)
    tags = it.get("tags") if isinstance(it.get("tags"), list) else _split(it.get("tags"))
    tags = (tags or []) + mitre  # surface ATT&CK technique ids on the alert
    return {
        "external_id": f"aisoc:{ext}",
        "name": name,
        "description": str(_first(it, "description", "narrative", "deep_explain", "rationale") or "")[:4000],
        "severity": sev,
        "status": _first(it, "status", "disposition", "state", "stage"),
        "category": category,
        "tags": tags,
        "assignee": _first(it, "assignee", "owner", "analyst"),
        "asset": _asset_of(it),
        "created": _first(it, "created_at", "createdAt", "date", "first_seen", "timestamp"),
        "source": SOURCE,
    }


def _ioc_to_intel(it: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    val = _first(it, "value", "indicator", "ioc", "observable", "data")
    ext = _first(it, "id", "_id") or val
    if not val and not ext:
        return None
    itype = str(_first(it, "type", "ioc_type", "dataType", "kind") or "ioc")
    mitre = _mitre(it)
    return {
        "reference": f"aisoc-ioc:{ext or val}",
        "external_id": str(ext or val),
        "name": (f"{itype}: {val}" if val else str(ext))[:300],
        "description": str(_first(it, "description", "context", "verdict", "reputation") or "")[:2000],
        "author": SOURCE,
        "date": _first(it, "first_seen", "created_at", "date"),
        "attack_tags": ", ".join(mitre),
        "actor_tags": _csv(_first(it, "actor", "threat_actor", "campaign")),
        "malware_tags": _csv(_first(it, "malware", "family")),
        "cve_tags": ", ".join(_cves(it)),
        "intel_tags": "AiSOC, IOC, " + itype,
    }


def _actor_to_intel(it: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = _first(it, "name", "actor", "id")
    if not name:
        return None
    aliases = _first(it, "aliases", "aka") or []
    aliases = aliases if isinstance(aliases, list) else _split(aliases)
    return {
        "reference": f"aisoc-actor:{name}",
        "external_id": str(_first(it, "mitre_id", "id", "name")),
        "name": f"Threat actor (AiSOC attribution): {name}"[:300],
        "description": str(_first(it, "description", "summary", "attribution", "notes") or
                           f"AiSOC attribution to {name} (score {_first(it, 'score', 'confidence') or '?'}).")[:2000],
        "author": SOURCE,
        "attack_tags": ", ".join(_mitre(it)),
        "actor_tags": ", ".join([str(name)] + [str(a) for a in aliases]),
        "malware_tags": _csv(_first(it, "tools", "malware")),
        "intel_tags": "AiSOC, threat-actor, attribution",
    }


def _to_detection(it: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ref = _first(it, "id", "reference", "rule_id", "name", "title")
    if not ref:
        return None
    yaml_text = _first(it, "yaml", "sigma", "rule", "content") or ""
    mitre = _mitre(it)
    return {
        "reference": f"aisoc:{ref}",
        "name": str(_first(it, "title", "name") or ref)[:300],
        "description": str(_first(it, "description", "hypothesis") or "")[:2000],
        "yaml": yaml_text if isinstance(yaml_text, str) else json.dumps(yaml_text),
        "logsource": _stringify(_first(it, "logsource", "log_source", "logsources")),
        "level": _sev(_first(it, "level", "severity", "risk")),
        "status": str(_first(it, "status", "lifecycle") or "experimental"),
        "author": str(_first(it, "author") or SOURCE),
        "attack_tags": ", ".join(mitre),
    }


def _split(s: Any) -> List[str]:
    if isinstance(s, list):
        return [str(x) for x in s]
    return [t.strip() for t in str(s or "").split(",") if t.strip()]


def _csv(s: Any) -> str:
    return ", ".join(_split(s))


def _stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    return json.dumps(v, default=str)[:300]


# ── collection from the many AiSOC export shapes ────────────────────────────
def _collect(data: Any, *keys: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                out += [x for x in v if isinstance(x, dict)]
            elif isinstance(v, dict) and isinstance(v.get("data"), list):
                out += [x for x in v["data"] if isinstance(x, dict)]
    return out


def _maybe_pull(url: str, key: str, path: str, limit: int) -> List[Dict[str, Any]]:
    """Best-effort read-only GET from the AiSOC API. Any failure -> []."""
    try:
        req = urllib.request.Request(
            f"{url.rstrip('/')}/{path.lstrip('/')}?limit={limit}",
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            d = json.loads(resp.read().decode("utf-8", "replace") or "null")
        if isinstance(d, list):
            return [x for x in d if isinstance(x, dict)]
        if isinstance(d, dict):
            for k in ("data", "items", "results"):
                if isinstance(d.get(k), list):
                    return [x for x in d[k] if isinstance(x, dict)]
        return []
    except Exception:
        return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    kind = str(params.get("kind") or "all").strip().lower()
    limit = max(1, min(int(params.get("limit") or 500), 5000))
    min_rank = _SEV_RANK.get(str(params.get("min_severity") or "info").lower(), 0)
    want = lambda k: kind in ("all", k)  # noqa: E731

    url = (os.environ.get("AISOC_URL") or "").strip()
    api = (os.environ.get("AISOC_API_KEY") or "").strip()

    cases: List[Dict[str, Any]] = []; alerts_raw: List[Dict[str, Any]] = []
    iocs: List[Dict[str, Any]] = []; actors: List[Dict[str, Any]] = []; dets: List[Dict[str, Any]] = []

    if url and api and not params.get("file"):
        cases = _maybe_pull(url, api, "/api/cases", limit) if want("cases") else []
        alerts_raw = _maybe_pull(url, api, "/api/alerts", limit) if want("alerts") else []
        iocs = _maybe_pull(url, api, "/api/intel/iocs", limit) if want("iocs") else []
        dets = _maybe_pull(url, api, "/api/detections", limit) if want("detections") else []
    if not (cases or alerts_raw or iocs or dets):
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if isinstance(data, list):  # a bare array == alerts
            alerts_raw = [x for x in data if isinstance(x, dict)]
        else:
            cases = _collect(data, "cases", "investigations")
            alerts_raw = _collect(data, "alerts", "events")
            iocs = _collect(data, "iocs", "intel", "indicators", "observables")
            actors = _collect(data, "actors", "threat_actors", "attributions", "attribution")
            dets = _collect(data, "detections", "rules", "sigma")

    # ── normalize per category (respecting kind + min_severity) ──
    alerts: List[Dict[str, Any]] = []
    if want("cases") or want("alerts"):
        for it in (cases if want("cases") else []):
            a = _to_alert(it, "Case")
            if a and _SEV_RANK.get(a["severity"], 0) >= min_rank:
                alerts.append(a)
        for it in (alerts_raw if want("alerts") else []):
            a = _to_alert(it, "Alert")
            if a and _SEV_RANK.get(a["severity"], 0) >= min_rank:
                alerts.append(a)

    intel: List[Dict[str, Any]] = []
    if want("iocs"):
        for it in iocs:
            r = _ioc_to_intel(it)
            if r:
                intel.append(r)
        for it in actors:
            r = _actor_to_intel(it)
            if r:
                intel.append(r)

    detections: List[Dict[str, Any]] = []
    if want("detections"):
        for it in dets:
            r = _to_detection(it)
            if r:
                detections.append(r)

    return {
        "source": SOURCE,
        "alerts": alerts[:limit],
        "intel": intel[:limit],
        "detections": detections[:limit],
    }


# ── offline dry-run (built-in sample) ───────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="AiSOC connector (offline dry run)")
    ap.add_argument("--file"); ap.add_argument("--kind", default="all"); ap.add_argument("--min-severity", default="info")
    a = ap.parse_args()
    if not a.file:
        sample = {
            "cases": [
                {"id": "INC-RT-001", "title": "Suspected ransomware staging on FINANCE-DC-01",
                 "severity": "critical", "status": "open", "narrative": "DetectAgent flagged mass file rename; TriageAgent correlated to T1486, T1490.",
                 "mitre": ["T1486", "T1490"], "entities": [{"type": "host", "value": "FINANCE-DC-01"}], "assignee": "tier2", "created_at": "2026-06-30T08:00:00Z"}
            ],
            "alerts": [
                {"id": "A-9001", "title": "Impossible-travel sign-in for j.doe", "severity": "high", "status": "new",
                 "mitre": ["T1078"], "hostname": "OKTA", "created_at": "2026-06-30T07:55:00Z"},
                {"id": "A-9002", "finding": "LSASS access by unsigned binary", "risk": 3, "mitre_techniques": ["T1003.001"], "device": {"name": "WS-204"}}
            ],
            "iocs": [
                {"id": "ioc-1", "type": "ipv4", "value": "185.220.101.5", "verdict": "malicious", "actor": "APT29", "mitre": ["T1071"]},
                {"id": "ioc-2", "type": "sha256", "value": "ab12...ef", "malware": "Cobalt Strike", "description": "Affected by CVE-2023-1234"}
            ],
            "actors": [{"name": "APT29", "aliases": ["Cozy Bear", "Midnight Blizzard"], "score": 0.82, "mitre": ["T1078", "T1071"], "tools": ["Cobalt Strike"]}],
            "detections": [
                {"id": "aisoc-det-101", "title": "Mass file rename (ransomware)", "severity": "high", "status": "active",
                 "logsource": {"category": "file_event"}, "mitre": ["T1486"],
                 "yaml": "title: Mass file rename\nlogsource:\n  category: file_event\ndetection:\n  sel: {EventID: 11}\n  condition: sel"}
            ],
        }
        fp = os.path.join(tempfile.mkdtemp(), "aisoc.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "kind": a.kind, "min_severity": a.min_severity}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[AiSOC] {len(res['alerts'])} alert(s) -> XINCIDENT.ALERT  |  {len(res['intel'])} intel -> INTELEXCHANGE  "
          f"|  {len(res['detections'])} detection(s) -> SIGMARULE   (tool: {TOOL_URL})", flush=True)
