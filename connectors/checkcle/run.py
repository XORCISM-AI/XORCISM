"""run.py — XORCISM connector: CheckCle → Asset Monitoring (monitors + incidents).

CheckCle (https://github.com/operacle/checkcle) is an open-source full-stack monitoring platform
(uptime, server, SSL/domain, incidents) built on PocketBase. This connector imports its monitored
services / servers / SSL certificates as XORCISM monitors and its incidents, mapping to:
    {"assets":  [{hostname, key}],                                  # the monitored hosts → ASSET
     "monitors":[{name, type, target, asset, status, uptime, response_time, ssl_expiry, ssl_issuer,
                  external_id, source}],                            # → MONITORINGCHECK
     "monitoring_incidents":[{title, monitor, asset, status, severity, started_at, resolved_at,
                  external_id, source}]}                            # → MONITORINGINCIDENT

Offline: params["file"] = a CheckCle JSON export ({services,servers,ssl,incidents}, a PocketBase
{items:[…]} page, or a flat list — type auto-detected). Live: PocketBase API at CHECKCLE_URL /
the `base` param, authenticated with CHECKCLE_TOKEN or CHECKCLE_USER + CHECKCLE_PASSWORD. NO DB
access here (remote-worker safe); stdlib only.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

TOOL_NAME = "CheckCle"
TOOL_URL = "https://github.com/operacle/checkcle"
SOURCE = "CheckCle"
_DEFAULT_COLLECTIONS = ["services", "servers", "ssl_certificates", "incident"]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        services, servers, ssl, incidents = _from_export(data)
    else:
        services, servers, ssl, incidents = _from_api(params)

    monitors: List[Dict[str, Any]] = []
    assets: Dict[str, Dict[str, Any]] = {}

    def add_asset(host: Optional[str]) -> Optional[str]:
        if not host:
            return None
        if host not in assets:
            assets[host] = {"hostname": host, "key": host}
        return host

    for rec in services:
        monitors.append(_map_service(rec, add_asset))
    for rec in servers:
        monitors.append(_map_server(rec, add_asset))
    for rec in ssl:
        monitors.append(_map_ssl(rec, add_asset))
    monitors = [m for m in monitors if m and m.get("external_id")]

    out_incidents = [_map_incident(rec) for rec in incidents]
    out_incidents = [i for i in out_incidents if i and i.get("external_id")]

    return {"assets": list(assets.values()), "services": [], "cpes": [],
            "monitors": monitors, "monitoring_incidents": out_incidents, "source": SOURCE}


# ── input loaders ─────────────────────────────────────────────────────────────────
def _records(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return [r for r in data["items"] if isinstance(r, dict)]   # PocketBase page
        if data.get("id"):
            return [data]
        return []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def _from_export(data: Any) -> tuple:
    if isinstance(data, dict) and any(k in data for k in ("services", "servers", "ssl", "ssl_certificates", "incidents", "incident")):
        return (_records(data.get("services")), _records(data.get("servers")),
                _records(data.get("ssl") or data.get("ssl_certificates")),
                _records(data.get("incidents") or data.get("incident")))
    # a flat list / PocketBase page → classify each record by shape
    services, servers, ssl, incidents = [], [], [], []
    for r in _records(data):
        if _g(r, "issuer", "valid_till", "expiry", "expiry_date", "not_after", "domain_expiry"):
            ssl.append(r)
        elif _g(r, "started_at", "start_time", "resolved_at", "end_time") and not _g(r, "uptime", "status"):
            incidents.append(r)
        elif _g(r, "cpu", "ram", "memory", "disk", "os_type", "server_id"):
            servers.append(r)
        else:
            services.append(r)
    return services, servers, ssl, incidents


def _from_api(params: Dict[str, Any]) -> tuple:
    base = str(params.get("base") or os.getenv("CHECKCLE_URL") or "").rstrip("/")
    if not base:
        raise RuntimeError("CheckCle live mode needs CHECKCLE_URL (or the base param) + CHECKCLE_TOKEN "
                           "(or CHECKCLE_USER + CHECKCLE_PASSWORD) — or pass an offline export via file=.")
    token = _auth(base)
    cols = [c.strip() for c in str(params.get("collections") or ",".join(_DEFAULT_COLLECTIONS)).split(",") if c.strip()]
    maxn = int(params.get("max_items") or 1000)
    buckets: Dict[str, List[Dict[str, Any]]] = {"services": [], "servers": [], "ssl": [], "incidents": []}
    for col in cols:
        recs = _pb_list(base, col, token, maxn)
        key = ("ssl" if "ssl" in col else "servers" if "server" in col else "incidents" if "incident" in col else "services")
        buckets[key].extend(recs)
    return buckets["services"], buckets["servers"], buckets["ssl"], buckets["incidents"]


def _auth(base: str) -> Optional[str]:
    tok = os.getenv("CHECKCLE_TOKEN")
    if tok:
        return tok.strip()
    user, pw = os.getenv("CHECKCLE_USER"), os.getenv("CHECKCLE_PASSWORD")
    if not (user and pw):
        return None
    body = json.dumps({"identity": user, "password": pw}).encode()
    for path in ("/api/collections/users/auth-with-password", "/api/admins/auth-with-password"):
        try:
            req = urllib.request.Request(base + path, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (configured CheckCle endpoint)
                return json.loads(r.read().decode("utf-8", "replace")).get("token")
        except Exception:
            continue
    return None


def _pb_list(base: str, collection: str, token: Optional[str], maxn: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    page = 1
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = token
    while len(out) < maxn:
        url = f"{base}/api/collections/{urllib.parse.quote(collection)}/records?perPage=200&page={page}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310
                d = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            break
        items = d.get("items") or []
        out.extend(items)
        if page >= int(d.get("totalPages") or 1) or not items:
            break
        page += 1
    return out[:maxn]


# ── mappers ─────────────────────────────────────────────────────────────────────
def _g(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
        for kk, vv in d.items():
            if kk.lower() == k.lower() and vv not in (None, ""):
                return vv
    return None


def _status(v: Any) -> str:
    s = str(v or "").strip().lower()
    if s in ("up", "down", "warning", "paused"):
        return s
    if "up" in s or "ok" in s or "online" in s:
        return "up"
    if "down" in s or "fail" in s or "offline" in s:
        return "down"
    if "warn" in s or "degrad" in s:
        return "warning"
    if "paus" in s or "maint" in s:
        return "paused"
    return "unknown"


def _host(target: Optional[str]) -> Optional[str]:
    if not target:
        return None
    t = str(target)
    m = re.match(r"^[a-z]+://([^/:]+)", t, re.IGNORECASE)
    if m:
        return m.group(1)
    return t.split(":")[0].split("/")[0] or None


def _num(v: Any) -> Optional[float]:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _map_service(r: Dict[str, Any], add_asset) -> Dict[str, Any]:
    target = _g(r, "url", "host", "address", "target", "domain", "ip")
    name = _g(r, "name", "service_name", "title") or target or _g(r, "id")
    typ = str(_g(r, "type", "service_type", "check_type", "monitor_type", "protocol") or "http").lower()
    typ = typ if typ in ("http", "ping", "tcp", "dns", "ssl", "server") else ("http" if "http" in typ else "tcp" if "tcp" in typ else "ping" if "ping" in typ else "dns" if "dns" in typ else "http")
    host = add_asset(_host(target) or (str(name) if name else None))
    return {
        "name": str(name)[:300], "type": typ, "target": target and str(target)[:500], "asset": host,
        "status": _status(_g(r, "status", "current_status")), "uptime": _num(_g(r, "uptime", "uptime_percentage", "uptime_percent")),
        "response_time": _num(_g(r, "response_time", "responsetime", "latency", "avg_response_time")),
        "last_checked": _g(r, "last_checked", "updated", "last_check_at"),
        "external_id": str(_g(r, "id", "service_id") or name), "source": SOURCE,
    }


def _map_server(r: Dict[str, Any], add_asset) -> Dict[str, Any]:
    name = _g(r, "name", "hostname", "server_name") or _g(r, "id")
    host = add_asset(str(name) if name else None)
    return {
        "name": str(name)[:300], "type": "server", "target": _g(r, "ip", "address", "hostname"), "asset": host,
        "status": _status(_g(r, "status", "health", "state")), "uptime": _num(_g(r, "uptime", "uptime_percentage")),
        "external_id": str(_g(r, "id", "server_id") or name), "source": SOURCE,
    }


def _map_ssl(r: Dict[str, Any], add_asset) -> Dict[str, Any]:
    domain = _g(r, "domain", "hostname", "name", "url")
    host = add_asset(_host(domain) if domain else None)
    expiry = _g(r, "valid_till", "expiry_date", "expiry", "not_after", "expires", "valid_until")
    return {
        "name": f"SSL: {domain}" if domain else f"SSL {_g(r, 'id')}", "type": "ssl",
        "target": domain and str(domain), "asset": host, "status": _status(_g(r, "status")),
        "ssl_expiry": str(expiry)[:10] if expiry else None, "ssl_issuer": _g(r, "issuer", "issued_by"),
        "external_id": str(_g(r, "id") or domain), "source": SOURCE,
    }


def _map_incident(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": str(_g(r, "title", "name", "description", "message") or "Incident")[:300],
        "monitor": str(_g(r, "service_id", "service", "monitor", "server_id") or ""),
        "asset": _g(r, "host", "hostname", "asset"),
        "status": _status(_g(r, "status", "current_status")),
        "severity": _g(r, "severity", "impact"),
        "started_at": _g(r, "started_at", "start_time", "created", "timestamp"),
        "resolved_at": _g(r, "resolved_at", "end_time", "resolved"),
        "duration": _g(r, "duration", "duration_minutes"),
        "description": _g(r, "description", "root_cause"),
        "external_id": str(_g(r, "id") or ""), "source": SOURCE,
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="CheckCle import (dry run)")
    ap.add_argument("--file", required=True)
    a = ap.parse_args()
    res = run({"file": a.file}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[checkcle] {len(res['assets'])} asset(s), {len(res['monitors'])} monitor(s), "
          f"{len(res['monitoring_incidents'])} incident(s)", flush=True)
