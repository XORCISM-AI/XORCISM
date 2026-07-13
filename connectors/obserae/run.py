"""run.py — XORCISM connector: Obserae (self-hosted Network Detection & Response).

Obserae (https://obserae.com) is a self-hosted NDR: a NetFlow/IPFIX collector that reconstructs
sessions, builds a cartography of hosts & services, and raises detection alerts. This connector
imports that into XORCISM in two ways:

  LIVE  — the Obserae REST API (https://obserae.com/docs/api-reference/). Bearer auth with an
          `obs_…` token. Reads:
            • GET /api/carto/graph      → hosts → ASSET, listening services → ASSETSERVICE
            • GET /api/sessions/riverview → reconstructed flows → NETWORKSESSION
            • GET /api/alerts           → detection alerts → XINCIDENT.ALERT (the SOC alert layer)
            • GET /api/status           → summary/health (best-effort)
  FILE  — an offline cartography + sessions (+ optional alerts) export (YAML or JSON).

Normalized output the runner imports:
  {"netflow": {assets, services, sessions}, "alerts": [...], "source": "Obserae NDR"}
    - runner.import_netflow   ← "netflow" → ASSET / ASSETSERVICE / NETWORKSESSION
    - runner.import_incidents ← "alerts"  → XINCIDENT.ALERT (+ ALERTFORASSET), idempotent by
                                 (DetectionSource="Obserae NDR", ExternalID). Surfaced in /soc.

Configuration (worker environment / params):
    OBSERAE_URL          base URL, e.g. http://127.0.0.1:8080   (or the base_url param)
    OBSERAE_API_TOKEN    API token (obs_…) for the Authorization: Bearer header
    params["file"]       offline export path (used when no base_url is given)

Python stdlib only (urllib); PyYAML is used for YAML files if present. Worker-safe.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "Obserae NDR"


# ── helpers ────────────────────────────────────────────────────────────────────
def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except Exception:  # noqa: BLE001
        return None


def _dt(v: Any) -> Optional[str]:
    """Coerce a value to a string timestamp (YAML parses ISO dates to datetime → not JSON-safe)."""
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)


def _load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return json.loads(text)  # YAML is a JSON superset for simple docs


def _api_get(base: str, token: str, path: str, timeout: int = 40) -> Any:
    """GET base+path with a Bearer obs_ token; returns parsed JSON (or None on 4xx/5xx/parse)."""
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "XORCISM-obserae/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted, self-hosted)
            return json.loads(resp.read().decode("utf-8", "replace") or "null")
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return None


def _as_list(obj: Any, *keys: str) -> List[Any]:
    """Coerce an API response to a list of items (bare array, or under one of `keys`)."""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in keys:
            v = obj.get(k)
            if isinstance(v, list):
                return v
        for v in obj.values():  # last resort: the first list-valued field
            if isinstance(v, list):
                return v
    return []


# ── normalizers (shared by live + file modes) ───────────────────────────────────
def _norm_assets(raw: List[Any]) -> List[Dict[str, Any]]:
    out = []
    for a in raw:
        if not isinstance(a, dict):
            continue
        ifaces = a.get("interfaces") or a.get("ifaces") or []
        ip = a.get("ip") or a.get("address")
        if not ip and isinstance(ifaces, list):
            ip = next((str(i.get("ip") or i.get("address")) for i in ifaces
                       if isinstance(i, dict) and (i.get("ip") or i.get("address"))), None)
        out.append({
            "name": a.get("name") or a.get("hostname") or a.get("label") or a.get("id") or ip,
            "ip": ip, "hostname": a.get("hostname") or a.get("fqdn"),
            "os": a.get("os") or a.get("os_name") or a.get("osType"),
            "zone": a.get("zone") or a.get("network") or a.get("group"),
            "tags": a.get("tags") or a.get("labels"),
        })
    return out


def _norm_services(raw: List[Any], proto_default: str) -> List[Dict[str, Any]]:
    out = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        out.append({
            "asset": s.get("asset") or s.get("host") or s.get("ip") or s.get("name"),
            "protocol": str(s.get("protocol") or s.get("proto") or s.get("l4") or proto_default).lower(),
            "port": _int(s.get("port")), "service": s.get("service") or s.get("name") or s.get("app"),
            "banner": s.get("banner"), "first_seen": _dt(s.get("first_seen") or s.get("firstSeen")),
            "last_seen": _dt(s.get("last_seen") or s.get("lastSeen")),
            "flows": _int(s.get("flows") or s.get("flow_count")),
        })
    return [x for x in out if x["asset"] and (x["port"] or x["service"])]


def _services_from_hosts(hosts: List[Any], proto_default: str) -> List[Dict[str, Any]]:
    """Cartography host nodes carry their own `services` list → flatten to ASSETSERVICE rows."""
    out = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        name = h.get("name") or h.get("hostname") or h.get("label") or h.get("id")
        for s in (h.get("services") or []):
            if not isinstance(s, dict):
                continue
            out.append({"asset": name, "protocol": str(s.get("protocol") or s.get("proto") or proto_default).lower(),
                        "port": _int(s.get("port")), "service": s.get("service") or s.get("name") or s.get("app"),
                        "banner": s.get("banner"), "first_seen": _dt(s.get("first_seen")), "last_seen": _dt(s.get("last_seen")),
                        "flows": _int(s.get("flows"))})
    return [x for x in out if x["asset"] and (x["port"] or x["service"])]


def _norm_sessions(raw: List[Any], proto_default: str) -> List[Dict[str, Any]]:
    out = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        src = f.get("src") or f.get("source") or f.get("src_ip") or f.get("client") or f.get("saddr")
        dst = f.get("dst") or f.get("destination") or f.get("dst_ip") or f.get("server") or f.get("daddr")
        if not src or not dst:
            continue
        out.append({
            "src": src, "dst": dst,
            "protocol": str(f.get("protocol") or f.get("proto") or f.get("l4") or proto_default).lower(),
            "src_port": _int(f.get("src_port") or f.get("sport")),
            "dst_port": _int(f.get("dst_port") or f.get("dport") or f.get("port")),
            "service": f.get("service") or f.get("app") or f.get("name"),
            "bytes": _int(f.get("bytes") or f.get("octets") or f.get("total_bytes")),
            "packets": _int(f.get("packets") or f.get("pkts")),
            "flows": _int(f.get("flows") or f.get("flow_count")) or 1,
            "first_seen": _dt(f.get("first_seen") or f.get("start") or f.get("first")),
            "last_seen": _dt(f.get("last_seen") or f.get("end") or f.get("last")),
            "state": f.get("state") or f.get("tcp_state"), "direction": f.get("direction"),
        })
    return out


_SEV = {"critical": "critical", "crit": "critical", "high": "high", "medium": "medium", "med": "medium",
        "moderate": "medium", "low": "low", "info": "info", "informational": "info", "warning": "medium"}


def _norm_alerts(raw: List[Any], base: str = "") -> List[Dict[str, Any]]:
    """Obserae detection alerts → the runner.import_incidents item shape (→ XINCIDENT.ALERT)."""
    out = []
    for a in raw:
        if not isinstance(a, dict):
            continue
        aid = a.get("id") or a.get("uuid") or a.get("alert_id") or a.get("_id")
        real_title = (a.get("title") or a.get("name") or a.get("rule") or a.get("rule_name")
                      or a.get("signature") or a.get("message"))
        src = a.get("src") or a.get("src_ip") or a.get("source_ip") or a.get("saddr")
        dst = a.get("dst") or a.get("dst_ip") or a.get("dest_ip") or a.get("daddr")
        host = a.get("host") or a.get("hostname") or a.get("entity") or src or dst
        if aid is None and not real_title and not host:  # no recognizable signal → skip junk
            continue
        title = real_title or "Obserae detection"
        sev = _SEV.get(str(a.get("severity") or a.get("level") or a.get("priority") or "").lower(), None)
        attack = a.get("attack") or a.get("mitre") or a.get("techniques") or a.get("mitre_attack")
        out.append({
            "external_id": str(aid) if aid is not None else f"{title}:{src or ''}:{dst or ''}",
            "name": str(title)[:300], "severity": sev,
            "description": a.get("description") or a.get("summary") or a.get("detail") or a.get("explanation"),
            "status": a.get("status") or a.get("state"), "category": "Alert",
            "attack": attack, "tags": a.get("tags") or a.get("labels"),
            "classification": a.get("kind") or a.get("type") or a.get("class"),
            "asset": host, "created": _dt(a.get("created") or a.get("timestamp") or a.get("ts")
                                          or a.get("first_seen") or a.get("time")),
            "url": (base.rstrip("/") + f"/alerts/{aid}") if (base and aid is not None) else a.get("url"),
        })
    return out


# ── entry point ──────────────────────────────────────────────────────────────────
def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    proto = str(params.get("default_protocol") or "tcp").lower()
    base = str(params.get("base_url") or os.environ.get("OBSERAE_URL") or "").strip()
    token = str(params.get("token") or os.environ.get("OBSERAE_API_TOKEN") or "").strip()
    path = params.get("file")
    max_alerts = _int(params.get("max_alerts")) or 500

    assets: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    sessions: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []
    status: Dict[str, Any] = {}

    if base:  # ── LIVE REST API mode ──
        if not token:
            raise RuntimeError("obserae: base_url set but no token (set OBSERAE_API_TOKEN or the 'token' param)")
        graph = _api_get(base, token, "/api/carto/graph")
        hosts = _as_list(graph, "nodes", "hosts", "assets")
        # cartography nodes are a mix (hosts/networks/groups) — keep the ones that look like hosts
        host_nodes = [h for h in hosts if isinstance(h, dict)
                      and (h.get("kind") in (None, "host", "device") or h.get("type") in (None, "host", "device"))
                      and (h.get("ip") or h.get("interfaces") or h.get("services") or h.get("hostname"))]
        assets = _norm_assets(host_nodes)
        services = _services_from_hosts(host_nodes, proto) or _norm_services(_as_list(graph, "services"), proto)
        river = _api_get(base, token, "/api/sessions/riverview?limit=1000")
        sessions = _norm_sessions(_as_list(river, "sessions", "rows", "data", "riverview"), proto)
        al = _api_get(base, token, f"/api/alerts?limit={max_alerts}")
        alerts = _norm_alerts(_as_list(al, "alerts", "rows", "data"), base)
        status = _api_get(base, token, "/api/status") or {}
    elif path:  # ── offline FILE mode ──
        data = _load_file(path) or {}
        if not isinstance(data, dict):
            raise RuntimeError("obserae: unexpected export shape (expected a mapping)")
        assets = _norm_assets(data.get("assets") or data.get("hosts") or data.get("cartography") or [])
        services = _norm_services(data.get("services") or data.get("ports") or [], proto) \
            or _services_from_hosts(data.get("assets") or data.get("hosts") or [], proto)
        sessions = _norm_sessions(data.get("sessions") or data.get("flows") or data.get("netflow") or [], proto)
        alerts = _norm_alerts(data.get("alerts") or data.get("detections") or [], "")
    else:
        raise RuntimeError("obserae: provide OBSERAE_URL/base_url (live API) or a 'file' (offline export)")

    assets = [a for a in assets if a.get("name")]
    out: Dict[str, Any] = {
        "source": SOURCE,
        "netflow": {"assets": assets, "services": services, "sessions": sessions},
        "alerts": alerts,
        "summary": {"assets": len(assets), "services": len(services), "sessions": len(sessions),
                    "alerts": len(alerts), "mode": "api" if base else "file",
                    "obserae_version": (status or {}).get("version")},
    }
    return out


if __name__ == "__main__":
    import argparse
    import tempfile
    ap = argparse.ArgumentParser(description="Obserae NDR connector (live REST API or offline export)")
    ap.add_argument("file", nargs="?", help="offline export (YAML/JSON); omit to use OBSERAE_URL live mode")
    ap.add_argument("--base-url", help="Obserae API base (or set OBSERAE_URL)")
    ap.add_argument("--default-protocol", default="tcp")
    ap.add_argument("--max-alerts", type=int, default=500)
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "base_url": a.base_url, "default_protocol": a.default_protocol,
                          "max_alerts": a.max_alerts}, tempfile.mkdtemp()), indent=2))
