"""run.py — XORCISM connector: NetBird (zero-trust mesh) device inventory → assets.

NetBird (https://netbird.io) is an open-source WireGuard-based mesh VPN. Its Management API
exposes the peers (devices) joined to the network. This connector turns each peer into an ASSET
for Asset Management — DNS label / hostname, overlay IP, OS, agent version, connectivity, groups.

    file          : a saved `GET /api/peers` JSON response to parse (offline).
    api_token     : live mode — list peers from the NetBird Management API (read-only).
    management_url: the Management API base URL (self-hosted or the NetBird cloud).

Emits the XORCISM findings model:
    assets [{hostname, ip?, key, os}]   — one per NetBird peer

No DB access (worker-safe): returns the normalized dict; the runner performs all writes.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional

_HOSTISH = re.compile(r"^[A-Za-z0-9_.\-]+$")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            peers = _load_peers(fh.read())
    else:
        token = str(params.get("api_token") or "").strip()
        if not token:
            raise RuntimeError("netbird: provide a 'file' (peers JSON) or an 'api_token' for live mode")
        base = str(params.get("management_url") or "https://api.netbird.io").strip().rstrip("/")
        peers = _load_peers(_fetch_peers(base, token))
    return {"assets": _to_assets(peers), "services": [], "cpes": [], "vulns": []}


# ── live mode ────────────────────────────────────────────────────────────────────
def _fetch_peers(base: str, token: str) -> str:
    import urllib.request
    if not re.match(r"^https?://", base):
        raise RuntimeError(f"netbird: invalid management_url {base!r}")
    req = urllib.request.Request(f"{base}/api/peers", headers={
        "Authorization": f"Token {token}", "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — operator-supplied mgmt URL
        return resp.read().decode("utf-8", "replace")


# ── parsing ────────────────────────────────────────────────────────────────────
def _load_peers(text: str) -> List[Dict[str, Any]]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        d = json.loads(text)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"netbird: could not parse peers JSON: {e}")
    if isinstance(d, dict):
        d = d.get("data") or d.get("peers") or d.get("items") or []
    return [p for p in d if isinstance(p, dict)] if isinstance(d, list) else []


def _first_ip(*vals: Any) -> Optional[str]:
    for v in vals:
        v = str(v or "").strip()
        if not v:
            continue
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            continue
    return None


def _to_assets(peers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for p in peers:
        # NetBird peer identity: prefer the stable DNS label, then hostname, then name.
        host = str(p.get("dns_label") or p.get("hostname") or p.get("name") or "").strip().lower().rstrip(".")
        if host and not _HOSTISH.match(host):
            host = re.split(r"[\s/]+", host)[0]
        ip = _first_ip(p.get("ip"), p.get("connection_ip"), p.get("nb_ip"))
        key = str(p.get("id") or host or ip or "").strip()
        if not (host or ip):
            continue
        a: Dict[str, Any] = {"hostname": host or None, "key": key or (host or ip)}
        if ip:
            a["ip"] = ip
        osname = str(p.get("os") or "").strip()
        if osname:
            a["os"] = osname[:160]
        # de-dup by key (peer id) or host
        dk = key or host or ip
        if dk in seen:
            seen[dk].update({k: v for k, v in a.items() if v})
        else:
            seen[dk] = {k: v for k, v in a.items() if v}
    return list(seen.values())


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="NetBird peers → assets (dry run)")
    ap.add_argument("--file", help="NetBird GET /api/peers JSON")
    ap.add_argument("--api-token", dest="api_token", default="")
    ap.add_argument("--management-url", dest="management_url", default="https://api.netbird.io")
    a = ap.parse_args()
    res = run({"file": a.file, "api_token": a.api_token, "management_url": a.management_url}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[netbird] {len(res['assets'])} asset(s)", flush=True)
