"""run.py — XORCISM connector: Shodan → assets + services + CPEs.

Offline: parse a Shodan JSON (a single `shodan host` object with a `data` list, a
         JSON-lines banner stream, or a `{matches:[...]}` search response).
Live:    if `query` is set and SHODAN_API_KEY is in the worker env, call the
         Shodan search API (needs `requests`).

Each host.ip -> ASSET (ip, os); each banner -> SERVICE (host:port + product); each
`cpe` -> a CPE linked to the asset. No DB access (worker-safe).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        data = _load(text)
    else:
        query = str(params.get("query") or "").strip()
        if not query:
            raise RuntimeError("shodan: provide a 'file' (Shodan JSON) or a 'query' for live API mode")
        data = {"matches": _search(query, int(params.get("limit") or 100))}
    return _parse(data)


def _load(text: str) -> Any:
    text = (text or "").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001 — JSON-lines fallback
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:  # noqa: BLE001
                continue
        return out


def _search(query: str, limit: int) -> List[Dict[str, Any]]:
    import requests

    key = os.getenv("SHODAN_API_KEY") or ""
    if not key:
        raise RuntimeError("SHODAN_API_KEY required in the worker env for live mode")
    matches: List[Dict[str, Any]] = []
    page = 1
    while len(matches) < limit:
        r = requests.get("https://api.shodan.io/shodan/host/search",
                         params={"key": key, "query": query, "page": page}, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"Shodan API HTTP {r.status_code}: {r.text[:200]}")
        body = r.json()
        ms = body.get("matches", [])
        if not ms:
            break
        matches.extend(ms)
        page += 1
    return matches[:limit]


def _banners(data: Any) -> List[Dict[str, Any]]:
    """Flatten the input into per-banner dicts that each carry ip_str/os/hostnames."""
    if isinstance(data, dict):
        if isinstance(data.get("matches"), list):
            return [b for b in data["matches"] if isinstance(b, dict)]
        if isinstance(data.get("data"), list) and data.get("ip_str"):
            out = []
            for b in data["data"]:
                if not isinstance(b, dict):
                    continue
                bb = dict(b)
                bb.setdefault("ip_str", data.get("ip_str"))
                bb.setdefault("os", data.get("os"))
                bb.setdefault("hostnames", data.get("hostnames"))
                out.append(bb)
            return out or [data]
        return [data]
    if isinstance(data, list):
        return [b for b in data if isinstance(b, dict)]
    return []


def _parse(data: Any) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []
    cpes: set = set()
    for b in _banners(data):
        ip = str(b.get("ip_str") or b.get("ip") or "").strip()
        if not ip:
            continue
        hostnames = b.get("hostnames") or []
        host = (hostnames[0] if hostnames else ip)
        a = assets.setdefault(ip, {"hostname": str(host), "key": ip, "ip": ip})
        if b.get("os") and not a.get("os"):
            a["os"] = str(b.get("os"))
        port = b.get("port")
        prod = " ".join(str(x) for x in [b.get("product"), b.get("version")] if x).strip()
        if port:
            services.append({"asset": ip, "cpe": f"{ip}:{port}" + (f" {prod}" if prod else "")})
        for cpe in (b.get("cpe") or b.get("cpe23") or []):
            if cpe and str(cpe).lower().startswith("cpe:"):
                cpes.add(str(cpe))
                services.append({"asset": ip, "cpe": str(cpe)})
    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": []}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Shodan import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--query", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "query": a.query}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[shodan] {len(res['assets'])} asset(s), {len(res['services'])} service(s), {len(res['cpes'])} cpe(s)", flush=True)
