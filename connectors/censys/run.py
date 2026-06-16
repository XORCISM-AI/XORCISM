"""run.py — XORCISM connector: Censys → assets + services + CPEs.

Offline: parse a Censys hosts JSON (a list of host objects, or a v2 hosts-search
         `{"result":{"hits":[...]}}` response, or `{"hosts":[...]}`).
Live:    if `query` is set and CENSYS_API_ID / CENSYS_API_SECRET are in the worker
         env, call the Censys v2 hosts search API (needs `requests`).

Mapping: host.ip -> ASSET (ip, os); each service -> SERVICE (host:port + name);
each detected software CPE -> a CPE linked to the asset. No DB access (worker-safe).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        query = str(params.get("query") or "").strip()
        if not query:
            raise RuntimeError("censys: provide a 'file' (hosts JSON) or a 'query' for live API mode")
        data = _fetch(query, int(params.get("limit") or 200))
    return _parse(data)


def _fetch(query: str, limit: int) -> Any:
    import requests

    api_id = os.getenv("CENSYS_API_ID") or ""
    api_secret = os.getenv("CENSYS_API_SECRET") or ""
    if not api_id or not api_secret:
        raise RuntimeError("CENSYS_API_ID / CENSYS_API_SECRET required in the worker env for live mode")
    hits: List[Dict[str, Any]] = []
    cursor = None
    while len(hits) < limit:
        params = {"q": query, "per_page": min(100, limit - len(hits))}
        if cursor:
            params["cursor"] = cursor
        r = requests.get("https://search.censys.io/api/v2/hosts/search",
                         params=params, auth=(api_id, api_secret), timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"Censys API HTTP {r.status_code}: {r.text[:200]}")
        body = r.json().get("result", {})
        hits.extend(body.get("hits", []))
        cursor = (body.get("links") or {}).get("next")
        if not cursor:
            break
    return {"result": {"hits": hits[:limit]}}


def _find_hosts(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [h for h in data if isinstance(h, dict)]
    if isinstance(data, dict):
        r = data.get("result")
        if isinstance(r, dict) and isinstance(r.get("hits"), list):
            return [h for h in r["hits"] if isinstance(h, dict)]
        for k in ("hosts", "hits", "results", "data"):
            if isinstance(data.get(k), list):
                return [h for h in data[k] if isinstance(h, dict)]
        if data.get("ip"):
            return [data]
    return []


def _parse(data: Any) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []
    cpes: set = set()
    for hrec in _find_hosts(data):
        ip = str(hrec.get("ip") or "").strip()
        if not ip:
            continue
        a = assets.setdefault(ip, {"hostname": ip, "key": ip, "ip": ip})
        os_name = (hrec.get("operating_system") or hrec.get("os") or {})
        prod = os_name.get("product") if isinstance(os_name, dict) else None
        if prod and not a.get("os"):
            a["os"] = str(prod)
        for sv in (hrec.get("services") or []):
            if not isinstance(sv, dict):
                continue
            port = sv.get("port")
            name = sv.get("extended_service_name") or sv.get("service_name") or ""
            if port:
                services.append({"asset": ip, "cpe": f"{ip}:{port}" + (f" {name}" if name else "")})
            for soft in (sv.get("software") or []):
                if not isinstance(soft, dict):
                    continue
                cpe = soft.get("uniform_resource_identifier") or soft.get("cpe")
                if cpe and str(cpe).startswith("cpe:"):
                    cpes.add(str(cpe))
                    services.append({"asset": ip, "cpe": str(cpe)})
    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": []}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Censys import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--query", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "query": a.query}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[censys] {len(res['assets'])} asset(s), {len(res['services'])} service(s), {len(res['cpes'])} cpe(s)", flush=True)
