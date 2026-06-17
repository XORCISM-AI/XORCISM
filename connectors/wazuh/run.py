"""run.py — XORCISM connector: Wazuh → assets / components / CPEs / vulns.

Wazuh (https://wazuh.com) is an open-source XDR/SIEM. This connector imports its
endpoint inventory and vulnerability findings:
  - each Wazuh agent             -> ASSET (name + IP + OS)
  - syscollector packages        -> components/CPEs on that asset
  - vulnerability-detector items -> VULNERABILITY (CVE + severity) on its agent

Offline: parse a saved Wazuh API JSON. Wazuh wraps results as
         {"data": {"affected_items": [...]}, "error": 0}; this also accepts a bare
         list or a {agents, vulnerabilities, packages} bundle.
Live:    if `manager` (or WAZUH_API_URL) is set and WAZUH_API_USER / WAZUH_API_PASSWORD
         are in the worker env, authenticate (JWT) and pull /agents + per-agent
         /vulnerability (best-effort: removed from the API in Wazuh 4.8+). Needs `requests`.

No DB access here (worker-safe). Returns the normalized result
{assets, services, cpes, vulns}.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    agent_hint = str(params.get("agent") or "").strip()
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        base = str(params.get("manager") or os.getenv("WAZUH_API_URL") or "").strip()
        if not base:
            raise RuntimeError("wazuh: provide a 'file' (Wazuh JSON export) or a 'manager' URL (+ WAZUH_API_USER/WAZUH_API_PASSWORD env) for live mode")
        data = _fetch(base, int(params.get("limit") or 200))
    return _parse(data, agent_hint)


# ── Live API ────────────────────────────────────────────────────────────────
def _fetch(base: str, limit: int) -> Dict[str, Any]:
    import requests  # noqa: PLC0415

    user = os.getenv("WAZUH_API_USER") or ""
    pw = os.getenv("WAZUH_API_PASSWORD") or ""
    if not user or not pw:
        raise RuntimeError("WAZUH_API_USER and WAZUH_API_PASSWORD required in the worker env for live mode")
    verify = (os.getenv("WAZUH_VERIFY_TLS") or "false").lower() in ("1", "true", "yes")
    base = base.rstrip("/")
    sess = requests.Session()
    sess.verify = verify
    if not verify:
        try:
            import urllib3  # noqa: PLC0415
            urllib3.disable_warnings()
        except Exception:  # noqa: BLE001
            pass

    auth = sess.post(f"{base}/security/user/authenticate", auth=(user, pw), timeout=60)
    if auth.status_code != 200:
        raise RuntimeError(f"Wazuh auth HTTP {auth.status_code}: {auth.text[:200]}")
    token = (auth.json().get("data") or {}).get("token")
    if not token:
        raise RuntimeError("Wazuh auth returned no token")
    hdr = {"Authorization": f"Bearer {token}"}

    def items(path: str) -> List[Dict[str, Any]]:
        r = sess.get(f"{base}{path}", headers=hdr, timeout=120)
        if r.status_code != 200:
            return []
        return ((r.json().get("data") or {}).get("affected_items") or [])

    agents = items(f"/agents?limit={limit}&select=id,name,ip,os")
    vulns: List[Dict[str, Any]] = []
    packages: List[Dict[str, Any]] = []
    for a in agents:
        aid = str(a.get("id") or "").strip()
        name = a.get("name") or aid
        if not aid or aid == "000":  # 000 = the manager itself
            continue
        for v in items(f"/vulnerability/{aid}?limit=2000"):
            v["_agent"] = name
            vulns.append(v)
        for p in items(f"/syscollector/{aid}/packages?limit=2000&select=name,version,vendor,architecture"):
            p["_agent"] = name
            packages.append(p)
    return {"agents": agents, "vulnerabilities": vulns, "packages": packages}


# ── Mapping ───────────────────────────────────────────────────────────────────
def _os_name(item: Dict[str, Any]) -> str:
    os_v = item.get("os")
    if isinstance(os_v, dict):
        return str(os_v.get("name") or os_v.get("platform") or "").strip()
    return str(os_v or "").strip()


def _parse(data: Any, agent_hint: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, str]] = []
    cpes: set = set()
    vulns: List[Dict[str, str]] = []

    def add_asset(name: Any = "", ip: Any = "", os_name: str = "") -> str:
        key = str(name or "").strip()
        if not key:
            return ""
        a = assets.setdefault(key, {"hostname": key, "key": key})
        if ip and not a.get("ip"):
            a["ip"] = str(ip).strip()
        if os_name and not a.get("os"):
            a["os"] = os_name
        return key

    def is_agent(it: Dict[str, Any]) -> bool:
        return ("os" in it or "ip" in it) and ("name" in it or "id" in it) and "cve" not in it

    def is_vuln(it: Dict[str, Any]) -> bool:
        return bool(it.get("cve")) or bool(_CVE.search(str(it.get("name") or it.get("title") or "")))

    def add_vuln(it: Dict[str, Any]) -> None:
        ref = str(it.get("cve") or "").strip()
        if not ref:
            m = _CVE.search(str(it.get("name") or it.get("title") or ""))
            ref = m.group(0).upper() if m else ""
        name = str(it.get("title") or it.get("condition") or it.get("name") or ref).strip()
        sev = str(it.get("severity") or "").strip().capitalize()
        akey = str(it.get("_agent") or it.get("agent_name") or agent_hint or "").strip()
        if ref or name:
            vulns.append({"asset": akey, "ref": ref or name, "name": name or ref, "severity": sev})

    def add_package(it: Dict[str, Any]) -> None:
        name = str(it.get("name") or "").strip()
        if not name:
            return
        ver = str(it.get("version") or "").strip()
        label = f"{name} {ver}".strip()
        cpes.add(label)
        akey = str(it.get("_agent") or agent_hint or "").strip()
        if akey:
            services.append({"asset": akey, "cpe": label})

    # Wazuh wraps results as {"data": {"affected_items": [...]}}.
    def affected(node: Any) -> List[Dict[str, Any]]:
        if isinstance(node, dict):
            d = node.get("data")
            if isinstance(d, dict) and isinstance(d.get("affected_items"), list):
                return d["affected_items"]
        return node if isinstance(node, list) else []

    if isinstance(data, dict) and any(k in data for k in ("agents", "vulnerabilities", "packages")):
        for a in affected(data.get("agents")):
            add_asset(a.get("name") or a.get("id"), a.get("ip", ""), _os_name(a))
        for v in affected(data.get("vulnerabilities")):
            add_vuln(v)
        for p in affected(data.get("packages")):
            add_package(p)
    else:
        for it in affected(data):
            if not isinstance(it, dict):
                continue
            if is_vuln(it):
                add_vuln(it)
            elif is_agent(it):
                add_asset(it.get("name") or it.get("id"), it.get("ip", ""), _os_name(it))

    # Ensure every referenced agent exists as an asset.
    for v in vulns:
        if v["asset"]:
            add_asset(v["asset"])
    for s in services:
        add_asset(s["asset"])

    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Wazuh import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--agent", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "agent": a.agent}, tempfile.mkdtemp()), indent=2))
