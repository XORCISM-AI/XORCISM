"""run.py — XORCISM connector: theHarvester → assets.

Offline: parse a theHarvester JSON output file (`theHarvester -f <name>`).
Live:    if `domain` is given and the `theHarvester` binary is on PATH, run it.

Hosts (and "host:ip" entries) and bare IP addresses become ASSETs. No DB access
(worker-safe): returns the normalized result {assets, services, cpes, vulns}.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List

_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        domain = str(params.get("domain") or params.get("target") or "").strip()
        if not domain:
            raise RuntimeError("theharvester: provide a 'file' (JSON output) or a 'domain' for live mode")
        data = _run_harvester(domain, str(params.get("sources") or "all"), workdir)
    return {"assets": _parse(data), "services": [], "cpes": [], "vulns": []}


def _run_harvester(domain: str, sources: str, workdir: str) -> Dict[str, Any]:
    exe = shutil.which("theHarvester") or shutil.which("theharvester")
    if not exe:
        raise RuntimeError("theHarvester binary not found on PATH; use the 'file' parameter instead")
    base = os.path.join(workdir, "harvest")
    subprocess.run([exe, "-d", domain, "-b", sources, "-f", base], timeout=1800, check=False)  # noqa: S603
    path = base + ".json"
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _parse(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    assets: Dict[str, Dict[str, Any]] = {}

    def add(host: str = "", ip: str = "") -> None:
        host = host.strip().lower().rstrip(".")
        ip = ip.strip()
        key = host or ip
        if not key:
            return
        a = assets.setdefault(key, {"hostname": key, "key": key})
        if ip and not a.get("ip"):
            a["ip"] = ip

    for h in (data.get("hosts") or []):
        s = str(h).strip()
        if ":" in s:
            host, ip = s.rsplit(":", 1)
            add(host, ip if _IPV4.match(ip.strip()) else "")
        else:
            add(s, "")
    for ip in (data.get("ips") or []):
        add("", str(ip))
    return list(assets.values())


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="theHarvester import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--domain", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "domain": a.domain}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[theharvester] {len(res['assets'])} asset(s)", flush=True)
