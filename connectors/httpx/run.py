"""run.py — XORCISM connector: ProjectDiscovery httpx → assets + services.

Offline: parse an httpx JSON-lines output (`httpx -json`).
Live:    if `target` is given and the `httpx` binary is on PATH, run
         `httpx -json -silent` against it.

Each probed host -> ASSET (hostname + resolved IP); each live URL -> SERVICE;
detected technologies (`tech`) -> component CPEs on the asset. No DB access.
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
            text = fh.read()
    else:
        target = str(params.get("target") or "").strip()
        if not target:
            raise RuntimeError("httpx: provide a 'file' (httpx -json output) or a 'target' for live mode")
        text = _run_httpx(target, workdir)
    return _parse(text)


def _run_httpx(target: str, workdir: str) -> str:
    exe = shutil.which("httpx")
    if not exe:
        raise RuntimeError("httpx binary not found on PATH; use the 'file' parameter instead")
    cmd = [exe, "-json", "-silent", "-tech-detect"]
    cmd += (["-l", target] if os.path.exists(target) else ["-u", target])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)  # noqa: S603
    return p.stdout or ""


def _parse(text: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []
    cpes: set = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(r, dict):
            continue
        host_field = str(r.get("input") or r.get("host") or "").strip().lower()
        ips = r.get("a") or []
        ip = next((str(x) for x in ips if x), "")
        if not ip and _IPV4.match(host_field):
            ip = host_field
        hostname = host_field if host_field and not _IPV4.match(host_field) else (ip or host_field)
        key = hostname or ip
        if not key:
            continue
        a = assets.setdefault(key, {"hostname": hostname or key, "key": key})
        if ip and not a.get("ip"):
            a["ip"] = ip
        url = str(r.get("url") or "").strip()
        if url:
            sc = r.get("status_code")
            services.append({"asset": key, "cpe": url + (f" [{sc}]" if sc else "")})
        for tech in (r.get("tech") or r.get("technologies") or []):
            if tech:
                cname = f"tech:{tech}"
                cpes.add(cname)
                services.append({"asset": key, "cpe": cname})
    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": []}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="httpx import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "target": a.target}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[httpx] {len(res['assets'])} asset(s), {len(res['services'])} service(s)", flush=True)
