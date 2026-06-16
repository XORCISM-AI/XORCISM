"""run.py — XORCISM connector: ProjectDiscovery naabu → assets + services.

Offline: parse a naabu JSON-lines output (`naabu -json`) or a plain `host:port`
         list (one per line).
Live:    if `target` is given and the `naabu` binary is on PATH, run `naabu -json`.

Each scanned host -> ASSET (host + IP); each open port -> SERVICE (host:port).
No DB access (worker-safe).
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
            raise RuntimeError("naabu: provide a 'file' (naabu output) or a 'target' for live mode")
        text = _run_naabu(target, workdir)
    return _parse(text)


def _run_naabu(target: str, workdir: str) -> str:
    exe = shutil.which("naabu")
    if not exe:
        raise RuntimeError("naabu binary not found on PATH; use the 'file' parameter instead")
    cmd = [exe, "-json", "-silent"]
    cmd += (["-list", target] if os.path.exists(target) else ["-host", target])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)  # noqa: S603
    return p.stdout or ""


def _parse(text: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []

    def add(host: str, ip: str, port, proto: str = "tcp") -> None:
        host = (host or ip or "").strip().lower()
        ip = (ip or "").strip()
        key = host or ip
        if not key:
            return
        a = assets.setdefault(key, {"hostname": host or ip, "key": key})
        if ip and not a.get("ip"):
            a["ip"] = ip
        if port:
            services.append({"asset": key, "cpe": f"{key}:{port}/{proto}"})

    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if isinstance(r, dict):
                add(str(r.get("host") or ""), str(r.get("ip") or ""), r.get("port"),
                    str(r.get("protocol") or "tcp"))
        elif ":" in line:
            host, port = line.rsplit(":", 1)
            if port.split("/")[0].isdigit():
                add(host, host if _IPV4.match(host) else "", port.split("/")[0])
    return {"assets": list(assets.values()), "services": services, "cpes": [], "vulns": []}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="naabu import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "target": a.target}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[naabu] {len(res['assets'])} asset(s), {len(res['services'])} service(s)", flush=True)
