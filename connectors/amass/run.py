"""run.py — XORCISM connector: OWASP Amass → assets.

Offline: parse an `amass enum -json` output file (JSON lines or a JSON array).
Live:    if `domain` is given and the `amass` binary is on PATH, run
         `amass enum -d <domain> -json <tmp>` and parse it.

Each discovered name → an ASSET {hostname, key, ip?}. No DB access (worker-safe):
returns the normalized result {assets, services, cpes, vulns}.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        domain = str(params.get("domain") or params.get("target") or "").strip()
        if not domain:
            raise RuntimeError("amass: provide a 'file' (amass -json output) or a 'domain' for live mode")
        text = _run_amass(domain, workdir)
    return {"assets": _parse(text), "services": [], "cpes": [], "vulns": []}


def _run_amass(domain: str, workdir: str) -> str:
    exe = shutil.which("amass")
    if not exe:
        raise RuntimeError("amass binary not found on PATH; use the 'file' parameter instead")
    out = os.path.join(workdir, "amass.json")
    subprocess.run([exe, "enum", "-d", domain, "-json", out], timeout=1800, check=False)  # noqa: S603
    if not os.path.exists(out):
        return ""
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _load_records(text: str) -> List[Dict[str, Any]]:
    text = (text or "").strip()
    if not text:
        return []
    try:  # JSON array or single object
        d = json.loads(text)
        if isinstance(d, list):
            return [x for x in d if isinstance(x, dict)]
        if isinstance(d, dict):
            return [d]
    except Exception:  # noqa: BLE001 — fall back to JSON-lines
        pass
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            if isinstance(o, dict):
                out.append(o)
        except Exception:  # noqa: BLE001
            continue
    return out


def _parse(text: str) -> List[Dict[str, Any]]:
    assets: Dict[str, Dict[str, Any]] = {}
    for r in _load_records(text):
        name = str(r.get("name") or r.get("hostname") or "").strip().lower().rstrip(".")
        if not name:
            continue
        a = assets.setdefault(name, {"hostname": name, "key": name})
        for addr in (r.get("addresses") or []):
            ip = (addr.get("ip") if isinstance(addr, dict) else str(addr)).strip()
            if ip and not a.get("ip"):
                a["ip"] = ip
    return list(assets.values())


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Amass import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--domain", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "domain": a.domain}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[amass] {len(res['assets'])} asset(s)", flush=True)
