"""run.py — XORCISM connector: BloodHound (SharpHound) computers → assets.

Parses a SharpHound / BloodHound `computers.json` (or any export shaped like
`{"data":[{"Properties":{"name":..., "operatingsystem":...}}]}`, or a bare list of
computer objects). Each computer becomes an ASSET (FQDN hostname + OS).

Offline import of already-collected AD data — no DB access (worker-safe): returns
the normalized result {assets, services, cpes, vulns}.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if not params.get("file"):
        raise RuntimeError("bloodhound: a 'file' (computers.json) is required")
    with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return {"assets": _parse(data), "services": [], "cpes": [], "vulns": []}


def _find_items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            return [x for x in data["data"] if isinstance(x, dict)]
        if data.get("Properties") or data.get("properties"):
            return [data]
    return []


def _parse(data: Any) -> List[Dict[str, Any]]:
    assets: Dict[str, Dict[str, Any]] = {}
    for it in _find_items(data):
        props = it.get("Properties") or it.get("properties") or it
        if not isinstance(props, dict):
            continue
        name = str(props.get("name") or props.get("Name") or "").strip().lower().rstrip(".")
        if not name:
            continue
        a = assets.setdefault(name, {"hostname": name, "key": name})
        os_ = props.get("operatingsystem") or props.get("operatingSystem") or props.get("OperatingSystem")
        if os_ and not a.get("os"):
            a["os"] = str(os_)
    return list(assets.values())


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="BloodHound computers import (dry run)")
    ap.add_argument("--file", required=True)
    a = ap.parse_args()
    res = run({"file": a.file}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[bloodhound] {len(res['assets'])} asset(s)", flush=True)
