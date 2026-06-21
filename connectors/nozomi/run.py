"""run.py — XORCISM connector: Nozomi Networks (Guardian/Vantage) → OT assets + findings.

Parses a Nozomi export of OT/IoT assets and their vulnerabilities and maps it to the normalized
XORCISM result: each node -> an ASSET (hostname = label/IP, with IP & OS), each vulnerability/CVE
-> a finding (ref = CVE id, name, severity). Accepts JSON ({nodes:[…], vulnerabilities:[…]} or a
bare list) or a CSV of either assets or vulnerabilities (auto-detected by columns).

Offline export parser only (no DB access, so it also runs on a remote worker). A live Vantage /
Guardian API path (NOZOMI_URL + NOZOMI_API_KEY) is a future enhancement.
"""
from __future__ import annotations

import csv
import json
from typing import Any, Dict, List, Optional

TOOL_NAME = "Nozomi Networks"
TOOL_URL = "https://www.nozominetworks.com"

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "info": "info", "informational": "info", "none": "info"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("nozomi: provide a 'file' (a Nozomi assets/vulnerabilities export, JSON or CSV)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        nodes, vulns = _from_json(json.loads(text))
    else:
        nodes, vulns = _from_csv(text)
    return _build(nodes, vulns, str(params.get("project") or "").strip())


def _get(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
        # case-insensitive fallback
        for kk, vv in d.items():
            if kk.lower() == k.lower() and vv not in (None, ""):
                return vv
    return None


def _from_json(data: Any) -> tuple:
    if isinstance(data, dict):
        nodes = data.get("nodes") or data.get("assets") or []
        vulns = data.get("vulnerabilities") or data.get("cves") or data.get("vulns") or []
        if not nodes and not vulns and isinstance(data.get("result"), list):
            # a flat result list — split by shape
            return _split_records(data["result"])
        return ([n for n in nodes if isinstance(n, dict)], [v for v in vulns if isinstance(v, dict)])
    if isinstance(data, list):
        return _split_records(data)
    return ([], [])


def _split_records(rows: List[Any]) -> tuple:
    nodes, vulns = [], []
    for r in rows:
        if not isinstance(r, dict):
            continue
        (vulns if _get(r, "cve", "cve_id", "cve_ids") else nodes).append(r)
    return nodes, vulns


def _from_csv(text: str) -> tuple:
    rows = list(csv.DictReader(text.splitlines()))
    return _split_records(rows)


def _build(nodes: List[Dict[str, Any]], vulns: List[Dict[str, Any]], project: str) -> Dict[str, Any]:
    # node id -> asset name (label/ip), so vulnerabilities referencing a node id resolve.
    id2name: Dict[str, str] = {}
    assets: Dict[str, Dict[str, Any]] = {}

    def add_asset(name: str, ip: Optional[str] = None, os_: Optional[str] = None) -> str:
        name = project or name
        if name not in assets:
            a: Dict[str, Any] = {"hostname": name, "key": name}
            if ip:
                a["ip"] = str(ip)
            if os_:
                a["os"] = str(os_)
            assets[name] = a
        return name

    for n in nodes:
        nid = _get(n, "id", "uuid", "node_id", "mac_address", "mac")
        ip = _get(n, "ip", "ip_address", "address")
        label = _get(n, "label", "name", "hostname") or ip or nid or "node"
        os_ = _get(n, "os", "firmware_version", "firmware", "product_name")
        nm = add_asset(str(label), ip and str(ip), os_ and str(os_))
        if nid is not None:
            id2name[str(nid)] = nm

    out_vulns: List[Dict[str, Any]] = []
    seen: set = set()
    for v in vulns:
        cve = _get(v, "cve", "cve_id")
        if isinstance(cve, list):
            cve = cve[0] if cve else None
        cve = str(cve).strip() if cve else None
        if not cve:
            continue
        nid = _get(v, "node_id", "asset_id", "id", "mac_address")
        host = project or id2name.get(str(nid)) if nid is not None else None
        if not host:
            host = project or str(_get(v, "ip", "ip_address", "label", "name") or "Nozomi OT")
            add_asset(host)
        name = str(_get(v, "name", "summary", "title") or cve)
        sev = _SEV.get(str(_get(v, "severity", "vulnerability_severity", "cvss_severity") or "").strip().lower(), "medium")
        key = (host, cve)
        if key in seen:
            continue
        seen.add(key)
        out_vulns.append({"asset": host, "ref": cve, "name": name[:300], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": out_vulns, "source": "Nozomi Networks"}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Nozomi import (dry run)")
    ap.add_argument("--file", required=True)
    ap.add_argument("--project", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "project": a.project}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[nozomi] {len(res['assets'])} OT asset(s), {len(res['vulns'])} finding(s)", flush=True)
