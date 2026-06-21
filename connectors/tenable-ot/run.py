"""run.py — XORCISM connector: Tenable OT Security (Tenable.ot) → OT assets + vulns.

Parses a Tenable OT Security export of OT assets and their findings and maps it to the normalized
XORCISM result: each asset -> an ASSET (name/IP, with OS), each finding/CVE -> a vulnerability
(ref = CVE id, name, severity). Accepts JSON ({assets:[…], findings:[…]} or a bare list) or a CSV
of either assets or findings (auto-detected by columns).

Offline export parser only (no DB access; remote-worker safe). A live Tenable OT API path
(TENABLE_OT_URL + access/secret keys) is a future enhancement.
"""
from __future__ import annotations

import csv
import json
import re
from typing import Any, Dict, List, Optional

TOOL_NAME = "Tenable OT Security"
TOOL_URL = "https://www.tenable.com/products/tenable-ot-security"

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "info": "info", "informational": "info", "none": "info"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("tenable-ot: provide a 'file' (a Tenable OT assets/findings export, JSON or CSV)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if text.lstrip()[:1] in ("{", "["):
        assets, findings = _from_json(json.loads(text))
    else:
        assets, findings = _from_csv(text)
    return _build(assets, findings, str(params.get("project") or "").strip())


def _get(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
        for kk, vv in d.items():
            if kk.lower() == k.lower() and vv not in (None, ""):
                return vv
    return None


def _from_json(data: Any) -> tuple:
    if isinstance(data, dict):
        assets = data.get("assets") or data.get("items") or []
        findings = data.get("findings") or data.get("vulnerabilities") or data.get("plugins") or []
        if not assets and not findings and isinstance(data.get("data"), list):
            return _split(data["data"])
        return ([a for a in assets if isinstance(a, dict)], [f for f in findings if isinstance(f, dict)])
    if isinstance(data, list):
        return _split(data)
    return ([], [])


def _split(rows: List[Any]) -> tuple:
    assets, findings = [], []
    for r in rows:
        if not isinstance(r, dict):
            continue
        is_finding = _get(r, "cve", "cves", "cve_id", "plugin_id", "pluginID") or _CVE_RE.search(json.dumps(r))
        (findings if is_finding else assets).append(r)
    return assets, findings


def _from_csv(text: str) -> tuple:
    return _split(list(csv.DictReader(text.splitlines())))


def _build(assets_in: List[Dict[str, Any]], findings: List[Dict[str, Any]], project: str) -> Dict[str, Any]:
    id2name: Dict[str, str] = {}
    assets: Dict[str, Dict[str, Any]] = {}

    def add(name: str, ip: Optional[str] = None, os_: Optional[str] = None) -> str:
        name = project or name
        if name not in assets:
            a: Dict[str, Any] = {"hostname": name, "key": name}
            if ip:
                a["ip"] = str(ip)
            if os_:
                a["os"] = str(os_)
            assets[name] = a
        return name

    for a in assets_in:
        aid = _get(a, "id", "asset_id", "uuid", "mac", "mac_address")
        ip = _get(a, "ip", "ip_address", "addresses", "address")
        if isinstance(ip, list):
            ip = ip[0] if ip else None
        name = _get(a, "name", "hostname", "asset_name", "label") or ip or aid or "asset"
        os_ = _get(a, "os", "operating_system", "firmware", "model")
        nm = add(str(name), ip and str(ip), os_ and str(os_))
        if aid is not None:
            id2name[str(aid)] = nm

    out: List[Dict[str, Any]] = []
    seen: set = set()
    for f in findings:
        cve = _get(f, "cve", "cve_id")
        if isinstance(cve, list):
            cve = cve[0] if cve else None
        if not cve:
            m = _CVE_RE.search(json.dumps(f))
            cve = m.group(0).upper() if m else None
        cve = str(cve).strip() if cve else None
        if not cve:
            continue
        aid = _get(f, "asset_id", "asset", "id", "mac")
        host = (project or id2name.get(str(aid))) if aid is not None else None
        if not host:
            host = project or str(_get(f, "asset_name", "ip", "ip_address", "hostname") or "Tenable OT")
            add(host)
        name = str(_get(f, "name", "plugin_name", "title", "synopsis") or cve)
        sev = _SEV.get(str(_get(f, "severity", "risk", "risk_factor", "vpr") or "").strip().lower(), "medium")
        key = (host, cve)
        if key in seen:
            continue
        seen.add(key)
        out.append({"asset": host, "ref": cve, "name": name[:300], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": out, "source": "Tenable OT Security"}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Tenable OT import (dry run)")
    ap.add_argument("--file", required=True)
    ap.add_argument("--project", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "project": a.project}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[tenable-ot] {len(res['assets'])} OT asset(s), {len(res['vulns'])} finding(s)", flush=True)
