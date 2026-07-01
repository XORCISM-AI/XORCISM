"""Faraday connector — normalize a Faraday (github.com/infobyte/faraday, GPL-3.0) workspace export
into XORCISM's finding shape (assets + vulns), so Faraday-aggregated results flow into the exposure
pipeline via the runner's import_findings path.

Faraday is the open-source collaborative vulnerability manager: ~90 plugins ingest many scanners
(Nessus/Nmap/Burp/OpenVAS/Qualys/Nuclei/…) into one Workspace -> Host -> Service -> Vulnerability
model (severity, CVE/refs, CVSS, status, confirmed), deduplicated. This connector consumes that
aggregated output (a faraday-cli / REST-GraphQL export) and maps Hosts -> ASSET and Vulnerabilities
-> VULNERABILITY (+ ASSETVULNERABILITY), preserving the CVE ref and CVSS.

Worker-safe & read-only: parses an exported JSON only (no scanning). Tolerant of Faraday's shapes
(top-level lists, {rows:[{value:{...}}]} wrappers, cvss3/cvss2 objects, refs typed cve/cwe/exploit).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

CVE_RX = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
OPEN_STATUSES = {"", "open", "opened", "re-opened", "reopened", "re_opened"}


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _unwrap(x: Any) -> Dict[str, Any]:
    """Faraday API rows are {"value": {...}} (or {"_source": {...}}); flatten to the object."""
    if isinstance(x, dict):
        if isinstance(x.get("value"), dict):
            return x["value"]
        if isinstance(x.get("_source"), dict):
            return x["_source"]
        return x
    return {}


def _listof(doc: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(doc, list):
        return [_unwrap(x) for x in doc if isinstance(x, dict)]
    if isinstance(doc, dict):
        for k in keys:
            v = doc.get(k)
            if isinstance(v, list):
                return [_unwrap(x) for x in v if isinstance(x, dict)]
    return []


def _cvss(v: Dict[str, Any]) -> Any:
    for k in ("cvss3", "cvss2", "cvssv3", "cvssv2", "cvss"):
        c = v.get(k)
        if isinstance(c, dict):
            for kk in ("base_score", "score", "base"):
                if c.get(kk) is not None:
                    return c[kk]
        elif isinstance(c, (int, float)):
            return c
    return None


def _cve(v: Dict[str, Any]) -> str:
    # explicit cve list/string
    cve = v.get("cve")
    if isinstance(cve, list):
        for c in cve:
            m = CVE_RX.search(str(c))
            if m:
                return m.group(0).upper()
    elif isinstance(cve, str):
        m = CVE_RX.search(cve)
        if m:
            return m.group(0).upper()
    # refs (Faraday: [{name, type}] or ["CVE-...", ...])
    for r in (v.get("refs") or v.get("references") or []):
        name = r.get("name") if isinstance(r, dict) else r
        m = CVE_RX.search(str(name or ""))
        if m:
            return m.group(0).upper()
    return ""


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")[:60]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    path = params.get("file") or os.path.join(here, "sample.json")
    if not os.path.isabs(path) and not os.path.exists(path):
        cand = os.path.join(workdir or here, path)
        if os.path.exists(cand):
            path = cand
    try:
        doc = _load(path)
    except FileNotFoundError:
        return {"assets": [], "vulns": [], "error": "file not found: %s" % path}
    except (json.JSONDecodeError, ValueError) as exc:
        return {"assets": [], "vulns": [], "error": "not valid JSON: %s" % exc}

    ws = str(params.get("workspace") or (doc.get("workspace") if isinstance(doc, dict) else "") or "faraday").strip()
    include_closed = str(params.get("include_closed")).lower() in ("1", "true", "yes")

    # ── Hosts -> assets ──
    assets: List[Dict[str, Any]] = []
    host_key: Dict[str, str] = {}  # ip / id -> asset name
    for h in _listof(doc, "hosts", "rows"):
        ip = str(h.get("ip") or h.get("address") or "").strip()
        names = h.get("hostnames") or h.get("hostname") or []
        if isinstance(names, str):
            names = [names]
        name = (names[0] if names else "") or ip or str(h.get("_id") or h.get("id") or "").strip()
        if not name:
            continue
        assets.append({"hostname": name, "ip": ip, "key": ip or name})
        if ip:
            host_key[ip] = name
        for idk in (h.get("_id"), h.get("id")):
            if idk is not None:
                host_key[str(idk)] = name

    # ── Vulnerabilities -> vulns ──
    vulns: List[Dict[str, Any]] = []
    seen_names = {a["hostname"] for a in assets}
    for v in _listof(doc, "vulnerabilities", "vulns", "rows"):
        status = str(v.get("status") or "").lower()
        if not include_closed and status not in OPEN_STATUSES:
            continue
        target = str(v.get("target") or v.get("host") or v.get("ip")
                     or (v.get("host_id") if v.get("host_id") is not None else "")).strip()
        asset = host_key.get(target, target)
        if asset and asset not in seen_names:
            assets.append({"hostname": asset, "key": asset})
            seen_names.add(asset)
        cve = _cve(v)
        name = str(v.get("name") or v.get("summary") or "Vulnerability").strip()
        # ref = the CVE when present (dedup by CVE across hosts/tools); else a stable Faraday key
        ref = cve or ("faraday:%s:%s" % (_slug(ws), _slug(name)))
        vulns.append({
            "asset": asset, "ref": ref, "name": name,
            "severity": str(v.get("severity") or "").strip().lower(),
            "cvss": _cvss(v), "cve": cve, "confirmed": bool(v.get("confirmed")),
            "status": status or "open", "workspace": ws,
        })

    return {"assets": assets, "vulns": vulns, "workspace": ws, "host_count": len(assets), "vuln_count": len(vulns)}


if __name__ == "__main__":  # python run.py [export.json]
    import sys
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    res = run(p, os.getcwd())
    print(json.dumps({k: (v if k not in ("assets", "vulns") else "[%d]" % len(v)) for k, v in res.items()}, indent=2))
