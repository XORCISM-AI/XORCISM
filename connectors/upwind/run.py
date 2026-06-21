"""run.py — XORCISM connector: Upwind (CNAPP) cloud-security findings -> assets + findings.

Upwind (https://www.upwind.io) is a runtime-powered CNAPP. This connector imports its findings
(vulnerabilities, misconfigurations, runtime threats): each affected cloud resource / host /
image -> ASSET, each finding -> VULNERABILITY / ASSETVULNERABILITY (ref = CVE if present else
UPWIND-<hash>, severity from the risk level).

Offline: export findings to JSON (`file`). Live: env UPWIND_API_URL + UPWIND_CLIENT_ID +
UPWIND_CLIENT_SECRET (OAuth2 client-credentials, best-effort). No DB access (worker-safe).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

_SEV = {"critical": "critical", "crit": "critical", "high": "high", "medium": "medium",
        "med": "medium", "moderate": "medium", "low": "low", "info": "info",
        "informational": "info", "none": "info", "negligible": "info"}
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        data = _fetch_live()
    return _parse(data, str(params.get("project") or params.get("target") or "").strip())


def _fetch_live() -> Any:
    base = (os.environ.get("UPWIND_API_URL") or "").strip().rstrip("/")
    cid = (os.environ.get("UPWIND_CLIENT_ID") or "").strip()
    sec = (os.environ.get("UPWIND_CLIENT_SECRET") or "").strip()
    tok = (os.environ.get("UPWIND_TOKEN") or "").strip()
    if not base or not (tok or (cid and sec)):
        raise RuntimeError("upwind: provide a 'file' (findings JSON) or set env UPWIND_API_URL + UPWIND_CLIENT_ID/SECRET (or UPWIND_TOKEN)")
    import urllib.request
    if not tok:
        body = json.dumps({"client_id": cid, "client_secret": sec, "grant_type": "client_credentials"}).encode()
        req = urllib.request.Request(base + "/oauth/token", data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
                tok = str((json.loads(r.read().decode("utf-8", "replace")) or {}).get("access_token") or "")
        except Exception as e:
            raise RuntimeError(f"upwind: OAuth token request failed ({e})")
    headers = {"Authorization": "Bearer " + tok, "Accept": "application/json", "User-Agent": "XORCISM-upwind"}
    for ep in ("/v1/findings", "/api/v1/findings", "/findings", "/v1/vulnerabilities"):
        try:
            req = urllib.request.Request(base + ep, headers=headers)
            with urllib.request.urlopen(req, timeout=45) as r:  # noqa: S310
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            continue
    raise RuntimeError("upwind live: no findings endpoint responded. Use a 'file' export instead.")


def _find_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("findings", "vulnerabilities", "vulns", "issues", "results", "data", "items", "alerts"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        for v in data.values():
            if isinstance(v, dict):
                got = _find_list(v)
                if got:
                    return got
    return []


def _first(d: Dict[str, Any], keys, default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, dict):
            v = v.get("name") or v.get("id") or v.get("arn") or v.get("displayName")
        if v not in (None, "", [], {}):
            return str(v).strip()
    return default


def _target_of(f: Dict[str, Any], fallback: str) -> str:
    raw = _first(f, ("resource", "resourceName", "asset", "host", "hostname", "image", "imageName",
                     "instance", "container", "cloudResource", "target", "arn", "uri", "url", "ip"))
    if not raw:
        return fallback
    if "://" in raw:
        try:
            h = urlparse(raw).hostname
            if h:
                return h
        except Exception:
            pass
    return raw


def _parse(data: Any, default_target: str) -> Dict[str, Any]:
    items = _find_list(data)
    fallback = default_target or "upwind-cloud"
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen: set = set()

    for f in items:
        title = _first(f, ("title", "name", "finding", "issue", "rule", "type", "category", "description"), "Finding")
        target = _target_of(f, fallback)
        sev = _SEV.get(_first(f, ("severity", "risk", "riskLevel", "risk_level", "level", "priority")).lower(), "medium")
        blob = " ".join(str(f.get(k, "")) for k in ("cve", "cves", "cveId", "references", "title", "name", "description", "id"))
        cve = _CVE.search(blob)
        ref = cve.group(0).upper() if cve else "UPWIND-" + hashlib.sha1(f"{title}|{target}".encode("utf-8")).hexdigest()[:12]
        kind = _first(f, ("type", "category", "findingType"))
        name = f"{title}{(' [' + kind + ']') if kind and kind.lower() not in title.lower() else ''}"
        key = (target, ref)
        if key in seen:
            continue
        seen.add(key)
        assets.setdefault(target, {"hostname": target, "key": target})
        vulns.append({"asset": target, "ref": ref, "name": name[:300], "severity": sev})

    return {"project": fallback, "assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Upwind import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--project", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "project": a.project}, "")
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[upwind] {len(res['assets'])} asset(s), {len(res['vulns'])} finding(s)", flush=True)
