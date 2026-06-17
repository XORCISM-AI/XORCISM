"""run.py — XORCISM connector: Security Suite → assets / services / CPEs / vulns.

Security Suite (https://github.com/TheSecuredAnalyst/security-suite) is an all-in-one
Python offensive toolkit (OSINT recon, web/API scanners, vulnerability scanning).

Offline: parse a Security Suite JSON export (`secsuite ... --json -o <file>`).
Live:    if `target` is set and the `secsuite` binary is on PATH, run it and parse.

Mapping into the normalized XORCISM result {assets, services, cpes, vulns}:
  - subdomains / hosts / DNS A-records  -> ASSET (hostname + IP)
  - detected technologies               -> service {asset, cpe} + global cpes
  - scanner findings (XSS, SQLi, SSL…)  -> VULNERABILITY {asset, ref, name, severity}

The Security Suite JSON schema is parsed defensively (several key spellings are
accepted and unknown shapes are ignored) so the connector tolerates version drift.
No DB access here (worker-safe).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List

_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_HOSTISH = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})+$")

_HOST_KEYS = ("subdomains", "subdomain", "hosts", "host", "domains", "domain", "targets")
_IP_KEYS = ("ips", "ip", "addresses", "a_records", "a", "ipv4")
_TECH_KEYS = ("technologies", "technology", "tech", "stack", "products", "fingerprints")
_VULN_KEYS = ("vulnerabilities", "vulns", "findings", "issues", "alerts", "results")
_SEV_KEYS = ("severity", "risk", "level", "criticality")
_NAME_KEYS = ("name", "title", "type", "vuln", "issue", "check", "id")
_REF_KEYS = ("reference", "ref", "id", "cve", "url", "link", "external_id")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        target = str(params.get("target") or "").strip()
    else:
        target = str(params.get("target") or "").strip()
        if not target:
            raise RuntimeError("security-suite: provide a 'file' (JSON export) or a 'target' for live mode")
        data = _run_secsuite(target, str(params.get("command") or "scan"), workdir)
    return _parse(data, target)


def _run_secsuite(target: str, command: str, workdir: str) -> Any:
    exe = shutil.which("secsuite") or shutil.which("security-suite")
    if not exe:
        raise RuntimeError("secsuite binary not found on PATH; use the 'file' parameter (offline JSON export) instead")
    out = os.path.join(workdir, "secsuite.json")
    # Best-effort invocation; the suite exposes `--json -o <file>` on its scan commands.
    argv = [exe] + command.split() + [target, "--json", "-o", out]
    subprocess.run(argv, timeout=3600, check=False)  # noqa: S603
    if not os.path.exists(out):
        raise RuntimeError("secsuite produced no JSON output; check the command, or import a JSON export via 'file'")
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _norm_sev(v: Any) -> str:
    s = str(v or "").strip().lower()
    if s in ("critical", "crit"):
        return "Critical"
    if s in ("high",):
        return "High"
    if s in ("medium", "med", "moderate"):
        return "Medium"
    if s in ("low",):
        return "Low"
    if s in ("info", "informational", "none"):
        return "Info"
    return s[:20] if s else ""


def _parse(data: Any, target: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, str]] = []
    cpes: set = set()
    vulns: List[Dict[str, str]] = []

    def add_asset(host: str = "", ip: str = "") -> str:
        host = str(host or "").strip().lower().rstrip(".")
        ip = str(ip or "").strip()
        if host and _IPV4.match(host) and not ip:  # host slot actually holds an IP
            host, ip = "", host
        key = host or ip
        if not key:
            return ""
        a = assets.setdefault(key, {"hostname": key, "key": key})
        if ip and not a.get("ip"):
            a["ip"] = ip
        return key

    default_key = add_asset(target) if target else ""

    def pull_host(item: Any) -> str:
        if isinstance(item, str):
            return add_asset(item) if (_HOSTISH.match(item.strip()) or _IPV4.match(item.strip())) else ""
        if isinstance(item, dict):
            host = item.get("host") or item.get("name") or item.get("hostname") or item.get("subdomain") or item.get("domain") or ""
            ip = item.get("ip") or item.get("address") or item.get("ipv4") or ""
            return add_asset(host, ip)
        return ""

    def pull_tech(item: Any, asset_key: str) -> None:
        label = item if isinstance(item, str) else (
            item.get("cpe") or item.get("name") or item.get("product") or item.get("technology") if isinstance(item, dict) else None)
        if not label:
            return
        label = str(label).strip()
        if not label:
            return
        cpes.add(label)
        if asset_key:
            services.append({"asset": asset_key, "cpe": label})

    def pull_vuln(item: Any, asset_key: str) -> None:
        if isinstance(item, str):
            vulns.append({"asset": asset_key or default_key, "ref": item, "name": item, "severity": ""})
            return
        if not isinstance(item, dict):
            return
        name = next((str(item[k]) for k in _NAME_KEYS if item.get(k)), "")
        ref = next((str(item[k]) for k in _REF_KEYS if item.get(k)), "") or name
        sev = _norm_sev(next((item[k] for k in _SEV_KEYS if item.get(k)), ""))
        akey = pull_host(item.get("asset") or item.get("host") or item.get("target") or {}) or asset_key or default_key
        if name or ref:
            vulns.append({"asset": akey, "ref": ref or name, "name": name or ref, "severity": sev})

    def walk(node: Any, asset_key: str, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            local_key = asset_key
            # a host context at this level updates the "current" asset
            if any(k in node for k in ("host", "hostname", "subdomain")) and not any(k in node for k in _VULN_KEYS):
                hk = pull_host(node)
                if hk:
                    local_key = hk
            for k, v in node.items():
                lk = k.lower()
                if lk in _HOST_KEYS and isinstance(v, list):
                    for it in v:
                        pull_host(it)
                elif lk in _IP_KEYS:
                    for it in (v if isinstance(v, list) else [v]):
                        if isinstance(it, str):
                            add_asset("", it)
                elif lk in _TECH_KEYS and isinstance(v, (list, dict)):
                    for it in (v.values() if isinstance(v, dict) else v):
                        pull_tech(it, local_key)
                elif lk in _VULN_KEYS and isinstance(v, list):
                    for it in v:
                        pull_vuln(it, local_key)
                else:
                    walk(v, local_key, depth + 1)
        elif isinstance(node, list):
            for it in node:
                walk(it, asset_key, depth + 1)

    walk(data, default_key)
    return {"assets": list(assets.values()), "services": services,
            "cpes": sorted(cpes), "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Security Suite import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target}, tempfile.mkdtemp()), indent=2))
