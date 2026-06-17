"""run.py — XORCISM connector: WPProbe → assets / components / CPEs / vulns.

WPProbe (https://github.com/Chocapikk/wpprobe) is a fast WordPress plugin/theme
scanner that correlates discovered components with known CVEs.

Offline: parse a WPProbe JSON export (`wpprobe scan -u <url> -o out.json`).
Live:    if `target` is set and the `wpprobe` binary is on PATH, run a scan and parse.

Mapping into the normalized XORCISM result {assets, services, cpes, vulns}:
  - scanned site URL          -> ASSET (host)
  - detected plugin / theme   -> component/CPE on that asset (name + version)
  - correlated CVE finding    -> VULNERABILITY (CVE ref + title + severity)

The WPProbe JSON shape is parsed defensively (nested {plugins:[{vulnerabilities:[…]}]}
or flat finding rows, list or {results:[…]} wrapper). No DB access (worker-safe).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.parse
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        target = str(params.get("target") or "").strip()
    else:
        target = str(params.get("target") or "").strip()
        if not target:
            raise RuntimeError("wpprobe: provide a 'file' (JSON export) or a 'target' URL for live mode")
        data = _run_wpprobe(target, str(params.get("mode") or "stealthy"), workdir)
    return _parse(data, target)


def _run_wpprobe(target: str, mode: str, workdir: str) -> Any:
    exe = shutil.which("wpprobe")
    if not exe:
        raise RuntimeError("wpprobe binary not found on PATH; use the 'file' parameter (offline JSON export) instead")
    out = os.path.join(workdir, "wpprobe.json")
    argv = [exe, "scan", "-u", target, "-o", out, "--output", "json"]
    if mode and mode != "stealthy":
        argv += ["--mode", mode]
    subprocess.run(argv, timeout=3600, check=False)  # noqa: S603
    if not os.path.exists(out):
        raise RuntimeError("wpprobe produced no JSON output; check the command/flags, or import a JSON export via 'file'")
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _host(url: str) -> str:
    s = str(url or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    netloc = urllib.parse.urlparse(s).netloc or ""
    return (netloc.split("@")[-1].split(":")[0] or s).strip().lower()


def _first(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _parse(data: Any, default_target: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, str]] = []
    cpes: set = set()
    vulns: List[Dict[str, str]] = []

    def add_asset(url_or_host: str) -> str:
        host = _host(url_or_host) or _host(default_target)
        if not host:
            return ""
        assets.setdefault(host, {"hostname": host, "key": host, "os": "WordPress"})
        return host

    def add_component(asset: str, name: str, version: str) -> None:
        name = (name or "").strip()
        if not name:
            return
        label = f"WordPress: {name} {version}".strip()
        cpes.add(label)
        if asset:
            services.append({"asset": asset, "cpe": label})

    def add_vuln(asset: str, item: Dict[str, Any], comp: str) -> None:
        ref = _first(item, "cve", "CVE", "id", "cve_id")
        if not ref:
            m = _CVE.search(_first(item, "title", "name", "description"))
            ref = m.group(0).upper() if m else ""
        title = _first(item, "title", "name", "description") or comp or ref
        sev = _first(item, "severity", "Severity", "cvss_severity").capitalize()
        if ref or title:
            vulns.append({"asset": asset, "ref": ref or title, "name": (f"{comp}: " if comp else "") + title, "severity": sev})

    def handle_component(asset: str, comp: Dict[str, Any]) -> None:
        name = _first(comp, "plugin", "name", "slug", "theme", "component")
        version = _first(comp, "version", "Version", "installed_version")
        add_component(asset, name, version)
        comp_label = f"{name} {version}".strip()
        vlist = comp.get("vulnerabilities") or comp.get("vulns") or comp.get("cves")
        added = False
        if isinstance(vlist, list):
            for v in vlist:
                if isinstance(v, dict):
                    add_vuln(asset, v, comp_label); added = True
                elif isinstance(v, str) and _CVE.search(v):
                    vulns.append({"asset": asset, "ref": _CVE.search(v).group(0).upper(), "name": comp_label, "severity": ""}); added = True
        # Flat finding: the component row itself carries a CVE / severity.
        if not added and (comp.get("cve") or comp.get("CVE") or comp.get("cve_id") or _CVE.search(_first(comp, "title", "name"))):
            add_vuln(asset, comp, comp_label)

    def handle_result(res: Dict[str, Any]) -> None:
        asset = add_asset(_first(res, "url", "target", "host", "site"))
        for key in ("plugins", "themes", "components", "findings"):
            lst = res.get(key)
            if isinstance(lst, list):
                for comp in lst:
                    if isinstance(comp, dict):
                        handle_component(asset, comp)
        # flat row: the result object itself is a single plugin/vuln finding
        if any(k in res for k in ("plugin", "slug", "theme")) and not res.get("plugins"):
            handle_component(asset, res)

    # Normalize the top-level shape.
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            for r in data["results"]:
                if isinstance(r, dict):
                    handle_result(r)
        else:
            handle_result(data)
    elif isinstance(data, list):
        for r in data:
            if isinstance(r, dict):
                handle_result(r)

    # Ensure referenced assets exist.
    for v in vulns:
        if v["asset"]:
            add_asset(v["asset"])
    if not assets and default_target:
        add_asset(default_target)

    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="WPProbe import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target}, tempfile.mkdtemp()), indent=2))
