"""run.py — XORCISM connector: Raccoon (offensive recon & information gathering) → findings.

Raccoon (https://github.com/evyatarmeged/Raccoon) runs a bundle of recon modules against a
target and saves one file per module under `raccoon_scan_results/<target>/`:
    subdomains.txt      DNS/subdomain enumeration
    dns_records.txt     A / AAAA / MX / NS / TXT records (+ WHOIS)
    <host>_report ...   host / nmap port scan
    tls_report.txt      TLS certificate & cipher data
    web_scan.txt        web-application fingerprint (server, CMS, headers, WAF, robots)
    url_fuzz.txt        discovered URLs / directories

This connector normalizes that output — it does NOT parse by hard-coded filenames only; it matches
files by keyword so it tolerates Raccoon version/format drift.

    dir    : a Raccoon results directory to parse (offline).
    file   : a single subdomains list (one hostname per line).
    target : live mode — if the `raccoon` binary is on PATH, run it into a temp dir and parse.

Emits the XORCISM findings model:
    assets   [{hostname, ip?, key}]   — target + every discovered subdomain (with resolved IP)
    services [{asset, port, protocol, service}]  — open ports from the host scan

Recon output (subdomains, IPs, open ports) is *attack surface*, so it maps to ASSET/services —
not to the threat-intel exchange. No DB access (worker-safe): returns the normalized dict; the
runner performs all writes.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_LINE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    target = str(params.get("target") or "").strip().lower().rstrip(".")

    # 1) single subdomains file
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            hosts = _hostnames(fh.read())
        assets = _assets_from_hosts(hosts, target)
        return {"assets": assets, "services": [], "cpes": [], "vulns": []}

    # 2) a Raccoon results directory (offline) — or run live into one
    results_dir = params.get("dir")
    if not results_dir:
        if not target:
            raise RuntimeError("raccoon: provide a 'dir' (results folder), a 'file' (subdomains), or a 'target' for live mode")
        results_dir = _run_raccoon(target, workdir)
    if not results_dir or not os.path.isdir(results_dir):
        raise RuntimeError(f"raccoon: results directory not found: {results_dir!r}")

    return _parse_dir(results_dir, target)


# ── live mode ────────────────────────────────────────────────────────────────────
def _run_raccoon(target: str, workdir: str) -> str:
    exe = shutil.which("raccoon")
    if not exe:
        raise RuntimeError("raccoon binary not found on PATH; use the 'dir' or 'file' parameter instead")
    outdir = os.path.join(workdir, "raccoon_scan_results")
    os.makedirs(outdir, exist_ok=True)
    # --no-health-check keeps it non-interactive; --outdir isolates output under the job workdir.
    subprocess.run([exe, "--no-health-check", "--outdir", outdir, target],  # noqa: S603
                   timeout=1800, check=False, cwd=workdir)
    # Raccoon writes raccoon_scan_results/<target>/… — return the per-target folder if present.
    cand = os.path.join(outdir, target)
    return cand if os.path.isdir(cand) else outdir


# ── offline parsing ───────────────────────────────────────────────────────────────
def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _hostnames(text: str) -> List[str]:
    out: List[str] = []
    for raw in (text or "").splitlines():
        h = raw.strip().lower().rstrip(".")
        # tolerate "sub.example.com -> 1.2.3.4" / "sub.example.com [1.2.3.4]" style lines
        h = re.split(r"[\s,\[\]()>]+", h)[0] if h else h
        if h and _HOSTNAME.match(h):
            out.append(h)
    return out


def _assets_from_hosts(hosts: List[str], target: str) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    if target and _HOSTNAME.match(target):
        seen[target] = {"hostname": target, "key": target}
    for h in hosts:
        seen.setdefault(h, {"hostname": h, "key": h})
    return list(seen.values())


def _classify(name: str) -> str:
    n = name.lower()
    if "subdomain" in n:
        return "subdomains"
    if "dns" in n or "whois" in n:
        return "dns"
    if "tls" in n or "ssl" in n or "cert" in n:
        return "tls"
    if "url_fuzz" in n or "fuzz" in n or "url" in n:
        return "urls"
    if "web" in n or "http" in n:
        return "web"
    if "nmap" in n or "port" in n or "host" in n or "scan" in n:
        return "ports"
    return "other"


def _parse_dir(results_dir: str, target: str) -> Dict[str, Any]:
    files: List[str] = []
    for root, _dirs, names in os.walk(results_dir):
        for nm in names:
            files.append(os.path.join(root, nm))

    # infer the scan target from the folder name if not supplied
    if not target:
        base = os.path.basename(os.path.normpath(results_dir)).lower().rstrip(".")
        if _HOSTNAME.match(base):
            target = base

    assets: Dict[str, Dict[str, Any]] = {}
    if target and _HOSTNAME.match(target):
        assets[target] = {"hostname": target, "key": target}
    services: List[Dict[str, Any]] = []
    seen_svc: set = set()

    def add_asset(host: str, ip: Optional[str] = None) -> None:
        host = (host or "").lower().rstrip(".")
        if not host or not _HOSTNAME.match(host):
            return
        a = assets.setdefault(host, {"hostname": host, "key": host})
        if ip and not a.get("ip"):
            a["ip"] = ip

    for path in files:
        kind = _classify(os.path.basename(path))
        text = _read(path)
        if not text.strip():
            continue

        if kind == "subdomains":
            for h in _hostnames(text):
                add_asset(h)

        elif kind == "dns":
            for h in _hostnames(text):
                add_asset(h)
            for ip in dict.fromkeys(_IPV4.findall(text)):  # de-dup, keep order
                if _is_public_ip(ip) and target:
                    add_asset(target, ip)

        elif kind == "ports":
            for line in text.splitlines():
                m = _PORT_LINE.match(line)
                if m and target:
                    port, proto, svc = int(m.group(1)), m.group(2).lower(), m.group(3)
                    k = (target, port, proto)
                    if k in seen_svc:
                        continue
                    seen_svc.add(k)
                    services.append({"asset": target, "port": port, "protocol": proto, "service": svc})

    return {
        "assets": list(assets.values()),
        "services": services,
        "cpes": [],
        "vulns": [],
    }


def _is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="Raccoon recon import (dry run)")
    ap.add_argument("--dir", help="Raccoon results directory")
    ap.add_argument("--file", help="subdomains file")
    ap.add_argument("--target", default="", help="target host/domain (live or to anchor a dir)")
    a = ap.parse_args()
    res = run({"dir": a.dir, "file": a.file, "target": a.target}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[raccoon] {len(res['assets'])} asset(s), {len(res['services'])} service(s)", flush=True)
