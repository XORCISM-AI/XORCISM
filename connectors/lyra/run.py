"""run.py — XORCISM connector: Lyra CTI/OSINT monitor → assets + services + exposures.

Lyra (https://github.com/K3lgy/lyra) is a defensive OSINT / digital-risk-protection
monitor: given an organisation's domains / emails / brands / keywords it scans ~10
open-web sources (HIBP, DeHashed, VirusTotal, URLScan, Shodan, GitHub, paste sites,
Google dorks, Ransomware.live, crt.sh) and exports a scored JSON report.

This connector ingests that report and maps it to the XORCISM model:
  • discovered hosts / subdomains / IPs              -> ASSET
  • Shodan-exposed services (open ports on an IP)    -> SERVICE
  • each finding (credential leak / mention / infra  -> VULN (exposure) on the asset,
    exposure / ransomware claim)                        or the monitored org as fallback

Two modes:
  offline  params["file"]  = a saved lyra_report.json -> parsed (no network, no keys).
  live     build a config from params + ENV api keys, run `python lyra.py --config …`,
           then parse the produced lyra_report.json.

No DB access here (worker-safe): returns {assets, hosts, services, cpes, vulns}.
API keys come ONLY from the worker environment, never the UI:
  LYRA_HIBP, LYRA_VIRUSTOTAL, LYRA_SHODAN, LYRA_URLSCAN, LYRA_DEHASHED, LYRA_DEHASHED_EMAIL.
Lyra's location: LYRA_PATH (default C:\\tools\\lyra\\lyra.py) or `lyra.py` on PATH.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
_PORTS = re.compile(r"\b(\d{1,5})\b")

# Lyra criticality (French) -> XORCISM severity.
_SEV = {"CRITIQUE": "Critical", "ÉLEVÉ": "High", "ELEVE": "High", "MOYEN": "Medium", "FAIBLE": "Low"}

DEFAULT_LYRA = r"C:\tools\lyra\lyra.py"


# ── helpers ───────────────────────────────────────────────────────────────────

def _csv(v: Any) -> List[str]:
    return [p.strip() for p in str(v or "").split(",") if p.strip()]


def _sev(crit: str) -> str:
    return _SEV.get(str(crit or "").strip().upper(), "Medium")


def _redact(s: str, n: int = 180) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s[: n - 1] + "…" if len(s) > n else s


def _new() -> Dict[str, Any]:
    return {"assets": {}, "hosts": set(), "services": {}, "cpes": set(), "vulns": []}


def _add_asset(acc: Dict[str, Any], host: str = "", ip: str = "") -> str:
    host = host.strip().lower().rstrip(".")
    ip = ip.strip()
    key = host or ip
    if not key:
        return ""
    a = acc["assets"].setdefault(key, {"hostname": host or ip, "key": key})
    if ip and not a.get("ip"):
        a["ip"] = ip
    # only real FQDNs feed the chaining engine's host facts (skip the org-name fallback asset)
    if host and not _IPV4.match(host) and "." in host and " " not in host:
        acc["hosts"].add(host)
    return key


# ── live mode: build a Lyra config + run it ──────────────────────────────────

def _locate_lyra() -> str:
    p = os.environ.get("LYRA_PATH")
    if p and os.path.exists(p):
        return p
    for cand in (shutil.which("lyra.py"), shutil.which("lyra")):
        if cand:
            return cand
    if os.path.exists(DEFAULT_LYRA):
        return DEFAULT_LYRA
    raise RuntimeError("lyra.py not found — set LYRA_PATH, put it on PATH, or use the 'file' parameter for offline import")


def _run_lyra(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    name = str(params.get("name") or "").strip()
    if not name:
        raise RuntimeError("lyra: provide a 'name' (organisation) for live mode, or a 'file' for offline import")
    cfg = {
        "company": {
            "name": name,
            "domains": _csv(params.get("domains")),
            "emails": _csv(params.get("emails")),
            "brands": _csv(params.get("brands")),
            "keywords": _csv(params.get("keywords")),
            "subsidiaries": [],
            "products": [],
        },
        "api_keys": {
            "hibp": os.environ.get("LYRA_HIBP", ""),
            "virustotal": os.environ.get("LYRA_VIRUSTOTAL", ""),
            "shodan": os.environ.get("LYRA_SHODAN", ""),
            "urlscan": os.environ.get("LYRA_URLSCAN", ""),
            "dehashed": os.environ.get("LYRA_DEHASHED", ""),
            "dehashed_email": os.environ.get("LYRA_DEHASHED_EMAIL", ""),
        },
        "options": {"timeout": 15, "max_results_per_source": 20, "output_dir": workdir},
    }
    cfg_path = os.path.join(workdir, "lyra_config.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False)
    exe = _locate_lyra()
    # --output's parent dir is where Lyra writes lyra_report.json.
    subprocess.run(  # noqa: S603
        [sys.executable, exe, "--config", cfg_path, "--output", os.path.join(workdir, "out.json")],
        timeout=3600, check=False, cwd=workdir,
    )
    report = os.path.join(workdir, "lyra_report.json")
    if not os.path.exists(report):
        return {"findings": []}
    with open(report, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


# ── mapping: Lyra report -> normalized contract ──────────────────────────────

def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            report = json.load(fh)
    else:
        report = _run_lyra(params, workdir)

    acc = _new()
    org = str(params.get("name") or (report.get("metadata") or {}).get("target") or "").strip()
    org_key = _add_asset(acc, org.lower()) if org else ""
    limit = int(params.get("limit", 1000) or 1000)

    findings = report.get("findings") or []
    for f in findings[:limit]:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title") or "")
        summary = str(f.get("summary") or "")
        source = str(f.get("source") or "OSINT")
        ftype = str(f.get("type") or "mention")
        blob = f"{title} {summary}"

        # Infra indicators (domains/subdomains, IPs) become assets — never emails/secrets.
        domains = [d for d in {m.group(0).lower() for m in _DOMAIN.finditer(blob.lower())} if "." in d]
        ips = sorted({m.group(0) for m in _IPV4.finditer(blob)})
        host_key = ""
        explicit = str(f.get("domain") or "").strip().lower()
        if explicit:
            host_key = _add_asset(acc, explicit)
        for d in domains:
            k = _add_asset(acc, d)
            host_key = host_key or k
        for ip in ips:
            _add_asset(acc, "", ip)

        # Shodan exposed ports -> services (best-effort extraction from the summary).
        if source.lower().startswith("shodan") and ips and "port" in blob.lower():
            seg = summary.split("Tous ports", 1)[-1]
            ports = {int(p) for p in _PORTS.findall(seg) if 0 < int(p) <= 65535}
            for ip in ips:
                ak = _add_asset(acc, "", ip)
                for port in sorted(ports)[:40]:
                    acc["services"].setdefault(f"{ip}:{port}", {"asset": ak, "port": port, "protocol": "tcp", "name": ""})

        ref = "LYRA-" + hashlib.sha1(f"{source}|{ftype}|{title}".encode("utf-8")).hexdigest()[:12]
        acc["vulns"].append({
            "asset": host_key or org_key,
            "ref": ref,
            "severity": _sev(f.get("criticality")),
            "name": _redact(f"[{source}] {title}"),  # title is a count/label — summaries (which may carry leaked accounts) are NOT imported
        })

    return {
        "assets": list(acc["assets"].values()),
        "hosts": sorted(acc["hosts"]),
        "services": list(acc["services"].values()),
        "cpes": sorted(acc["cpes"]),
        "vulns": acc["vulns"],
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Lyra OSINT import (dry run)")
    ap.add_argument("--file", help="a saved lyra_report.json")
    ap.add_argument("--name", default="", help="organisation (live mode)")
    ap.add_argument("--domains", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "name": a.name, "domains": a.domains}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[lyra] {len(res['assets'])} asset(s), {len(res['services'])} service(s), {len(res['vulns'])} exposure(s)", flush=True)
