"""run.py — XORCISM connector for Vigolium (github.com/vigolium/vigolium, AGPL-3.0).

Vigolium is a high-fidelity web vulnerability scanner "fusing agentic AI with native speed" — a Go
engine with 317 scanner modules (SQLi/XSS/SSTI/cmd-injection, IDOR/BOLA, path traversal, SSRF/XXE,
misconfig, race conditions…) plus an agentic mode (autopilot/swarm) and OAST/interactsh blind
testing. It emits findings as JSONL / JSON / SQLite / HTML.

This connector parses a Vigolium findings export and maps it to XORCISM's finding model (the shared
runner.import_findings path): each finding's target host -> ASSET, each finding -> VULNERABILITY
(name + severity + CWE/CVSS + matched URL), so Vigolium results feed the exposure-fusion score,
attack-path, Unified Exposure queue and the pentest attack-chain (chain.ts: a web service detected
by nmap -> Vigolium).

Modes (in order):
    file  : params["file"] -> a Vigolium export — JSONL (one finding/line), a JSON array, or
            {"findings"/"results"/"vulnerabilities": [...]}.
    live  : params["target"] (+ VIGOLIUM_SERVER / VIGOLIUM_API_KEY) -> a running `vigolium server`.
    demo  : neither -> the bundled sample.jsonl.

Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "Vigolium"
# Vigolium severity vocabulary -> XORCISM severity
_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
        "low": "Low", "info": "Info", "informational": "Info", "unknown": "Info"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CWE_RE = re.compile(r"CWE[-\s]?(\d{1,5})", re.I)


def _first(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, dict):
            v = v.get("name") or v.get("id") or v.get("value")
        if v not in (None, "", [], {}):
            return str(v).strip()
    return ""


def _host(url: str) -> str:
    s = str(url or "").strip()
    if not s:
        return ""
    if "://" not in s and ("/" in s or "." in s):
        s = "http://" + s
    if "://" in s:
        netloc = urllib.parse.urlparse(s).netloc or ""
        return (netloc.split("@")[-1].split(":")[0] or "").strip().lower()
    return s.split("/")[0].split(":")[0].strip().lower()


def _rows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("findings", "results", "vulnerabilities", "vulns", "items", "data"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _load(path: str) -> List[Dict[str, Any]]:
    """Parse a Vigolium export: JSONL (one object/line) or a single JSON document."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read().strip()
    if not text:
        return []
    # Try JSONL first (Vigolium's native --format jsonl): every non-empty line is a finding.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) > 1 and all(ln.lstrip().startswith("{") for ln in lines):
        out: List[Dict[str, Any]] = []
        for ln in lines:
            try:
                obj = json.loads(ln)
                if isinstance(obj, dict):
                    out.append(obj)
            except json.JSONDecodeError:
                continue
        if out:
            return out
    try:
        return _rows(json.loads(text))
    except json.JSONDecodeError:
        return []


def _live(target: str, workdir: str) -> List[Dict[str, Any]]:
    base = (os.environ.get("VIGOLIUM_SERVER") or "http://localhost:9002").rstrip("/")
    key = (os.environ.get("VIGOLIUM_API_KEY") or "").strip()
    payload = json.dumps({"target": target, "targets": [target]}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    last = ""
    for path in ("/api/scan", "/api/v1/scan", "/scan", "/api/findings"):
        try:
            req = urllib.request.Request(base + path, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3600) as resp:  # noqa: S310 (operator-supplied server)
                body = resp.read().decode("utf-8", "replace")
            with open(os.path.join(workdir, "vigolium.json"), "w", encoding="utf-8") as fh:
                fh.write(body)
            return _rows(json.loads(body))
        except Exception as e:  # noqa: BLE001
            last = f"{path}: {e}"
            continue
    raise RuntimeError(
        f"vigolium live mode could not reach {base} ({last}). Run `vigolium scan -t {target} "
        "--format jsonl -o out.jsonl` and import the file via the 'file' parameter instead.")


def _parse(rows: List[Dict[str, Any]], default_target: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen: set = set()

    def add_asset(url_or_host: str) -> str:
        host = _host(url_or_host) or _host(default_target)
        if host:
            assets.setdefault(host, {"hostname": host, "key": host})
        return host

    for it in rows:
        name = _first(it, "name", "title", "template", "check", "rule", "type", "vuln", "id") or "Vigolium finding"
        url = _first(it, "url", "target", "location", "endpoint", "matched", "matched_at", "host", "uri")
        host = add_asset(url)
        if not host:
            continue
        sev = _SEV.get(_first(it, "severity", "risk", "level", "impact").lower(), "Medium")
        blob = json.dumps(it)
        cve = (_CVE_RE.search(blob) or [None])[0] if _CVE_RE.search(blob) else None
        cwe_m = _CWE_RE.search(_first(it, "cwe", "cwe_id") or blob)
        cwe = f"CWE-{cwe_m.group(1)}" if cwe_m else ""
        cvss_raw = _first(it, "cvss", "cvss_score", "cvssScore", "score")
        cvss = None
        try:
            cvss = float(cvss_raw) if cvss_raw else None
        except ValueError:
            cvss = None
        desc_bits = [_first(it, "description", "detail", "info", "message", "matcher", "matcher_name", "extracted")]
        if cwe:
            desc_bits.append(cwe)
        rem = _first(it, "remediation", "solution", "fix")
        if rem:
            desc_bits.append(f"Remediation: {rem}")
        param = _first(it, "parameter", "param", "injection_point")
        if param:
            desc_bits.append(f"Parameter: {param}")
        desc = f"{name} [{sev}] via Vigolium at {url or host}. " + " ".join(b for b in desc_bits if b)
        # ref: CVE if present, else a stable synthetic id from finding id/name+url
        fid = _first(it, "id", "finding_id", "uuid")
        ref = cve or f"VIGOLIUM-{fid}" if (cve or fid) else f"VIGOLIUM-{abs(hash((name, url))) % (10 ** 9)}"
        if ref in seen:
            continue
        seen.add(ref)
        v: Dict[str, Any] = {"ref": ref, "name": name[:300], "severity": sev,
                             "asset": host, "description": desc[:1500]}
        if cvss is not None:
            v["cvss"] = cvss
        vulns.append(v)

    return {"source": SOURCE, "assets": list(assets.values()), "vulns": vulns, "cpes": [], "services": []}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    target = str(params.get("target") or "").strip()
    if params.get("file"):
        rows = _load(params["file"])
    elif target and (os.environ.get("VIGOLIUM_SERVER") or params.get("live")):
        rows = _live(target, workdir)
    else:
        rows = _load(os.path.join(os.path.dirname(__file__), "sample.jsonl"))
    return _parse(rows, target)


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print(json.dumps({"source": r["source"], "assets": len(r["assets"]), "vulns": len(r["vulns"])}))
    print(json.dumps(r, indent=1)[:1400])
