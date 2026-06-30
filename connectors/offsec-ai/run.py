"""run.py — Import an offsec-ai JSON report into XORCISM (findings).

offsec-ai (https://github.com/Htunn/offsec-ai, MIT) is an offensive-security toolkit combining network
recon with AI/LLM security testing: an OWASP LLM Top 10 scanner for live LLM endpoints, an MCP (Model
Context Protocol) security scanner + authorized active attacker, and infrastructure checks (port scan,
L7/WAF detection, mTLS, certificate analysis, hybrid identity, web OWASP Top 10, security headers).

This connector parses an offsec-ai JSON report (the `--output json` of ai-owasp-scan / mcp-scan /
owasp-scan / scan / cert-check) and normalizes it to XORCISM findings:

  * the scanned endpoint / host  -> ASSET
  * open ports / services        -> CPEs linked to the asset
  * each OWASP-LLM / MCP / web / TLS / header finding -> VULNERABILITY (ref + severity + name)

Config (worker / params — this connector never runs offsec-ai or any live/active attack itself):
    params["file"]          an offsec-ai JSON report (object, or an array of findings)
    params["target"]        override the asset name (default: from the report)
    params["min_severity"]  info|low|medium|high|critical — minimum severity to import (default low)

Worker-safe: it only reads an exported report; the operator runs offsec-ai (with --i-have-authorization
for active tests) and feeds the report here.

Normalized result: {assets:[…], services:[…], cpes:[], vulns:[…], intel:[], source:"offsec-ai"}.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/Htunn/offsec-ai"
_SEV_RANK = {"info": 0, "informational": 0, "none": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4, "severe": 4}
_GRADE_SEV = {"a": "info", "b": "low", "c": "medium", "d": "high", "f": "critical"}
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    min_rank = _SEV_RANK.get(str(params.get("min_severity") or "low").lower(), 1)
    with open(params["file"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    target = str(params.get("target") or _target_of(data) or "offsec-ai target").strip()

    vulns: List[Dict[str, Any]] = []
    seen = set()
    for f in _findings(data):
        rec = _to_vuln(f, target, min_rank)
        if not rec or rec["ref"] in seen:
            continue
        seen.add(rec["ref"])
        vulns.append(rec)

    services = [{"asset": target, "cpe": c} for c in _service_cpes(data, target)]
    assets = [{"key": target, "hostname": target}]
    return {"assets": assets, "services": services, "cpes": [], "vulns": vulns, "intel": [], "source": "offsec-ai"}


# ── extraction helpers (defensive: offsec-ai report shape varies per command) ──
def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _target_of(data: Any) -> Optional[str]:
    if isinstance(data, dict):
        t = _first(data, "target", "host", "url", "endpoint", "address", "hostname", "asset")
        if t:
            return str(t)
        for k in ("scan", "report", "result", "summary", "meta"):
            if isinstance(data.get(k), dict):
                t = _target_of(data[k])
                if t:
                    return t
    return None


def _findings(data: Any) -> List[Dict[str, Any]]:
    """Collect finding-like dicts from the many offsec-ai report shapes."""
    out: List[Dict[str, Any]] = []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return out
    # flat finding lists
    for k in ("findings", "vulnerabilities", "vulns", "issues", "results", "detections", "cves"):
        v = data.get(k)
        if isinstance(v, list):
            out += [x for x in v if isinstance(x, dict)]
    # OWASP categories: {categories: {LLM01: {...}, ...}} or {owasp: {...}}
    cats = _first(data, "categories", "owasp", "owasp_llm", "checks")
    if isinstance(cats, dict):
        for cid, cat in cats.items():
            if isinstance(cat, dict):
                # a failing/graded category becomes a finding; its own sub-findings are added too
                sub = cat.get("findings") or cat.get("issues")
                if isinstance(sub, list) and sub:
                    for s in sub:
                        if isinstance(s, dict):
                            out.append({**s, "category": s.get("category") or cid})
                elif _is_fail(cat):
                    out.append({**cat, "id": cat.get("id") or cid, "category": cid})
    elif isinstance(cats, list):
        out += [x for x in cats if isinstance(x, dict) and _is_fail(x)]
    # MCP scanner: a flagged tool / cve
    for k in ("mcp_findings", "tools", "tool_findings"):
        v = data.get(k)
        if isinstance(v, list):
            out += [x for x in v if isinstance(x, dict) and _is_fail(x)]
    # nested single-scan blocks
    for k in ("scan", "report", "result", "web", "infra", "mcp", "ai"):
        if isinstance(data.get(k), dict):
            out += _findings(data[k])
    return out


def _is_fail(d: Dict[str, Any]) -> bool:
    s = str(_first(d, "status", "result", "outcome", "state", "passed", "vulnerable") or "").lower()
    if s in ("fail", "failed", "vulnerable", "true", "detected", "found", "open", "flagged"):
        return True
    if s in ("pass", "passed", "ok", "false", "secure", "not_vulnerable", "not vulnerable"):
        return False
    # grade/severity present and bad → fail
    g = str(_first(d, "grade") or "").strip().lower()
    if g and g not in ("a", "a+"):
        return True
    sev = str(_first(d, "severity", "risk") or "").lower()
    return sev in ("low", "medium", "moderate", "high", "critical", "severe")


def _to_vuln(f: Dict[str, Any], target: str, min_rank: int) -> Optional[Dict[str, Any]]:
    name = str(_first(f, "title", "name", "issue", "description", "message", "category", "id", "check") or "").strip()
    if not name:
        return None
    # severity: explicit, else from a letter grade, else medium
    sev = str(_first(f, "severity", "risk", "level") or "").strip().lower()
    if not sev:
        g = str(_first(f, "grade") or "").strip().lower()[:1]
        sev = _GRADE_SEV.get(g, "medium")
    sev = {"informational": "info", "moderate": "medium", "severe": "critical"}.get(sev, sev)
    if _SEV_RANK.get(sev, 1) < min_rank:
        return None

    cat = str(_first(f, "category", "owasp", "owasp_category", "id") or "").strip()
    cve = ""
    m = _CVE_RX.search(json.dumps(f))
    if m:
        cve = m.group(0).upper()
    ref = cve or f"offsec-ai:{target}:{(cat + ':' if cat else '')}{_slug(name)}"
    label = (f"[{cat}] " if cat and cat.lower() not in name.lower() else "") + name
    return {"asset": target, "ref": ref[:200], "severity": sev.capitalize(), "name": label[:300]}


def _service_cpes(data: Any, target: str) -> List[str]:
    """Best-effort: open ports/services → coarse CPEs (cpe:2.3:a:offsec-ai:<service>:…)."""
    cpes: List[str] = []
    ports = _first(data, "ports", "open_ports", "services") if isinstance(data, dict) else None
    if isinstance(ports, list):
        for p in ports:
            if isinstance(p, dict):
                svc = str(_first(p, "service", "name", "product") or "").strip()
                port = _first(p, "port", "number")
                if svc:
                    cpes.append(f"cpe:2.3:a:offsec-ai:{_slug(svc)}:-:*:*:*:*:*:*:*")
                elif port:
                    cpes.append(f"cpe:2.3:a:offsec-ai:port-{port}:-:*:*:*:*:*:*:*")
    return cpes


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "finding"


# ── Standalone CLI (offline dry run, with a built-in sample) ───────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="offsec-ai connector (offline dry run)")
    ap.add_argument("--file", help="offsec-ai JSON report")
    ap.add_argument("--target", default=None)
    ap.add_argument("--min-severity", default="low")
    a = ap.parse_args()
    if not a.file:
        sample = {
            "target": "https://api.example.com/v1/chat/completions",
            "overall_grade": "D", "total_score": 41,
            "categories": {
                "LLM01: Prompt Injection": {"grade": "F", "severity": "critical", "status": "fail", "description": "Direct prompt injection altered the system instructions."},
                "LLM02: Insecure Output Handling": {"grade": "C", "severity": "medium", "status": "fail"},
                "LLM06: Sensitive Information Disclosure": {"grade": "A", "status": "pass"},
            },
            "findings": [
                {"title": "MCP server exposes tool without authentication", "severity": "high", "category": "MCP", "status": "fail"},
                {"title": "Affected by CVE-2025-1234 (MCP path traversal)", "severity": "critical", "status": "vulnerable"},
                {"title": "Missing HSTS header", "severity": "low", "category": "Headers", "status": "fail"},
            ],
            "ports": [{"port": 443, "service": "https"}, {"port": 22, "service": "ssh"}],
        }
        fp = os.path.join(tempfile.mkdtemp(), "offsec-ai.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "target": a.target, "min_severity": a.min_severity}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[offsec-ai] asset={res['assets'][0]['key']} · {len(res['vulns'])} finding(s) · {len(res['services'])} service(s) (tool: {TOOL_URL})", flush=True)
