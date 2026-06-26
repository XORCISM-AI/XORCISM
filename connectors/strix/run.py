"""run.py -- XORCISM connector for Strix (github.com/usestrix/strix), the autonomous AI hacking agent.

Strix runs AI agents that act like real pentesters: it dynamically tests a codebase, GitHub repo, web
app or API, exploits issues and validates them with a proof-of-concept (IDOR/auth bypass, SQL/NoSQL/cmd
injection, SSRF/XXE/deserialization, XSS, business-logic, JWT/session, misconfig...). Results are written
to strix_runs/<run-name>/. This connector parses a Strix findings JSON into XORCISM's normalized result
{project, assets, vulns} consumed by runner.import_findings: the assessed target becomes an ASSET and
each validated finding a VULNERABILITY / ASSETVULNERABILITY, with the vuln class / CWE in the description
and the PoC / reproduction noted. Severity from the finding. Offline: pass `file`, or run the sample.

Worker-safe: stdlib only, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "Strix"
_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
        "low": "low", "info": "info", "informational": "info", "none": "info"}


def _sev(v: Any) -> str:
    if isinstance(v, (int, float)):
        n = float(v)
        return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low" if n > 0 else "info"
    return _SEV.get(str(v or "").strip().lower(), "medium")


def _pick(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for k in keys:
        cur: Any = d
        ok = True
        for part in k.split("."):
            if isinstance(cur, dict) and part in cur and cur[part] not in (None, "", [], {}):
                cur = cur[part]
            else:
                ok = False
                break
        if ok:
            return cur
    return default


def _findings(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if isinstance(data, dict):
        for k in ("findings", "vulnerabilities", "results", "issues", "validated_findings"):
            v = data.get(k)
            if isinstance(v, list):
                return [f for f in v if isinstance(f, dict)]
            if isinstance(v, dict) and isinstance(v.get("items"), list):
                return [f for f in v["items"] if isinstance(f, dict)]
    return []


def _target(data: Any, params: Dict[str, Any]) -> str:
    t = params.get("target")
    if not t and isinstance(data, dict):
        t = _pick(data, ["target", "run.target", "scope.target", "application", "url", "repository", "project"])
    return (str(t).strip() if t else "strix-target")[:200]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    target = _target(data, params)
    vulns: List[Dict[str, Any]] = []
    for i, f in enumerate(_findings(data), 1):
        title = str(_pick(f, ["title", "name", "vulnerability", "summary"], "Strix finding"))[:200]
        vclass = str(_pick(f, ["type", "category", "vulnerability_type", "class", "cwe"], ""))
        sev = _sev(_pick(f, ["severity", "risk", "cvss", "score"]))
        desc = str(_pick(f, ["description", "detail", "summary"], ""))
        loc = str(_pick(f, ["url", "endpoint", "location", "path", "file", "request"], ""))
        poc = str(_pick(f, ["poc", "proof_of_concept", "reproduction", "exploit", "steps"], ""))
        remed = str(_pick(f, ["remediation", "fix", "recommendation"], ""))
        validated = _pick(f, ["validated", "confirmed", "exploited"], None)
        cwe = ""
        m = _CWE.search(f"{vclass} {desc} {title}")
        if m:
            cwe = m.group(0).upper()
        ref = str(_pick(f, ["id", "finding_id", "uuid"], f"STRIX-{i}"))
        parts = [vclass and f"class: {vclass}", desc, loc and f"location: {loc}",
                 poc and f"PoC: {poc}", remed and f"fix: {remed}",
                 (validated is True) and "validated by Strix (PoC confirmed)"]
        full = "; ".join(str(p) for p in parts if p)[:1500]
        vulns.append({"asset": target, "ref": (cwe + "-" + ref) if cwe else f"STRIX-{ref}",
                      "name": f"{title}"[:240], "severity": sev, "description": f"Strix: {full}"[:1600]})
    assets = [{"hostname": target, "key": target, "tags": "strix,ai-pentest"}]
    return {"source": SOURCE, "project": "Strix", "assets": assets, "vulns": vulns}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print("Strix: target=%s findings=%d" % (r["assets"][0]["hostname"], len(r["vulns"])))
    for v in r["vulns"][:8]:
        print("  %-8s %-10s %s" % (v["severity"], v["ref"][:10], v["name"][:54]))
