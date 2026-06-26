"""run.py -- XORCISM connector for Praxen (open-agent-ai-security.github.io/praxen, by Exabeam).

Praxen verifies that an AI agent "does its job, and only its job": it compares a declared Worker Remit
(mission, authorized tools, channels, counterparties, forbidden actions) against the agent's source code,
deployment config and conversation logs, and emits findings -- policy-implementation divergence,
credential/secret exposure, missing controls (rate limits, loop detection), capability drift
(unauthorized tools / outbound destinations), hidden secondary prompts and compound attack paths --
mapped to the OWASP Top 10 for LLM Applications (2025) and Agentic AI (2026).

This connector parses Praxen's machine-readable JSON report and produces:
  - {project, assets, vulns}  -> the agent as an ASSET, each finding as a VULNERABILITY (import_findings;
                                 this is what attack-chain steps and the engagement roll-up consume).
  - {aibas: {results: [...]}} -> the OWASP-LLM outcome list ingested by the LLM red-team / AI-BAS module
                                 (POST /api/ai-redteam/import/<aiSystemId>), which auto-fills /llm-pentest.

A Praxen finding == an issue, so every finding is a `fail` outcome. Output is ASCII-only, stdlib-only.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "praxen"

_CANON = {
    "LLM01": "Prompt injection", "LLM02": "Sensitive information disclosure", "LLM03": "Supply chain",
    "LLM04": "Data and model poisoning", "LLM05": "Improper output handling", "LLM06": "Excessive agency",
    "LLM07": "System prompt leakage", "LLM08": "Vector and embedding weaknesses",
    "LLM09": "Misinformation", "LLM10": "Unbounded consumption",
}

# keyword -> OWASP-LLM, first match wins (ordered most-specific first)
_KEYWORDS = [
    ("LLM07", ("system prompt", "hidden prompt", "soul.md", "secondary prompt", "prompt leak", "prompt extraction")),
    ("LLM02", ("credential", "secret", "api key", "apikey", "api-key", "token", "password", "data exposure", "leak", "pii", "exfil")),
    ("LLM10", ("rate limit", "rate-limit", "loop", "unbounded", "wallet", "cost", "budget", "quota", "denial of service", " dos", "consumption", "recursion")),
    ("LLM01", ("prompt injection", "jailbreak", "injection attack")),
    ("LLM05", ("output handling", "xss", "sqli", "sql injection", "ssrf", "command injection", "unsanit", "downstream")),
    ("LLM04", ("poison", "training data", "data integrity")),
    ("LLM03", ("supply chain", "supply-chain", "dependency", "third-party", "third party", "model provenance")),
    ("LLM08", ("rag", "vector", "embedding", "retrieval")),
    ("LLM09", ("hallucinat", "misinformation", "overreliance")),
    ("LLM06", ("capability drift", "unauthorized tool", "excessive", "agency", "outbound", "destination",
               "privilege", "permission", "scope", "forbidden", "unauthorized", "policy", "remit", "tool use", "counterpart")),
]


def _norm_sev(s: Any) -> str:
    t = str(s or "").strip().lower()
    if t in ("critical", "crit", "5"):
        return "Critical"
    if t in ("high", "4"):
        return "High"
    if t in ("medium", "med", "moderate", "3"):
        return "Medium"
    if t in ("low", "2", "1"):
        return "Low"
    if t in ("info", "informational", "0", "none"):
        return "Info"
    return "Medium"


def _map_owasp(finding: Dict[str, Any]) -> Dict[str, str]:
    # explicit OWASP-LLM id on the finding wins
    raw = " ".join(str(finding.get(k) or "") for k in ("owasp", "owaspLlm", "owasp_llm", "mapping", "reference"))
    for code in _CANON:
        if code.lower() in raw.lower():
            return {"owasp": code, "category": _CANON[code]}
    # otherwise infer from category/type/title/description text
    hay = " ".join(str(finding.get(k) or "") for k in ("category", "type", "class", "title", "name", "description", "detail", "summary")).lower()
    for code, kws in _KEYWORDS:
        if any(k in hay for k in kws):
            return {"owasp": code, "category": _CANON[code]}
    return {"owasp": "LLM06", "category": _CANON["LLM06"]}  # default: agent policy/agency issue


def _findings(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if isinstance(data, dict):
        for k in ("findings", "results", "issues", "detections", "observations"):
            v = data.get(k)
            if isinstance(v, list):
                return [f for f in v if isinstance(f, dict)]
            if isinstance(v, dict) and isinstance(v.get("items"), list):
                return [f for f in v["items"] if isinstance(f, dict)]
    return []


def _agent_name(data: Any) -> str:
    if isinstance(data, dict):
        for k in ("agent", "agentName", "worker", "target", "name", "project"):
            v = data.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()[:120]
            if isinstance(v, dict):
                for kk in ("name", "id", "title"):
                    if isinstance(v.get(kk), str) and v[kk].strip():
                        return v[kk].strip()[:120]
        rem = data.get("remit") or data.get("workerRemit")
        if isinstance(rem, dict) and isinstance(rem.get("name"), str):
            return rem["name"].strip()[:120]
    return "ai-agent"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    agent = _agent_name(data)
    vulns: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    for i, f in enumerate(_findings(data), 1):
        m = _map_owasp(f)
        sev = _norm_sev(f.get("severity") or f.get("risk") or f.get("level"))
        title = str(f.get("title") or f.get("name") or f.get("summary") or m["category"])[:200]
        detail = str(f.get("description") or f.get("detail") or f.get("summary") or "")
        loc = str(f.get("location") or f.get("file") or f.get("path") or "")
        remed = str(f.get("remediation") or f.get("recommendation") or "")
        ref = str(f.get("id") or f.get("findingId") or f"PRAXEN-{m['owasp']}-{i}")
        full = "; ".join(x for x in [detail, (f"location: {loc}" if loc else ""), (f"fix: {remed}" if remed else "")] if x)[:1000]
        vulns.append({"asset": agent, "ref": ref, "name": f"{m['owasp']} {title}"[:240], "severity": sev.lower(),
                      "description": f"Praxen ({m['category']}): {full}"[:1500]})
        results.append({"probe": ref, "owasp": m["owasp"], "category": m["category"], "name": title,
                        "outcome": "fail", "severity": sev, "detail": (full or title)[:480]})
    assets = [{"hostname": agent, "key": agent, "tags": "praxen,ai-agent"}]
    return {"source": SOURCE, "project": "Praxen", "assets": assets, "vulns": vulns, "aibas": {"results": results}}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print("agent=%s findings=%d" % (r["assets"][0]["hostname"], len(r["vulns"])))
    for v, a in zip(r["vulns"][:8], r["aibas"]["results"][:8]):
        print("  %-8s %-5s %s" % (v["severity"], a["owasp"], v["name"][:64]))
