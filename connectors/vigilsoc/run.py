"""run.py — XORCISM connector for Vigil SOC (vigilsoc.org, github.com/Vigil-SOC/vigil).

Vigil is an open-source (Apache-2.0) AI-SOC: 13 coordinated agents (Triage, Investigator, Threat
Hunter, Correlator, Responder, Reporter, MITRE Analyst, Forensics, Threat Intel, Compliance,
Malware Analyst, Network Analyst, Auto Responder), 30+ MCP integrations, and a Detection
Engineering library of 7,200+ rules across Sigma, Splunk, Elastic and KQL. Local-first: FastAPI on
:6987 + PostgreSQL/pgvector.

This connector brings both halves of Vigil into XORCISM, reusing two existing ingest paths:
  * its **detection rules** -> XTHREAT.SIGMARULE (runner.import_sigma_rules) keeping the Sigma
    YAML *and* the Splunk / Elastic / KQL variants on the one rule row;
  * its **cases** (the agents' output, with their MITRE tags, confidence and containment state)
    -> XINCIDENT.ALERT (runner.import_incidents), so an autonomous Vigil containment shows up in
    the XORCISM incident layer next to every other source.

Modes (in order):
    live    : VIGILSOC_URL (+ VIGILSOC_API_KEY) -> the Vigil REST API.
    offline : params["file"] -> a saved Vigil export JSON.
    demo    : neither -> the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    VIGILSOC_URL        base URL of a Vigil instance, e.g. http://localhost:6987   (live)
    VIGILSOC_API_KEY    API key (sent as `Authorization: Bearer <...>`)            (live, optional)
    VIGILSOC_RULES_PATH override the rules endpoint path                           (optional)
    VIGILSOC_CASES_PATH override the cases endpoint path                           (optional)

Vigil publishes the port (:6987) and FastAPI /docs but not a frozen public path list, so the live
mode tries the plausible paths in turn and parses tolerantly; set the *_PATH overrides to pin it
to your deployment. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

SOURCE = "Vigil SOC"
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
# severity -> XORCISM alert severity
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
        "informational": "info"}
_RULE_PATHS = ["/api/detections/rules", "/api/rules", "/api/v1/detections", "/detections/rules"]
_CASE_PATHS = ["/api/cases", "/api/v1/cases", "/cases", "/api/findings"]


def _attack_from(*vals: Any) -> str:
    """ATT&CK ids from explicit lists ('mitre'/'tags') or anywhere in the rule text."""
    out: List[str] = []
    for v in vals:
        if not v:
            continue
        if isinstance(v, (list, tuple)):
            for x in v:
                out.extend(m.upper() for m in _ATTACK_RE.findall(str(x)))
        else:
            out.extend(m.upper() for m in _ATTACK_RE.findall(str(v)))
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return ", ".join(uniq)


def _norm_rules(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        rid = r.get("id") or r.get("rule_id") or r.get("uuid") or r.get("title")
        if not rid:
            continue
        sigma = r.get("sigma") or r.get("yaml") or r.get("rule") or ""
        spl = r.get("splunk") or r.get("spl")
        eql = r.get("elastic") or r.get("eql")
        kql = r.get("kql") or r.get("sentinel")
        if not (sigma or spl or eql or kql):
            continue
        out.append({
            "reference": f"vigilsoc:{rid}",
            "name": str(r.get("title") or r.get("name") or rid)[:300],
            "description": str(r.get("description") or "")[:2000],
            "yaml": str(sigma or "")[:20000],
            "spl": str(spl)[:8000] if spl else None,
            "eql": str(eql)[:8000] if eql else None,
            "kql": str(kql)[:8000] if kql else None,
            "logsource": str(r.get("logsource") or "")[:200] or None,
            "level": str(r.get("level") or r.get("severity") or "medium").lower(),
            "status": str(r.get("status") or "experimental").lower(),
            "author": str(r.get("author") or SOURCE)[:120],
            "attack_tags": _attack_from(r.get("mitre"), r.get("tags"), sigma, spl, eql, kql) or None,
        })
    return out


def _norm_cases(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in rows or []:
        if not isinstance(c, dict):
            continue
        cid = c.get("id") or c.get("case_id") or c.get("uuid")
        if not cid:
            continue
        conf = c.get("confidence")
        agent = c.get("agent") or c.get("assigned_agent")
        detail = str(c.get("summary") or c.get("description") or "")
        bits = [detail]
        if agent:
            bits.append(f"[agent: {agent}]")
        if isinstance(conf, (int, float)):
            bits.append(f"[confidence: {conf}]")
        out.append({
            "external_id": str(cid),
            "name": str(c.get("title") or c.get("name") or cid)[:300],
            "description": " ".join(b for b in bits if b)[:4000],
            "severity": _SEV.get(str(c.get("severity") or "medium").lower(), "medium"),
            "status": str(c.get("status") or "") or None,
            "category": "AI-SOC case",
            "assignee": str(agent or c.get("assignee") or "") or None,
            "tags": ", ".join(str(x) for x in (c.get("tags") or [])) or None,
            "url": c.get("url"),
            "asset": c.get("host") or c.get("hostname") or c.get("asset"),
            "created": c.get("created_at") or c.get("created"),
            "attack": _attack_from(c.get("mitre"), c.get("attack"), c.get("techniques")) or None,
        })
    return out


def _rows(data: Any, *keys: str) -> List[Dict[str, Any]]:
    """Pull a list out of the plausible response shapes ({key:[…]}, {items|results|data:[…]}, […])."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in list(keys) + ["items", "results", "data"]:
            v = data.get(k)
            if isinstance(v, list):
                return v
    return []


def _get(base: str, path: str, key: str, limit: int) -> Optional[Any]:
    url = base.rstrip("/") + path + ("?" + urllib.parse.urlencode({"limit": str(limit)}))
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "replace") or "null")
    except Exception:  # noqa: BLE001 — try the next candidate path
        return None


def _live(base: str, key: str, limit: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rpaths = [os.environ["VIGILSOC_RULES_PATH"]] if os.environ.get("VIGILSOC_RULES_PATH") else _RULE_PATHS
    cpaths = [os.environ["VIGILSOC_CASES_PATH"]] if os.environ.get("VIGILSOC_CASES_PATH") else _CASE_PATHS
    rules: List[Dict[str, Any]] = []
    cases: List[Dict[str, Any]] = []
    for p in rpaths:
        d = _get(base, p, key, limit)
        if d is not None:
            rules = _rows(d, "rules", "detections")
            if rules:
                break
    for p in cpaths:
        d = _get(base, p, key, limit)
        if d is not None:
            cases = _rows(d, "cases", "findings", "alerts")
            if cases:
                break
    return rules, cases


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    want = str(params.get("import") or "both").lower()   # rules | cases | both
    base = (os.environ.get("VIGILSOC_URL") or "").strip()
    key = (os.environ.get("VIGILSOC_API_KEY") or "").strip()

    if base:
        raw_rules, raw_cases = _live(base, key, limit)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        raw_rules = _rows(data, "rules", "detections")
        raw_cases = _rows(data, "cases", "findings", "alerts")

    out: Dict[str, Any] = {"source": SOURCE}
    if want in ("both", "rules"):
        out["detections"] = _norm_rules(raw_rules)[:limit]
    if want in ("both", "cases"):
        out["alerts"] = _norm_cases(raw_cases)[:limit]
    return out


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in r.items()}))
    print(json.dumps(r, indent=1)[:1500])
