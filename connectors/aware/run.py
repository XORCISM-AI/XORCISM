"""run.py — Import an AWARE (GoodCISO/aware) governance export into XORCISM.

AWARE (https://github.com/GoodCISO/aware, Apache-2.0) is open-source autonomous-compliance infrastructure
for AI agent systems: cryptographic non-human identity, audit trails, a parent->child revocation cascade
(kill-switch), constraint-enforcement tiers T0-T4, and compliance mapping to CSA AICM / NIST AI RMF /
ISO 27001 / DORA / OWASP-LLM.

This connector is import-type and worker-safe: it parses an exported AWARE JSON and normalizes it so the
runner fans it into two cockpits:
  * governed agents (tier / identity / parent)         -> `aware_agents`         -> XAGENT.AIAGENT (/aware, AI Guardrails)
  * policy / guardrail enforcement violations          -> `guardrail_violations` -> XAGENT.AIGUARDRAILVIOLATION

Config:
    params["file"]   an AWARE export JSON ({agents:[...], violations:[...]} or an array of agents)
    params["limit"]  max agents (default 1000)
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/GoodCISO/aware"
SOURCE = "AWARE"
_TIER_WORD = {"audit": "T0", "identity": "T1", "guard": "T2", "policy": "T3", "autonom": "T4"}


def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _norm_tier(v: Any) -> Optional[str]:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        n = int(v)
        return f"T{n}" if 0 <= n <= 4 else None
    s = str(v).strip().upper()
    if s in ("T0", "T1", "T2", "T3", "T4"):
        return s
    if s.isdigit() and 0 <= int(s) <= 4:
        return f"T{int(s)}"
    low = s.lower()
    for k, t in _TIER_WORD.items():
        if k in low:
            return t
    return None


def _collect(data: Any, *keys: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                out += [x for x in v if isinstance(x, dict)]
    return out


def _to_agent(a: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = _first(a, "name", "agent_name", "agent_id", "id", "agentId")
    if not name:
        return None
    revoked = bool(_first(a, "revoked", "disabled", "killed")) or str(_first(a, "status") or "").lower() in ("revoked", "disabled", "killed")
    return {
        "name": str(name)[:200],
        "framework": str(_first(a, "framework", "runtime", "platform") or ""),
        "model": str(_first(a, "model", "llm") or ""),
        "autonomous": bool(_first(a, "autonomous", "self_operating")) or _norm_tier(_first(a, "tier", "constraint_tier", "enforcement_tier")) == "T4",
        "uses_tools": bool(_first(a, "uses_tools", "tools", "has_tools")),
        "tier": _norm_tier(_first(a, "tier", "constraint_tier", "enforcement_tier", "t")),
        "fingerprint": str(_first(a, "fingerprint", "identity", "identity_fingerprint", "public_key", "agent_identity") or "")[:64] or None,
        "parent": str(_first(a, "parent", "parent_agent", "parent_id", "spawned_by") or "")[:200] or None,
        "revoked": revoked,
        "revoked_reason": str(_first(a, "revoked_reason", "kill_reason") or ""),
        "score": int(_first(a, "score", "compliance_score") or 50),
    }


def _to_violation(v: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rule = _first(v, "rule", "policy", "name", "control", "constraint")
    if not rule and not _first(v, "action", "decision"):
        return None
    sev = str(_first(v, "severity", "risk") or "medium").lower()
    return {
        "rule": str(rule or "policy violation")[:200],
        "action": str(_first(v, "action", "decision", "outcome") or "blocked").lower(),
        "severity": sev if sev in ("info", "low", "medium", "high", "critical") else "medium",
        "technique": str(_first(v, "technique", "owasp_llm", "llm") or "AIX-01")[:40],
        "detail": str(_first(v, "detail", "description", "reason") or "")[:240],
        "ai_agent": str(_first(v, "agent", "agent_name", "ai_agent") or ""),
    }


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = max(1, min(int(params.get("limit") or 1000), 10000))
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    raw_agents = _collect(data, "agents", "registry", "governed_agents")
    if not raw_agents and isinstance(data, list):
        raw_agents = [x for x in data if isinstance(x, dict)]
    raw_viol = _collect(data, "violations", "audit", "enforcement", "events")

    agents = [a for a in (_to_agent(x) for x in raw_agents) if a][:limit]
    # only enforcement events that were blocked/flagged become violations
    violations = [v for v in (_to_violation(x) for x in raw_viol) if v and v["action"] in ("blocked", "flagged", "denied", "killed")]
    violations = [{**v, "action": "blocked" if v["action"] in ("denied", "killed") else v["action"]} for v in violations]

    return {"source": SOURCE, "host": "aware", "aware_agents": agents, "guardrail_violations": violations}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="AWARE connector (offline dry run)")
    ap.add_argument("--file")
    a = ap.parse_args()
    if not a.file:
        sample = {
            "agents": [
                {"name": "orchestrator-prime", "framework": "crewai", "model": "gpt-4o", "tier": 4, "autonomous": True, "fingerprint": "a1b2c3d4e5f6", "score": 78},
                {"name": "retrieval-worker", "framework": "langchain", "tier": "T2", "parent": "orchestrator-prime", "uses_tools": True, "score": 64},
                {"name": "payments-agent", "framework": "autogen", "tier": "policy", "parent": "orchestrator-prime", "autonomous": True, "score": 41},
                {"name": "shadow-agent", "framework": "openai", "autonomous": True, "score": 28},
            ],
            "violations": [
                {"agent": "payments-agent", "rule": "tool-allowlist breach", "action": "blocked", "severity": "high", "technique": "LLM06", "detail": "attempted call to un-allowlisted wire-transfer tool"},
                {"agent": "shadow-agent", "rule": "rate-limit exceeded", "action": "flagged", "severity": "medium", "detail": "1200 calls in 60s"},
            ],
        }
        fp = os.path.join(tempfile.mkdtemp(), "aware.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[AWARE] {len(res['aware_agents'])} governed agent(s) -> XAGENT.AIAGENT  |  {len(res['guardrail_violations'])} violation(s) -> AIGUARDRAILVIOLATION   (tool: {TOOL_URL})", flush=True)
