"""run.py — Import a Microsoft Agent Governance Toolkit (AGT) export bundle into XORCISM.

AGT (https://github.com/microsoft/agent-governance-toolkit, MIT) enforces deterministic governance for
autonomous AI agents: a policy engine (allow / deny / require-approval / transform / log), zero-trust
agent identity (SPIFFE/DID/mTLS), execution sandboxing (privilege rings), tamper-evident decision
records (Merkle audit) and OWASP Agentic Top 10 verification (`agt verify`).

This connector parses an AGT export bundle (JSON) and normalizes it to XORCISM findings:

  * each governed agent (registration)            -> ASSET (an AI-agent asset)
  * each FAILING OWASP Agentic Top 10 category    -> VULNERABILITY (ASI-T# / OWASP-Agentic, severity)
  * each MCP-gateway / tool finding               -> VULNERABILITY (tool poisoning / drift / typosquat)
  * blocked policy violations (deny decision recs)-> a per-agent VULNERABILITY summarising the denials

Config (worker / params — this connector never runs AGT or any agent itself):
    params["file"]          an AGT export bundle (object, or an array of findings)
    params["agent"]         override the agent/asset name (default: from the bundle)
    params["min_severity"]  info|low|medium|high|critical — minimum severity to import (default low)

Worker-safe & read-only: it only reads an exported bundle; the operator runs AGT against the agents and
feeds the export here. Normalized result:
    {assets:[…], vulns:[…], intel:[], source:"agent-governance-toolkit"}.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/microsoft/agent-governance-toolkit"
_SEV_RANK = {"info": 0, "informational": 0, "none": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4, "severe": 4}
_GRADE_SEV = {"a": "info", "b": "low", "c": "medium", "d": "high", "f": "critical"}
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# OWASP Agentic Top 10 (OWASP Agentic Security Initiative — Agentic AI Threats & Mitigations, T1–T10).
# Used to normalise the id of a failing verification category so it lands with a stable ASI-T# ref.
_ASI = {
    "t1": "Memory Poisoning", "t2": "Tool Misuse", "t3": "Privilege Compromise",
    "t4": "Resource Overload", "t5": "Cascading Hallucination", "t6": "Intent Breaking & Goal Manipulation",
    "t7": "Misaligned & Deceptive Behaviors", "t8": "Repudiation & Untraceability",
    "t9": "Identity Spoofing & Impersonation", "t10": "Overwhelming Human-in-the-Loop",
}
_ASI_KW = [
    ("t1", ("memory poison", "memory-poison", "memory")),
    ("t3", ("privilege", "escalation", "privesc")),
    ("t2", ("tool misuse", "tool-misuse", "tool poisoning", "tool_poison", "typosquat", "mcp")),
    ("t4", ("resource", "overload", "dos", "flooding", "rate")),
    ("t5", ("cascading", "hallucinat")),
    ("t6", ("intent", "goal manipulation", "goal-manip", "jailbreak", "prompt injection", "injection")),
    ("t7", ("misalign", "deceptive", "deception")),
    ("t8", ("repudiation", "untraceab", "audit", "tamper", "provenance")),
    ("t9", ("identity", "spoof", "impersonat", "did", "spiffe")),
    ("t10", ("human-in-the-loop", "hitl", "human in the loop", "approval fatigue", "human")),
]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    min_rank = _SEV_RANK.get(str(params.get("min_severity") or "low").lower(), 1)
    with open(params["file"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    agent = str(params.get("agent") or _agent_of(data) or "AI agent").strip()

    vulns: List[Dict[str, Any]] = []
    seen = set()
    for f in _findings(data):
        rec = _to_vuln(f, agent, min_rank)
        if not rec or rec["ref"] in seen:
            continue
        seen.add(rec["ref"])
        vulns.append(rec)

    # Blocked policy violations (deny / require_approval decision records) → one summary finding.
    denies = _denials(data)
    if denies:
        top = ", ".join(sorted({str(d)[:40] for d in denies})[:6])
        ref = f"agt:{agent}:policy-denials"
        if ref not in seen:
            vulns.append({"asset": agent, "ref": ref[:200], "severity": "Low",
                          "name": f"[OWASP-Agentic T8] {len(denies)} policy denial(s) recorded (blocked actions): {top}"[:300]})

    assets = [{"key": agent, "hostname": agent, "name": agent}]
    return {"assets": assets, "vulns": vulns, "intel": [], "source": "agent-governance-toolkit"}


# ── extraction helpers (defensive: AGT export shape varies per subcommand) ─────
def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _agent_of(data: Any) -> Optional[str]:
    if isinstance(data, dict):
        t = _first(data, "agent", "agent_name", "agent_id", "name", "target", "subject", "spiffe_id", "did")
        if t:
            return str(t)
        for k in ("evidence", "report", "result", "summary", "meta", "registration", "identity"):
            if isinstance(data.get(k), dict):
                t = _agent_of(data[k])
                if t:
                    return t
    return None


def _findings(data: Any) -> List[Dict[str, Any]]:
    """Collect finding-like dicts from the many AGT export shapes."""
    out: List[Dict[str, Any]] = []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return out
    # flat finding lists (verification failures, MCP-gateway findings, red-team results)
    for k in ("findings", "violations", "issues", "results", "detections", "failures", "vulnerabilities", "vulns"):
        v = data.get(k)
        if isinstance(v, list):
            out += [x for x in v if isinstance(x, dict)]
    # OWASP Agentic categories: {categories:{T1:{...}}} / {owasp_agentic:{...}} / {checks:[...]}
    cats = _first(data, "categories", "owasp_agentic", "owasp", "agentic", "checks", "controls", "evidence")
    if isinstance(cats, dict):
        for cid, cat in cats.items():
            if isinstance(cat, dict):
                sub = cat.get("findings") or cat.get("issues")
                if isinstance(sub, list) and sub:
                    for s in sub:
                        if isinstance(s, dict):
                            out.append({**s, "category": s.get("category") or cid})
                elif _is_fail(cat):
                    out.append({**cat, "id": cat.get("id") or cid, "category": cid})
    elif isinstance(cats, list):
        out += [x for x in cats if isinstance(x, dict) and _is_fail(x)]
    # MCP security gateway: flagged tools (poisoning / drift / typosquatting)
    for k in ("mcp_findings", "tools", "tool_findings", "gateway"):
        v = data.get(k)
        if isinstance(v, list):
            out += [x for x in v if isinstance(x, dict) and _is_fail(x)]
    # nested single blocks
    for k in ("verify", "verification", "compliance", "report", "result", "mcp", "redteam", "red_team"):
        if isinstance(data.get(k), dict):
            out += _findings(data[k])
    return out


def _denials(data: Any) -> List[str]:
    """Action types from deny / require_approval decision records (best-effort, bounded)."""
    out: List[str] = []
    if not isinstance(data, dict):
        return out
    for k in ("decisions", "decision_records", "audit", "audit_log", "records", "ledger"):
        v = data.get(k)
        if isinstance(v, list):
            for r in v:
                if not isinstance(r, dict):
                    continue
                verdict = str(_first(r, "verdict", "action", "decision", "outcome") or "").lower()
                if verdict in ("deny", "denied", "block", "blocked", "require_approval", "require-approval"):
                    act = _first(r, "action_type", "tool", "operation", "request", "type", "name")
                    out.append(str(act or verdict))
                    if len(out) >= 500:
                        return out
    return out


def _is_fail(d: Dict[str, Any]) -> bool:
    s = str(_first(d, "status", "result", "outcome", "state", "passed", "compliant", "verdict") or "").lower()
    if s in ("fail", "failed", "violation", "non_compliant", "non-compliant", "deny", "denied", "true", "detected", "found", "flagged", "vulnerable"):
        return True
    if s in ("pass", "passed", "ok", "compliant", "allow", "allowed", "false", "secure", "satisfied"):
        return False
    g = str(_first(d, "grade") or "").strip().lower()
    if g and g not in ("a", "a+"):
        return True
    sev = str(_first(d, "severity", "risk") or "").lower()
    return sev in ("low", "medium", "moderate", "high", "critical", "severe")


def _asi_code(text: str) -> str:
    t = text.lower()
    m = re.search(r"\b(?:asi[-\s]?)?t(\d{1,2})\b", t)
    if m and f"t{m.group(1)}" in _ASI:
        return f"T{m.group(1)}"
    for code, kws in _ASI_KW:
        if any(kw in t for kw in kws):
            return code.upper()
    return ""


def _to_vuln(f: Dict[str, Any], agent: str, min_rank: int) -> Optional[Dict[str, Any]]:
    name = str(_first(f, "title", "name", "issue", "description", "message", "category", "id", "check", "control") or "").strip()
    if not name:
        return None
    sev = str(_first(f, "severity", "risk", "level") or "").strip().lower()
    if not sev:
        g = str(_first(f, "grade") or "").strip().lower()[:1]
        sev = _GRADE_SEV.get(g, "medium")
    sev = {"informational": "info", "moderate": "medium", "severe": "critical"}.get(sev, sev)
    if _SEV_RANK.get(sev, 1) < min_rank:
        return None

    cat = str(_first(f, "category", "owasp", "owasp_category", "id", "control") or "").strip()
    blob = json.dumps(f, ensure_ascii=False)
    asi = _asi_code(cat + " " + name + " " + blob)
    cve = ""
    m = _CVE_RX.search(blob)
    if m:
        cve = m.group(0).upper()
    tag = asi or (cat[:24] if cat else "")
    ref = cve or f"agt:{agent}:{(tag + ':' if tag else '')}{_slug(name)}"
    prefix = f"[OWASP-Agentic {asi}] " if asi else (f"[{cat}] " if cat and cat.lower() not in name.lower() else "")
    return {"asset": agent, "ref": ref[:200], "severity": sev.capitalize(), "name": (prefix + name)[:300]}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "finding"


# ── Standalone CLI (offline dry run, with a built-in sample) ───────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Agent Governance Toolkit connector (offline dry run)")
    ap.add_argument("--file", help="AGT export bundle JSON")
    ap.add_argument("--agent", default=None)
    ap.add_argument("--min-severity", default="low")
    a = ap.parse_args()
    if not a.file:
        sample = {
            "agent": "invoice-processing-agent",
            "spiffe_id": "spiffe://acme/agent/invoice",
            "verify": {
                "overall_grade": "C",
                "categories": {
                    "T2 Tool Misuse": {"grade": "F", "severity": "critical", "status": "fail", "description": "Agent invoked an unapproved MCP tool (send_email) without an approval gate."},
                    "T3 Privilege Compromise": {"grade": "D", "severity": "high", "status": "fail"},
                    "T8 Repudiation & Untraceability": {"grade": "A", "status": "pass"},
                    "T10 Overwhelming Human-in-the-Loop": {"grade": "C", "severity": "medium", "status": "fail"},
                },
            },
            "mcp_findings": [
                {"title": "Tool poisoning: description mismatch on 'read_file'", "severity": "high", "status": "flagged"},
                {"title": "Typosquatting MCP server 'githib.com' detected", "severity": "medium", "status": "flagged"},
            ],
            "decisions": [
                {"verdict": "deny", "action_type": "drop_table", "policy": "block-destructive"},
                {"verdict": "require_approval", "action_type": "send_email", "policy": "approval-for-send"},
                {"verdict": "allow", "action_type": "read_file"},
            ],
        }
        fp = os.path.join(tempfile.mkdtemp(), "agt.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "agent": a.agent, "min_severity": a.min_severity}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[agent-governance-toolkit] agent={res['assets'][0]['key']} · {len(res['vulns'])} finding(s) (tool: {TOOL_URL})", flush=True)
