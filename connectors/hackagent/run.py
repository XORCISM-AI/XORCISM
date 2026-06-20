"""run.py — XORCISM connector: HackAgent AI-agent attack results -> findings.

HackAgent (https://github.com/AISecurityLab/hackagent) tests AI agents for prompt
injection, jailbreaking, goal hijacking and tool misuse. Export its results to JSON;
this connector maps each AI agent under test to an ASSET and every SUCCESSFUL attack to
a VULNERABILITY / ASSETVULNERABILITY (ref = HACKAGENT-<category>-<hash>, severity by
attack category). With `all=true`, every attempt is imported.

Defensive: accepts a results array, or a {results|runs|attacks|evaluations:[...]} object.
A result counts as a successful attack when a success/jailbroken/vulnerable flag is truthy,
or a verdict/result field reads success/jailbreak/bypass/vulnerable/fail(ed defence).
No DB access (worker-safe).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from typing import Any, Dict, List

# attack category -> severity
_CAT_SEV = {"jailbreak": "high", "jailbreaking": "high", "prompt injection": "high",
            "prompt_injection": "high", "injection": "high", "goal hijacking": "high",
            "goal_hijacking": "high", "goal-hijack": "high", "tool misuse": "high",
            "tool_misuse": "high", "tool-misuse": "high"}
_SUCCESS_WORDS = re.compile(r"\b(success|successful|jailbro?ke?n?|bypass|bypassed|vulnerable|compromis|"
                            r"defen[cs]e[_ ]?fail|fail(ed)?|broken|leaked|exploited)\b", re.I)
_NEG = re.compile(r"\b(refus|blocked|denied|safe|defended|mitigat|no[_ ]?vuln|not[_ ]?vulnerable|pass(ed)?)\b", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if not params.get("file"):
        raise RuntimeError("hackagent: provide a 'file' (HackAgent results JSON export)")
    with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    want_all = str(params.get("all")).lower() in ("1", "true", "yes", "on")
    return _parse(data, str(params.get("agent") or params.get("target") or "").strip(), want_all)


def _find_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("results", "runs", "attacks", "evaluations", "findings", "data", "items", "tests"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        for v in data.values():
            if isinstance(v, dict):
                got = _find_list(v)
                if got:
                    return got
    return []


def _first(d: Dict[str, Any], keys, default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return str(v).strip()
    return default


def _succeeded(r: Dict[str, Any]) -> bool:
    for k in ("success", "successful", "jailbroken", "vulnerable", "compromised", "is_vulnerable", "passed_attack"):
        if k in r and isinstance(r[k], bool):
            return r[k]
    verdict = _first(r, ("verdict", "result", "outcome", "status", "evaluation", "judgement", "label"))
    if verdict:
        if _NEG.search(verdict):
            return False
        if _SUCCESS_WORDS.search(verdict):
            return True
    score = r.get("score") or r.get("asr") or r.get("attack_success_rate")
    try:
        if score is not None and float(score) > 0:
            return True
    except Exception:
        pass
    return False


def _parse(data: Any, default_agent: str, want_all: bool) -> Dict[str, Any]:
    items = _find_list(data)
    fallback = default_agent or "ai-agent-under-test"
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen: set = set()

    for r in items:
        ok = _succeeded(r)
        if not ok and not want_all:
            continue
        agent = _first(r, ("agent", "agent_name", "target", "target_name", "model", "system", "victim", "endpoint"), fallback)
        category = _first(r, ("attack_type", "category", "technique", "attack", "type", "vector", "threat"), "attack")
        technique = _first(r, ("method", "algorithm", "strategy", "attack_method"))
        prompt = _first(r, ("prompt", "goal", "objective", "payload", "input", "query", "request"))
        sev = _CAT_SEV.get(category.lower(), "high" if ok else "medium")
        label = category if not technique else f"{category} via {technique}"
        name = f"AI-agent {('vulnerability' if ok else 'attempt')}: {label}"
        ref = ("HACKAGENT-" + re.sub(r"[^A-Za-z0-9]+", "-", category.lower()).strip("-") + "-"
               + hashlib.sha1(f"{agent}|{category}|{technique}|{prompt}".encode("utf-8")).hexdigest()[:10])
        key = (agent, ref)
        if key in seen:
            continue
        seen.add(key)
        assets.setdefault(agent, {"hostname": agent, "key": agent})
        vulns.append({"asset": agent, "ref": ref, "name": name[:300], "severity": sev})

    return {"project": fallback, "assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import tempfile
    ap = argparse.ArgumentParser(description="HackAgent import (dry run)")
    ap.add_argument("--file", required=True)
    ap.add_argument("--agent", default="")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    res = run({"file": a.file, "agent": a.agent, "all": a.all}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[hackagent] {len(res['assets'])} agent asset(s), {len(res['vulns'])} finding(s)", flush=True)
