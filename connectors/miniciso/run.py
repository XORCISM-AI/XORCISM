"""run.py — XORCISM connector for miniCISO (github.com/icidade/miniCISO, MIT, by Irlan Cidade).

miniCISO is an "agentic security staff": nine specialist roles run a disciplined, evidence-driven
assessment and classify every output as a Finding, Observation, Hypothesis or Missing-Evidence,
with a mandatory Security-QA gate before anything is delivered. XORCISM replicates this natively in
the /miniciso cockpit; this connector imports a miniCISO assessment export into that cockpit
(runner.import_miniciso -> XCOMPLIANCE.MINICISOASSESSMENT / MINICISOEVIDENCE / MINICISOOUTPUT).

miniCISO does not publish a single frozen machine export schema, so the parser is tolerant: it
accepts {"assessments":[...]}, a single assessment object {name, evidence, outputs}, or a bare list
of outputs, and normalizes role/class/tier/severity/gate to the cockpit's vocabulary. The cockpit
re-applies the discipline on import (recon output never lands as a finding; a finding with no cited
evidence is demoted to a hypothesis).

Modes:
    file  : params["file"] -> a miniCISO JSON export.
    demo  : no file -> the bundled sample.json.

Worker-safe: stdlib only, no secrets, ASCII-only output.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "miniCISO"
_ROLE_ALIASES = {
    "chief of staff": "chief-of-staff", "chief": "chief-of-staff", "coordinator": "chief-of-staff",
    "threat modeling": "threat-modeling", "threat model": "threat-modeling",
    "security architecture": "security-architecture", "architecture": "security-architecture",
    "code review": "code-review", "appsec": "appsec-assessment", "appsec assessment": "appsec-assessment",
    "application security": "appsec-assessment", "compliance": "compliance-mapper",
    "compliance mapper": "compliance-mapper", "offensive security": "offensive-security",
    "offensive": "offensive-security", "recon": "recon-attack-surface",
    "recon & attack surface": "recon-attack-surface", "attack surface": "recon-attack-surface",
    "security qa": "security-qa", "qa": "security-qa",
}
_ROLES = set(_ROLE_ALIASES.values())
_CLASS_ALIASES = {"finding": "finding", "observation": "observation", "hypothesis": "hypothesis",
                  "missing evidence": "missing-evidence", "missing-evidence": "missing-evidence",
                  "gap": "missing-evidence", "candidate": "hypothesis"}
_TIER_ALIASES = {"declared": "declared", "declared configuration": "declared",
                 "runtime": "runtime", "effective": "runtime", "runtime configuration": "runtime",
                 "validated": "validated", "validated behavior": "validated", "validated behaviour": "validated"}
_SEV = {"critical", "high", "medium", "low", "info"}


def _norm(v: Any, aliases: Dict[str, str], default: str) -> str:
    s = str(v or "").strip().lower()
    return aliases.get(s, s if s in set(aliases.values()) else default)


def _norm_assessment(a: Dict[str, Any]) -> Dict[str, Any]:
    ev: List[Dict[str, Any]] = []
    for e in (a.get("evidence") or []):
        if not isinstance(e, dict):
            continue
        ev.append({
            "title": str(e.get("title") or e.get("name") or "Evidence")[:300],
            "tier": _norm(e.get("tier") or e.get("type"), _TIER_ALIASES, "declared"),
            "source": str(e.get("source") or e.get("origin") or "")[:300],
            "content": str(e.get("content") or e.get("detail") or e.get("text") or "")[:8000],
        })
    outs: List[Dict[str, Any]] = []
    raw_outs = a.get("outputs") or a.get("findings") or []
    for o in raw_outs:
        if not isinstance(o, dict) or not (o.get("title") or o.get("name")):
            continue
        sev = str(o.get("severity") or o.get("impact") or "info").strip().lower()
        outs.append({
            "role": _norm(o.get("role") or o.get("sme"), _ROLE_ALIASES, "recon-attack-surface"),
            "cls": _norm(o.get("cls") or o.get("class") or o.get("type"), _CLASS_ALIASES, "hypothesis"),
            "title": str(o.get("title") or o.get("name"))[:300],
            "detail": str(o.get("detail") or o.get("description") or o.get("summary") or "")[:8000],
            "severity": sev if sev in _SEV else "info",
            "gate": str(o.get("gate") or "").strip().lower(),
            "confidence": o.get("confidence"),
            "residualRisk": str(o.get("residualRisk") or o.get("residual_risk") or "")[:2000],
            "qaStatus": str(o.get("qaStatus") or o.get("qa") or "").strip().lower(),
            "evidence": [str(x) for x in (o.get("evidence") or o.get("evidenceRefs") or [])],
        })
    return {
        "name": str(a.get("name") or a.get("title") or "miniCISO assessment")[:300],
        "objective": str(a.get("objective") or "")[:4000],
        "scope": str(a.get("scope") or "")[:4000],
        "operator": str(a.get("operator") or a.get("owner") or "")[:200],
        "evidence": ev, "outputs": outs,
    }


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("assessments"), list):
        assessments = [a for a in data["assessments"] if isinstance(a, dict)]
    elif isinstance(data, dict):
        assessments = [data]
    elif isinstance(data, list):
        # a bare list of outputs -> one assessment
        assessments = [{"name": params.get("name") or "miniCISO assessment", "outputs": data}]
    else:
        assessments = []
    out = [_norm_assessment(a) for a in assessments]
    if params.get("name") and out:
        out[0]["name"] = str(params["name"])[:300]
    return {"source": SOURCE, "miniciso": out}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    a = r["miniciso"][0]
    print(json.dumps({"source": r["source"], "name": a["name"], "evidence": len(a["evidence"]), "outputs": len(a["outputs"])}))
    print(json.dumps(a, indent=1)[:1400])
