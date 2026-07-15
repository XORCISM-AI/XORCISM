"""run.py — XORCISM connector for Giskard (AI evaluation & red-teaming framework).

Giskard (github.com/Giskard-AI/giskard, Apache-2.0) scans ML/LLM models and agents for
vulnerabilities. `giskard.scan(model, dataset)` returns a ScanReport whose issues each carry an
IssueGroup (Prompt Injection, Harmfulness, Hallucination, Sensitive Information Disclosure,
Stereotypes, Robustness, Output Formatting, Performance, Data Leakage, Stochasticity, ...), a
level (major / medium / minor), a description, a metric/deviation and examples.

This connector ingests a Giskard scan report (`report.to_json()`) and normalises each issue into
an XORCISM **AI-BAS red-team result** (XORCISM.AIBASRUN + AIBASRESULT via runner.import_ai_results)
- the same store fed by garak / PyRIT / promptfoo - so Giskard findings land in the /ai-redteam
cockpit, mapped to the OWASP LLM Top 10.

Modes (in order):
    live    : GISKARD_HUB_URL (+ GISKARD_API_KEY) -> Giskard Hub API (best-effort, tolerant).
    offline : params["file"] -> a saved Giskard scan report JSON.
    demo    : neither -> the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    GISKARD_HUB_URL    base URL of a Giskard Hub, e.g. https://hub.example.com   (live)
    GISKARD_API_KEY    Hub API key (sent as `Authorization: Bearer <...>`)       (live)
    GISKARD_PROJECT    project/model key to fetch                                (optional)

Params: system (the XORCISM AI system name to attach the run to), min_level (drop issues below
major|medium|minor). Normalized result: {"source":"Giskard","aibas":{"system":...,"results":[...]}}
- the same envelope the garak connector emits, ingested by runner.import_aibas.
Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "Giskard"

# Giskard IssueLevel -> XORCISM severity (AIBASRESULT.Severity / sevW weighting).
_SEV = {"major": "High", "medium": "Medium", "minor": "Low", "critical": "Critical", "info": "Info"}
_LEVEL_RANK = {"minor": 1, "medium": 2, "major": 3, "critical": 4}

# Giskard IssueGroup -> OWASP LLM Top 10 (2025). Only the security-relevant groups map; the
# model-quality groups (robustness, performance, over/underconfidence, stochasticity, spurious
# correlation) have no honest OWASP-LLM equivalent, so their Owasp is left empty and the
# Category carries the meaning.
_OWASP = {
    "prompt injection": "LLM01",
    "jailbreak": "LLM01",
    "sensitive information disclosure": "LLM02",
    "information disclosure": "LLM02",
    "disclosure": "LLM02",
    "data leakage": "LLM02",
    "harmfulness": "LLM05",
    "harmful content generation": "LLM05",
    "output formatting": "LLM05",
    "excessive agency": "LLM06",
    "system prompt leakage": "LLM07",
    "hallucination": "LLM09",
    "hallucination and misinformation": "LLM09",
    "misinformation": "LLM09",
}
# Canonical XORCISM AI-BAS probe categories (aibas.ts PROBES) so imported issues match a known
# probe when possible; otherwise the runner synthesises one from these fields.
_CATEGORY = {
    "prompt injection": "Prompt injection",
    "sensitive information disclosure": "Sensitive info disclosure",
    "information disclosure": "Sensitive info disclosure",
    "data leakage": "Sensitive info disclosure",
    "output formatting": "Insecure output handling",
    "hallucination": "Misinformation",
    "hallucination and misinformation": "Misinformation",
    "misinformation": "Misinformation",
    "system prompt leakage": "System-prompt leakage",
    "excessive agency": "Excessive agency",
}
_OWASP_RE = re.compile(r"\bllm[\s:_-]?(\d{1,2})\b", re.I)


def _owasp_from_taxonomy(tax: Any) -> Optional[str]:
    """Prefer an OWASP LLM id carried in the issue's taxonomy tags (e.g. 'owasp:llm01')."""
    for t in tax or []:
        m = _OWASP_RE.search(str(t))
        if m:
            return "LLM%02d" % int(m.group(1))
    return None


def _first_example(ex: Any) -> str:
    """Giskard examples are a DataFrame in-process; in JSON they are rows (dicts) or strings."""
    if isinstance(ex, list) and ex:
        e = ex[0]
        if isinstance(e, dict):
            inp = e.get("input") or e.get("Input") or e.get("question") or ""
            out = e.get("output") or e.get("Output") or e.get("answer") or ""
            if inp or out:
                return f"e.g. input: {str(inp)[:160]} | output: {str(out)[:160]}"
            return json.dumps(e, default=str)[:320]
        return str(e)[:320]
    if isinstance(ex, dict) and ex:
        return json.dumps(ex, default=str)[:320]
    return ""


def _normalize(issues: List[Dict[str, Any]], min_level: str) -> List[Dict[str, Any]]:
    floor = _LEVEL_RANK.get((min_level or "minor").lower(), 1)
    out: List[Dict[str, Any]] = []
    for it in issues or []:
        if not isinstance(it, dict):
            continue
        # group may be a plain string or an IssueGroup object {name, description}
        g = it.get("group")
        group = (g.get("name") if isinstance(g, dict) else g) or it.get("category") or "Unknown"
        group = str(group).strip()
        gl = group.lower()
        level = str(it.get("level") or it.get("severity") or "medium").strip().lower()
        if _LEVEL_RANK.get(level, 2) < floor:
            continue
        detector = str(it.get("detector_name") or it.get("detector") or "").strip()
        domain = str(it.get("domain") or it.get("name") or "").strip()
        desc = str(it.get("description") or "").strip()
        metric = str(it.get("metric") or "").strip()
        deviation = str(it.get("deviation") or "").strip()
        meta = it.get("meta") if isinstance(it.get("meta"), dict) else {}
        if not metric:
            metric = str(meta.get("metric") or "").strip()
        if not deviation:
            deviation = str(meta.get("deviation") or "").strip()
        example = _first_example(it.get("examples"))

        owasp = _owasp_from_taxonomy(it.get("taxonomy")) or _OWASP.get(gl, "")
        detail_bits = [desc]
        if metric or deviation:
            detail_bits.append(f"[{metric}: {deviation}]" if metric and deviation else (metric or deviation))
        if example:
            detail_bits.append(example)
        out.append({
            "probe": detector or (f"giskard-{gl.replace(' ', '-')}" if gl else "giskard-issue"),
            "owasp": owasp,
            "category": _CATEGORY.get(gl, group),
            "name": domain or group,
            "technique": detector or "giskard-scan",
            "outcome": "fail",  # a Giskard issue IS a detected vulnerability
            "severity": _SEV.get(level, "Medium"),
            "detail": " ".join(b for b in detail_bits if b)[:500],
            "giskard_group": group,
            "level": level,
        })
    return out


def _extract(data: Any) -> (List[Dict[str, Any]], str):
    """Find the issue list + the model name across the plausible report shapes."""
    model = ""
    if isinstance(data, dict):
        m = data.get("model")
        if isinstance(m, dict):
            model = str(m.get("name") or "")
        elif isinstance(m, str):
            model = m
        model = model or str(data.get("model_name") or "")
        for key in ("issues", "results", "scan_results"):
            v = data.get(key)
            if isinstance(v, list):
                return v, model
        return [], model
    if isinstance(data, list):
        return data, model
    return [], model


def _live(base: str, key: str, project: str) -> Any:
    base = base.rstrip("/")
    path = f"/api/v2/scan-results/{project}" if project else "/api/v2/scan-results"
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base + path, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    min_level = str(params.get("min_level") or "minor")
    system = str(params.get("system") or "").strip()
    base = (os.environ.get("GISKARD_HUB_URL") or "").strip()
    key = (os.environ.get("GISKARD_API_KEY") or "").strip()
    project = (os.environ.get("GISKARD_PROJECT") or "").strip()

    if base:
        data = _live(base, key, project)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    issues, model = _extract(data)
    results = _normalize(issues, min_level)
    # Same envelope as the garak connector ({"aibas": {"results": [...]}}) so both feed the one
    # AI-BAS ingest path (runner.import_aibas -> XORCISM.AIBASRUN + AIBASRESULT, /ai-redteam).
    return {"source": SOURCE, "aibas": {"system": system or model, "results": results}}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=1)[:2500])
