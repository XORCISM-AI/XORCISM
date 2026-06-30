"""bawbel-scanner connector — parse the AVE reference scanner's output and emit per-artifact AVE
findings for import into XORCISM.AVESCANFINDING (the runner's import_ave_scan_findings path).

The bawbel-scanner (`pip install bawbel-scanner`, github.com/bawbel/ave, Apache-2.0) scans agentic-AI
components (skill files / MCP manifests / system prompts / agents) for behavioral vulnerability
classes and emits **AVE-in-SARIF 2.1.0** — each result references an AVE-2026-##### rule (with AIVSS
score + OWASP MCP / MITRE ATLAS mappings) and a file:line location + confidence + detection engine.

Worker-safe & read-only: parses an exported report only (no scanning). Accepts the SARIF, or a flat
{findings:[]} / array JSON. Defaults to the bundled sample SARIF.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sev_from_level(lvl: str) -> str:
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get((lvl or "").lower(), "")


def _from_sarif(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for run in doc.get("runs") or []:
        rules: Dict[str, Any] = {}
        try:
            for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
                rules[r.get("id")] = r
        except Exception:  # noqa: BLE001
            pass
        for res in run.get("results") or []:
            rule = rules.get(res.get("ruleId"), {}) or {}
            rp = rule.get("properties", {}) or {}
            p = res.get("properties", {}) or {}
            loc = ((res.get("locations") or [{}])[0] or {}).get("physicalLocation", {}) or {}
            out.append({
                "ave_id": res.get("ruleId"), "rule_id": p.get("rule_id") or rule.get("name"),
                "title": (rule.get("shortDescription") or {}).get("text") or rule.get("name"),
                "severity": rp.get("severity") or _sev_from_level(res.get("level")),
                "aivss_score": rp.get("aivss_score"), "confidence": p.get("confidence"),
                "component_type": rp.get("component_type") or p.get("component_type"),
                "file": (loc.get("artifactLocation") or {}).get("uri"),
                "line": (loc.get("region") or {}).get("startLine"),
                "message": (res.get("message") or {}).get("text"),
                "evidence_kind": p.get("evidence_kind"), "evidence_stage": p.get("evidence_stage"),
                "owasp_mcp": rp.get("owasp_mcp"), "mitre_atlas": rp.get("mitre_atlas"),
            })
    return out


def _collect(doc: Any) -> List[Dict[str, Any]]:
    if isinstance(doc, dict) and (doc.get("runs") or "sarif" in str(doc.get("$schema", "")).lower()):
        return _from_sarif(doc)
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        for k in ("findings", "ave_scan_findings", "results"):
            if isinstance(doc.get(k), list):
                return [f for f in doc[k] if isinstance(f, dict)]
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    path = params.get("file") or os.path.join(here, "sample.sarif.json")
    if not os.path.isabs(path) and not os.path.exists(path):
        cand = os.path.join(workdir or here, path)
        if os.path.exists(cand):
            path = cand
    try:
        doc = _load(path)
    except FileNotFoundError:
        return {"ave_scan_findings": [], "error": "file not found: %s" % path}
    except (json.JSONDecodeError, ValueError) as exc:
        return {"ave_scan_findings": [], "error": "not valid JSON: %s" % exc}
    return {
        "ave_scan_findings": _collect(doc),
        "source": str(params.get("source") or "bawbel-scanner"),
        "scan_ref": str(params.get("scan_ref") or ""),
        "count": len(_collect(doc)),
    }


if __name__ == "__main__":  # python run.py [report.sarif|findings.json]
    import sys
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    res = run(p, os.getcwd())
    print(json.dumps({k: (v if k != "ave_scan_findings" else "[%d findings]" % len(v)) for k, v in res.items()}, indent=2))
