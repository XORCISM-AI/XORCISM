"""run.py — XORCISM connector for ISMS Builder (github.com/coolstartnow/isms-builder, AGPL-3.0).

ISMS Builder is a self-hosted Information Security Management System (ISO 27001:2022, NIS2,
GDPR/DSGVO, BSI IT-Grundschutz, EUCS, EU AI Act, CRA) by Claude Hecker — a full ISMS: a Statement
of Applicability across 313 controls / 8 frameworks, policy templates (draft→review→approved→
archived), a risk register, assets, suppliers, BCM and audit tooling; Node/Express + JSON/SQLite.

XORCISM already has native homes for each ISMS module, so this connector *feeds* them rather than
duplicating them. It parses an ISMS Builder export and maps the GRC core:
  * the Statement of Applicability -> runner.import_soa: one Compliance AUDIT per framework, one
    AUDITFINDING per applicable-but-unimplemented control (the gap) -> /compliance-management;
  * the risk register -> the same import_soa: a "Risk register" AUDIT with a finding per open risk;
  * policy templates -> runner.import_documents -> XORCISM.DOCUMENT (/policy-management), keeping the
    lifecycle status and version.

Accepts a combined export ({soa|controls, risks, templates|policies, assets}) or a single-entity file
(a bare array, or {controls:[...]} / {risks:[...]} / {templates:[...]}). Assets are intentionally
not mapped (XORCISM's ASSET import is host-oriented; ISMS org-assets would not fit cleanly).

Modes: file (params["file"]) or demo (bundled sample.json). Worker-safe: stdlib only, no secrets.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "ISMS Builder"
_STATUSES = {"not_started", "in_progress", "implemented", "not_applicable"}


def _controls(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        for k in ("soa", "controls", "soaControls"):
            v = data.get(k)
            if isinstance(v, list):
                return [c for c in v if isinstance(c, dict)]
    if isinstance(data, list) and data and isinstance(data[0], dict) and ("applicable" in data[0] or "status" in data[0] and "framework" in data[0]):
        return [c for c in data if isinstance(c, dict)]
    return []


def _pick(data: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _norm_control(c: Dict[str, Any]) -> Dict[str, Any]:
    st = str(c.get("status") or "not_started").lower()
    return {
        "id": str(c.get("id") or c.get("ref") or c.get("control") or "")[:60],
        "framework": str(c.get("framework") or "ISO27001")[:60],
        "theme": str(c.get("theme") or c.get("category") or "")[:120],
        "title": str(c.get("title") or c.get("name") or c.get("id") or "")[:300],
        "applicable": c.get("applicable") is not False,
        "status": st if st in _STATUSES else "not_started",
        "owner": str(c.get("owner") or "")[:120],
        "justification": str(c.get("justification") or c.get("rationale") or "")[:1500],
        "linkedPolicies": [str(p) for p in (c.get("linkedPolicies") or c.get("linkedTemplates") or [])][:20],
    }


def _norm_risk(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(r.get("id") or "")[:60], "title": str(r.get("title") or r.get("name") or "")[:300],
        "category": str(r.get("category") or "")[:120], "description": str(r.get("description") or "")[:1500],
        "probability": r.get("probability"), "impact": r.get("impact"), "score": r.get("score"),
        "treatment": str(r.get("treatment") or "")[:120], "status": str(r.get("status") or "open")[:40],
        "owner": str(r.get("owner") or "")[:120],
    }


def _norm_policy(t: Dict[str, Any]) -> Dict[str, Any]:
    content = str(t.get("content") or "")
    st = str(t.get("status") or "draft")
    return {
        "external_id": str(t.get("id") or t.get("title") or "")[:120],
        "name": str(t.get("title") or t.get("id") or "Policy")[:300],
        "description": (content[:400] or str(t.get("type") or "Policy document")),
        "author": str(t.get("owner") or ""), "version": str(t.get("version") or ""),
        "status": st.capitalize(), "category": str(t.get("type") or "Policy"),
        "type": "Policy", "language": str(t.get("language") or "en"),
        "framework": "ISO 27001", "date": t.get("updatedAt") or t.get("createdAt"),
        "source": SOURCE,
    }


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]

    controls = [_norm_control(c) for c in _controls(data) if (c.get("id") or c.get("title"))]
    risks = [_norm_risk(r) for r in _pick(data, "risks", "riskRegister") if (r.get("id") or r.get("title"))]
    policies = [_norm_policy(t) for t in _pick(data, "templates", "policies", "documents") if (t.get("id") or t.get("title"))]

    out: Dict[str, Any] = {"source": SOURCE}
    if controls:
        out["soa"] = controls
    if risks:
        out["risks"] = risks
    if policies:
        out["documents"] = policies
    return out


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print(json.dumps({"source": r["source"], "soa": len(r.get("soa", [])),
                      "risks": len(r.get("risks", [])), "documents": len(r.get("documents", []))}))
    print(json.dumps(r, indent=1)[:1200])
