"""run.py — XORCISM connector: SkillAegis (CEXF cyber-exercise scenarios) -> Crisis / Tabletop exercises.

SkillAegis (https://github.com/SkillAegis, CIRCL / MISP ecosystem) is a platform to design, run and
monitor cyber-exercise scenarios. The SkillAegis-Editor authors scenarios in the **Common Exercise
Format (CEXF)** (JSON) and the SkillAegis-Dashboard runs them, tracking participants, injects and
scores in real time.

This connector imports CEXF exercise scenarios into XORCISM's Crisis Management / Tabletop-Exercise
library: each CEXF *exercise* becomes a **CRISISSCENARIO** (a reusable scenario template) and each
CEXF *inject* (task), ordered by the scenario's `inject_flow`, becomes an **EXERCISEINJECT** — so a
SkillAegis scenario can be launched as a XORCISM tabletop exercise (/crisis-management).

Input (params["file"]): a CEXF scenario `.json`, a directory of scenarios, or a JSON list/export.

Normalized output the runner imports (runner.import_exercises):
  {"exercises": [ {guid,name,description,type,severity,objectives,refs,attack,author,duration,
                   injects:[{guid,title,description,type,expected,order}]} ], "source": "SkillAegis (CEXF)"}

Python stdlib only. Worker-safe (no DB, no network).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "SkillAegis (CEXF)"
_TCODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ATTACK_TAG_RE = re.compile(r"attack[._]t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)  # CEXF tag: attack.t1486
# CEXF meta.level -> a coarse XORCISM severity (drill difficulty ~ exercise intensity).
_LEVEL_SEV = {"beginner": "Low", "easy": "Low", "intermediate": "Medium", "medium": "Medium",
              "advanced": "High", "hard": "High", "expert": "Critical"}


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.loads(fh.read())


def _iter_scenarios(path: str) -> List[Dict[str, Any]]:
    """A CEXF file (dict with an 'exercise'), a JSON list of them, or a directory of .json files."""
    out: List[Dict[str, Any]] = []
    if os.path.isdir(path):
        for root, _d, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(".json"):
                    try:
                        out.extend(_iter_scenarios(os.path.join(root, fn)))
                    except Exception:  # noqa: BLE001
                        continue
        return out
    data = _load(path)
    if isinstance(data, list):
        for d in data:
            if isinstance(d, dict) and (d.get("exercise") or d.get("injects")):
                out.append(d)
    elif isinstance(data, dict):
        if data.get("exercises") and isinstance(data["exercises"], list):
            out.extend(x for x in data["exercises"] if isinstance(x, dict))
        elif data.get("exercise") or data.get("injects"):
            out.append(data)
    return out


def _inject_order(cexf: Dict[str, Any]) -> Dict[str, int]:
    """Map inject_uuid -> step order. Prefer the authored inject_flow sequence; else injects order."""
    order: Dict[str, int] = {}
    flow = cexf.get("inject_flow") or []
    for i, f in enumerate(flow):
        u = f.get("inject_uuid") if isinstance(f, dict) else None
        if u and u not in order:
            order[u] = i + 1
    n = len(order)
    for i, inj in enumerate(cexf.get("injects") or []):
        u = inj.get("uuid") if isinstance(inj, dict) else None
        if u and u not in order:
            n += 1
            order[u] = n
    return order


def _flow_desc(cexf: Dict[str, Any]) -> Dict[str, str]:
    return {f.get("inject_uuid"): _s(f.get("description")) for f in (cexf.get("inject_flow") or [])
            if isinstance(f, dict) and f.get("inject_uuid")}


def _expected(inj: Dict[str, Any]) -> str:
    """The 'result' strings across an inject's evaluations = what the participant must achieve."""
    res = []
    for ev in (inj.get("inject_evaluation") or []):
        if isinstance(ev, dict) and ev.get("result"):
            res.append(str(ev["result"]))
    return " · ".join(dict.fromkeys(res))


def _normalize(cexf: Dict[str, Any]) -> Dict[str, Any]:
    ex = cexf.get("exercise") or {}
    meta = ex.get("meta") or {}
    tags = ex.get("tags") or []
    text = " ".join(str(t) for t in tags) + " " + _s(ex.get("name")) + " " + _s(ex.get("description"))
    attack = sorted({m.upper() for m in _TCODE_RE.findall(text)}
                    | {("T" + m.group(1)).upper() for t in tags for m in [_ATTACK_TAG_RE.search(str(t))] if m})
    order = _inject_order(cexf)
    fdesc = _flow_desc(cexf)
    injects = []
    for inj in (cexf.get("injects") or []):
        if not isinstance(inj, dict):
            continue
        u = inj.get("uuid")
        injects.append({
            "guid": u, "title": _s(inj.get("name"))[:300] or "Inject",
            "description": (fdesc.get(u) or _s(inj.get("description")) or _s(inj.get("name")))[:4000],
            "type": _s(inj.get("action") or inj.get("target_tool") or "task")[:80],
            "expected": _expected(inj)[:2000] or None,
            "order": order.get(u, 999),
        })
    injects.sort(key=lambda x: x["order"])
    for i, inj in enumerate(injects, start=1):  # renumber to a dense 1..N
        inj["order"] = i
    return {
        "guid": ex.get("uuid"),
        "name": _s(ex.get("name"))[:300] or "SkillAegis exercise",
        "description": (_s(ex.get("description")) or _s(ex.get("expanded")))[:8000],
        "type": "Cyber Exercise",
        "severity": _LEVEL_SEV.get(str(meta.get("level") or "").lower()),
        "objectives": (_s(ex.get("expanded")) or _s(ex.get("description")))[:4000],
        "attack": ", ".join(attack),
        "author": _s(meta.get("author")) or None,
        "duration": _s(ex.get("total_duration")) or None,
        "namespace": _s(ex.get("namespace")) or None,
        "refs": f"SkillAegis CEXF {ex.get('uuid') or ''}".strip()
                + (f" · {ex.get('namespace')}" if ex.get("namespace") else "")
                + (f" · tags: {', '.join(str(t) for t in tags)}" if tags else ""),
        "injects": injects,
    }


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("skillaegis: provide a 'file' (a CEXF scenario .json, a directory, or a JSON list)")
    if not os.path.exists(path):
        raise RuntimeError(f"skillaegis: file not found: {path}")
    scenarios = _iter_scenarios(path)
    exercises = [_normalize(s) for s in scenarios]
    exercises = [e for e in exercises if e["name"]]
    return {
        "source": SOURCE,
        "exercises": exercises,
        "summary": {"exercises": len(exercises), "injects": sum(len(e["injects"]) for e in exercises)},
    }


if __name__ == "__main__":
    import argparse
    import tempfile
    ap = argparse.ArgumentParser(description="Import SkillAegis CEXF exercise scenarios")
    ap.add_argument("file", help="a CEXF scenario .json, a directory of scenarios, or a JSON list")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file}, tempfile.mkdtemp()), indent=2, ensure_ascii=False))
