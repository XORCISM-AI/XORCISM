"""run.py — XORCISM connector: SOC Prime detection content → XTHREAT.

Imports Sigma detection rules from SOC Prime's Threat Detection Marketplace / Platform
(https://socprime.com) and returns them BOTH as detection content and as intel:
  • "detections" → XTHREAT.SIGMARULE  (idempotent by rule reference) — feeds the
    Threat-Informed Defense 'detect' pillar and Purple-Team coverage.
  • "intel"      → XTHREAT.INTELEXCHANGE (idempotent by the same reference) — so each
    detection shows in the intel feed and its MITRE ATT&CK techniques are cross-linked
    into INTELEXCHANGEATTACK for ATT&CK coverage.

This module performs NO database access (so it also runs on a remote worker): it returns
{"detections": [ ... ], "intel": [ ... ], "source": "SOC Prime"}.

Python stdlib only (PyYAML is used if installed, else a built-in Sigma field extractor).

Live mode (worker environment variables):
    SOCPRIME_API_KEY   API token (Bearer) for the SOC Prime platform/API
    SOCPRIME_API_URL   override the API endpoint returning a JSON list of rules

Offline / air-gapped / test mode:
    params["path"] (or params["file"]) = a single Sigma .yml file, a directory of Sigma
        rules, or a JSON list/export of rules.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List
from uuid import uuid4

SOURCE = "SOC Prime"
_ATTACK_TAG_RE = re.compile(r"attack[._]t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

try:                       # PyYAML is nice-to-have, not required
    import yaml            # type: ignore
    _HAVE_YAML = True
except Exception:          # noqa: BLE001
    _HAVE_YAML = False


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    max_items = int(params.get("max_items") or 200)
    path = params.get("path") or params.get("file")
    rules: List[Dict[str, Any]] = []
    if path:
        rules = _load_offline(path)
    else:
        rules = _fetch_live(max_items)
    rules = rules[:max_items]
    detections = [_to_sigma_item(r) for r in rules]
    detections = [d for d in detections if d]
    intel = [_to_intel_item(d) for d in detections]
    return {"detections": detections, "intel": intel, "source": SOURCE}


# ── input loaders ─────────────────────────────────────────────────────────────
def _load_offline(path: str) -> List[Dict[str, Any]]:
    if os.path.isdir(path):
        out = []
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith((".yml", ".yaml")):
                    with open(os.path.join(root, fn), "r", encoding="utf-8", errors="replace") as fh:
                        out.append({"_yaml": fh.read(), "_file": fn})
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if path.lower().endswith((".yml", ".yaml")):
        return [{"_yaml": text, "_file": os.path.basename(path)}]
    # JSON: a list of rules, an export {"rules": [...]} / {"data": [...]}, or a single rule
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("rules") or data.get("data") or data.get("items") or [data]
    out = []
    for r in (data if isinstance(data, list) else []):
        if isinstance(r, str):
            out.append({"_yaml": r})
        elif isinstance(r, dict):
            # rule may carry the sigma body under sigma/yaml/body/rule, else be the dict itself
            body = r.get("sigma") or r.get("yaml") or r.get("body") or r.get("rule")
            if isinstance(body, str):
                r = {**r, "_yaml": body}
            out.append(r)
    return out


def _fetch_live(limit: int) -> List[Dict[str, Any]]:
    key = os.getenv("SOCPRIME_API_KEY") or ""
    url = os.getenv("SOCPRIME_API_URL") or ""
    if not key or not url:
        raise RuntimeError(
            "SOC Prime live mode needs SOCPRIME_API_KEY (+ SOCPRIME_API_URL) — or pass a "
            "saved export with path=/file= (a Sigma .yml, a directory of rules, or a JSON export)."
        )
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310 (configured endpoint)
        data = json.loads(r.read().decode("utf-8", "replace"))
    if isinstance(data, dict):
        data = data.get("rules") or data.get("data") or data.get("items") or []
    return [d for d in (data if isinstance(data, list) else [])][:limit]


# ── Sigma parsing ─────────────────────────────────────────────────────────────
def _re_field(text: str, key: str) -> str:
    m = re.search(rf"^{key}:\s*(.+)$", text, re.MULTILINE)
    return (m.group(1).strip().strip("'\"") if m else "")


def _parse_sigma(text: str) -> Dict[str, Any]:
    """Extract the fields we need from a Sigma rule (PyYAML if available, else regex)."""
    doc: Dict[str, Any] = {}
    if _HAVE_YAML:
        try:
            loaded = yaml.safe_load(text)
            if isinstance(loaded, dict):
                doc = loaded
        except Exception:  # noqa: BLE001 — fall back to regex
            doc = {}
    if doc:
        ls = doc.get("logsource") or {}
        logsource = ", ".join(f"{k}={v}" for k, v in ls.items() if v) if isinstance(ls, dict) else str(ls)
        refs = doc.get("references") or []
        return {
            "title": doc.get("title") or "", "id": doc.get("id") or "",
            "description": doc.get("description") or "", "level": (doc.get("level") or ""),
            "status": (doc.get("status") or ""), "author": doc.get("author") or "",
            "logsource": logsource,
            "reference": (refs[0] if isinstance(refs, list) and refs else ""),
            "tags": doc.get("tags") or [],
        }
    # regex fallback
    ls_block = re.search(r"logsource:\s*\n((?:[ \t]+.+\n?)+)", text)
    logsource = ""
    if ls_block:
        pairs = re.findall(r"^\s*(\w+):\s*(.+)$", ls_block.group(1), re.MULTILINE)
        logsource = ", ".join(f"{k}={v.strip().strip(chr(39)+chr(34))}" for k, v in pairs)
    return {
        "title": _re_field(text, "title"), "id": _re_field(text, "id"),
        "description": _re_field(text, "description"), "level": _re_field(text, "level"),
        "status": _re_field(text, "status"), "author": _re_field(text, "author"),
        "logsource": logsource, "reference": "", "tags": [],
    }


def _to_sigma_item(raw: Dict[str, Any]) -> Dict[str, Any] | None:
    yaml_text = raw.get("_yaml")
    if yaml_text:
        f = _parse_sigma(yaml_text)
    else:
        # already-structured rule dict (no raw yaml) — read keys directly
        f = {k: raw.get(k, "") for k in ("title", "id", "description", "level", "status", "author", "logsource")}
        f["reference"] = raw.get("reference") or raw.get("url") or ""
        f["tags"] = raw.get("tags") or []
        yaml_text = ""
    # ATT&CK techniques: from tags list AND from the raw yaml text (robust)
    tag_blob = " ".join(str(t) for t in (f.get("tags") or [])) + " " + (yaml_text or "")
    attack = sorted({("T" + m).upper() for m in _ATTACK_TAG_RE.findall(tag_blob)})
    cves = sorted({m.upper() for m in _CVE_RE.findall(tag_blob + " " + (f.get("description") or ""))})
    title = f.get("title") or (raw.get("_file") or "SOC Prime detection")
    rid = f.get("id") or raw.get("id") or ""
    ref = f.get("reference") or (raw.get("url") if isinstance(raw.get("url"), str) else "") \
        or (f"socprime:rule:{rid}" if rid else f"socprime:rule:{title}")
    return {
        "name": str(title)[:300],
        "title": str(title)[:300],
        "description": str(f.get("description") or "")[:2000],
        "yaml": yaml_text,
        "logsource": str(f.get("logsource") or "")[:300],
        "level": str(f.get("level") or "medium").lower(),
        "status": str(f.get("status") or "experimental").lower(),
        "author": str(f.get("author") or SOURCE)[:200],
        "reference": ref,
        "guid": rid or None,
        "attack_tags": ", ".join(attack),
        "cve_tags": ", ".join(cves),
    }


def _to_intel_item(d: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": f"[Detection] {d['name']}"[:500],
        "description": (d.get("description") or "")
        + (f"\nLog source: {d['logsource']}." if d.get("logsource") else "")
        + f"\nSeverity: {d.get('level')}. Source: SOC Prime (Sigma detection content)."[:8000],
        "reference": d["reference"],
        "external_id": d.get("guid"),
        "author": d.get("author") or SOURCE,
        "date": "",
        "attack_tags": d.get("attack_tags") or "",
        "actor_tags": "",
        "malware_tags": "",
        "cve_tags": d.get("cve_tags") or "",
        "tags": f"SOC Prime, Sigma, detection, level:{d.get('level')}",
        "views": None,
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="SOC Prime → SIGMARULE + INTELEXCHANGE import (dry run)")
    ap.add_argument("--path", help="Sigma .yml file, a directory of rules, or a JSON export")
    ap.add_argument("--max-items", type=int, default=200)
    a = ap.parse_args()
    res = run({"path": a.path, "max_items": a.max_items}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[socprime] {len(res['detections'])} detection(s) / {len(res['intel'])} intel item(s) "
          f"from {res['source']}", flush=True)
