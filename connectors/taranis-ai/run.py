#!/usr/bin/env python3
"""run.py — XORCISM connector: Taranis AI (OSINT/CTI) → XTHREAT.INTELEXCHANGE.

Taranis AI (https://github.com/taranis-ai/taranis-ai, EUPL-1.2) is an AI-powered OSINT
tool: it collects unstructured news from web/RSS sources, AI-enriches them, and lets
analysts refine them into structured reports. This connector turns Taranis news items /
reports into XORCISM threat-intel items (INTELEXCHANGE), extracting CVE / MITRE ATT&CK /
threat-actor tags. It does NOT touch the DB (worker-safe): it returns
{"intel": [...], "source": "taranis-ai"} that the runner's import_threat_intel() maps to
INTELEXCHANGE (idempotent by reference) + cross-links ATT&CK techniques.

Modes:
  - file=<json>   import a Taranis JSON export (news items / reports)        ← primary, reliable
  - live          fetch from the Taranis Core REST API (env TARANIS_URL +
                  TARANIS_API_KEY, Bearer/JWT); best-effort across versions.

Dry-run (no DB):
    python connectors/taranis-ai/run.py --file connectors/taranis-ai/sample.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from typing import Any, Dict, List

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ACTOR_RE = re.compile(r"\b(?:APT[\s-]?\d{1,3}|FIN\d{1,2}|UNC\d{3,5}|TA\d{3,4}|TEMP\.[A-Za-z0-9]+|UTA-\d{2,4})\b", re.I)
_HTML_RE = re.compile(r"<[^>]+>")


def _strip_html(s: str) -> str:
    return re.sub(r"\s+", " ", _HTML_RE.sub(" ", s or "")).strip()


def _csv(values) -> str:
    out: List[str] = []
    for v in values:
        v = str(v).strip()
        if v and v not in out:
            out.append(v)
    return ", ".join(out)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    items = _load(params)
    intel = [x for x in (_to_intel(it) for it in items) if x]
    return {"intel": intel, "source": "taranis-ai"}


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            return _find_list(json.load(fh))
    base = (os.environ.get("TARANIS_URL") or str(params.get("url") or "")).strip().rstrip("/")
    if not base:
        raise RuntimeError("taranis-ai: provide a 'file' (Taranis JSON export) or set env TARANIS_URL (+ TARANIS_API_KEY) for live mode")
    return _fetch_live(base, int(params.get("max_items") or 100))


def _find_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("items", "news_items", "newsItems", "reports", "products", "data", "results"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        if data.get("title") or data.get("id"):   # a single object
            return [data]
    return []


def _fetch_live(base: str, max_items: int) -> List[Dict[str, Any]]:
    import urllib.request
    key = (os.environ.get("TARANIS_API_KEY") or "").strip()
    headers = {"Accept": "application/json", "User-Agent": "XORCISM-taranis"}
    if key:
        headers["Authorization"] = key if key.lower().startswith("bearer ") else "Bearer " + key
    endpoints = [
        "/api/assess/news-items?limit=%d" % max_items, "/api/assess/news-items",
        "/api/analyze/reports", "/api/news-items",
    ]
    last: Any = None
    for ep in endpoints:
        try:
            req = urllib.request.Request(base + ep, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (operator-provided URL)
                lst = _find_list(json.loads(r.read().decode("utf-8", "replace")))
            if lst:
                return lst[:max_items]
        except Exception as e:  # try the next candidate endpoint
            last = e
    raise RuntimeError(f"taranis-ai live: no news-item endpoint returned items ({last}). Use a 'file' JSON export instead.")


def _first(d: Dict[str, Any], keys, default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, dict):                    # e.g. source: {name: ...}
            v = v.get("name") or v.get("title") or v.get("id")
        if v not in (None, "", [], {}):
            return str(v).strip()
    return default


def _tag_names(d: Dict[str, Any]) -> List[str]:
    t = d.get("tags") or d.get("attributes") or []
    if isinstance(t, dict):
        t = list(t.values())
    out: List[str] = []
    for x in (t if isinstance(t, list) else []):
        if isinstance(x, dict):
            x = x.get("name") or x.get("tag") or x.get("value")
        if x:
            out.append(str(x))
    return out


def _to_intel(d: Dict[str, Any]) -> Dict[str, Any] | None:
    title = _first(d, ("title", "name", "headline", "subject"))
    body = _strip_html(_first(d, ("content", "review", "summary", "abstract", "description", "body", "text")))
    if not title and not body:
        return None
    link = _first(d, ("link", "web_url", "url", "source_url", "source_link"))
    ext = _first(d, ("id", "uuid", "news_item_id", "osint_source_id"))
    ref = link or ("taranis:" + (ext or hashlib.sha1((title + body).encode("utf-8")).hexdigest()[:16]))
    author = _first(d, ("source", "author", "collector", "feed", "osint_source")) or "Taranis AI"
    date = _first(d, ("published", "published_date", "collected", "created", "last_change", "date"))
    tagnames = _tag_names(d)
    blob = " ".join([title, body, " ".join(tagnames)])
    return {
        "name": (title or "Taranis news item")[:500],
        "description": body[:6000],
        "reference": ref[:500],
        "external_id": (ext[:120] if ext else None),
        "author": author[:200],
        "date": (date or None),
        "attack_tags": _csv(m.group(0).upper() for m in ATTACK_RE.finditer(blob)),
        "cve_tags": _csv(m.group(0).upper() for m in CVE_RE.finditer(blob)),
        "actor_tags": _csv(re.sub(r"\s+", "", m.group(0)).upper() for m in ACTOR_RE.finditer(blob)),
        "tags": _csv(["taranis-ai"] + tagnames),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Taranis AI → INTELEXCHANGE (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--url", default="")
    ap.add_argument("--max-items", type=int, default=100)
    a = ap.parse_args()
    res = run({"file": a.file, "url": a.url, "max_items": a.max_items}, "")
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[taranis-ai] {len(res['intel'])} intel item(s)", flush=True)
