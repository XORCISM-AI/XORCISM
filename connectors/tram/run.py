"""run.py — XORCISM connector for MITRE TRAM (Threat Report ATT&CK Mapper).

TRAM (github.com/center-for-threat-informed-defense/tram) uses NLP (SciBERT) to map the
sentences of a finished CTI report to MITRE ATT&CK techniques with a confidence score. This
connector ingests TRAM's report-export JSON and normalises it into XORCISM as a threat report
plus its sentence→technique mappings (XTHREAT.THREATREPORT + REPORTMAPPING via
runner.import_report_mappings), so TRAM's mappings feed XORCISM's ATT&CK coverage & CTI.

Modes (in order):
    live    : TRAM_URL (+ TRAM_TOKEN) -> TRAM REST API (report-export). TRAM_REPORT_ID for one
              report, else list /api/reports/ and export up to `limit`.
    offline : params["file"] -> a saved TRAM report-export JSON (one object or a list).
    demo    : neither -> the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    TRAM_URL         base URL of a TRAM instance, e.g. http://localhost:8000   (live)
    TRAM_TOKEN       API token (sent as `Authorization: Token <...>`)          (live, optional)
    TRAM_REPORT_ID   export just this report id                                (optional)

Params: limit (max reports), min_confidence (drop mappings below), only_accepted (keep only
sentences the analyst accepted). Normalized result: {"source":"TRAM","reportmappings":[...]}.
Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "TRAM"
_TECH_RE = None  # lazy


def _tid_ok(s: str) -> bool:
    import re
    return bool(re.match(r"^T\d{4}(\.\d{3})?$", s or "", re.I))


def _f(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _normalize_report(rep: Dict[str, Any], min_conf: float, only_accepted: bool) -> Optional[Dict[str, Any]]:
    if not isinstance(rep, dict):
        return None
    rid = rep.get("id") or rep.get("document_id") or rep.get("name")
    if rid is None:
        return None
    out_sentences: List[Dict[str, Any]] = []
    accepted_tags: List[str] = []
    for s in rep.get("sentences") or []:
        if not isinstance(s, dict):
            continue
        disp = str(s.get("disposition") or "").lower()
        if only_accepted and disp and disp != "accept":
            continue
        maps: List[Dict[str, Any]] = []
        for m in s.get("mappings") or []:
            if not isinstance(m, dict):
                continue
            aid = str(m.get("attack_id") or m.get("attackId") or "").strip().upper()
            conf = _f(m.get("confidence"))
            if not _tid_ok(aid) or conf < min_conf:
                continue
            maps.append({"attack_id": aid, "name": str(m.get("name") or aid)[:200], "confidence": round(conf, 4)})
            if disp == "accept" or not disp:
                accepted_tags.append(aid)
        if maps:
            out_sentences.append({
                "text": str(s.get("text") or "")[:2000],
                "order": int(s.get("order") or 0) if str(s.get("order") or "").lstrip("-").isdigit() else 0,
                "disposition": disp or "review",
                "mappings": maps,
            })
    # de-dup accepted tags, preserve order
    seen, tags = set(), []
    for t in accepted_tags:
        if t not in seen:
            seen.add(t)
            tags.append(t)
    return {
        "external_id": str(rid),
        "name": str(rep.get("name") or f"TRAM report {rid}")[:300],
        "reference": rep.get("reference") or rep.get("url"),
        "text": str(rep.get("text") or "")[:8000],
        "ml_model": rep.get("ml_model"),
        "status": rep.get("status"),
        "author": rep.get("created_by") or rep.get("byline"),
        "created": rep.get("created_on") or rep.get("updated_on"),
        "attack_tags": ", ".join(tags),
        "sentences": out_sentences,
    }


def _normalize(data: Any, min_conf: float, only_accepted: bool, limit: int) -> List[Dict[str, Any]]:
    reports = data if isinstance(data, list) else (data.get("reports") if isinstance(data, dict) and isinstance(data.get("reports"), list) else [data])
    out: List[Dict[str, Any]] = []
    for rep in reports[:limit]:
        n = _normalize_report(rep, min_conf, only_accepted)
        if n and n["sentences"]:
            out.append(n)
    return out


def _get(url: str, token: str) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Token {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def _live(base: str, token: str, report_id: str, min_conf: float, only_accepted: bool, limit: int) -> List[Dict[str, Any]]:
    base = base.rstrip("/")
    ids: List[str] = []
    if report_id:
        ids = [report_id]
    else:
        listing = _get(f"{base}/api/reports/", token)
        rows = listing.get("results") if isinstance(listing, dict) else listing
        for r in (rows or [])[:limit]:
            rid = r.get("id") if isinstance(r, dict) else None
            if rid is not None:
                ids.append(str(rid))
    reports: List[Dict[str, Any]] = []
    for rid in ids[:limit]:
        try:
            reports.append(_get(f"{base}/api/report-export/{rid}/", token))
        except Exception:  # noqa: BLE001
            continue
    return _normalize(reports, min_conf, only_accepted, limit)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 50) or 50)
    min_conf = _f(params.get("min_confidence"), 0.0)
    only_accepted = bool(params.get("only_accepted", False))
    base = (os.environ.get("TRAM_URL") or "").strip()
    token = (os.environ.get("TRAM_TOKEN") or "").strip()
    report_id = (os.environ.get("TRAM_REPORT_ID") or str(params.get("report_id") or "")).strip()

    if base:
        reports = _live(base, token, report_id, min_conf, only_accepted, limit)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        reports = _normalize(data, min_conf, only_accepted, limit)
    return {"source": SOURCE, "reportmappings": reports}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
