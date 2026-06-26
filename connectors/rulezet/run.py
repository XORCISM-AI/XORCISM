"""run.py -- XORCISM connector for Rulezet (rulezet.org), the open-source detection-rule repository.

Rulezet aggregates ~197k community detection rules (YARA, Sigma, Suricata, Zeek, CRS, Nova, Wazuh,
Elastic) covering 858+ ATT&CK techniques, and exposes a public API. This connector searches Rulezet and
imports the matching rules into XORCISM's detection-content stores:

  - cve=<CVE-id>     rules linked to a CVE  (CIRCL Vulnerability-Lookup proxy:
                     GET /api/rulezet/search_rules_by_vulnerabilities/<cve>)  -> "search rules for a CVE"
  - technique=<Txxxx>  rules for an ATT&CK technique  (an attack-chain step)
  - query=<text>    free-text rule search

Sigma (and other non-YARA formats) -> XTHREAT.SIGMARULE (runner import_sigma_rules); YARA -> XTHREAT.YARARULE.
Both idempotent by reference, with the ATT&CK techniques kept as tags (feeds Threat-Informed Defense and
Purple-Team coverage). Offline: pass `file`, or run the bundled sample. Worker-safe: stdlib urllib only,
no auth required (optional RULEZET_TOKEN), ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List

SOURCE = "Rulezet"
BASE = os.environ.get("RULEZET_BASE", "https://rulezet.org/api").rstrip("/")
CIRCL = os.environ.get("RULEZET_CIRCL", "https://vulnerability.circl.lu/api/rulezet").rstrip("/")
_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
YARA_FMT = {"yara", "yara-l", "yaral"}


def _get(url: str, timeout: int = 30) -> Any:
    headers = {"Accept": "application/json", "User-Agent": "XORCISM-rulezet"}
    tok = os.environ.get("RULEZET_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (https)
            return json.loads(r.read().decode("utf-8", "replace") or "null")
    except (urllib.error.URLError, ValueError, TimeoutError):
        return None


def _pick(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return default


def _csv(xs: Any) -> str:
    if isinstance(xs, (list, tuple, set)):
        return ", ".join(str(x) for x in xs if x not in (None, ""))
    return str(xs) if xs not in (None, "") else ""


def _attack_tags(r: Dict[str, Any]) -> str:
    blob = " ".join(_csv(_pick(r, [k], "")) for k in ("mitre_attack", "attack", "attack_ids", "techniques", "mitre", "tags", "description"))
    return ", ".join(sorted({m.upper() for m in _ATTACK.findall(blob)}))


def _items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("rules", "data", "results", "items", "matches", "hits"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
            if isinstance(v, dict) and isinstance(v.get("rules"), list):
                return [x for x in v["rules"] if isinstance(x, dict)]
    return []


def _normalize(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    sigma: List[Dict[str, Any]] = []
    yara: List[Dict[str, Any]] = []
    for r in rules:
        fmt = str(_pick(r, ["format", "type", "rule_type", "kind", "language"], "sigma")).lower().strip()
        text = str(_pick(r, ["content", "rule", "raw", "rule_content", "source", "body", "yaml", "definition"], ""))
        name = str(_pick(r, ["name", "title", "rule_name"], "Rulezet rule"))[:300]
        desc = str(_pick(r, ["description", "summary"], ""))[:2000]
        author = str(_pick(r, ["author", "creator", "submitter"], "Rulezet"))[:200]
        rid = _pick(r, ["id", "rule_id", "uuid", "slug"])
        url = _pick(r, ["url", "source_url", "reference", "permalink"])
        ref = str(url or (f"https://rulezet.org/rules/{rid}" if rid else f"rulezet:{fmt}:{name}"))[:300]
        attack = _attack_tags(r)
        level = str(_pick(r, ["level", "severity"], "")) or None
        status = str(_pick(r, ["status"], "")) or "experimental"
        if fmt in YARA_FMT:
            yara.append({"name": name, "description": desc, "source": text, "author": author,
                         "reference": ref, "attack": attack, "tags": f"rulezet, {fmt}", "status": status})
        else:
            sigma.append({"name": name, "description": (f"[{fmt}] " + desc) if fmt != "sigma" else desc,
                          "yaml": text, "logsource": fmt, "level": level, "status": status, "author": author,
                          "reference": ref, "attack": attack})
    return {"sigma": sigma, "yara": yara}


def _search(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        limit = max(1, min(500, int(params.get("limit") or 100)))
    except (TypeError, ValueError):
        limit = 100
    cve = str(params.get("cve") or "").strip().upper()
    tech = str(params.get("technique") or "").strip().upper()
    query = str(params.get("query") or "").strip()
    if cve:
        return _items(_get(f"{CIRCL}/search_rules_by_vulnerabilities/{urllib.parse.quote(cve)}?page=1&per_page={limit}"))
    if tech:
        for path in (f"{BASE}/rules?attack={tech}&per_page={limit}", f"{BASE}/search?attack={tech}&per_page={limit}",
                     f"{BASE}/rules/search?q={tech}&per_page={limit}"):
            got = _items(_get(path))
            if got:
                return got
        return []
    if query:
        q = urllib.parse.quote(query)
        for path in (f"{BASE}/rules/search?q={q}&per_page={limit}", f"{BASE}/search?q={q}&per_page={limit}"):
            got = _items(_get(path))
            if got:
                return got
        return []
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            rules = _items(json.load(fh))
    elif params.get("cve") or params.get("technique") or params.get("query"):
        rules = _search(params)
    else:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json"), "r", encoding="utf-8", errors="replace") as fh:
            rules = _items(json.load(fh))
    out = _normalize(rules)
    return {"source": SOURCE, "sigma": out["sigma"], "yara": out["yara"], "count": len(out["sigma"]) + len(out["yara"])}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    print("Rulezet: %d rules (sigma/other=%d, yara=%d)" % (r["count"], len(r["sigma"]), len(r["yara"])))
    for x in (r["sigma"] + r["yara"])[:8]:
        fmt = x.get("logsource") or "yara"
        print("  %-9s %-40s %s" % (fmt, x["name"][:40], x.get("attack", "")))
