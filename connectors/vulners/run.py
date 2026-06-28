"""run.py - XORCISM connector: Vulners (vulners.com) vulnerability intelligence -> VULNERABILITY findings.

Queries the Vulners enriched vulnerability database and normalizes the result into the XORCISM model.
Three modes:
  - search : a Vulners Lucene query (or product) -> POST /api/v3/search/lucene
  - id     : a CVE / bulletin id              -> POST /api/v3/search/id
  - audit  : a Linux host's OS + packages     -> POST /api/v3/audit/audit (agentless package audit)
Each bulletin / referenced CVE becomes a VULN (ref = CVE, severity from CVSS, exploit flag for type=exploit);
the audit target host becomes an ASSET. Requires a Vulners API key (param apiKey or env VULNERS_API_KEY).
For offline use / testing, pass a saved Vulners JSON response via 'file' and it is normalized without a
network call. No DB access (worker-safe); uses only the stdlib (urllib).
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List

SOURCE = "Vulners"
API = "https://vulners.com/api/v3"
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _sev(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def _post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    req = urllib.request.Request(API + path, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json", "User-Agent": "XORCISM-connector"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (fixed https host)
        return json.loads(r.read().decode("utf-8", "replace"))


def _bulletins(data: Any) -> List[Dict[str, Any]]:
    """Pull the list of bulletin documents out of a Vulners response (search / id / audit shapes)."""
    d = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
    if not isinstance(d, dict):
        return []
    for k in ("search", "documents", "result", "vulnerabilities", "bulletins"):
        v = d.get(k)
        if isinstance(v, list):
            return [x.get("_source", x) if isinstance(x, dict) else x for x in v]
    # id mode: data.documents is a dict {id: {_source}}
    for k in ("documents", "references"):
        v = d.get(k)
        if isinstance(v, dict):
            return [x.get("_source", x) if isinstance(x, dict) else x for x in v.values()]
    return []


def _normalize(data: Any, target: str) -> Dict[str, Any]:
    vulns: List[Dict[str, Any]] = []
    seen = set()
    n = 0
    for b in _bulletins(data):
        if not isinstance(b, dict):
            continue
        bid = str(b.get("id") or b.get("_id") or "")
        cvss = ((b.get("cvss") or {}).get("score") if isinstance(b.get("cvss"), dict) else b.get("cvss")) or b.get("cvss3", {}).get("cvssV3", {}).get("baseScore") if isinstance(b.get("cvss3"), dict) else b.get("cvss")
        is_exploit = str(b.get("type") or "").lower() in ("exploit", "exploitdb", "metasploit", "githubexploit", "packetstorm", "zdt", "0day")
        title = str(b.get("title") or b.get("description") or bid)[:200]
        href = b.get("href") or (("https://vulners.com/" + str(b.get("type")) + "/" + bid) if b.get("type") and bid else "")
        cves = [c.upper() for c in (b.get("cvelist") or []) if _CVE.match(str(c))]
        if not cves and _CVE.match(bid):
            cves = [bid.upper()]
        refs = cves or ([bid] if bid else [])
        for ref in refs:
            key = ref + "|" + target
            if key in seen:
                continue
            seen.add(key)
            n += 1
            vulns.append({
                "asset": target, "ref": ref[:120], "name": title,
                "severity": _sev(cvss),
                "description": ("Vulners%s: %s%s" % (" exploit" if is_exploit else "", title, (" (CVSS %s)" % cvss) if cvss else ""))[:1600],
            })
    # audit: also a flat data.cvelist
    d = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else (data if isinstance(data, dict) else {})
    for c in (d.get("cvelist") or []):
        ref = str(c).upper()
        if _CVE.match(ref) and (ref + "|" + target) not in seen:
            seen.add(ref + "|" + target); n += 1
            vulns.append({"asset": target, "ref": ref, "name": "Vulners audit: %s affects %s" % (ref, target), "severity": "medium",
                          "description": "Reported by the Vulners package audit for %s." % target})
    assets = [{"name": target, "tags": ["vulners", "host" if "@" not in target else "query"]}] if target else []
    return {"source": SOURCE, "assets": assets, "vulns": vulns}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    # Offline: normalize a saved Vulners JSON response.
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        target = str(params.get("query") or params.get("os") or "vulners-import")
        return _normalize(data, target)

    api_key = params.get("apiKey") or os.environ.get("VULNERS_API_KEY")
    if not api_key:
        raise RuntimeError("vulners: set an apiKey (param) or VULNERS_API_KEY env, or pass a 'file' (saved response)")

    mode = str(params.get("mode") or "").lower()
    if not mode:
        mode = "audit" if (params.get("os") and params.get("packages")) else ("id" if params.get("cve") else "search")

    if mode == "id":
        cve = str(params.get("cve") or "").strip()
        if not cve:
            raise RuntimeError("vulners id: provide a 'cve' / bulletin id")
        return _normalize(_post("/search/id", {"id": cve, "apiKey": api_key}), cve)
    if mode == "audit":
        os_name = str(params.get("os") or "").strip()
        pkgs = [p.strip() for p in str(params.get("packages") or "").splitlines() if p.strip()]
        if not os_name or not pkgs:
            raise RuntimeError("vulners audit: provide 'os' and 'packages'")
        target = ("%s %s" % (os_name, params.get("osversion") or "")).strip()
        return _normalize(_post("/audit/audit", {"os": os_name, "version": str(params.get("osversion") or ""), "package": pkgs, "apiKey": api_key}), target)
    # search
    q = str(params.get("query") or "").strip()
    if not q:
        raise RuntimeError("vulners search: provide a 'query'")
    return _normalize(_post("/search/lucene", {"query": q, "size": 100, "apiKey": api_key}), q)


if __name__ == "__main__":
    import sys
    r = run({"file": sys.argv[1], "query": (sys.argv[2] if len(sys.argv) > 2 else "vulners")}, ".")
    print("Vulners: %d assets, %d vulns" % (len(r["assets"]), len(r["vulns"])))
    for v in r["vulns"][:10]:
        print("  %-9s %-18s %s" % (v["severity"], v["ref"], v["name"][:56]))
