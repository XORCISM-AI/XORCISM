"""run.py — XORCISM connector: OpenCVE → vulnerabilities (CVEs).

OpenCVE (https://www.opencve.io) is a CVE monitoring & alerting platform. This connector pulls
CVEs from its REST API — filtered by vendor / product / keyword / CVSS severity / tag — and maps
each to a vulnerability finding (ref = CVE id, name = description, severity from CVSS). With a
`project`, the CVEs are attached to that asset (ASSETVULNERABILITY); otherwise they just enrich
the CVE database (XVULNERABILITY).

Auth comes from the WORKER ENVIRONMENT (never the UI):
    OPENCVE_API_TOKEN                      Bearer organization token (preferred), OR
    OPENCVE_USERNAME + OPENCVE_PASSWORD    HTTP Basic (legacy OpenCVE v1)
    OPENCVE_URL                            base URL (or the `base` param); default app.opencve.io

Offline / test mode: params["file"] = a saved OpenCVE JSON response ({results:[...]}, a bare
list, or a single CVE object). Python stdlib only; NO database access (remote-worker safe).
"""
from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

TOOL_NAME = "OpenCVE"
TOOL_URL = "https://www.opencve.io"
_DEFAULT_BASE = "https://app.opencve.io"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    project = str(params.get("project") or "").strip()
    cvss = str(params.get("cvss") or "").strip().lower()
    max_items = int(params.get("max_items") or 200)

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        records = _records(data)
    else:
        records = _fetch(params, max_items)

    records = records[:max_items]
    want_details = _truthy(params.get("details")) and not params.get("file")
    auth, base = (_auth(), _base(params)) if want_details else (None, None)

    vulns: List[Dict[str, Any]] = []
    seen: set = set()
    for rec in records:
        cid = str(rec.get("cve_id") or rec.get("id") or "").strip().upper()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        sev = _severity_from_record(rec)
        if not sev and cvss in ("low", "medium", "high", "critical"):
            sev = cvss  # the list was filtered by this severity
        if not sev and want_details:
            sev = _fetch_severity(base, auth, cid)  # one extra request per CVE
        name = str(rec.get("description") or rec.get("title") or cid)
        v: Dict[str, Any] = {"ref": cid, "name": name[:300], "severity": sev or "unknown"}
        if project:
            v["asset"] = project
        vulns.append(v)

    out: Dict[str, Any] = {"assets": [], "services": [], "cpes": [], "vulns": vulns, "source": "OpenCVE"}
    if project:
        out["project"] = project
    return out


# ── HTTP (stdlib) ────────────────────────────────────────────────────────────────
def _base(params: Dict[str, Any]) -> str:
    b = str(params.get("base") or os.getenv("OPENCVE_URL") or _DEFAULT_BASE).rstrip("/")
    return b if b.endswith("/api") else b + "/api"


def _auth() -> Optional[str]:
    tok = os.getenv("OPENCVE_API_TOKEN")
    if tok:
        return f"Bearer {tok.strip()}"
    user, pw = os.getenv("OPENCVE_USERNAME"), os.getenv("OPENCVE_PASSWORD")
    if user and pw:
        return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    return None


def _get(url: str, auth: Optional[str]) -> Any:
    headers = {"Accept": "application/json"}
    if auth:
        headers["Authorization"] = auth
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (configured OpenCVE endpoint)
        return json.loads(r.read().decode("utf-8", "replace"))


def _fetch(params: Dict[str, Any], max_items: int) -> List[Dict[str, Any]]:
    auth = _auth()
    if not auth:
        raise RuntimeError(
            "OpenCVE live mode needs OPENCVE_API_TOKEN (or OPENCVE_USERNAME + OPENCVE_PASSWORD) in "
            "the worker environment — or pass an offline export via file=.")
    base = _base(params)
    q = {k: str(params[k]).strip() for k in ("vendor", "product", "search", "tag")
         if params.get(k) and str(params[k]).strip()}
    cvss = str(params.get("cvss") or "").strip().lower()
    if cvss in ("low", "medium", "high", "critical"):
        q["cvss"] = cvss
    url: Optional[str] = base + "/cve" + ("?" + urllib.parse.urlencode(q) if q else "")
    out: List[Dict[str, Any]] = []
    while url and len(out) < max_items:
        page = _get(url, auth)
        out.extend(_records(page))
        url = page.get("next") if isinstance(page, dict) else None
    return out


def _fetch_severity(base: Optional[str], auth: Optional[str], cve_id: str) -> str:
    if not base:
        return ""
    try:
        return _severity_from_record(_get(f"{base}/cve/{urllib.parse.quote(cve_id)}", auth))
    except Exception:
        return ""


# ── parsing ──────────────────────────────────────────────────────────────────────
def _records(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return [r for r in data["results"] if isinstance(r, dict)]
        if data.get("cve_id") or data.get("id"):
            return [data]
        return []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def _severity_from_record(rec: Dict[str, Any]) -> str:
    metrics = rec.get("metrics") if isinstance(rec.get("metrics"), dict) else {}
    score: Optional[float] = None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        m = metrics.get(key) if isinstance(metrics.get(key), dict) else None
        d = m.get("data") if m and isinstance(m.get("data"), dict) else None
        if d and d.get("score") is not None:
            try:
                score = float(d["score"]); break
            except (TypeError, ValueError):
                pass
    # OpenCVE list rows sometimes carry a flat cvss/score
    if score is None:
        for k in ("cvss", "cvss3", "score"):
            try:
                if rec.get(k) is not None:
                    score = float(rec[k]); break
            except (TypeError, ValueError):
                pass
    if score is None:
        return ""
    return ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4
            else "low" if score > 0 else "info")


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("1", "true", "yes", "on")


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="OpenCVE → vulnerabilities (dry run)")
    ap.add_argument("--file", help="saved OpenCVE JSON response")
    ap.add_argument("--base", default="")
    ap.add_argument("--vendor", default="")
    ap.add_argument("--product", default="")
    ap.add_argument("--search", default="")
    ap.add_argument("--cvss", default="")
    ap.add_argument("--project", default="")
    ap.add_argument("--max-items", type=int, default=200)
    a = ap.parse_args()
    res = run({"file": a.file, "base": a.base, "vendor": a.vendor, "product": a.product,
               "search": a.search, "cvss": a.cvss, "project": a.project, "max_items": a.max_items},
              tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[opencve] {len(res['vulns'])} CVE finding(s)"
          + (f" -> asset '{res.get('project')}'" if res.get("project") else " (CVE database enrichment)"), flush=True)
