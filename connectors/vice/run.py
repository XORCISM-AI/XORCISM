"""run.py — XORCISM connector: VICE web-app security audit → assets + vulns.

VICE (vice-security, https://github.com/Webba-Creative-Technologies/vice) is a
black-box & white-box security auditor for web applications. It emits SARIF, so
this connector reuses the shared SARIF parser (connectors/_sarif.py) — the same
mapping that serves semgrep / CodeQL / Trivy / nuclei -sarif …:
    audited project / scanned host  -> ASSET
    each SARIF result               -> VULN (ref=CVE if any, else VICE-<rule>@loc;
                                             severity from security-severity / level)

Two live modes + an offline mode:
    white-box  source=<dir>  ->  vice audit <dir> --ci --format sarif --min-score N --output <f>
    black-box  url=<url>     ->  vice scan --url <url> --ci --format sarif --output <f>
    offline    file=<sarif>  ->  parse a saved VICE SARIF report

No DB access here (worker-safe): returns {assets, services, cpes, vulns}.
Locate VICE via VICE_PATH (a .js is run with node; default C:\\tools\\vice\\bin\\vice.js)
or `vice` on PATH. VICE_ACCEPT_TERMS=1 is set automatically. Live mode needs Node ≥18
and VICE's dependencies installed (`npm install` in the clone, or `npm i -g vice-security`).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _sarif import load_sarif, parse_sarif  # noqa: E402

DEFAULT_VICE = r"C:\tools\vice\bin\vice.js"
_EMPTY: Dict[str, Any] = {"assets": [], "services": [], "cpes": [], "vulns": []}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    source = str(params.get("source") or "").strip()
    url = str(params.get("url") or "").strip()
    proj = source or url

    if params.get("file"):
        data = load_sarif(params["file"])
        return parse_sarif(data, default_project=proj or os.path.basename(str(params["file"])))

    if not source and not url:
        raise RuntimeError("vice: provide 'source' (a project dir to audit), 'url' (a host to scan), or 'file' (a saved VICE SARIF report)")

    sarif_path = os.path.join(workdir, "vice.sarif")
    _run_vice(params, source, url, sarif_path, workdir)
    if not os.path.exists(sarif_path):
        return dict(_EMPTY)
    return parse_sarif(load_sarif(sarif_path), default_project=proj)


def _locate_vice() -> List[str]:
    p = os.environ.get("VICE_PATH")
    if p and os.path.exists(p):
        return ["node", p] if p.lower().endswith(".js") else [p]
    onpath = shutil.which("vice")
    if onpath:
        return [onpath]
    if os.path.exists(DEFAULT_VICE):
        return ["node", DEFAULT_VICE]
    raise RuntimeError("VICE not found — set VICE_PATH, put `vice` on PATH (npm i -g vice-security), or use the 'file' parameter for offline import")


def _run_vice(params: Dict[str, Any], source: str, url: str, out: str, workdir: str) -> None:
    base = _locate_vice()
    if url:
        argv = base + ["scan", "--url", url, "--ci", "--format", "sarif", "--output", out]
    else:
        min_score = int(params.get("min_score", 0) or 0)
        argv = base + ["audit", source, "--ci", "--format", "sarif", "--min-score", str(min_score), "--output", out]
    env = {**os.environ, "VICE_ACCEPT_TERMS": "1"}
    subprocess.run(argv, timeout=3600, check=False, cwd=workdir, env=env)  # noqa: S603


if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="VICE import (dry run)")
    ap.add_argument("--file", help="a saved VICE SARIF report")
    ap.add_argument("--source", default="", help="project dir to audit (live)")
    ap.add_argument("--url", default="", help="URL to scan (live)")
    a = ap.parse_args()
    res = run({"file": a.file, "source": a.source, "url": a.url}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[vice] {len(res['assets'])} asset(s), {len(res['vulns'])} finding(s)", flush=True)
