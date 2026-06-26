"""run.py -- XORCISM connector for OASIS (github.com/psyray/oasis), the
Ollama Automated Security Intelligence Scanner.

OASIS is an AI-powered SAST tool: it uses local Ollama LLMs + vector embeddings to find 24+
vulnerability classes (SQLi, XSS, command injection, RCE, SSRF, path traversal, insecure
deserialization, JWT flaws, sensitive-data exposure, auth/session, crypto, CORS, ...) and writes a
SARIF 2.1.0 report under security_reports/<project>/<timestamp>/. This connector imports that SARIF:
parsing is delegated to the shared connectors/_sarif.py parser, so the scanned project becomes an
ASSET and each finding a VULNERABILITY / ASSETVULNERABILITY (severity from security-severity / level).
The runner additionally records the run as a DevSecOps SAST scan (mapping=oasis).

No database access (so it also runs on a remote worker). Returns {assets, services, cpes, vulns}.

    oasis -i ./my-app -sm gemma3:4b -m llama3:latest --vulns all --output-format sarif
    # then import the produced .sarif:
    python run.py --file security_reports/my-app/<ts>/report.sarif
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

# Make the shared parser (connectors/_sarif.py) importable wherever this runs.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _sarif import load_sarif, parse_sarif  # noqa: E402

SOURCE = "oasis"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.sarif")
    if not os.path.isfile(path):
        raise RuntimeError(f"OASIS SARIF report not found: {path}")
    data = load_sarif(path)
    res = parse_sarif(data, default_project=params.get("project"))
    res["source"] = SOURCE
    return res


# ── Standalone CLI (offline dry run) ──────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="Import an OASIS SARIF report (dry run / offline)")
    ap.add_argument("--file", help="Path to the OASIS .sarif report (default: bundled sample)")
    ap.add_argument("--project", help="Asset name to attach the findings to")
    a = ap.parse_args()
    out = run({"file": a.file, "project": a.project}, tempfile.mkdtemp())
    sev: Dict[str, int] = {}
    for v in out["vulns"]:
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1
    print("[oasis] %d asset(s), %d finding(s) %s" % (len(out["assets"]), len(out["vulns"]), sev))
    for v in out["vulns"][:8]:
        print("  %-8s %s" % (v["severity"], v["name"][:72]))
