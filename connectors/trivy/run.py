"""run.py — XORCISM connector: Aqua Trivy → project asset + components + vulns.

Offline: parse a Trivy JSON report (`trivy ... -f json`).
Live:    if `source` is given and the `trivy` binary is on PATH, run
         `trivy image|fs --format json <source>`.

The scanned artifact -> ASSET (project), each package -> a component CPE, each
finding -> a vulnerability (ref = CVE/advisory id, severity). No DB access.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        source = str(params.get("source") or "").strip()
        if not source:
            raise RuntimeError("trivy: provide a 'file' (Trivy JSON) or a 'source' for live mode")
        data = _run_trivy(source, workdir)
    return _parse(data, str(params.get("project") or "").strip())


def _run_trivy(source: str, workdir: str) -> Any:
    exe = shutil.which("trivy")
    if not exe:
        raise RuntimeError("trivy binary not found on PATH; use the 'file' parameter instead")
    mode = "fs" if os.path.exists(source) else "image"
    out = os.path.join(workdir, "trivy.json")
    subprocess.run([exe, mode, "--quiet", "--format", "json", "--output", out, source],  # noqa: S603
                   timeout=1800, check=False)
    if not os.path.exists(out):
        return {}
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _parse(data: Any, project_override: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {"assets": [], "services": [], "cpes": [], "vulns": []}
    project = project_override or str(data.get("ArtifactName") or data.get("artifactName") or "trivy scan")
    vulns: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = []
    seen_v: set = set()
    seen_c: set = set()
    for result in (data.get("Results") or []):
        if not isinstance(result, dict):
            continue
        for v in (result.get("Vulnerabilities") or []):
            ref = str(v.get("VulnerabilityID") or "").strip()
            if not ref or ref in seen_v:
                continue
            seen_v.add(ref)
            pkg = v.get("PkgName") or ""
            name = str(v.get("Title") or (f"{pkg} {v.get('InstalledVersion','')}".strip()) or ref)
            sev = _SEV.get(str(v.get("Severity") or "").upper(), "medium")
            vulns.append({"asset": project, "ref": ref, "name": name[:300], "severity": sev})
            if pkg:
                comp = f"{pkg}@{v.get('InstalledVersion','')}"
                if comp not in seen_c:
                    seen_c.add(comp)
                    components.append({"name": pkg, "version": str(v.get("InstalledVersion") or "")})
    return {"project": project, "assets": [{"hostname": project, "key": project}],
            "services": [], "cpes": [], "components": components, "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Trivy import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--source", default="")
    ap.add_argument("--project", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "source": a.source, "project": a.project}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[trivy] project={res.get('project')!r}, {len(res['vulns'])} vuln(s), {len(res.get('components',[]))} component(s)", flush=True)
