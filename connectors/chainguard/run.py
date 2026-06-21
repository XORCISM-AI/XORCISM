"""run.py — XORCISM connector: Chainguard container-image vulnerabilities -> findings.

Chainguard (https://www.chainguard.dev) ships minimal, low-CVE Wolfi images and the chainctl
platform. This connector imports a vulnerability report: the image -> ASSET, each package -> a
component, each vulnerability -> VULNERABILITY / ASSETVULNERABILITY (ref = CVE/GHSA, severity).

Offline: a Grype JSON report (`grype <image> -o json`), an {images:[{name,vulnerabilities:[...]}]}
export, or a flat findings list. Live: if `image` is set and grype/chainctl is on the worker,
scans it. No DB access (worker-safe).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "negligible": "info", "unknown": "info", "none": "info", "informational": "info"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    image = str(params.get("image") or params.get("project") or "").strip()
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        if not image:
            raise RuntimeError("chainguard: provide a 'file' (Grype/Chainguard JSON) or an 'image' for live mode")
        data = _scan(image, workdir)
    return _parse(data, image)


def _scan(image: str, workdir: str) -> Any:
    exe = shutil.which("grype") or shutil.which("chainctl")
    if not exe:
        raise RuntimeError("grype/chainctl not found on PATH; use the 'file' parameter instead")
    out = os.path.join(workdir, "chainguard.json")
    if exe.endswith("grype") or exe.endswith("grype.exe"):
        subprocess.run([exe, image, "-o", "json", "--file", out], timeout=1800, check=False)  # noqa: S603
    else:
        with open(out, "w", encoding="utf-8") as fh:
            subprocess.run([exe, "images", "diff", image], stdout=fh, timeout=1800, check=False)  # noqa: S603
    if not os.path.exists(out):
        return {}
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _sev(v: Any) -> str:
    return _SEV.get(str(v or "").strip().lower(), "medium")


def _ref(raw: str, fallback_seed: str) -> str:
    r = str(raw or "").strip()
    if r.upper().startswith(("CVE-", "GHSA-", "ALAS", "ALSA", "ELSA", "RHSA", "CGA-")):
        return r
    return r or ("CHAINGUARD-" + hashlib.sha1(fallback_seed.encode("utf-8")).hexdigest()[:12])


def _parse(data: Any, image_override: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = []
    seen_v: set = set()
    seen_c: set = set()

    def ensure_asset(name: str) -> None:
        if name and name not in assets:
            assets[name] = {"hostname": name, "key": name}

    def add(target: str, vid: str, pkg: str, ver: str, sev: str) -> None:
        target = target or image_override or "chainguard-image"
        ref = _ref(vid, f"{pkg}|{vid}|{target}")
        ensure_asset(target)
        key = (target, ref)
        if key not in seen_v:
            seen_v.add(key)
            name = (f"{pkg} {ver}: {ref}".strip() if pkg else ref)
            vulns.append({"asset": target, "ref": ref, "name": name[:300], "severity": sev})
        if pkg and pkg not in seen_c:
            seen_c.add(pkg)
            components.append({"name": pkg, "version": ver or ""})

    if isinstance(data, dict) and isinstance(data.get("matches"), list):   # Grype JSON
        target = image_override or str(((data.get("source") or {}).get("target") or {}).get("userInput") or "").strip()
        for m in data["matches"]:
            if not isinstance(m, dict):
                continue
            v = m.get("vulnerability") or {}
            a = m.get("artifact") or {}
            add(target, str(v.get("id") or ""), str(a.get("name") or ""), str(a.get("version") or ""), _sev(v.get("severity")))
    else:
        # {images:[{name, vulnerabilities:[...]}]} or a flat findings list
        items: List[Dict[str, Any]] = []
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            for k in ("images", "results", "vulnerabilities", "findings", "data", "items"):
                if isinstance(data.get(k), list):
                    items = [x for x in data[k] if isinstance(x, dict)]
                    break
        for it in items:
            nested = it.get("vulnerabilities") or it.get("vulns") or it.get("matches")
            if isinstance(nested, list):                                   # an image with nested vulns
                target = image_override or str(it.get("name") or it.get("reference") or it.get("image") or "").strip()
                for v in nested:
                    if isinstance(v, dict):
                        pkg = v.get("package") or v.get("artifact") or v.get("pkgName") or ""
                        if isinstance(pkg, dict):
                            pkg = pkg.get("name") or ""
                        add(target, str(v.get("id") or v.get("cve") or v.get("vulnerability") or v.get("vulnerabilityID") or ""),
                            str(pkg), str(v.get("version") or v.get("installedVersion") or ""), _sev(v.get("severity")))
            else:                                                          # a flat finding row
                target = image_override or str(it.get("image") or it.get("target") or it.get("asset") or it.get("artifact") or "").strip()
                pkg = it.get("package") or it.get("pkgName") or ""
                if isinstance(pkg, dict):
                    pkg = pkg.get("name") or ""
                add(target, str(it.get("id") or it.get("cve") or it.get("vulnerabilityID") or ""),
                    str(pkg), str(it.get("version") or it.get("installedVersion") or ""), _sev(it.get("severity")))

    project = image_override or (next(iter(assets), "chainguard-image"))
    return {"project": project, "assets": list(assets.values()), "services": [], "cpes": [], "components": components, "vulns": vulns}


if __name__ == "__main__":
    import tempfile
    ap = argparse.ArgumentParser(description="Chainguard import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--image", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "image": a.image}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[chainguard] {len(res['assets'])} asset(s), {len(res['vulns'])} vuln(s), {len(res.get('components', []))} component(s)", flush=True)
