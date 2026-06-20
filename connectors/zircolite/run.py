"""run.py — XORCISM connector: Zircolite (Sigma-based log detection) -> host findings.

Zircolite (https://github.com/wagga40/Zircolite) applies Sigma rules to logs
(Windows EVTX/XML/JSONL, Auditd, Sysmon for Linux, CSV, JSON array) and emits a
JSON report of the rules that fired. This connector turns that report into
XORCISM findings: each log source's Computer/host -> ASSET, and every fired
Sigma rule -> a VULNERABILITY / ASSETVULNERABILITY (ref = ZIRCOLITE-<sigma id>,
severity from the rule level, ATT&CK technique(s) in the finding name).

Offline: parse a Zircolite JSON report (`zircolite.py ... -o detected_events.json`).
Live:    if `events` (+ `ruleset`) are set and Zircolite is on the worker
         (env ZIRCOLITE_PATH, else `zircolite` on PATH), run it and parse the output.
No DB access in run.py (worker-safe).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List

# Zircolite rule levels -> XORCISM severity
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "informational": "info", "info": "info"}
# log-event keys that name the originating host, across Zircolite's input formats
_HOST_KEYS = ("Computer", "computer", "ComputerName", "Hostname", "hostname", "host",
              "host_name", "HostName", "MachineName", "machine", "system_name", "node")
_ATTACK_RE = re.compile(r"attack[._]t(\d{4}(?:\.\d{3})?)", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        data = _load(params["file"])
    else:
        events = str(params.get("events") or "").strip()
        if not events:
            raise RuntimeError("zircolite: provide a 'file' (Zircolite JSON report) or 'events' for live mode")
        data = _run_zircolite(events, str(params.get("ruleset") or "").strip(), workdir)
    return _parse(data, str(params.get("host") or "").strip())


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        txt = fh.read()
    stripped = txt.lstrip()
    if stripped[:1] in ("[", "{"):
        try:
            return json.loads(txt)
        except Exception:
            pass
    rows: List[Any] = []  # JSONL fallback (one detection per line)
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def _run_zircolite(events: str, ruleset: str, workdir: str) -> Any:
    exe = os.environ.get("ZIRCOLITE_PATH", r"C:\tools\Zircolite\zircolite.py")
    if os.path.isfile(exe):
        cmd: List[str] = ["python", exe]
    else:
        found = shutil.which("zircolite")
        if not found:
            raise RuntimeError("zircolite not found (set ZIRCOLITE_PATH or install on PATH); use the 'file' parameter instead")
        cmd = [found]
    if not ruleset:
        ruleset = os.environ.get("ZIRCOLITE_RULESET", "").strip()
    if not ruleset:
        raise RuntimeError("zircolite live mode needs a 'ruleset' (Sigma rules JSON/YAML) or env ZIRCOLITE_RULESET")
    out = os.path.join(workdir, "zircolite.json")
    cmd += ["--events", events, "--ruleset", ruleset, "-o", out]
    subprocess.run(cmd, timeout=3600, check=False)  # noqa: S603
    if not os.path.exists(out):
        return []
    return _load(out)


def _detections(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for k in ("detections", "results", "events", "data"):
            v = data.get(k)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
        if data.get("title") or data.get("id"):   # a single detection object
            return [data]
    return []


def _host_of(match: Dict[str, Any]) -> str:
    for k in _HOST_KEYS:
        v = match.get(k)
        if v:
            return str(v).strip()
    return ""


def _attack(tags: Any) -> List[str]:
    items = tags if isinstance(tags, (list, tuple)) else ([tags] if isinstance(tags, str) else [])
    techs: List[str] = []
    for t in items:
        m = _ATTACK_RE.search(str(t))
        if m:
            tid = "T" + m.group(1).upper()
            if tid not in techs:
                techs.append(tid)
    return techs


def _parse(data: Any, host_default: str) -> Dict[str, Any]:
    dets = _detections(data)
    fallback = host_default or "zircolite-host"
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen: set = set()

    def ensure_asset(name: str) -> None:
        if name and name not in assets:
            assets[name] = {"hostname": name, "key": name}

    for d in dets:
        title = str(d.get("title") or d.get("name") or "Sigma detection").strip()
        sid = str(d.get("id") or d.get("rule_id") or d.get("sigma_id") or "").strip()
        level = str(d.get("rule_level") or d.get("level") or "medium").strip().lower()
        sev = _SEV.get(level, "medium")
        techs = _attack(d.get("tags"))
        matches = d.get("matches") if isinstance(d.get("matches"), list) else []
        by_host: Dict[str, int] = {}
        for m in matches:
            if isinstance(m, dict):
                h = _host_of(m) or fallback
                by_host[h] = by_host.get(h, 0) + 1
        if not by_host:
            by_host[fallback] = int(d.get("count") or 0) or 1
        slug = sid or (re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-")[:40] or "rule")
        ref = "ZIRCOLITE-" + slug   # same Sigma rule = same VULNERABILITY, linked to each host
        attack_str = (" [ATT&CK " + ", ".join(techs) + "]") if techs else ""
        for host, cnt in by_host.items():
            ensure_asset(host)
            key = (host, ref)
            if key in seen:
                continue
            seen.add(key)
            name = f"Zircolite: {title}{attack_str} (x{cnt})"
            vulns.append({"asset": host, "ref": ref, "name": name[:300], "severity": sev})

    return {"project": fallback, "assets": list(assets.values()),
            "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Zircolite import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--events", default="")
    ap.add_argument("--ruleset", default="")
    ap.add_argument("--host", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "events": a.events, "ruleset": a.ruleset, "host": a.host}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[zircolite] {len(res['assets'])} asset(s), {len(res['vulns'])} finding(s)", flush=True)
