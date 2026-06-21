"""run.py — XORCISM connector: Rustinel EDR → host assets + detection findings.

Rustinel (https://github.com/Karib0u/rustinel) is an open-source cross-platform endpoint
detection engine. It collects native telemetry — ETW on Windows, eBPF on Linux, Endpoint
Security on macOS — normalizes it into a shared event model, and evaluates it against Sigma
rules, YARA signatures and atomic IOCs, writing ECS-compatible NDJSON alerts to
`logs/alerts.json.<date>`.

This connector parses that ECS NDJSON alert log and maps it to the normalized XORCISM
result: each alert's `host.name` -> an ASSET, each detection rule -> a finding
(ref = `rule.id`, name = `rule.name`, severity from the Sigma level). Repeated alerts for
the same rule on the same host collapse to a single finding. NO database access here, so the
connector is safe to run on a remote worker.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

TOOL_NAME = "Rustinel"
TOOL_URL = "https://github.com/Karib0u/rustinel"

# Sigma rule levels (also surfaced via ECS event.severity / log.level) → XORCISM severity.
_SEV = {"critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "informational": "info", "info": "info"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError(
            "rustinel: provide a 'file' (Rustinel ECS NDJSON alert log, e.g. logs/alerts.json.<date>)")
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue  # skip non-JSON / partial lines (a tailed file may end mid-write)
            if isinstance(rec, dict):
                records.append(rec)
    return _parse(records, str(params.get("project") or "").strip())


def _get(d: Dict[str, Any], *paths: str) -> Optional[Any]:
    """Read a value from an ECS record by dotted path, trying a flat dotted key first
    (ECS may be emitted nested {rule:{name}} or flattened {'rule.name':...})."""
    for path in paths:
        if path in d and not isinstance(d[path], (dict, list)):
            return d[path]
        cur: Any = d
        ok = True
        for k in path.split("."):
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and cur not in (None, "", {}, []):
            return cur
    return None


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:80] or "alert"


def _parse(records: List[Dict[str, Any]], project_override: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen: set = set()
    for rec in records:
        host = project_override or str(
            _get(rec, "host.name", "host.hostname", "agent.name", "observer.hostname") or "rustinel")
        if host not in assets:
            a: Dict[str, Any] = {"hostname": host, "key": host}
            ip = _get(rec, "host.ip", "source.ip")
            if isinstance(ip, list):
                ip = ip[0] if ip else None
            if ip:
                a["ip"] = str(ip)
            osn = _get(rec, "host.os.name", "host.os.family")
            if osn:
                a["os"] = str(osn)
            assets[host] = a
        rule_name = str(_get(rec, "rule.name", "rule.description", "message") or "Rustinel detection")
        rid = _get(rec, "rule.id", "rule.uuid")
        ref = str(rid).strip() if rid else f"RUSTINEL-{_slug(rule_name)}"
        level = str(_get(rec, "rule.level", "event.severity", "log.level") or "").lower()
        sev = _SEV.get(level, "high")
        key = (host, ref)
        if key in seen:
            continue
        seen.add(key)
        vulns.append({"asset": host, "ref": ref, "name": rule_name[:300], "severity": sev})
    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Rustinel import (dry run)")
    ap.add_argument("--file", required=True)
    ap.add_argument("--project", default="")
    a = ap.parse_args()
    res = run({"file": a.file, "project": a.project}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[rustinel] {len(res['assets'])} asset(s), {len(res['vulns'])} detection finding(s)", flush=True)
