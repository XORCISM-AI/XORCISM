"""run.py -- XORCISM connector for X-OSINT (github.com/TermuxHackz/X-osint).

X-OSINT is an open-source OSINT framework (Termux/Linux) that gathers intelligence on a
phone number, email, username or domain: VIN OSINT, reverse phone/email lookups, subdomain
enumeration and email-discovery-from-a-name. It is an interactive CLI with no stable API, so
this connector ingests the *output of a run* rather than driving it live. It accepts:

  * an X-OSINT case JSON:
      {"target": "...", "kind": "phone|email|username|domain",
       "results": [{"module": "subdomains", "type": "domain", "value": "...", "source": "..."}, ...]}
    (also tolerates {"target","subdomains":[...],"emails":[...],"phones":[...],"hosts":[...]}), or
  * the raw console text of a run -- observables (emails, subdomains/hosts, IPs, phones, URLs,
    @usernames) are extracted with regex.

Each observable becomes an INTELEXCHANGE intel item {name, reference, external_id, description,
tags} -> XTHREAT.INTELEXCHANGE (idempotent by reference, see connectors/runner.py
import_threat_intel). The native /cti-expert cockpit maps OSINT techniques to this connector.

Modes: offline `file` (a saved export), else the bundled sample.json. Worker-safe: stdlib only,
ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "X-OSINT"

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)\+?\d[\d\s().\-]{6,}\d(?!\d)")
_USER = re.compile(r"(?:^|\s)@([A-Za-z0-9._\-]{2,40})")

# Lines of pure UI chrome / banners we never want to mine as observables.
_NOISE = re.compile(r"^(?:\s*[#=*\-_+|>.\\/ ]+\s*|.*\bX-?OSINT\b.*|.*TermuxHackz.*)$", re.I)


def _item(value: str, otype: str, target: str, module: str, source: str = "") -> Dict[str, Any]:
    value = value.strip()
    tags = ["x-osint", "osint", otype]
    if module:
        tags.append("module:" + module)
    desc = "X-OSINT %s observation" % otype
    if target:
        desc += " for %s" % target
    if source:
        desc += " (source: %s)" % source
    return {
        "name": ("%s: %s" % (otype, value))[:200],
        "reference": ("x-osint:%s" % value)[:200],
        "external_id": value[:200],
        "description": desc[:1000],
        "tags": ",".join(tags),
    }


def _from_case(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    target = str(case.get("target") or case.get("query") or "").strip()
    kind = str(case.get("kind") or case.get("type") or "target").strip()

    def add(value: str, otype: str, module: str = "", source: str = "") -> None:
        v = (value or "").strip()
        key = (otype, v.lower())
        if not v or key in seen:
            return
        seen.add(key)
        out.append(_item(v, otype, target, module, source))

    # an INTSUM-style header item for the run itself
    if target:
        out.append({
            "name": ("OSINT - %s (%s)" % (target, kind))[:200],
            "reference": ("x-osint:case:%s:%s" % (kind, target))[:200],
            "external_id": ("%s:%s" % (kind, target))[:200],
            "description": ("X-OSINT investigation of %s (%s)" % (target, kind))[:1000],
            "tags": ",".join(["x-osint", "osint", "intsum", kind]),
        })

    # structured results list
    for r in case.get("results") or []:
        if not isinstance(r, dict):
            continue
        add(str(r.get("value") or ""), str(r.get("type") or "observable"),
            str(r.get("module") or ""), str(r.get("source") or ""))

    # convenience buckets
    for module, otype in (("subdomains", "domain"), ("hosts", "domain"), ("emails", "email"),
                          ("phones", "phone"), ("urls", "url"), ("accounts", "username"),
                          ("ips", "ip"), ("usernames", "username")):
        for v in case.get(module) or []:
            if isinstance(v, dict):
                add(str(v.get("value") or v.get("name") or ""), otype, module, str(v.get("source") or ""))
            else:
                add(str(v), otype, module)
    return out


def _from_text(text: str, target: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(value: str, otype: str) -> None:
        v = (value or "").strip().strip(".,);:'\"")
        key = (otype, v.lower())
        if not v or key in seen:
            return
        seen.add(key)
        out.append(_item(v, otype, target, "text"))

    lines = [ln for ln in text.splitlines() if ln.strip() and not _NOISE.match(ln)]
    body = "\n".join(lines)
    for m in _EMAIL.findall(body):
        add(m, "email")
    for m in _URL.findall(body):
        add(m, "url")
    for m in _IPV4.findall(body):
        add(m, "ip")
    # domains, minus ones already captured as part of an email/url
    consumed = " ".join(o["external_id"] for o in out).lower()
    for m in _DOMAIN.findall(body):
        if m.lower() not in consumed:
            add(m, "domain")
    for m in _PHONE.findall(body):
        if "." in m:
            continue  # dotted -> IPv4 / version, not a phone number
        digits = re.sub(r"\D", "", m)
        if 7 <= len(digits) <= 15:
            add(m.strip(), "phone")
    for m in _USER.findall(body):
        add(m, "username")
    if target and not any(o.get("external_id", "").lower() == target.lower() for o in out):
        out.insert(0, _item(target, "target", target, "text"))
    return out


def _normalize(data: Any, target: str) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        return _from_case(data)
    if isinstance(data, list):
        merged: List[Dict[str, Any]] = []
        for d in data:
            if isinstance(d, dict):
                merged.extend(_from_case(d))
        return merged
    if isinstance(data, str):
        return _from_text(data, target)
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    target = str(params.get("target") or "").strip()
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    try:
        data: Any = json.loads(raw)
    except Exception:
        data = raw  # raw console output -> text extraction
    intel = _normalize(data, target)
    return {"source": SOURCE, "assets": [], "services": [], "cpes": [], "vulns": [], "intel": intel[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
