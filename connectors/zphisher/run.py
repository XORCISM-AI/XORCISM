"""run.py — XORCISM connector: Zphisher phishing-simulation results → Security Awareness.

Zphisher (https://github.com/htr-tech/zphisher) is an automated phishing tool used here strictly
for AUTHORISED internal security-awareness simulations. During a run it records:
    • a visitor IP log        (auth/ip.txt / ip.txt)          → a recipient opened / clicked the page
    • a captured-credential log (auth/usernames.dat / login.txt) → a recipient submitted credentials

This connector PARSES that already-collected output (it never runs Zphisher and captures nothing
itself) and normalizes it into the XORCISM phishing-simulation model:
    { "phishing": { "campaign": {name, template, theme, sentDate}, "results": [ {identity, email?, ip?, clicked, submitted} ] } }
The runner maps that to XORCISM.PHISHINGSIMULATION + PHISHINGRESULT (opened/clicked/submitted),
matching recipients to PERSON by e-mail where possible. Each visitor is one recipient; anyone in
the credential log is marked as having submitted data. No DB access here (worker-safe).

    dir           : a Zphisher session / auth folder (parses the ip + credential logs it contains)
    file          : a single Zphisher output file (ip.txt or usernames.dat)
    campaign_name : name for the recorded campaign
    template      : the Zphisher template used (Facebook / Instagram / Microsoft …)
"""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import date
from typing import Any, Dict, List, Optional

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    ip_texts: List[str] = []      # visitor logs (opened/clicked)
    cred_texts: List[str] = []    # captured-credential logs (submitted)

    if params.get("file"):
        p = params["file"]
        (cred_texts if _is_cred_file(p) else ip_texts).append(_read(p))
    elif params.get("dir"):
        d = params["dir"]
        if not os.path.isdir(d):
            raise RuntimeError(f"zphisher: directory not found: {d!r}")
        for root, _dirs, names in os.walk(d):
            for nm in names:
                path = os.path.join(root, nm)
                (cred_texts if _is_cred_file(nm) else ip_texts).append(_read(path))
    else:
        raise RuntimeError("zphisher: provide a 'dir' (session/auth folder) or a 'file' to parse")

    # Build a recipient per distinct identity (email if captured, else visitor IP).
    recips: Dict[str, Dict[str, Any]] = {}

    def rec(identity: str) -> Dict[str, Any]:
        return recips.setdefault(identity, {"identity": identity, "clicked": 0, "submitted": 0})

    # visitors → opened/clicked
    for text in ip_texts:
        for ip in _uniq(_IPV4.findall(text or "")):
            if _routable(ip):
                r = rec(ip)
                r["ip"] = ip
                r["clicked"] = 1
    # credential submissions → submitted (+ email/identity)
    for text in cred_texts:
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            email = (_EMAIL.search(line) or [None])[0] if _EMAIL.search(line) else None
            ip = next((x for x in _IPV4.findall(line) if _routable(x)), None)
            ident = email or ip or _first_token(line)
            if not ident:
                continue
            r = rec(ident)
            r["submitted"] = 1
            r["clicked"] = 1
            if email:
                r["email"] = email
            if ip:
                r.setdefault("ip", ip)

    # Correlate: if a credential submitter carried an IP, drop the bare IP-only visitor for that IP
    # (same person, observed twice) so campaign counts aren't inflated.
    submitter_ips = {r.get("ip") for r in recips.values() if r.get("submitted") and r.get("email") and r.get("ip")}
    for ip in submitter_ips:
        v = recips.get(ip)
        if v is not None and v.get("identity") == ip and not v.get("email"):
            recips.pop(ip, None)

    results = [{k: v for k, v in r.items() if v not in (None, "")} for r in recips.values()]
    campaign = {
        "name": str(params.get("campaign_name") or "Zphisher simulation")[:200],
        "template": str(params.get("template") or "")[:120],
        "theme": str(params.get("template") or "")[:120],
        "difficulty": "medium",
        "description": "Phishing-simulation results imported from Zphisher output.",
        "sentDate": date.today().isoformat(),
    }
    return {"phishing": {"campaign": campaign, "results": results}, "source": "Zphisher"}


def _is_cred_file(name: str) -> bool:
    n = os.path.basename(str(name)).lower()
    return any(k in n for k in ("username", "usernames.dat", "login", "cred", "password", "account", "saved"))


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _uniq(seq: List[str]) -> List[str]:
    return list(dict.fromkeys(seq))


def _routable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_loopback or a.is_unspecified or a.is_multicast or a.is_reserved)
    except ValueError:
        return False


def _first_token(line: str) -> Optional[str]:
    m = re.split(r"[\s:=,;|]+", line, maxsplit=1)
    return m[0][:120] if m and m[0] else None


if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="Zphisher phishing-sim results (dry run)")
    ap.add_argument("--dir")
    ap.add_argument("--file")
    ap.add_argument("--campaign-name", dest="campaign_name", default="Zphisher simulation")
    ap.add_argument("--template", default="")
    a = ap.parse_args()
    res = run({"dir": a.dir, "file": a.file, "campaign_name": a.campaign_name, "template": a.template}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    r = res["phishing"]["results"]
    print(f"\n[zphisher] {len(r)} recipient(s), {sum(x.get('submitted',0) for x in r)} submitted credential(s)", flush=True)
