"""run.py — XORCISM connector: Telegram OSINT (Dark Web Informer) export → assets + findings.

telegram_osint (https://github.com/DarkWebInformer/telegram_osint) profiles Telegram
users / channels / groups with Telethon and exports a structured JSON file per run
(user / chat / members / search modes). This connector ingests that JSON and maps it
into the XORCISM model:

  • the investigated subject (user / channel / group) -> ASSET  (tg:<handle|title>)
  • shared / linked real domains                       -> host ASSET (feeds chaining)
  • notable items                                       -> VULN (finding):
       - a scam / fake / restricted flag on the entity
       - a keyword-search hit (message snippet, TRUNCATED)
       - investigative pivots (other @handles, t.me links, external/social links)

PRIVACY: phone numbers and personal names are NOT imported — only handles, links,
domains, risk flags and truncated keyword snippets. No DB access here (worker-safe):
returns the normalized result {assets, services, cpes, vulns}.

Live collection needs Telegram API credentials + Telethon on YOUR account, so this is
import-only: export from telegram_osint (`--export json`) and pass the file.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
# t.me / telegram.me / telegram subjects are NOT infrastructure assets.
_TG_HOSTS = {"t.me", "telegram.me", "telegram.org", "telegram.dog"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("telegram-osint: provide a 'file' (a telegram_osint JSON export)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    limit = int(params.get("limit", 500) or 500)

    acc = _new()
    for obj in (data if isinstance(data, list) else [data]):
        if isinstance(obj, dict):
            _map_export(obj, acc, limit)
    return _finish(acc)


# ── accumulator ───────────────────────────────────────────────────────────────

def _new() -> Dict[str, Any]:
    return {"assets": {}, "hosts": set(), "services": {}, "cpes": set(), "vulns": [], "n": 0}


def _add_asset(acc: Dict[str, Any], name: str, is_host: bool = False) -> str:
    key = (name or "").strip().lower()
    if not key:
        return ""
    acc["assets"].setdefault(key, {"hostname": name.strip(), "key": key})
    if is_host and "." in key and " " not in key:
        acc["hosts"].add(key)
    return key


def _add_finding(acc: Dict[str, Any], asset: str, label: str, severity: str, seed: str, limit: int) -> None:
    if acc["n"] >= limit:
        return
    ref = "TELEGRAM-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
    acc["vulns"].append({"asset": asset, "ref": ref, "severity": severity, "name": label[:240]})
    acc["n"] += 1


def _trunc(s: Any, n: int = 140) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return (s[: n - 1] + "…") if len(s) > n else s


def _domain_of(url: str) -> str:
    host = urlparse(url if "://" in url else "http://" + url).netloc.lower()
    return host[4:] if host.startswith("www.") else host


# ── per-export mapping ────────────────────────────────────────────────────────

def _subject(obj: Dict[str, Any]) -> str:
    uname = obj.get("username")
    if uname:
        return "tg:@" + str(uname).lstrip("@")
    title = obj.get("title") or obj.get("full_name")
    if title:
        return "tg:" + _trunc(title, 60)
    sid = obj.get("id")
    return f"tg:id{sid}" if sid is not None else "tg:subject"


def _map_export(obj: Dict[str, Any], acc: Dict[str, Any], limit: int) -> None:
    kind = str(obj.get("type") or "subject")
    subj = _subject(obj)
    subj_key = _add_asset(acc, subj)  # pseudo-host: the TG subject (not a real FQDN)

    # 1) risk flags on the entity
    flags = [k[3:] for k in ("is_scam", "is_fake", "is_restricted") if obj.get(k)]
    if flags:
        sev = "High" if ("scam" in flags or "fake" in flags) else "Medium"
        _add_finding(acc, subj_key, f"Telegram {kind} flagged: {', '.join(flags)}", sev, f"{subj}|flags|{flags}", limit)

    # 2) real shared / linked domains (from analytics + socials + bio/description text)
    domains: set = set()
    an = obj.get("analytics") or {}
    for entry in (an.get("top_domains") or []):
        d = (entry[0] if isinstance(entry, (list, tuple)) and entry else entry)
        if isinstance(d, str):
            domains.add(d.strip().lower())
    piv = obj.get("pivots") or {}
    for entry in (piv.get("socials") or []):
        url = entry[1] if isinstance(entry, (list, tuple)) and len(entry) > 1 else entry
        if isinstance(url, str):
            domains.add(_domain_of(url))
    for txt in (obj.get("bio"), obj.get("description"), obj.get("about")):
        for m in _DOMAIN.finditer(str(txt or "").lower()):
            domains.add(m.group(0))
    for d in sorted(x for x in domains if x and x not in _TG_HOSTS and not x.endswith(".onion")):
        ak = _add_asset(acc, d, is_host=True)
        _add_finding(acc, ak, f"Domain seen via Telegram {kind} {subj}", "Low", f"{subj}|domain|{d}", limit)

    # 3) investigative pivots — other @handles + t.me links (leads, not hosts)
    leads: List[str] = []
    for entry in (piv.get("mentions") or []):
        leads.append(str(entry))
    for entry in (an.get("top_mentions") or []):
        leads.append(str(entry[0] if isinstance(entry, (list, tuple)) and entry else entry))
    for entry in (piv.get("tme_links") or []):
        leads.append(str(entry))
    leads = sorted({x.strip() for x in leads if x and x.strip()})
    if leads:
        _add_finding(acc, subj_key, f"Pivots from {subj}: {_trunc(', '.join(leads[:30]), 200)}", "Low", f"{subj}|pivots", limit)

    # 4) keyword-search hits — each matching message becomes a finding (snippet truncated)
    if kind == "search":
        for msg in (obj.get("messages") or obj.get("results") or []):
            if not isinstance(msg, dict):
                continue
            text = msg.get("text") or msg.get("message") or ""
            if not str(text).strip():
                continue
            when = str(msg.get("date") or "")[:10]
            _add_finding(acc, subj_key, f"Search hit in {subj}{(' ' + when) if when else ''}: {_trunc(text)}",
                         "Medium", f"{subj}|hit|{msg.get('id') or text}", limit)

    # 5) members roster — record the count (entities/PII not imported individually)
    members = obj.get("members")
    if isinstance(members, list) and members:
        admins = sum(1 for m in members if isinstance(m, dict) and str(m.get("role", "")).lower() in ("creator", "admin"))
        _add_finding(acc, subj_key, f"{len(members)} member(s) enumerated in {subj} ({admins} admin/creator)",
                     "Low", f"{subj}|members", limit)


def _finish(acc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "assets": list(acc["assets"].values()),
        "hosts": sorted(acc["hosts"]),
        "services": list(acc["services"].values()),
        "cpes": sorted(acc["cpes"]),
        "vulns": acc["vulns"],
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Telegram OSINT import (dry run)")
    ap.add_argument("file", help="a telegram_osint JSON export")
    a = ap.parse_args()
    res = run({"file": a.file}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[telegram-osint] {len(res['assets'])} asset(s), {len(res['vulns'])} finding(s)", flush=True)
