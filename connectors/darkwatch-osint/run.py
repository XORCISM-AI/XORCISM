"""run.py — XORCISM connector: dark-web asset monitoring via DARKWATCH-OSINT.

DARKWATCH-OSINT (https://github.com/K3lgy/DARKWATCH-OSINT) is a defensive dark-web
monitoring platform: it crawls .onion sites for an organisation's keywords / domains
/ emails / file hashes and raises alerts (data leaks, ransomware posts, exploit
sales) with extracted entities. This connector ingests those alerts and maps them
to the XORCISM findings model:

  • a monitored host / domain / IP that surfaced  -> ASSET
  • each alert (leak / ransomware / exploit / mention) -> a finding (vuln) on the
    relevant asset (or the monitored brand as a fallback)
  • extracted entities (domains, IPs, emails, hashes) enrich the asset / finding

This module performs NO database access (so it also runs on a remote worker): it
returns the normalized result {assets, services, cpes, vulns}.

Config (worker environment variables, never entered in the UI):
    DARKWATCH_API_URL    base URL of a DARKWATCH-OSINT instance        (optional)
                         e.g. http://127.0.0.1:8080
    DARKWATCH_API_KEY    API key (sent as Bearer + ?api_key=)          (optional)
    DARKWATCH_VERIFY_TLS "0"/"false" to skip TLS verification          (default: verify)

Offline / test mode:
    params["file"] = a saved JSON alerts/entities export -> parsed instead of the API.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional

# ── Entity-extraction regexes (defensive, lower-cased input) ──────────────────
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_ONION = re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
RE_HASH = re.compile(r"\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b")

# alert category keyword -> severity
SEVERITY_RULES = [
    ("critical", ("ransomware", "ransom", "extortion", "sold", "for sale", "auction")),
    ("high", ("leak", "breach", "dump", "database", "credential", "password", "stealer",
              "exploit", "0day", "zero-day", "cve-", "malware", "backdoor", "rce")),
    ("medium", ("mention", "keyword", "chatter", "post", "listing", "forum", "paste")),
]


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    brand = str(params.get("brand") or "").strip()
    limit = int(params.get("limit", 2000) or 2000)
    if not brand and not params.get("file"):
        raise RuntimeError("darkwatch-osint connector requires a 'brand' parameter")

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        payload = _fetch(brand, limit)

    records = _find_records(payload)
    return _map(records[:limit], brand)


# ── DARKWATCH-OSINT API (best-effort) ─────────────────────────────────────────
def _fetch(brand: str, limit: int) -> Any:
    import requests

    base = (os.getenv("DARKWATCH_API_URL") or "").rstrip("/")
    if not base:
        raise RuntimeError(
            "No 'file' given and DARKWATCH_API_URL is not set (worker env). "
            "Export DARKWATCH-OSINT alerts to JSON and pass them via the 'file' parameter, "
            "or set DARKWATCH_API_URL.")
    key = os.getenv("DARKWATCH_API_KEY") or ""
    verify = (os.getenv("DARKWATCH_VERIFY_TLS") or "1").strip().lower() not in ("0", "false", "no", "off")
    if not verify:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # noqa: BLE001
            pass

    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    query: Dict[str, Any] = {"q": brand, "limit": limit}
    if key:
        query["api_key"] = key

    last_err: Optional[Exception] = None
    # DARKWATCH-OSINT has no single documented REST path — try the likely ones.
    for path in ("/api/alerts", "/api/v1/alerts", "/api/search", "/api/entities", "/alerts.json"):
        try:
            r = requests.get(base + path, headers=headers, params=query, timeout=120, verify=verify)
            if r.status_code == 200:
                return r.json()
            last_err = RuntimeError(f"{path} -> HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001
            last_err = e
    raise RuntimeError(f"DARKWATCH-OSINT API: no endpoint responded ({last_err})")


# ── Record extraction ─────────────────────────────────────────────────────────
def _find_records(payload: Any) -> List[Dict[str, Any]]:
    """Find the list of alert / entity objects anywhere in the export."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    if isinstance(payload, dict):
        for k in ("alerts", "results", "hits", "findings", "entities", "data", "items", "matches"):
            v = payload.get(k)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
        # Elasticsearch-style {"hits": {"hits": [{"_source": {...}}]}}
        hits = ((payload.get("hits") or {}).get("hits")) if isinstance(payload.get("hits"), dict) else None
        if isinstance(hits, list):
            return [(h.get("_source") or h) for h in hits if isinstance(h, dict)]
        vals = list(payload.values())
        if vals and all(isinstance(v, dict) for v in vals):
            return vals  # type: ignore[return-value]
    return []


def _first(rec: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = rec.get(k)
        if v:
            return str(v).strip()
    return ""


def _severity(text: str, explicit: str) -> str:
    e = (explicit or "").strip().lower()
    if e in ("critical", "high", "medium", "low", "info", "informational"):
        return "info" if e == "informational" else e
    low = text.lower()
    for sev, kws in SEVERITY_RULES:
        if any(k in low for k in kws):
            return sev
    return "medium"


def _explicit_entities(rec: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for k in ("entities", "iocs", "indicators", "matches", "extracted"):
        v = rec.get(k)
        if isinstance(v, list):
            for it in v:
                if isinstance(it, str):
                    out.append(it)
                elif isinstance(it, dict):
                    out.append(str(it.get("value") or it.get("indicator") or it.get("name") or ""))
        elif isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, list):
                    out.extend(str(x.get("value") if isinstance(x, dict) else x) for x in vv)
    return [s for s in out if s]


def _classify(blob: str) -> Dict[str, List[str]]:
    """Pull domains / IPs / emails / hashes / onion sites out of a text blob."""
    low = blob.lower()
    onions = set(RE_ONION.findall(low))
    emails = set(RE_EMAIL.findall(low))
    ips = set(RE_IPV4.findall(low))
    hashes = set(RE_HASH.findall(low))
    # domains, excluding onion hosts and the domain parts of emails already captured
    domains = set()
    for d in RE_DOMAIN.findall(low):
        if d.endswith(".onion") or any(d == e.split("@", 1)[-1] for e in emails):
            continue
        domains.add(d)
    domains |= {e.split("@", 1)[-1] for e in emails}
    return {"onion": sorted(onions), "email": sorted(emails), "ip": sorted(ips),
            "hash": sorted(hashes), "domain": sorted(d for d in domains if not d.endswith(".onion"))}


# ── Mapping to the normalized findings model ──────────────────────────────────
def _map(records: List[Dict[str, Any]], brand: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen_refs: set = set()

    def add_asset(name: str, ip: Optional[str] = None) -> str:
        name = name.strip().lower().rstrip(".")
        a = assets.setdefault(name, {"hostname": name, "key": name})
        if ip and not a.get("ip"):
            a["ip"] = ip
        return name

    # The monitored brand is always an asset (so the dashboard shows it even with 0 hits).
    brand_host = brand.split("@", 1)[-1].strip().lower() if brand else ""
    brand_key = add_asset(brand_host) if brand_host else None

    for rec in records:
        title = _first(rec, "title", "name", "alert", "summary", "rule")
        desc = _first(rec, "description", "details", "body", "text", "snippet", "content", "message")
        source = _first(rec, "source", "url", "site", "onion", "host", "link")
        category = _first(rec, "category", "type", "alert_type", "kind", "tag")
        sev_field = _first(rec, "severity", "risk", "level", "priority")
        rid = _first(rec, "id", "_id", "uuid", "alert_id", "hit_id")

        blob = " ".join([title, desc, source, category] + _explicit_entities(rec))
        ent = _classify(blob)

        # Register real assets (non-onion domains / IPs the org may own).
        for d in ent["domain"]:
            add_asset(d)
        for ip in ent["ip"]:
            add_asset(ip, ip)

        # Choose the asset this alert is about. Prefer the monitored brand when it
        # is referenced (single pane for the org), then a concrete domain/IP.
        brand_referenced = bool(brand_host) and (
            brand_host in blob.lower() or any(d == brand_host or d.endswith("." + brand_host) for d in ent["domain"]))
        target = (brand_key if brand_referenced
                  else ent["domain"][0] if ent["domain"]
                  else ent["ip"][0] if ent["ip"]
                  else brand_key)
        if not target:
            target = add_asset("dark-web-monitoring")

        name = title or (f"Dark-web {category}" if category else "Dark-web exposure")
        if source:
            name = f"{name} - {source}"
        sev = _severity(blob, sev_field)

        # Stable, idempotent ref.
        basis = rid or hashlib.sha1((source + "|" + (title or desc)).encode("utf-8", "replace")).hexdigest()[:16]
        ref = f"DARKWATCH-{re.sub(r'[^A-Za-z0-9._-]+', '-', basis)[:48]}"
        if ref in seen_refs:
            continue
        seen_refs.add(ref)

        extras = []
        if ent["email"]:
            extras.append(f"emails: {', '.join(ent['email'][:5])}")
        if ent["hash"]:
            extras.append(f"hashes: {', '.join(ent['hash'][:3])}")
        if ent["onion"]:
            extras.append(f"onion: {', '.join(ent['onion'][:3])}")
        full_name = name[:240] + (f" [{'; '.join(extras)}]" if extras else "")

        vulns.append({"asset": target, "ref": ref, "name": full_name[:300], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="DARKWATCH-OSINT alerts import (dry run)")
    ap.add_argument("--file", help="Saved JSON alerts/entities export instead of the live API")
    ap.add_argument("--brand", default="example.com")
    ap.add_argument("--limit", type=int, default=2000)
    a = ap.parse_args()
    res = run({"file": a.file, "brand": a.brand, "limit": a.limit}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[darkwatch-osint] {len(res['assets'])} asset(s), {len(res['vulns'])} finding(s)", flush=True)
