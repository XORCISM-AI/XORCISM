#!/usr/bin/env python3
"""run.py — XORCISM connector: VoidAccess (dark-web OSINT) → XTHREAT.INTELEXCHANGE.

VoidAccess (https://github.com/KatrielMoses/voidaccess, MIT) is a self-hosted dark-web
OSINT platform: it runs autonomous investigations across Tor/clearnet sources, extracts
entities (CVEs, threat actors, domains, IPs, emails, hashes, crypto wallets, paste links)
and builds relationship graphs. This connector turns a VoidAccess investigation/findings
export into XORCISM threat-intel items (INTELEXCHANGE), extracting CVE / MITRE ATT&CK /
threat-actor tags and an indicator summary. It does NOT touch the DB (worker-safe): it
returns {"intel": [...], "source": "voidaccess"} that the runner's import_threat_intel()
maps to INTELEXCHANGE (idempotent by reference) + cross-links ATT&CK techniques.

Privacy: emails / wallets / hashes are summarised as counts, never dumped verbatim.

Dry-run (no DB):
    python connectors/voidaccess/run.py --file connectors/voidaccess/sample.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from typing import Any, Dict, List

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ACTOR_RE = re.compile(r"\b(?:APT[\s-]?\d{1,3}|FIN\d{1,2}|UNC\d{3,5}|TA\d{3,4}|TEMP\.[A-Za-z0-9]+|UTA-\d{2,4})\b", re.I)
_HTML_RE = re.compile(r"<[^>]+>")
# entity-dict key aliases → canonical bucket
_ENT_KEYS = {
    "cve": ("cve", "cves", "vulnerabilities", "vulns"),
    "actor": ("threat_actors", "actors", "threat_actor", "actor", "ta"),
    "domain": ("domains", "domain", "hostnames", "fqdns"),
    "ip": ("ips", "ip", "ip_addresses", "ipv4", "addresses"),
    "email": ("emails", "email", "email_addresses"),
    "hash": ("hashes", "hash", "file_hashes", "md5", "sha1", "sha256"),
    "wallet": ("wallets", "wallet", "crypto", "bitcoin", "btc", "cryptocurrency", "addresses_crypto"),
}


def _strip(s: str) -> str:
    return re.sub(r"\s+", " ", _HTML_RE.sub(" ", s or "")).strip()


def _csv(values) -> str:
    out: List[str] = []
    for v in values:
        v = str(v).strip()
        if v and v not in out:
            out.append(v)
    return ", ".join(out)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    cap = int(params.get("max_items") or 200)
    findings, ctx = _findings(data)
    intel = [x for x in (_to_intel(f, ctx) for f in findings[:cap]) if x]
    return {"intel": intel, "source": "voidaccess"}


def _findings(data: Any):
    """Return (findings_list, context). Handles a bare list, a single investigation
    ({query, findings/results/items/hits/entities}), or {investigations:[...]}."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)], {}
    if isinstance(data, dict):
        invs = data.get("investigations")
        if isinstance(invs, list):
            out: List[Dict[str, Any]] = []
            for inv in invs:
                if isinstance(inv, dict):
                    fs, _ = _findings(inv)
                    q = inv.get("query") or inv.get("term")
                    for f in fs:
                        f.setdefault("_query", q)
                    out.append({"_query": q, **inv}) if not fs else out.extend(fs)
            return out, {}
        for k in ("findings", "results", "items", "hits", "documents", "data"):
            v = data.get(k)
            if isinstance(v, list):
                q = data.get("query") or data.get("term")
                fs = [x for x in v if isinstance(x, dict)]
                for f in fs:
                    f.setdefault("_query", q)
                return fs, {"entities": data.get("entities")}
        if data.get("title") or data.get("content") or data.get("url"):
            return [data], {}
    return [], {}


def _first(d: Dict[str, Any], keys, default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, dict):
            v = v.get("name") or v.get("title") or v.get("id")
        if v not in (None, "", [], {}):
            return str(v).strip()
    return default


def _entities(d: Dict[str, Any]) -> Dict[str, List[str]]:
    """Normalise the entity dict (or a flat list of typed entities) to canonical buckets."""
    out: Dict[str, List[str]] = {k: [] for k in _ENT_KEYS}
    ent = d.get("entities") or d.get("extracted_entities") or d.get("iocs") or {}
    # flat list form: [{type:"cve", value:"CVE-..."}]
    if isinstance(ent, list):
        flat: Dict[str, List[str]] = {}
        for e in ent:
            if isinstance(e, dict):
                t = str(e.get("type") or e.get("kind") or "").lower()
                val = e.get("value") or e.get("name") or e.get("id")
                if t and val:
                    flat.setdefault(t, []).append(str(val))
        ent = flat
    if not isinstance(ent, dict):
        ent = {}
    for bucket, aliases in _ENT_KEYS.items():
        for a in aliases:
            v = ent.get(a)
            if isinstance(v, list):
                for x in v:
                    val = x.get("value") or x.get("name") if isinstance(x, dict) else x
                    if val:
                        out[bucket].append(str(val).strip())
    return out


def _to_intel(f: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any] | None:
    title = _first(f, ("title", "name", "headline"))
    snippet = _strip(_first(f, ("content", "snippet", "text", "summary", "excerpt", "description", "body")))
    query = _first(f, ("_query",)) or _first(f, ("query", "term"))
    if not title:
        title = (f"VoidAccess: {query}" if query else "VoidAccess dark-web finding")
    if not title and not snippet:
        return None
    url = _first(f, ("url", "link", "onion", "onion_url", "source_url", "uri"))
    source = _first(f, ("source", "engine", "site", "feed")) or "VoidAccess"
    date = _first(f, ("found_at", "discovered_at", "date", "timestamp", "created", "collected"))
    ext = _first(f, ("id", "uuid", "finding_id"))
    ref = url or ("voidaccess:" + (ext or hashlib.sha1((title + snippet).encode("utf-8")).hexdigest()[:16]))

    e = _entities(f)
    if isinstance(ctx.get("entities"), (dict, list)):       # merge investigation-level entities
        ce = _entities({"entities": ctx["entities"]})
        for k in e:
            e[k] = list(dict.fromkeys(e[k] + ce[k]))
    blob = " ".join([title, snippet, " ".join(e["cve"] + e["actor"])])

    # Build a redaction-aware indicator summary (named IOCs + counts for sensitive ones).
    summ: List[str] = []
    if e["domain"]:
        summ.append("domains: " + _csv(e["domain"][:10]))
    if e["ip"]:
        summ.append("IPs: " + _csv(e["ip"][:10]))
    for label, key in (("emails", "email"), ("wallets", "wallet"), ("hashes", "hash"), ("paste links", "wallet")):
        if key == "wallet" and label == "paste links":
            continue
        if e.get(key):
            summ.append(f"{len(e[key])} {label}")
    desc = snippet
    if summ:
        desc = (desc + "  ").strip() + " — Indicators: " + "; ".join(summ)

    return {
        "name": title[:500],
        "description": desc[:6000],
        "reference": ref[:500],
        "external_id": (ext[:120] if ext else None),
        "author": source[:200],
        "date": (date or None),
        "attack_tags": _csv(m.group(0).upper() for m in ATTACK_RE.finditer(blob)),
        "cve_tags": _csv(list(dict.fromkeys([m.group(0).upper() for m in CVE_RE.finditer(blob)] + [c.upper() for c in e["cve"]]))),
        "actor_tags": _csv(list(dict.fromkeys([re.sub(r"\s+", "", m.group(0)).upper() for m in ACTOR_RE.finditer(blob)] + e["actor"]))),
        "tags": _csv(["voidaccess", "dark-web"] + ([source] if source != "VoidAccess" else []) + ([query] if query else [])),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="VoidAccess → INTELEXCHANGE (dry run)")
    ap.add_argument("--file", required=True)
    ap.add_argument("--max-items", type=int, default=200)
    a = ap.parse_args()
    res = run({"file": a.file, "max_items": a.max_items}, "")
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[voidaccess] {len(res['intel'])} intel item(s)", flush=True)
