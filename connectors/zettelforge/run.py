#!/usr/bin/env python3
"""
zettelforge connector — turn CTI analyst notes / threat reports into XORCISM
XTHREAT.INTELEXCHANGE intel items, using ZettelForge's entity extraction
(https://github.com/rolandpg/zettelforge).

ZettelForge is an agentic CTI memory: it extracts CVEs, MITRE ATT&CK techniques,
threat actors (with alias resolution), malware/tools and IOCs from free-text notes.
This connector reproduces ZettelForge's *regex tier* (stdlib-only, fully offline) so it
works with no dependency, and transparently upgrades to the installed `zettelforge`
package (LLM-grade NER + knowledge-graph persistence) when present.

It does NOT touch the database (worker-safe): it returns the normalized
`{"intel": [...], "source": "zettelforge"}` that the runner's import_threat_intel()
maps to INTELEXCHANGE (idempotent by reference) + cross-links ATT&CK techniques.

Modes:
  - notes=<file|dir>   extract entities from CTI note(s) (markdown/text)   ← primary
  - file=<json>        import a saved ZettelForge JSON export (memories/entities)

Dry-run (no DB):
    python connectors/zettelforge/run.py --notes connectors/zettelforge/sample.md
    python connectors/zettelforge/run.py --file  connectors/zettelforge/sample.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# ── Entity extraction (ZettelForge "regex tier", reimplemented stdlib-only) ──────
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ACTOR_RE = re.compile(r"\b(?:APT[\s-]?\d{1,3}|FIN\d{1,2}|UNC\d{3,5}|TA\d{3,4}|TEMP\.[A-Za-z0-9]+|UTA-\d{2,4})\b", re.I)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"\bh(?:tt|xx)ps?://\S+", re.I)
# defang-aware IPv4 and domains ("1[.]2[.]3[.]4", "evil[.]com")
_SEP = r"(?:\[\.\]|\(\.\)|\{\.\}|\s?\.\s?|\.)"
IPV4_RE = re.compile(r"\b(?:\d{1,3}" + _SEP + r"){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" + _SEP + r")+"
    r"(?:com|net|org|io|info|biz|co|ru|cn|ir|kp|onion|gov|edu|mil|xyz|top|live|app|dev|cloud|tk|uk|de|fr|nl|br|in|us)\b",
    re.I,
)

# Threat-actor alias resolution (a representative subset — ZettelForge unifies these).
ACTOR_ALIASES = {
    "fancy bear": "APT28", "sofacy": "APT28", "strontium": "APT28", "sednit": "APT28",
    "pawn storm": "APT28", "forest blizzard": "APT28",
    "cozy bear": "APT29", "the dukes": "APT29", "nobelium": "APT29", "midnight blizzard": "APT29",
    "lazarus": "Lazarus Group", "hidden cobra": "Lazarus Group", "diamond sleet": "Lazarus Group",
    "sandworm": "Sandworm Team", "voodoo bear": "Sandworm Team", "seashell blizzard": "Sandworm Team",
    "wizard spider": "Wizard Spider", "volt typhoon": "Volt Typhoon", "vanguard panda": "Volt Typhoon",
    "scattered spider": "Scattered Spider", "muddywater": "MuddyWater", "kimsuky": "Kimsuky",
    "charming kitten": "APT35", "phosphorus": "APT35", "mint sandstorm": "APT35",
}
# Known malware / offensive tools (substring, word-boundary checked).
MALWARE_TOOLS = [
    "cobalt strike", "mimikatz", "emotet", "trickbot", "qakbot", "qbot", "ryuk", "conti",
    "lockbit", "blackcat", "alphv", "icedid", "bumblebee", "raspberry robin", "plugx",
    "njrat", "agent tesla", "redline", "raccoon", "gootloader", "brute ratel", "sliver",
    "metasploit", "psexec", "anydesk", "rclone", "winrar", "wmiexec",
]

# ── helpers ──────────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _defang(s: str) -> str:
    return (s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
             .replace("[dot]", ".").replace("(dot)", ".").replace(" dot ", ".")
             .replace("[:]", ":").replace("hxxp", "http").replace("hXXp", "http")
             .replace("[@]", "@").replace("[at]", "@"))


def _neutralize(v: str, kind: str) -> str:
    """Defang an IOC for safe (non-clickable) storage/display."""
    if kind == "urls":
        return v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return v.replace(".", "[.]")  # ips / domains / emails


def _extract(text: str) -> dict:
    """Regex + alias extraction → buckets of STIX-ish entity values."""
    low = text.lower()
    cve = {m.group(0).upper() for m in CVE_RE.finditer(text)}
    attack = {m.group(0).upper() for m in ATTACK_RE.finditer(text)}
    actors = {re.sub(r"\s+", "", m.group(0)).upper().replace("APT", "APT").replace("-", "")
              if m.group(0).upper().startswith(("APT", "FIN", "UNC", "TA"))
              else m.group(0) for m in ACTOR_RE.finditer(text)}
    # normalise APT spacing/case (APT 28 / apt-28 → APT28)
    actors = {re.sub(r"(?i)^apt[\s-]?(\d+)$", lambda x: "APT" + x.group(1), a) for a in actors}
    for alias, canon in ACTOR_ALIASES.items():
        if re.search(r"\b" + re.escape(alias) + r"\b", low):
            actors.add(canon)
    malware = {m for m in MALWARE_TOOLS if re.search(r"\b" + re.escape(m) + r"\b", low)}
    dtext = _defang(text)  # emails/URLs are easiest to read off the refanged text
    emails = {m.group(0).lower() for m in EMAIL_RE.finditer(dtext)}
    urls = {_defang(m.group(0)).rstrip(".,;:)]}>\"'") for m in URL_RE.finditer(text)}
    ips = set()
    for m in IPV4_RE.finditer(text):
        ip = _defang(m.group(0)).strip().rstrip(".")
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            ips.add(ip)
    email_doms = {e.split("@", 1)[1] for e in emails if "@" in e}
    domains = set()
    for m in DOMAIN_RE.finditer(text):
        d = _defang(m.group(0)).strip(". ").lower()
        if d and d not in email_doms and not d.replace(".", "").isdigit():
            domains.add(d)
    # don't double-count domains that only appear inside an extracted URL/email
    return {"cve": cve, "attack": attack, "actors": {a for a in actors if a},
            "malware": malware, "ips": ips, "domains": domains, "urls": urls,
            "hashes": {h.lower() for h in HASH_RE.findall(text)}, "emails": emails}


# ── best-effort live ZettelForge integration (LLM NER + knowledge graph) ─────────
_STIX_MAP = {
    "vulnerability": "cve", "attack-pattern": "attack", "technique": "attack",
    "threat-actor": "actors", "intrusion-set": "actors", "campaign": "actors",
    "malware": "malware", "tool": "malware",
    "ipv4-addr": "ips", "ipv6-addr": "ips", "domain-name": "domains", "url": "urls",
    "file": "hashes", "email-addr": "emails",
}


def _normalize_zf_entities(ents) -> dict:
    """Map ZettelForge's (STIX 2.1-typed) entities into our buckets, defensively."""
    out = {k: set() for k in ("cve", "attack", "actors", "malware", "ips", "domains", "urls", "hashes", "emails")}
    seq = ents.values() if isinstance(ents, dict) else ents
    for e in (seq or []):
        if isinstance(e, dict):
            typ = str(e.get("type") or e.get("stix_type") or e.get("entity_type") or "").lower()
            val = e.get("value") or e.get("name") or e.get("id")
        else:
            typ, val = "", e
        bucket = _STIX_MAP.get(typ)
        if bucket and val:
            out[bucket].add(str(val))
    return out


def _zettelforge_live(text: str, persist: bool) -> dict | None:
    """Use the installed `zettelforge` package: persist the note into its memory and
    pull richer (LLM) entities. Returns None on any mismatch → caller uses regex."""
    try:
        import zettelforge  # noqa: F401
    except Exception:
        return None
    ents = None
    try:
        from zettelforge import MemoryManager
        mm = MemoryManager()
        if persist:
            try:
                mm.remember(text)
            except Exception:
                pass
        for owner in (mm, zettelforge):
            for attr in ("extract_entities", "extract", "entities", "ner"):
                fn = getattr(owner, attr, None)
                if callable(fn):
                    try:
                        ents = fn(text)
                        break
                    except Exception:
                        ents = None
            if ents:
                break
    except Exception:
        return None
    if not ents:
        return None
    try:
        return _normalize_zf_entities(ents)
    except Exception:
        return None


def _merge(a: dict, b: dict | None) -> dict:
    if not b:
        return a
    return {k: set(a.get(k, set())) | set(b.get(k, set())) for k in a}


# ── note → intel record ──────────────────────────────────────────────────────────
def _title_of(text: str, fallback: str) -> str:
    for line in text.splitlines():
        s = line.strip().lstrip("#").strip()
        if s:
            return s[:200]
    return fallback[:200]


def _intel_record(title: str, text: str, author: str, date: str, ent: dict) -> dict:
    sha1 = hashlib.sha1(re.sub(r"\s+", " ", text).strip().encode("utf-8", "ignore")).hexdigest()
    ioc_counts = [f"{k}:{len(ent[k])}" for k in ("ips", "domains", "urls", "hashes", "emails") if ent.get(k)]
    tags = ["zettelforge"] + ioc_counts
    # preserve IOCs (defanged) without losing them — INTELEXCHANGE has no IOC column
    ioc_lines = []
    for label, key in (("IPs", "ips"), ("Domains", "domains"), ("URLs", "urls"), ("Hashes", "hashes"), ("Emails", "emails")):
        vals = sorted(ent.get(key, []))
        if vals:
            shown = ", ".join((v if key == "hashes" else _neutralize(v, key)) for v in vals[:25])
            ioc_lines.append(f"{label}: {shown}")
    desc = text.strip()[:6000]
    if ioc_lines:
        desc = desc + "\n\n— Indicators (ZettelForge) —\n" + "\n".join(ioc_lines)
    return {
        "name": title or f"CTI note {sha1[:8]}",
        "description": desc,
        "reference": f"zettelforge:{sha1[:16]}",
        "external_id": sha1,
        "author": author or "ZettelForge",
        "date": date or _now(),
        "attack_tags": ",".join(sorted(ent.get("attack", []))),
        "cve_tags": ",".join(sorted(ent.get("cve", []))),
        "actor_tags": ",".join(sorted(ent.get("actors", []))),
        "malware_tags": ",".join(sorted(ent.get("malware", []))),
        "tags": ", ".join(tags),
    }


# ── note gathering / offline export ──────────────────────────────────────────────
_NOTE_EXT = (".md", ".markdown", ".txt", ".text", ".log")


def _looks_json(path: str) -> bool:
    if path.lower().endswith((".json", ".ndjson")):
        return True
    if path.lower().endswith(_NOTE_EXT):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(256).lstrip()[:1] in ("{", "[")
    except Exception:
        return False


def _gather_notes(path: str) -> list:
    out = []
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in sorted(files):
                if f.lower().endswith(_NOTE_EXT):
                    out.append(os.path.join(root, f))
    elif os.path.isfile(path):
        out.append(path)
    return out


def _from_export(path: str, author: str) -> list:
    """Import a saved ZettelForge JSON export (defensive about its shape)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        data = json.load(fh)
    items = data
    if isinstance(data, dict):
        for k in ("memories", "notes", "items", "records", "results", "data"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
        else:
            items = [data]
    records = []
    for it in (items or []):
        if not isinstance(it, dict):
            it = {"text": str(it)}
        text = (it.get("text") or it.get("content") or it.get("note") or it.get("memory")
                or it.get("body") or it.get("summary") or "")
        if not text:
            continue
        ent = _extract(text)
        ent = _merge(ent, _normalize_zf_entities(it.get("entities")) if it.get("entities") else None)
        title = it.get("title") or it.get("name") or _title_of(text, "CTI memory")
        records.append(_intel_record(title, text, it.get("author") or author, it.get("date") or _now(), ent))
    return records


# ── entrypoint ───────────────────────────────────────────────────────────────────
def run(params: dict, workdir: str = ".") -> dict:
    params = params or {}
    author = str(params.get("author") or "ZettelForge")
    max_items = int(params.get("max_items") or 200)
    use_zf = str(params.get("use_zettelforge", True)).lower() not in ("0", "false", "no")

    # accept the path from either parameter; auto-detect a JSON export vs raw notes so
    # `notes`, `file` and the runner's --selftest (which sets `file`) all work.
    path = params.get("notes") or params.get("file")
    if not path or not os.path.exists(str(path)):
        raise SystemExit("zettelforge: provide 'notes' (file/dir of CTI notes) or 'file' (ZettelForge JSON export)")
    path = str(path)
    records = []
    if os.path.isfile(path) and _looks_json(path):
        records = _from_export(path, author)
    else:
        for fp in _gather_notes(path):
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            if not text.strip():
                continue
            ent = _extract(text)
            if use_zf:
                ent = _merge(ent, _zettelforge_live(text, persist=True))
            date = datetime.fromtimestamp(os.path.getmtime(fp), timezone.utc).replace(microsecond=0).isoformat()
            records.append(_intel_record(_title_of(text, os.path.basename(fp)), text, author, date, ent))

    # dedupe by reference, cap
    seen, uniq = set(), []
    for r in records:
        if r["reference"] in seen:
            continue
        seen.add(r["reference"])
        uniq.append(r)
        if len(uniq) >= max_items:
            break
    return {"intel": uniq, "source": "zettelforge"}


def main() -> None:
    ap = argparse.ArgumentParser(description="ZettelForge CTI connector (notes/reports → INTELEXCHANGE intel)")
    ap.add_argument("--notes", help="CTI note file or directory")
    ap.add_argument("--file", help="ZettelForge JSON export (offline)")
    ap.add_argument("--author", default="ZettelForge")
    ap.add_argument("--no-zettelforge", action="store_true", help="regex extractor only (skip the zettelforge package)")
    args = ap.parse_args()
    res = run({"notes": args.notes, "file": args.file, "author": args.author,
               "use_zettelforge": not args.no_zettelforge}, ".")
    print(json.dumps(res, indent=2, ensure_ascii=False))
    n = len(res["intel"])
    tt = sum(len([t for t in (i["attack_tags"] or "").split(",") if t]) for i in res["intel"])
    cc = sum(len([t for t in (i["cve_tags"] or "").split(",") if t]) for i in res["intel"])
    aa = sum(len([t for t in (i["actor_tags"] or "").split(",") if t]) for i in res["intel"])
    print(f"\n[zettelforge] {n} intel item(s) · {tt} ATT&CK · {cc} CVE · {aa} actor tag(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
