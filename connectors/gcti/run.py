"""run.py — XORCISM connector: Google Threat Intelligence blog → XTHREAT.

Reads the RSS feed of Google's Threat Intelligence blog (Google Threat Intelligence
Group / Mandiant):

    https://cloud.google.com/blog/topics/threat-intelligence   (feed below)
    https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/

Each post becomes a normalized intel item; the XORCISM runner imports them into
XTHREAT.INTELEXCHANGE (idempotent by post URL) and cross-links any MITRE ATT&CK
techniques into INTELEXCHANGEATTACK. MITRE ATT&CK IDs, CVEs and adversary group
codes (APT##, UNC####, FIN##, TEMP.*, UTA-###) are extracted from the text.

This module performs NO database access (so it also runs on a remote worker): it
returns the normalized result {"intel": [ ... ], "source": ...}.

Python stdlib only (urllib + xml.etree) — no extra worker packages.

Config (worker environment variable, optional):
    GCTI_FEED_URL   override the RSS feed URL (default: the GTIG threat-intel feed)

Offline / test mode:
    params["file"] = path to a saved RSS XML file -> parsed instead of fetching.
"""
from __future__ import annotations

import html
import os
import re
import urllib.request
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List
from xml.etree import ElementTree as ET

DEFAULT_FEED = "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"
SOURCE = "Google Threat Intelligence (GTIG/Mandiant)"
UA = "Mozilla/5.0 (XORCISM threat-feed connector; +https://github.com/) Python-urllib"

_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Adversary group codes commonly used by GTIG/Mandiant.
_ACTOR_RE = re.compile(r"\b(?:APT\s?-?\d{1,4}|UNC\d{3,5}|FIN\d{1,3}|TEMP\.[A-Za-z]+|UTA-?\d{2,4})\b")
_TAG_RE = re.compile(r"<[^>]+>")
_DC = "{http://purl.org/dc/elements/1.1/}"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    max_items = int(params.get("max_items") or 40)
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            xml_text = fh.read()
    else:
        xml_text = _fetch(os.getenv("GCTI_FEED_URL") or DEFAULT_FEED)
    return {"intel": _parse(xml_text, max_items), "source": SOURCE}


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rss+xml, application/xml, text/xml"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (fixed https feed)
        return r.read().decode("utf-8", "replace")


def _strip_html(s: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(_TAG_RE.sub(" ", s or ""))).strip()


def _to_date(pubdate: str) -> str:
    if not pubdate:
        return ""
    try:
        return parsedate_to_datetime(pubdate).strftime("%Y-%m-%d")
    except Exception:  # noqa: BLE001
        return ""


def _csv(values) -> str:
    return ", ".join(sorted({v for v in values if v}))


def _parse(xml_text: str, max_items: int) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise RuntimeError(f"GCTI feed is not valid XML: {e}")

    items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    out: List[Dict[str, Any]] = []
    for it in items[:max_items]:
        def txt(tag: str) -> str:
            el = it.find(tag)
            return (el.text or "").strip() if el is not None and el.text else ""

        title = txt("title") or txt("{http://www.w3.org/2005/Atom}title")
        link = txt("link")
        if not link:  # Atom: <link href="..."/>
            le = it.find("{http://www.w3.org/2005/Atom}link")
            link = le.get("href", "") if le is not None else ""
        desc_raw = txt("description") or txt("{http://www.w3.org/2005/Atom}summary") \
            or txt("{http://purl.org/rss/1.0/modules/content/}encoded")
        author = txt("author") or txt(f"{_DC}creator") or txt("{http://www.w3.org/2005/Atom}author")
        pub = txt("pubDate") or txt("{http://www.w3.org/2005/Atom}published") \
            or txt("{http://www.w3.org/2005/Atom}updated")
        guid = txt("guid") or txt("{http://www.w3.org/2005/Atom}id")

        ref = link or guid
        if not ref or not title:
            continue
        blob = f"{title} {_strip_html(desc_raw)}"
        out.append({
            "name": title[:500],
            "description": _strip_html(desc_raw)[:8000],
            "reference": ref,
            "external_id": guid or None,
            "author": author or "Google Threat Intelligence Group",
            "date": _to_date(pub),
            "attack_tags": _csv(m.upper() for m in _ATTACK_RE.findall(blob)),
            "actor_tags": _csv(re.sub(r"\s|-", "", m).upper() if m.upper().startswith(("APT", "UTA"))
                               else m.upper() for m in _ACTOR_RE.findall(blob)),
            "malware_tags": "",
            "cve_tags": _csv(m.upper() for m in _CVE_RE.findall(blob)),
            "tags": "GTIG, Mandiant, blog",
            "views": None,
        })
    return out


if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="Google Threat Intelligence blog import (dry run)")
    ap.add_argument("--file", help="Saved RSS XML file instead of the live feed")
    ap.add_argument("--max-items", type=int, default=40)
    a = ap.parse_args()
    res = run({"file": a.file, "max_items": a.max_items}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[gcti] {len(res['intel'])} item(s) from {res['source']}", flush=True)
