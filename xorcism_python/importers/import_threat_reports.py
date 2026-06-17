"""
import_threat_reports.py — Collect cyber threat reports from the internet (the
curated CTI RSS feeds in XTHREAT.THREATFEED) into XTHREAT.THREATREPORT, then
extract their indicators of compromise into XTHREAT.IOC.

For each report it fetches the article body, refangs it (hxxp -> http, [.] -> .,
etc.) and extracts IPv4 addresses, domains (TLD-allowlisted), URLs, MD5/SHA1/SHA256
hashes and CVEs — filtering out benign/source domains to keep the noise down.

Idempotent: THREATREPORT keyed by its URL, IOC keyed by (value, type). Re-runnable.

    python import_threat_reports.py                 # 50 reports + their IOCs
    python import_threat_reports.py --count 10
    python import_threat_reports.py --count 5 --dry-run
    python import_threat_reports.py --no-fetch       # IOCs from the RSS summary only
"""
from __future__ import annotations

import argparse
import html
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XORCISM-CTI/1.0"

# Real TLDs we accept for domain IOCs (avoids treating file names like foo.exe as domains).
TLDS = set("com net org io co info biz ru cn de fr uk us eu nl br in jp kr ca au it es pl ua "
           "tk top xyz online site app dev cloud me tv cc gov mil edu int pro link live one "
           "su ir kp sy vn id tw hk sg ch se no fi dk cz ro gr pt be at ae sa za mx ar cl".split())
# Benign / infrastructure / source domains dropped from IOC extraction.
BENIGN = set(("google.com googleapis.com gstatic.com googletagmanager.com youtube.com youtu.be "
              "twitter.com x.com t.co facebook.com fb.com linkedin.com instagram.com mastodon.social "
              "infosec.exchange reddit.com redd.it github.com githubusercontent.com github.io gitlab.com "
              "microsoft.com windows.com office.com live.com bing.com apple.com icloud.com amazon.com "
              "amazonaws.com cloudfront.net cloudflare.com akamai.net akamaihd.net fastly.net jsdelivr.net "
              "unpkg.com w3.org schema.org mozilla.org wikipedia.org creativecommons.org gravatar.com "
              "wordpress.com wp.com gstatic.com doubleclick.net google-analytics.com mitre.org first.org "
              "cisa.gov ncsc.gov.uk virustotal.com abuse.ch shodan.io censys.io archive.org web.archive.org "
              "bleepingcomputer.com thehackernews.com krebsonsecurity.com darkreading.com therecord.media "
              "securityaffairs.com welivesecurity.com securelist.com talosintelligence.com unit42.paloaltonetworks.com "
              "crowdstrike.com sentinelone.com sophos.com malwarebytes.com rapid7.com checkpoint.com "
              "trendmicro.com kaspersky.com eset.com cisco.com paloaltonetworks.com recordedfuture.com "
              "theregister.com cyberscoop.com grahamcluley.com schneier.com volexity.com withsecure.com "
              "feedburner.com feeds.feedburner.com gstatic.com cloudblog.withgoogle.com").split())

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"https?://[^\s\"'<>)\]}]+", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_PRIVATE = re.compile(r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|22[4-9]\.|23\d\.|255\.)")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportReports] {msg}", flush=True)


def safe_host(u: str) -> str:
    try:
        return urlparse(u).netloc.split("@")[-1].split(":")[0].strip().lower()
    except ValueError:
        return ""


def refang(t: str) -> str:
    t = re.sub(r"h[xX]{2}p", "http", t)
    t = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\s+dot\s+", ".", t, flags=re.I)
    t = t.replace("[:]", ":").replace("[://]", "://").replace("[//]", "//")
    t = re.sub(r"\[@\]|\(at\)|\[at\]|\s+at\s+", "@", t, flags=re.I)
    return t


def strip_html(s: str) -> str:
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return html.unescape(s)


def tag(block: str, name: str) -> str:
    m = re.search(rf"<{name}\b[^>]*>(.*?)</{name}>", block, re.S | re.I)
    if not m:
        return ""
    v = m.group(1)
    v = re.sub(r"(?s)<!\[CDATA\[(.*?)\]\]>", r"\1", v)
    return html.unescape(strip_html(v)).strip()


def parse_feed(xml: str, limit: int) -> list[dict]:
    blocks = re.findall(r"<item\b[^>]*>(.*?)</item>", xml, re.S | re.I) or \
        re.findall(r"<entry\b[^>]*>(.*?)</entry>", xml, re.S | re.I)
    out = []
    for b in blocks[:limit]:
        link = tag(b, "link")
        if not link:
            m = re.search(r'<link[^>]*href="([^"]+)"', b)
            link = m.group(1) if m else ""
        out.append({
            "title": tag(b, "title")[:250],
            "link": link.strip(),
            "summary": (tag(b, "description") or tag(b, "summary") or tag(b, "content"))[:8000],
            "date": (tag(b, "pubDate") or tag(b, "updated") or tag(b, "published")).strip(),
        })
    return out


def extract_iocs(text: str, source_host: str) -> list[tuple[str, str, str]]:
    """Returns deduped (value, type, stix_type) IOC tuples from `text`."""
    t = refang(text)
    found: "dict[str, tuple[str, str, str]]" = {}

    def add(val: str, kind: str, stix: str) -> None:
        key = (kind + ":" + val).lower()
        if key not in found:
            found[key] = (val, kind, stix)

    for h in set(_SHA256.findall(t)):
        add(h.lower(), "sha256", "file")
    for h in set(_SHA1.findall(t)):
        add(h.lower(), "sha1", "file")
    for h in set(_MD5.findall(t)):
        add(h.lower(), "md5", "file")
    for ip in set(_IPV4.findall(t)):
        if not _PRIVATE.match(ip):
            add(ip, "ipv4", "ipv4-addr")
    for cve in set(m.group(0).upper() for m in _CVE.finditer(t)):
        add(cve, "cve", "vulnerability")
    for url in set(_URL.findall(t)):
        host = safe_host(url)
        if host and not _is_benign(host, source_host):
            add(url.rstrip(".,);'\"").lower(), "url", "url")
            add(host, "domain", "domain-name")
    for m in _DOMAIN.finditer(t):
        dom, tld = m.group(0).lower(), m.group(1).lower()
        if tld in TLDS and not _is_benign(dom, source_host):
            add(dom, "domain", "domain-name")
    return list(found.values())


def _is_benign(host: str, source_host: str) -> bool:
    host = host.strip(".").lower()
    if not host or "." not in host:
        return True
    if source_host and (host == source_host or host.endswith("." + source_host)):
        return True
    return any(host == b or host.endswith("." + b) for b in BENIGN)


def main() -> int:
    ap = argparse.ArgumentParser(description="Import threat reports + their IOCs")
    ap.add_argument("--count", type=int, default=50, help="Number of new reports to import")
    ap.add_argument("--no-fetch", action="store_true", help="Don't fetch article bodies (IOCs from RSS summary only)")
    ap.add_argument("--dry-run", action="store_true", help="Parse only; write nothing")
    args = ap.parse_args()

    if not os.path.exists(DB_PATH):
        log(f"XTHREAT.db not found: {DB_PATH}")
        return 1
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=15000")
    feeds = conn.execute(
        "SELECT ThreatFeedName, FeedURL FROM THREATFEED WHERE Enabled=1 AND FeedURL IS NOT NULL"
    ).fetchall()
    have = {r[0] for r in conn.execute("SELECT ThreatReportReference FROM THREATREPORT WHERE ThreatReportReference IS NOT NULL").fetchall()}

    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    # Gather candidates (round-robin across feeds for source diversity).
    per_feed: list[list[dict]] = []
    for name, url in feeds:
        try:
            r = sess.get(url, timeout=25)
            items = parse_feed(r.text, 40) if r.status_code == 200 else []
            for it in items:
                it["feed"] = name
            per_feed.append([it for it in items if it.get("link")])
        except Exception:  # noqa: BLE001
            per_feed.append([])
    candidates: list[dict] = []
    i = 0
    while any(i < len(f) for f in per_feed):  # round-robin across all fetched items
        for f in per_feed:
            if i < len(f):
                candidates.append(f[i])
        i += 1

    chosen = []
    seen_url: set[str] = set()
    for c in candidates:
        u = c["link"][:500]
        if u in have or u in seen_url:
            continue
        seen_url.add(u)
        chosen.append(c)
        if len(chosen) >= args.count:
            break

    log(f"{len(feeds)} feeds, {sum(len(f) for f in per_feed)} items fetched, {len(chosen)} new report(s) to import.")

    rep_ins = ioc_ins = 0
    seen_ioc = {(r[0] or "").lower(): True for r in conn.execute("SELECT IOCName FROM IOC").fetchall()}
    ts = now()
    trcols = {r[1] for r in conn.execute('PRAGMA table_info("THREATREPORT")').fetchall()}
    has_cve = "CveTags" in trcols

    for c in chosen:
        host = safe_host(c["link"])
        body = c["summary"]
        if not args.no_fetch:
            try:
                ar = sess.get(c["link"], timeout=25)
                if ar.status_code == 200:
                    body = strip_html(ar.text)[:200000]
            except Exception:  # noqa: BLE001
                pass
        iocs = extract_iocs(f"{c['title']}\n{body}", host)
        cves = ",".join(sorted({v for v, k, _ in iocs if k == "cve"}))

        if args.dry_run:
            log(f"  · {c['title'][:70]}  [{c['feed']}]  {len(iocs)} IOC(s)")
            rep_ins += 1
            ioc_ins += len(iocs)
            continue

        with conn:  # one transaction per report → IDs via subquery stay race-safe vs the live poller
            desc = (c["summary"][:1500] + f"\n\nSource: {c['feed']} — {c['link']}").strip()
            if has_cve:
                conn.execute(
                    """INSERT INTO THREATREPORT (ThreatReportID, ThreatReportGUID, ThreatReportName,
                       ThreatReportDescription, CreatedDate, ThreatReportSource, ThreatReportReference, CveTags)
                       VALUES ((SELECT COALESCE(MAX(ThreatReportID),0)+1 FROM THREATREPORT),?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), c["title"] or "(untitled)", desc, ts, c["feed"], c["link"][:500], cves or None))
            else:
                conn.execute(
                    """INSERT INTO THREATREPORT (ThreatReportID, ThreatReportGUID, ThreatReportName,
                       ThreatReportDescription, CreatedDate, ThreatReportSource, ThreatReportReference)
                       VALUES ((SELECT COALESCE(MAX(ThreatReportID),0)+1 FROM THREATREPORT),?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), c["title"] or "(untitled)", desc, ts, c["feed"], c["link"][:500]))
            for val, kind, stix in iocs:
                if val.lower() in seen_ioc:
                    continue
                seen_ioc[val.lower()] = True
                pattern = f"[{stix}:value = '{val}']" if stix in ("ipv4-addr", "domain-name", "url") else (
                    f"[file:hashes.'{kind.upper()}' = '{val}']" if stix == "file" else val)
                conn.execute(
                    """INSERT INTO IOC (IOCID, IOCGUID, IOCName, IOCDescription, CreatedDate, IOCtype,
                       Pattern, PatternType, Labels, ValidFrom, Confidence, TenantID)
                       VALUES ((SELECT COALESCE(MAX(IOCID),0)+1 FROM IOC),?,?,?,?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), val[:400], f"From: {c['title'][:200]} ({c['link'][:300]})",
                     ts, kind, pattern[:600], "stix", c["feed"][:100], ts[:10], 50, 3))
                ioc_ins += 1
            rep_ins += 1

    conn.close()
    verb = "would import" if args.dry_run else "imported"
    log(f"OK — {verb} {rep_ins} THREATREPORT and {ioc_ins} IOC(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
