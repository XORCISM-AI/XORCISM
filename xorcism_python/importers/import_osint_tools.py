"""
import_osint_tools.py — Import the OSINT tools listed in the OSINT Newsletter
tools library into XORCISM.TOOL.

Source: https://tools.osintnewsletter.com/  (a GitBook directory organised in
17 categories + social-media sub-pages). The library exposes each tool on its own
page at /osint-tools/<slug>; this importer embeds the tool NAMES, their CATEGORY
and their canonical library page URL (gathered from the category indexes). Tool
NAMES and categories are factual; the descriptions written here are short ORIGINAL
labels (the library's prose is not reproduced).

Idempotent: a TOOL row is skipped when a row with the same ToolURL OR the same
ToolName (case-insensitive) already exists for the tenant. Tools that appear in
several categories are de-duplicated by name (first category wins).

    python import_osint_tools.py             # import / refresh
    python import_osint_tools.py --dry-run   # print what would be imported, touch no DB
    python import_osint_tools.py --tenant 3  # target tenant (default 3)
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

# Windows consoles default to cp1252; force UTF-8 so accents / arrows don't crash.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

DB_PATH = os.path.join(config.DB_DIR, "XORCISM.db")
SOURCE = "https://tools.osintnewsletter.com/"
BASE = "https://tools.osintnewsletter.com/osint-tools/"
DEFAULT_TENANT = 3

# (category, tool name, library slug, optional platform/context note).
# Order matters: the first category in which a tool appears becomes its category.
CATALOG: list[tuple[str, str, str, str]] = [
    # ── Email Address OSINT ─────────────────────────────────────────────
    ("Email Address OSINT", "OSINT Industries", "osint-industries", ""),
    ("Email Address OSINT", "Epieos", "epieos", ""),
    ("Email Address OSINT", "LoLArchiver", "lolarchiver", ""),
    ("Email Address OSINT", "Ghunt", "ghunt", ""),
    ("Email Address OSINT", "Zen", "zen", ""),
    ("Email Address OSINT", "Osintly", "osintly", ""),
    ("Email Address OSINT", "Zehef", "zehef", ""),
    ("Email Address OSINT", "Sherlock Eye", "sherlock-eye", ""),
    ("Email Address OSINT", "Analyst Research Tools", "analyst-research-tools", ""),
    # ── Username OSINT ──────────────────────────────────────────────────
    ("Username OSINT", "WhatsMyName", "whatsmyname", ""),
    ("Username OSINT", "TheBigBrother", "thebigbrother", ""),
    ("Username OSINT", "NAMINT", "namint", ""),
    ("Username OSINT", "Hippie OSINT Toolkit", "hippie-osint-toolkit", ""),
    # ── Phone Number OSINT ──────────────────────────────────────────────
    ("Phone Number OSINT", "Telegram Phone Number Checker", "telegram-phone-number-checker", ""),
    ("Phone Number OSINT", "Phunter", "phunter", ""),
    # ── People OSINT ────────────────────────────────────────────────────
    ("People OSINT", "192.com", "192.com", ""),
    ("People OSINT", "Forebears", "forebears", ""),
    ("People OSINT", "District 4 Labs Darkside", "district-4-labs-darkside", ""),
    ("People OSINT", "That's Them", "thats-them", ""),
    ("People OSINT", "IDCrawl", "idcrawl", ""),
    # ── Domain Name OSINT ───────────────────────────────────────────────
    ("Domain Name OSINT", "Domain Dossier", "domain-dossier", ""),
    ("Domain Name OSINT", "WHOIS API", "whois-api", ""),
    ("Domain Name OSINT", "urlscan.io", "urlscan.io", ""),
    ("Domain Name OSINT", "Have I Been Squatted?", "have-i-been-squatted", ""),
    ("Domain Name OSINT", "Host.io", "host.io", ""),
    ("Domain Name OSINT", "DNS Dumpster", "dns-dumpster", ""),
    ("Domain Name OSINT", "Central Ops", "central-ops", ""),
    ("Domain Name OSINT", "ARIN", "arin", ""),
    # ── Network Infrastructure OSINT ────────────────────────────────────
    ("Network Infrastructure OSINT", "Censys", "censys", ""),
    ("Network Infrastructure OSINT", "Shodan", "shodan", ""),
    ("Network Infrastructure OSINT", "IPinfo", "ipinfo", ""),
    ("Network Infrastructure OSINT", "IntelligenceX", "intelligencex", ""),
    ("Network Infrastructure OSINT", "PhishTank", "phishtank", ""),
    ("Network Infrastructure OSINT", "FOFA", "fofa", ""),
    ("Network Infrastructure OSINT", "Netlas", "netlas", ""),
    ("Network Infrastructure OSINT", "Domain Digger", "domain-digger", ""),
    ("Network Infrastructure OSINT", "Tiny Scan", "tiny-scan", ""),
    ("Network Infrastructure OSINT", "Dorky", "dorky", ""),
    ("Network Infrastructure OSINT", "XResolver", "xresolver", ""),
    ("Network Infrastructure OSINT", "Lookyloo", "lookyloo", ""),
    # ── Cyberthreat Intelligence OSINT ──────────────────────────────────
    ("Cyberthreat Intelligence OSINT", "Hudson Rock", "hudson-rock", ""),
    ("Cyberthreat Intelligence OSINT", "Meawfy", "meawfy", ""),
    ("Cyberthreat Intelligence OSINT", "File Phish", "file-phish", ""),
    ("Cyberthreat Intelligence OSINT", "JSON Crack", "json-crack", ""),
    # ── Public Records OSINT ────────────────────────────────────────────
    ("Public Records OSINT", "Companies House (UK)", "companies-house", ""),
    ("Public Records OSINT", "USPTO", "uspto", ""),
    ("Public Records OSINT", "FPDS", "fpds", ""),
    ("Public Records OSINT", "527 Explorer (US)", "527-explorer", ""),
    ("Public Records OSINT", "EU Sanctions Map", "eu-sanctions-map", ""),
    ("Public Records OSINT", "OpenSecrets", "opensecrets", ""),
    ("Public Records OSINT", "Import Yeti", "import-yeti", ""),
    # ── Data Extraction OSINT ───────────────────────────────────────────
    ("Data Extraction OSINT", "Thunderbit", "thunderbit", ""),
    ("Data Extraction OSINT", "Simple Scraper", "simple-scraper", ""),
    # ── Foundational OSINT ──────────────────────────────────────────────
    ("Foundational OSINT", "Finger Printer", "finger-printer", ""),
    ("Foundational OSINT", "Cover Your Tracks", "cover-your-tracks", ""),
    ("Foundational OSINT", "Known Agents", "known-agents", ""),
    ("Foundational OSINT", "Human or AI", "human-or-ai", ""),
    ("Foundational OSINT", "Your social media fingerprint", "your-social-media-fingerprint", ""),
    ("Foundational OSINT", "Maltego", "maltego", ""),
    ("Foundational OSINT", "Forensic OSINT", "forensic-osint", ""),
    ("Foundational OSINT", "Hunchly", "hunchly", ""),
    ("Foundational OSINT", "Ubikron", "ubikron", ""),
    ("Foundational OSINT", "OpenGraph Intel", "opengraph-intel", ""),
    ("Foundational OSINT", "SIERRA", "sierra", ""),
    ("Foundational OSINT", "Authentic8 Silo Workspace", "authentic8-silo-workspace", ""),
    # ── Image & Video Analysis OSINT ────────────────────────────────────
    ("Image & Video Analysis OSINT", "Amazon Rekognition", "amazon-rekognition", ""),
    ("Image & Video Analysis OSINT", "Autostitch", "autostitch", ""),
    ("Image & Video Analysis OSINT", "Face Comparison by Toolpie", "face-comparison-by-toolpie", ""),
    ("Image & Video Analysis OSINT", "Forensically", "forensically", ""),
    ("Image & Video Analysis OSINT", "Google Lens", "google-lens", ""),
    ("Image & Video Analysis OSINT", "Filmot", "filmot", ""),
    ("Image & Video Analysis OSINT", "Profile Image Intel", "profile-image-intel", ""),
    ("Image & Video Analysis OSINT", "Crowd Counter", "crowd-counter", ""),
    ("Image & Video Analysis OSINT", "TinEye", "tineye", ""),
    ("Image & Video Analysis OSINT", "Pic Detective", "pic-detective", ""),
    ("Image & Video Analysis OSINT", "PimEyes", "pimeyes", ""),
    ("Image & Video Analysis OSINT", "Image Whisperer", "image-whisperer", ""),
    # ── Geolocation & Maps OSINT ────────────────────────────────────────
    ("Geolocation & Maps OSINT", "Apple Maps", "apple-maps", ""),
    ("Geolocation & Maps OSINT", "Baidu Maps", "baidu-maps", ""),
    ("Geolocation & Maps OSINT", "Bellingcat OpenStreetMap Search", "bellingcat-openstreetmap-search", ""),
    ("Geolocation & Maps OSINT", "GeoHints", "geohints", ""),
    ("Geolocation & Maps OSINT", "ShadeMap", "shademap", ""),
    ("Geolocation & Maps OSINT", "Wikimapia", "wikimapia", ""),
    ("Geolocation & Maps OSINT", "GeoSpy", "geospy", ""),
    ("Geolocation & Maps OSINT", "Surveillance under Surveillance", "surveillance-under-surveillance", ""),
    ("Geolocation & Maps OSINT", "MW Geofind", "mw-geofind", ""),
    ("Geolocation & Maps OSINT", "Picarta", "picarta", ""),
    ("Geolocation & Maps OSINT", "SPOT", "spot", ""),
    ("Geolocation & Maps OSINT", "Copernicus Browser", "copernicus-browser", ""),
    # ── Transport OSINT ─────────────────────────────────────────────────
    ("Transport OSINT", "Flightradar24", "flightradar24", ""),
    ("Transport OSINT", "VIN Decoder from NHTSA", "vin-decoder-from-nhtsa", ""),
    ("Transport OSINT", "Vehicle AI", "vehicle-ai", ""),
    ("Transport OSINT", "MarineTraffic", "marinetraffic", ""),
    ("Transport OSINT", "Global ADS-B Exchange", "global-ads-b-exchange", ""),
    # ── Archiving OSINT ─────────────────────────────────────────────────
    ("Archiving OSINT", "Wayback Machine", "wayback-machine", ""),
    ("Archiving OSINT", "Anna's Archive", "annas-archive", ""),
    # ── Blockchain/Cryptocurrency OSINT ─────────────────────────────────
    ("Blockchain/Cryptocurrency OSINT", "Arkham Intelligence", "arkham", ""),
    ("Blockchain/Cryptocurrency OSINT", "Dune", "dune", ""),
    ("Blockchain/Cryptocurrency OSINT", "Block Explorer", "block-explorer", ""),
    # ── Language Translation OSINT ──────────────────────────────────────
    ("Language Translation OSINT", "DeepL Translator", "deepl-translator", ""),
    ("Language Translation OSINT", "2lingual Search", "2lingual-search", ""),
    # ── Social Media OSINT (platform noted in the description) ───────────
    ("Social Media OSINT", "Who posted what?", "who-posted-what-facebook-tool", "Facebook"),
    ("Social Media OSINT", "Facebook Video Downloader", "facebook-video-downloader", "Facebook"),
    ("Social Media OSINT", "Sowsearch", "sowsearch", "Facebook"),
    ("Social Media OSINT", "Story Saver", "story-saver-instagram", "Instagram"),
    ("Social Media OSINT", "Instagram Map", "instagram-map", "Instagram"),
    ("Social Media OSINT", "Inflact Instagram Profile Viewer", "inflact-instagram-profile-viewer", "Instagram"),
    ("Social Media OSINT", "BirdHunt", "birdhunt", "Twitter/X"),
    ("Social Media OSINT", "Twitter Viewer", "twitter-viewer", "Twitter/X"),
    ("Social Media OSINT", "Sotwe", "sotwe", "Twitter/X"),
    ("Social Media OSINT", "Nitter", "nitter", "Twitter/X"),
    ("Social Media OSINT", "Telegago", "telegago-telegram", "Telegram"),
    ("Social Media OSINT", "Telegram Spoiler Decoder", "telegram-spoiler-decoder", "Telegram"),
    ("Social Media OSINT", "Deaddrop", "deaddrop", "Telegram"),
    ("Social Media OSINT", "Telemetry", "telemetry", "Telegram"),
    ("Social Media OSINT", "Bluesky Follow Finder", "bluesky-follow-finder", "Bluesky"),
    ("Social Media OSINT", "Treeverse", "treeverse", "Bluesky"),
    ("Social Media OSINT", "Govsky", "govsky", "Bluesky"),
    ("Social Media OSINT", "AzSky", "azsky", "Bluesky"),
    ("Social Media OSINT", "Internect.info", "internect.info", "Bluesky"),
    ("Social Media OSINT", "Snap Map", "snap-map", "Snapchat"),
    ("Social Media OSINT", "YouTube Video Finder", "youtube-video-finder", "YouTube"),
    ("Social Media OSINT", "Waybien", "waybien", "Multiple platforms"),
    ("Social Media OSINT", "Open Measures", "open-measures", "Multiple platforms"),
    ("Social Media OSINT", "ToolsCord", "toolscord", "Multiple platforms / Discord"),
    ("Social Media OSINT", "Discord Leaks", "discord-leaks", "Multiple platforms / Discord"),
]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportOSINTTools] {msg}", flush=True)


def dedup(rows: list[tuple[str, str, str, str]]) -> list[tuple[str, str, str, str]]:
    """First occurrence (by lowercase name) wins."""
    seen: set[str] = set()
    out: list[tuple[str, str, str, str]] = []
    for cat, name, slug, note in rows:
        key = name.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        out.append((cat, name, slug, note))
    return out


def describe(category: str, note: str) -> str:
    ctx = f" — {note}" if note else ""
    return (f"{category}{ctx}. OSINT tool from the OSINT Newsletter tools library "
            f"({SOURCE}).")


def main() -> int:
    ap = argparse.ArgumentParser(description="Import OSINT Newsletter tools into XORCISM.TOOL")
    ap.add_argument("--dry-run", action="store_true", help="print, do not write")
    ap.add_argument("--tenant", type=int, default=DEFAULT_TENANT, help="target TenantID (default 3)")
    args = ap.parse_args()

    catalog = dedup(CATALOG)
    log(f"{len(CATALOG)} entries, {len(catalog)} unique tools after de-duplication.")

    if not os.path.exists(DB_PATH):
        log(f"XORCISM.db introuvable: {DB_PATH}")
        return 1

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=15000")
    try:
        cols = {r[1] for r in conn.execute('PRAGMA table_info("TOOL")').fetchall()}
        if not cols:
            log("Table TOOL absente.")
            return 1
        has_tenant = "TenantID" in cols

        # Existing names/urls (case-insensitive) to keep the import idempotent.
        existing_names = {
            (r[0] or "").strip().lower()
            for r in conn.execute('SELECT ToolName FROM "TOOL"').fetchall()
        }
        existing_urls = {
            (r[0] or "").strip().lower()
            for r in conn.execute('SELECT ToolURL FROM "TOOL"').fetchall()
        }

        next_id = (conn.execute('SELECT COALESCE(MAX(ToolID),0)+1 FROM "TOOL"').fetchone()[0])
        ts = now()
        inserted = 0
        skipped = 0
        to_insert = []
        for cat, name, slug, note in catalog:
            url = f"{BASE}{slug}"
            if name.strip().lower() in existing_names or url.strip().lower() in existing_urls:
                skipped += 1
                continue
            to_insert.append((next_id, str(uuid.uuid4()), name, describe(cat, note),
                              ts, ts, cat, url, args.tenant))
            existing_names.add(name.strip().lower())
            existing_urls.add(url.strip().lower())
            next_id += 1
            inserted += 1

        log(f"À insérer: {inserted}  |  déjà présents (ignorés): {skipped}")
        if args.dry_run:
            for row in to_insert[:10]:
                log(f"  + [{row[6]}] {row[2]}  →  {row[7]}")
            if len(to_insert) > 10:
                log(f"  … (+{len(to_insert) - 10} de plus)")
            log("DRY-RUN: aucune écriture.")
            return 0

        if to_insert:
            sql = (
                'INSERT INTO "TOOL" '
                "(ToolID, ToolGUID, ToolName, ToolDescription, CreatedDate, ValidFromDate, "
                "Category, ToolURL" + (", TenantID" if has_tenant else "") + ") "
                "VALUES (?,?,?,?,?,?,?,?" + (",?" if has_tenant else "") + ")"
            )
            payload = to_insert if has_tenant else [r[:8] for r in to_insert]
            with conn:
                conn.executemany(sql, payload)
        log(f"OK — {inserted} TOOL insérés (tenant {args.tenant}), {skipped} ignorés.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
