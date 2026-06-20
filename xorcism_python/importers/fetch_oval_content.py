"""
fetch_oval_content.py — populate XORCISM's central OVAL content cache.
Jerome Athias - XORCISM

XORCISM cannot *regenerate* evaluatable OVAL from its imported definitions (the
import is metadata-only — OVALOBJECT/OVALSTATE/entities are empty, so oscap has
nothing to evaluate). Instead, this downloads the real, maintained, *evaluatable*
distro OVAL feeds into the content directory the server serves to agents
(GET /api/agent/oval-content). Offline agents then pull complete content from
XORCISM instead of reaching the internet themselves.

Content dir (must match the server): XORCISM_OVAL_CONTENT_DIR, else <DB_DIR>/oval-content.

    python fetch_oval_content.py --platform ubuntu-jammy
    python fetch_oval_content.py --all
    python fetch_oval_content.py --url <oval.xml[.bz2]>      # arbitrary feed
    python fetch_oval_content.py --file <local oval file>    # offline import/copy
    python fetch_oval_content.py --list                      # show the catalogue + cache

Run it on a schedule (cron) to keep the cache fresh.
"""
from __future__ import annotations

import argparse
import bz2
import gzip
import os
import shutil
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from xorcism_python import config
    _DB_DIR = config.DB_DIR
except Exception:
    _DB_DIR = os.environ.get("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

MODULE = "FetchOVAL"

# Maintained, evaluatable distro OVAL feeds. name = served file (matched by platform token).
CATALOGUE = {
    # Ubuntu (Canonical) — CVE OVAL, bz2
    "ubuntu-focal":  "https://security-metadata.canonical.com/oval/com.ubuntu.focal.cve.oval.xml.bz2",
    "ubuntu-jammy":  "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.cve.oval.xml.bz2",
    "ubuntu-noble":  "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2",
    # Debian — plain xml
    "debian-bullseye": "https://www.debian.org/security/oval/oval-definitions-bullseye.xml",
    "debian-bookworm": "https://www.debian.org/security/oval/oval-definitions-bookworm.xml",
    # Red Hat (RHEL) — bz2
    "rhel-8": "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2",
    "rhel-9": "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2",
}


def log(msg: str) -> None:
    print(f"[{MODULE}] {msg}", flush=True)


def content_dir() -> str:
    d = os.environ.get("XORCISM_OVAL_CONTENT_DIR") or os.path.join(_DB_DIR, "oval-content")
    os.makedirs(d, exist_ok=True)
    return d


def _decompress_inplace(path: str) -> str:
    """If path is .bz2/.gz, write the plain .xml next to it and remove the archive."""
    if path.endswith(".bz2"):
        plain = path[:-4]
        with bz2.open(path) as f, open(plain, "wb") as out:
            shutil.copyfileobj(f, out)
        os.remove(path)
        return plain
    if path.endswith(".gz"):
        plain = path[:-3]
        with gzip.open(path) as f, open(plain, "wb") as out:
            shutil.copyfileobj(f, out)
        os.remove(path)
        return plain
    return path


def _dest_name(url_or_name: str) -> str:
    # os.path.basename handles both URL "/" and Windows "\" separators.
    return os.path.basename(url_or_name.rstrip("/")) or "oval-content.xml"


def fetch_url(url: str, dest_dir: str) -> str:
    name = _dest_name(url)
    tmp = os.path.join(dest_dir, name)
    log(f"download {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "XORCISM-OVAL-fetch"})
    with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as out:
        shutil.copyfileobj(r, out)
    plain = _decompress_inplace(tmp)
    log(f"  -> {os.path.basename(plain)} ({os.path.getsize(plain) // 1024} KB)")
    return plain


def copy_file(path: str, dest_dir: str) -> str:
    name = _dest_name(path)
    dest = os.path.join(dest_dir, name)
    shutil.copyfile(path, dest)
    plain = _decompress_inplace(dest)
    log(f"cached {os.path.basename(plain)} ({os.path.getsize(plain) // 1024} KB)")
    return plain


def main() -> None:
    ap = argparse.ArgumentParser(description="Fetch evaluatable OVAL content into XORCISM's agent content cache")
    ap.add_argument("--platform", help="catalogue key, e.g. ubuntu-jammy / debian-bookworm / rhel-9")
    ap.add_argument("--all", action="store_true", help="fetch every catalogue feed")
    ap.add_argument("--url", help="arbitrary OVAL feed URL (.xml/.bz2/.gz)")
    ap.add_argument("--file", help="local OVAL file to copy into the cache (offline)")
    ap.add_argument("--list", action="store_true", help="show the catalogue + current cache")
    args = ap.parse_args()

    d = content_dir()
    if args.list:
        log(f"content dir: {d}")
        log("catalogue: " + ", ".join(CATALOGUE))
        cached = [f for f in sorted(os.listdir(d)) if f.lower().endswith((".xml", ".bz2", ".gz"))]
        log(f"cached ({len(cached)}): " + (", ".join(cached) or "(empty)"))
        return

    done = 0
    try:
        if args.file:
            copy_file(args.file, d); done += 1
        elif args.url:
            fetch_url(args.url, d); done += 1
        elif args.platform:
            url = CATALOGUE.get(args.platform)
            if not url:
                log(f"unknown platform '{args.platform}'. Known: {', '.join(CATALOGUE)}"); sys.exit(2)
            fetch_url(url, d); done += 1
        elif args.all:
            for k, url in CATALOGUE.items():
                try:
                    fetch_url(url, d); done += 1
                except Exception as e:  # noqa: BLE001
                    log(f"  {k} failed: {e}")
        else:
            ap.print_help(); sys.exit(1)
    except Exception as e:  # noqa: BLE001
        log(f"error: {e}"); sys.exit(1)
    log(f"done — {done} feed(s) cached in {d}; agents fetch via GET /api/agent/oval-content")


if __name__ == "__main__":
    main()
