"""
import_honeypots.py — import the awesome-honeypots catalogue into XORCISM.
Jerome Athias - XORCISM

Source: https://github.com/paralax/awesome-honeypots (README.md)

  * The honeypot / tool entries (Honeypots, Honeyd Tools, Network and Artifact Analysis,
    Data Tools, Commercial Honeypots sections) → XORCISM.TOOL with Category='Honeypot'.
  * The "Guides" section (tutorials, deployment notes, research papers) → XORCISM.DOCUMENT.

The legacy XORCISM.DOCUMENT table is extended (idempotent ALTER, never recreated — see the
project's legacy-table convention) with DocumentName / DocumentDescription / DocumentURL /
Category / Author so a guide's title and link can be stored.

Idempotent: TOOL by ToolName (case-insensitive, skips names already present), DOCUMENT by
DocumentName. Legacy non-autoincrement PKs → new rows take MAX(id)+1.

    python import_honeypots.py                 # fetch the README from GitHub
    python import_honeypots.py --file README.md  # offline: parse a saved README
    python import_honeypots.py --list          # parse + report, write nothing
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sqlite3
import sys
import urllib.request
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from xorcism_python import config
    _DB_DIR = config.DB_DIR
except Exception:
    _DB_DIR = os.environ.get("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

README_URL = "https://raw.githubusercontent.com/paralax/awesome-honeypots/master/README.md"
SOURCE = "awesome-honeypots"
TOOL_CATEGORY = "Honeypot"
GUIDE_CATEGORY = "Honeypot Guide"

# Section headers (the `## ` text, stripped) whose link entries are honeypot tools. The
# "Related Lists" links live under an anchored `## <a name=...>Honeypots` header whose stripped
# text is NOT exactly "Honeypots", so they are excluded automatically.
TOOL_SECTIONS = {"Honeypots", "Honeyd Tools", "Network and Artifact Analysis", "Data Tools",
                 "Commercial Honepots", "Commercial Honeypots"}
GUIDE_SECTIONS = {"Guides"}

_H2 = re.compile(r"^##\s+(.*?)\s*$")
_ENTRY = re.compile(r"^\s*[-*]\s+\[([^\]]+)\]\(([^)\s]+)\)\s*(?:[-–—]\s*(.*))?$")


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def parse(md: str):
    """Return (tools, guides): lists of {name, url, description}."""
    section = None
    tools, guides, seen_tool, seen_guide = [], [], set(), set()
    for line in md.splitlines():
        h = _H2.match(line)
        if h:
            section = _clean(h.group(1))
            continue
        m = _ENTRY.match(line)
        if not m:
            continue
        name, url, desc = _clean(m.group(1)), m.group(2).strip(), _clean(m.group(3) or "")
        if not name or not url:
            continue
        if section in TOOL_SECTIONS:
            k = name.lower()
            if k not in seen_tool:
                seen_tool.add(k)
                tools.append({"name": name, "url": url, "description": desc})
        elif section in GUIDE_SECTIONS:
            k = name.lower()
            if k not in seen_guide:
                seen_guide.add(k)
                guides.append({"name": name, "url": url, "description": desc})
    return tools, guides


def _ensure_document_cols(cur):
    have = {r[1] for r in cur.execute('PRAGMA table_info("DOCUMENT")')}
    for col, typ in (("DocumentName", "TEXT"), ("DocumentDescription", "TEXT"),
                     ("DocumentURL", "TEXT"), ("Category", "TEXT"), ("Author", "TEXT")):
        if col not in have:
            cur.execute(f'ALTER TABLE "DOCUMENT" ADD COLUMN "{col}" {typ}')


def import_all(md: str, list_only: bool = False) -> None:
    tools, guides = parse(md)
    print(f"[parse] {len(tools)} tool(s), {len(guides)} guide(s) from {SOURCE}")
    if list_only:
        for t in tools[:10]:
            print(f"   TOOL  {t['name']} — {t['url']}")
        print("   ...")
        for g in guides:
            print(f"   GUIDE {g['name']} — {g['url']}")
        return

    con = sqlite3.connect(os.path.join(_DB_DIR, "XORCISM.db"), timeout=20)
    con.execute("PRAGMA busy_timeout=20000")
    cur = con.cursor()

    # ── TOOL (Category=Honeypot), idempotent by ToolName (case-insensitive) ──
    existing = {str(r[0]).lower() for r in cur.execute("SELECT ToolName FROM TOOL WHERE ToolName IS NOT NULL")}
    tid = cur.execute("SELECT COALESCE(MAX(ToolID),0) FROM TOOL").fetchone()[0]
    n_tool = n_tool_skip = 0
    for t in tools:
        if t["name"].lower() in existing:
            n_tool_skip += 1
            continue
        tid += 1
        cur.execute(
            "INSERT INTO TOOL (ToolID, ToolGUID, ToolName, ToolDescription, Category, ToolURL, "
            "CreatedDate, ValidFromDate, VocabularyID, isEncrypted) VALUES (?,?,?,?,?,?,?,?,1,0)",
            (tid, str(uuid.uuid4()), t["name"][:200], t["description"][:2000] or None,
             TOOL_CATEGORY, t["url"][:500], _now(), _now()),
        )
        existing.add(t["name"].lower())
        n_tool += 1

    # ── DOCUMENT (Guides), idempotent by DocumentName ──
    _ensure_document_cols(cur)
    have_docs = {str(r[0]).lower() for r in cur.execute("SELECT DocumentName FROM DOCUMENT WHERE DocumentName IS NOT NULL")}
    did = cur.execute("SELECT COALESCE(MAX(DocumentID),0) FROM DOCUMENT").fetchone()[0]
    n_doc = n_doc_skip = 0
    for g in guides:
        if g["name"].lower() in have_docs:
            n_doc_skip += 1
            continue
        did += 1
        cur.execute(
            "INSERT INTO DOCUMENT (DocumentID, DocumentGUID, DocumentName, DocumentDescription, "
            "DocumentURL, Category, Author, CreatedDate, ValidFromDate, isEncrypted) "
            "VALUES (?,?,?,?,?,?,?,?,?,0)",
            (did, str(uuid.uuid4()), g["name"][:300], g["description"][:2000] or None,
             g["url"][:500], GUIDE_CATEGORY, SOURCE, _now(), _now()),
        )
        have_docs.add(g["name"].lower())
        n_doc += 1

    con.commit()
    con.close()
    print(f"[TOOL]     {n_tool} new (Category='{TOOL_CATEGORY}'), {n_tool_skip} already present")
    print(f"[DOCUMENT] {n_doc} new (Category='{GUIDE_CATEGORY}'), {n_doc_skip} already present")


def main() -> None:
    ap = argparse.ArgumentParser(description="Import awesome-honeypots tools → TOOL, guides → DOCUMENT")
    ap.add_argument("--file", help="parse a saved README.md instead of fetching from GitHub")
    ap.add_argument("--list", action="store_true", help="parse + report, write nothing")
    a = ap.parse_args()
    if a.file:
        md = open(a.file, encoding="utf-8", errors="replace").read()
    else:
        req = urllib.request.Request(README_URL, headers={"User-Agent": "XORCISM honeypot importer"})
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (fixed https source)
            md = r.read().decode("utf-8", "replace")
    import_all(md, a.list)


if __name__ == "__main__":
    main()
