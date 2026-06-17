"""
import_sigma.py — Import Sigma detection rules from the SigmaHQ main repository
(https://github.com/SigmaHQ/sigma) into XTHREAT.SIGMARULE.

Each YAML rule file under the repo's rules* directories becomes one SIGMARULE row:
  title -> SigmaRuleName, id -> SigmaRuleGUID, description -> SigmaRuleDescription,
  the raw YAML -> SigmaYaml, logsource -> LogSource, level/status/author -> their
  columns, attack.Txxxx tags -> AttackTags (comma-separated ATT&CK technique ids),
  the GitHub blob URL -> SigmaReference, the rule date -> ValidFrom.
The SPL/KQL/EQL columns are left empty (backend conversion is on-demand in the UI).

Source: by default a shallow `git clone` of the repo into a temp dir (removed after);
or point at an existing local clone with --repo. Idempotent: keyed by SigmaRuleGUID
(the rule's stable UUID) — existing rules are updated, new ones inserted. Re-runnable.

    python import_sigma.py                        # shallow-clone + import everything
    python import_sigma.py --repo /path/to/sigma  # import from an existing clone
    python import_sigma.py --limit 50 --dry-run   # parse 50 rules, write nothing
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
REPO_URL = "https://github.com/SigmaHQ/sigma.git"
BLOB_BASE = "https://github.com/SigmaHQ/sigma/blob/master/"
_ATTACK = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportSigma] {msg}", flush=True)


def clone_repo(dest: str) -> None:
    log(f"shallow-cloning {REPO_URL} …")
    subprocess.run(["git", "clone", "--depth", "1", REPO_URL, dest], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def iter_rule_files(root: str):
    """Yields (abs_path, rel_path) for *.yml under the repo's rules* directories
    (skipping deprecated / unsupported)."""
    for dirpath, _dirs, files in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        top = rel.split("/", 1)[0]
        if not top.startswith("rules"):
            continue
        for f in files:
            if f.endswith((".yml", ".yaml")):
                yield os.path.join(dirpath, f), f"{rel}/{f}"


def parse_file(text: str):
    """Returns the importable Sigma docs (those with a title) from a (possibly
    multi-document) rule file."""
    out = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return out
    for doc in docs:
        if isinstance(doc, dict) and doc.get("title"):
            out.append(doc)
    return out


def map_rule(doc: dict, rel_path: str, raw: str) -> dict:
    ls = doc.get("logsource") or {}
    logsource = ", ".join(
        f"{k}={ls[k]}" for k in ("product", "category", "service") if ls.get(k)
    ) if isinstance(ls, dict) else ""
    techs = sorted({m.group(1).upper() for tag in (doc.get("tags") or [])
                    if (m := _ATTACK.match(str(tag)))})
    date = str(doc.get("date") or "").replace("/", "-") or None
    return {
        "guid": str(doc.get("id") or "").strip() or str(uuid.uuid4()),
        "name": str(doc.get("title") or "")[:300],
        "desc": str(doc.get("description") or "")[:4000],
        "yaml": raw[:60000],
        "logsource": logsource[:300],
        "level": str(doc.get("level") or "")[:50],
        "status": str(doc.get("status") or "")[:50],
        "author": str(doc.get("author") or "")[:300],
        "reference": BLOB_BASE + rel_path,
        "attack": ",".join(techs)[:500],
        "validfrom": date,
    }


def collect(root: str, limit: int) -> list[dict]:
    rules: list[dict] = []
    for abspath, rel in iter_rule_files(root):
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        for doc in parse_file(raw):
            rules.append(map_rule(doc, rel, raw))
            if limit and len(rules) >= limit:
                return rules
    return rules


def upsert(rules: list[dict]) -> tuple[int, int]:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=15000")
    inserted = updated = 0
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS SIGMARULE (
            SigmaRuleID INTEGER PRIMARY KEY, SigmaRuleGUID TEXT, SigmaRuleName TEXT,
            SigmaRuleDescription TEXT, SigmaYaml TEXT, LogSource TEXT, Level TEXT,
            Status TEXT, Author TEXT, SigmaReference TEXT, AttackTags TEXT,
            SplQuery TEXT, KqlQuery TEXT, EqlQuery TEXT,
            CreatedDate DATE, ValidFrom DATE, ValidUntil DATE)""")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_sigmarule_guid ON SIGMARULE(SigmaRuleGUID)")
        next_id = cur.execute("SELECT COALESCE(MAX(SigmaRuleID),0)+1 FROM SIGMARULE").fetchone()[0]
        ts = now()
        seen: set[str] = set()
        with conn:
            for r in rules:
                if r["guid"] in seen:
                    continue
                seen.add(r["guid"])
                row = cur.execute("SELECT SigmaRuleID FROM SIGMARULE WHERE SigmaRuleGUID=?", (r["guid"],)).fetchone()
                if row:
                    cur.execute("""UPDATE SIGMARULE SET SigmaRuleName=?, SigmaRuleDescription=?, SigmaYaml=?,
                        LogSource=?, Level=?, Status=?, Author=?, SigmaReference=?, AttackTags=?, ValidFrom=?
                        WHERE SigmaRuleID=?""",
                        (r["name"], r["desc"], r["yaml"], r["logsource"], r["level"], r["status"],
                         r["author"], r["reference"], r["attack"], r["validfrom"], row[0]))
                    updated += 1
                else:
                    cur.execute("""INSERT INTO SIGMARULE
                        (SigmaRuleID, SigmaRuleGUID, SigmaRuleName, SigmaRuleDescription, SigmaYaml,
                         LogSource, Level, Status, Author, SigmaReference, AttackTags, CreatedDate, ValidFrom)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (next_id, r["guid"], r["name"], r["desc"], r["yaml"], r["logsource"], r["level"],
                         r["status"], r["author"], r["reference"], r["attack"], ts, r["validfrom"]))
                    next_id += 1
                    inserted += 1
    finally:
        conn.close()
    return inserted, updated


def main() -> int:
    ap = argparse.ArgumentParser(description="Import SigmaHQ rules into XTHREAT.SIGMARULE")
    ap.add_argument("--repo", help="Path to an existing SigmaHQ/sigma clone (else a shallow clone is made)")
    ap.add_argument("--limit", type=int, default=0, help="Cap the number of rules (0 = all)")
    ap.add_argument("--dry-run", action="store_true", help="Parse only; write nothing")
    args = ap.parse_args()

    tmp = None
    try:
        if args.repo:
            root = args.repo
            if not os.path.isdir(root):
                log(f"repo path not found: {root}")
                return 1
        else:
            tmp = tempfile.mkdtemp(prefix="sigma_")
            try:
                clone_repo(tmp)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                log(f"git clone failed ({e}); pass --repo <path> to an existing clone instead.")
                return 1
            root = tmp

        log("parsing rules …")
        rules = collect(root, args.limit)
        log(f"{len(rules)} Sigma rule(s) parsed.")
        if args.dry_run:
            for r in rules[:10]:
                log(f"  · {r['name']}  [{r['level'] or '-'}/{r['status'] or '-'}]  {r['attack'] or ''}")
            log("DRY-RUN: nothing written.")
            return 0
        if not os.path.exists(DB_PATH):
            log(f"XTHREAT.db not found: {DB_PATH}")
            return 1
        ins, upd = upsert(rules)
        log(f"OK — {ins} inserted, {upd} updated in SIGMARULE.")
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
