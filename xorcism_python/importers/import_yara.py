"""
import_yara.py — Import YARA rules into XTHREAT.YARARULE.
Jerome Athias - XORCISM

The "support" side of YARA in XORCISM: bulk-load a directory (or a single file) of
.yar/.yara rules into the YARARULE store, where they are browsable in the explorer, served
to XOR agents (GET /api/agent/yara-rules) and reused by the yara connector. The rule parser
is shared with connectors/yara/run.py (single source of truth) so the store and the
connector agree on how rules are read.

Target : XTHREAT.db, table YARARULE. The importer makes the table self-sufficient: it
creates YARARULE if missing and ALTERs in any missing column, so it runs against an existing
database whatever the server version. Idempotent by YaraReference (yara:<namespace>:<rule>):
existing rows are updated, new ones inserted (YaraRuleID auto-increments).

Usage:
    python import_yara.py /path/to/rules            # a .yar file or a directory of rules
    python import_yara.py rules/ --db-dir C:\\Users\\me\\XORCISM_databases
    # Popular free rule sets to point it at:
    #   https://github.com/Yara-Rules/rules   ·   https://github.com/Neo23x0/signature-base
"""
import argparse
import importlib.util
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid4

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..", "..")

# Reuse the connector's rule parser (so the store and the connector stay in sync).
_spec = importlib.util.spec_from_file_location(
    "yara_connector", os.path.join(_ROOT, "connectors", "yara", "run.py"))
_yc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_yc)  # type: ignore
_parse_rule_file = _yc._parse_rule_file

_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_YARA_COLUMNS = {
    "YaraRuleID": "INTEGER PRIMARY KEY", "YaraRuleGUID": "TEXT", "YaraRuleName": "TEXT",
    "YaraRuleDescription": "TEXT", "YaraSource": "TEXT", "Namespace": "TEXT", "Tags": "TEXT",
    "Meta": "TEXT", "Author": "TEXT", "YaraReference": "TEXT", "AttackTags": "TEXT",
    "StringCount": "INTEGER", "Status": "TEXT", "CreatedDate": "DATE",
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def import_yara(path, db_dir):
    items = _parse_rule_file(path)
    con = sqlite3.connect(os.path.join(db_dir, "XTHREAT.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    cols_sql = ", ".join(f"{n} {t}" for n, t in _YARA_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS YARARULE ({cols_sql})")
    have = {r[1] for r in cur.execute("PRAGMA table_info(YARARULE)").fetchall()}
    for name, typ in _YARA_COLUMNS.items():
        if name not in have:
            cur.execute(f"ALTER TABLE YARARULE ADD COLUMN {name} {typ.replace(' PRIMARY KEY', '')}")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_yararule_ref ON YARARULE(YaraReference)")

    created = updated = 0
    for it in items:
        ref = it["reference"]
        attack = ", ".join(sorted({m.upper() for m in _ATTACK_RE.findall(it.get("source") or "")}))
        common = (it.get("name"), it.get("description"), it.get("source"), it.get("namespace"),
                  it.get("tags"), it.get("meta"), (it.get("author") or "YARA import"),
                  ref, attack, it.get("string_count"), "active")
        row = cur.execute("SELECT YaraRuleID FROM YARARULE WHERE YaraReference=?", (ref,)).fetchone()
        if row:
            cur.execute(
                """UPDATE YARARULE SET YaraRuleName=?, YaraRuleDescription=?, YaraSource=?,
                     Namespace=?, Tags=?, Meta=?, Author=?, YaraReference=?, AttackTags=?,
                     StringCount=?, Status=? WHERE YaraRuleID=?""",
                (*common, row[0]),
            )
            updated += 1
        else:
            cur.execute(
                """INSERT INTO YARARULE (YaraRuleName, YaraRuleDescription, YaraSource, Namespace,
                     Tags, Meta, Author, YaraReference, AttackTags, StringCount, Status,
                     YaraRuleGUID, CreatedDate)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*common, str(uuid4()), _now()),
            )
            created += 1
    con.commit()
    con.close()
    return created, updated, len(items)


def main():
    ap = argparse.ArgumentParser(description="Import YARA rules into XTHREAT.YARARULE")
    ap.add_argument("path", help="a .yar/.yara file or a directory of rules")
    ap.add_argument("--db-dir", default=os.getenv("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases"),
                    help="directory holding XTHREAT.db (default: $XORCISM_DB_DIR)")
    a = ap.parse_args()
    if not os.path.exists(a.path):
        print(f"[yara] path not found: {a.path}", file=sys.stderr)
        sys.exit(1)
    created, updated, total = import_yara(a.path, a.db_dir)
    print(f"[yara] {total} rule(s) parsed → {created} inserted, {updated} updated in XTHREAT.YARARULE")


if __name__ == "__main__":
    main()
