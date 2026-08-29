"""import_cticmm.py - auto-populate a CTI-CMM assessment in XORCISM (XCOMPLIANCE).

CTI-CMM (Cyber Threat Intelligence Capability Maturity Model, cti-cmm.org) v1.3 is scored across 11
stakeholder-aligned domains, each broken into CTI use cases graded on the CTI0-CTI3 maturity scale
(Pre-Foundational / Foundational / Advanced / Leading). The XORCISM cockpit at /cti-cmm reads these
tables in XCOMPLIANCE:

  CTICMMASSESSMENT  -> one row per named assessment (Name, ProgramName, Assessor, TargetLevel, ...)
  CTICMMSCORE       -> one row per scored use case (UseCaseId, Domain, Level 0..3, Notes)
  CTICMMDOMAIN      -> per-assessment domain applicability (Applicable 0/1, for out-of-scope domains)

This script creates (or refreshes, in place) a fully-scored assessment so the cockpit populates
immediately - the Python equivalent of the built-in demo seed, but runnable against any DB / tenant /
profile. The CTI-CMM structure is read from a committed snapshot at data/cticmm_catalogue.json
(generated from the app's server/data/cticmmCatalogue.ts). The (c) normative practice statements are
NOT reproduced - only the domain / use-case skeleton and the maturity scores this tool assigns.

Idempotent: keyed by (Name, TenantID); a re-run replaces the same assessment's scores in place.

    python xorcism_python/importers/import_cticmm.py
    python xorcism_python/importers/import_cticmm.py --tenant 3 --profile realistic
    python xorcism_python/importers/import_cticmm.py --name "ACME CTI 2026" --profile target \
        --assessor "Head of CTI" --program "Global Threat Intel" --na-domains FRAUD
    python xorcism_python/importers/import_cticmm.py --profile leading --db-dir /path/to/dbs

Profiles: baseline (mostly Foundational), target (one below each use case's target), leading (at
target), realistic (deterministic spread around target-1). All profiles are deterministic, so re-runs
are stable. DB dir = --db-dir or $XORCISM_DB_DIR or the default XORCISM_databases path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cticmm_catalogue.json")
PROFILES = ("baseline", "target", "leading", "realistic")


def _db(name: str, db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _ensure_tables(cur: sqlite3.Cursor) -> None:
    """Mirror ensureCtiCmmTables() in server/cticmm.ts so a fresh DB works too."""
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS CTICMMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, ProgramName TEXT, Assessor TEXT, TargetLevel INTEGER DEFAULT 2, Status TEXT,
      Score REAL, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CTICMMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, UseCaseId TEXT, Domain TEXT,
      Level REAL, Notes TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CTICMMDOMAIN(
      RowID INTEGER PRIMARY KEY, AssessmentID INTEGER, DomainCode TEXT, Applicable INTEGER DEFAULT 1);
    CREATE INDEX IF NOT EXISTS ix_cticmm_tenant ON CTICMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_cticmmscore_assess ON CTICMMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_cticmmscore ON CTICMMSCORE(AssessmentID, UseCaseId);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_cticmmdomain ON CTICMMDOMAIN(AssessmentID, DomainCode);
    """)


def _next_id(cur: sqlite3.Cursor, table: str, col: str) -> int:
    return int(cur.execute(f"SELECT COALESCE(MAX({col}),0) FROM {table}").fetchone()[0] or 0) + 1


def _jitter(seed: str, uc_id: str) -> int:
    """Deterministic value in {-1,0,+1} from a stable hash of the seed + use-case id."""
    h = hashlib.md5(f"{seed}:{uc_id}".encode()).digest()[0]
    return (h % 3) - 1


def _level(profile: str, uc: dict, target: int, seed: str, demote: int = 0) -> int:
    """Assign a CTI0..3 level for one use case under the chosen profile.

    `demote` subtracts levels for older snapshots in a --count series (improving-trend ramp).
    """
    tgt = int(uc.get("targetLevel") or target)
    if profile == "baseline":
        base = 1
    elif profile == "target":
        base = tgt - 1
    elif profile == "leading":
        base = tgt
    else:  # realistic
        base = (tgt - 1) + _jitter(seed, uc["id"])
    return max(0, min(3, base - demote))


def _quarter_label(dt: datetime) -> str:
    return f"{dt.year}-Q{(dt.month - 1) // 3 + 1}"


def _populate(cur: sqlite3.Cursor, args, name: str, created_iso: str, demote: int,
              domains: list, na: set) -> tuple:
    """Create or (idempotently) refresh one assessment + its scores. Returns a summary tuple."""
    row = cur.execute(
        "SELECT AssessmentID FROM CTICMMASSESSMENT WHERE Name=? AND TenantID IS ?",
        (name, args.tenant)).fetchone()
    note = f"Auto-populated ({args.profile} profile)"
    if row:
        aid = int(row[0])
        cur.execute("DELETE FROM CTICMMSCORE WHERE AssessmentID=?", (aid,))
        cur.execute("DELETE FROM CTICMMDOMAIN WHERE AssessmentID=?", (aid,))
        cur.execute("UPDATE CTICMMASSESSMENT SET ProgramName=?, Assessor=?, TargetLevel=?, Notes=?, "
                    "CreatedDate=?, UpdatedDate=? WHERE AssessmentID=?",
                    (args.program, args.assessor, args.target, note, created_iso, created_iso, aid))
        action = "refreshed"
    else:
        aid = _next_id(cur, "CTICMMASSESSMENT", "AssessmentID")
        cur.execute(
            "INSERT INTO CTICMMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, ProgramName, "
            "Assessor, TargetLevel, Status, Score, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, str(uuid.uuid4()), args.tenant, name, args.program, args.assessor, args.target,
             "draft", 0, note, created_iso, created_iso))
        action = "created"

    rid = _next_id(cur, "CTICMMDOMAIN", "RowID")
    for code in sorted(na):
        cur.execute("INSERT INTO CTICMMDOMAIN (RowID, AssessmentID, DomainCode, Applicable) VALUES (?,?,?,?)",
                    (rid, aid, code, 0))
        rid += 1

    sid = _next_id(cur, "CTICMMSCORE", "ScoreID")
    scored = 0
    total_in_scope = 0
    dom_levels: dict[str, list[int]] = {}
    for d in domains:
        if d["code"] in na:
            continue
        for uc in d["useCases"]:
            total_in_scope += 1
            lvl = _level(args.profile, uc, args.target, name, demote)
            cur.execute(
                "INSERT INTO CTICMMSCORE (ScoreID, AssessmentID, UseCaseId, Domain, Level, Notes, UpdatedDate) "
                "VALUES (?,?,?,?,?,?,?)",
                (sid, aid, uc["id"], d["code"], lvl, "", created_iso))
            sid += 1
            scored += 1
            dom_levels.setdefault(d["code"], []).append(lvl)

    dom_mat = [sum(v) / len(v) for v in dom_levels.values() if v]
    overall = round(sum(dom_mat) / len(dom_mat), 1) if dom_mat else 0.0
    status = "draft" if scored == 0 else ("completed" if scored >= total_in_scope else "in-progress")
    cur.execute("UPDATE CTICMMASSESSMENT SET Score=?, Status=?, UpdatedDate=? WHERE AssessmentID=?",
                (overall, status, created_iso, aid))
    return (action, aid, name, scored, total_in_scope, overall, status)


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-populate CTI-CMM assessment(s) in XORCISM.")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID (default 3 = demo)")
    ap.add_argument("--name", default="CTI-CMM assessment (auto)", help="assessment name (idempotency key)")
    ap.add_argument("--program", default="Cyber Threat Intelligence program", help="CTI program name")
    ap.add_argument("--assessor", default="CTI lead", help="assessor name")
    ap.add_argument("--target", type=int, default=2, choices=(1, 2, 3), help="assessment target level (1..3)")
    ap.add_argument("--profile", default="realistic", choices=PROFILES, help="scoring profile")
    ap.add_argument("--na-domains", default="", help="comma-separated domain codes to mark out of scope (e.g. FRAUD)")
    ap.add_argument("--count", type=int, default=1,
                    help="generate N backdated quarterly snapshots with an improving-maturity trend (default 1)")
    ap.add_argument("--db-dir", default=None, help="override DB directory")
    args = ap.parse_args()

    cat = json.load(open(DATA, encoding="utf-8"))
    domains = cat["domains"]
    na = {d.strip().upper() for d in args.na_domains.split(",") if d.strip()}
    valid_codes = {d["code"] for d in domains}
    unknown = na - valid_codes
    if unknown:
        print(f"[cticmm] warning: unknown --na-domains ignored: {', '.join(sorted(unknown))}")
        na &= valid_codes

    count = max(1, args.count)
    now = datetime.now(timezone.utc)
    con = sqlite3.connect(_db("XCOMPLIANCE", args.db_dir))
    con.execute("PRAGMA busy_timeout=20000")
    cur = con.cursor()
    _ensure_tables(cur)

    results = []
    for i in range(count):
        offset_q = count - 1 - i                       # 0 = newest, count-1 = oldest
        dt = now - timedelta(days=91 * offset_q)       # ~one quarter apart
        # improving trend: older snapshots demoted up to 2 levels, newest at full profile
        demote = round(offset_q / (count - 1) * 2) if count > 1 else 0
        name = args.name if count == 1 else f"{args.name} - {_quarter_label(dt)}"
        results.append(_populate(cur, args, name, dt.isoformat(), demote, domains, na))

    con.commit()
    con.close()
    for action, aid, name, scored, total, overall, status in results:
        print(f"[cticmm] {action} #{aid} '{name}' (tenant {args.tenant}, {args.profile}): "
              f"{scored}/{total} use cases, {len(na)} out-of-scope, overall {overall}/3, {status}.")
    if count > 1:
        trend = " -> ".join(str(r[5]) for r in results)
        print(f"[cticmm] {count} quarterly snapshots - maturity trend (oldest->newest): {trend}/3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
