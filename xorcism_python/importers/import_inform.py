"""import_inform.py - auto-populate a MITRE INFORM (Threat-Informed Defense) assessment in XORCISM.

MITRE CTID INFORM (ctid.mitre.org/inform, Apache 2.0) scores Threat-Informed Defense (TID) maturity
across three weighted dimensions - Cyber Threat Intelligence (CTI, 35%), Defensive Measures (DM, 40%)
and Test & Evaluation (TNE, 25%). Each dimension has components; a component is answered by picking an
achieved maturity level (0 = least, up to len(levels)-1 = most threat-informed). A dimension's score is
the percentage of its possible points earned; the overall TID score is the weighted sum of the three.

The XORCISM cockpit at /inform reads these tables in XCOMPLIANCE:

  INFORMASSESSMENT  -> one row per named assessment (Name, OrgName, Assessor, ...)
  INFORMSCORE       -> one row per scored component (ComponentId, Dimension, Level, Notes)

This script creates (or refreshes, in place) a fully-scored assessment so the cockpit populates
immediately - the Python equivalent of the built-in demo seed, but runnable against any DB / tenant /
profile. The INFORM structure is read from a committed snapshot at data/inform_catalogue.json
(generated from the app's server/data/informCatalogue.ts).

Idempotent: keyed by (Name, TenantID); a re-run replaces the same assessment's scores in place.

    python xorcism_python/importers/import_inform.py
    python xorcism_python/importers/import_inform.py --tenant 3 --profile realistic
    python xorcism_python/importers/import_inform.py --name "ACME TID 2026" --profile target \
        --org "Enterprise SOC" --assessor "Head of detection"
    python xorcism_python/importers/import_inform.py --profile leading --db-dir /path/to/dbs

Profiles: baseline (mostly level 1), target (one below max), leading (at max), realistic (deterministic
spread around max-1). All profiles are deterministic, so re-runs are stable. DB dir = --db-dir or
$XORCISM_DB_DIR or the default XORCISM_databases path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "inform_catalogue.json")
PROFILES = ("baseline", "target", "leading", "realistic")


def _db(name: str, db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _ensure_tables(cur: sqlite3.Cursor) -> None:
    """Mirror ensureInformTables() in server/inform.ts so a fresh DB works too."""
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS INFORMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, Assessor TEXT, Status TEXT, Score REAL, Notes TEXT,
      CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS INFORMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, ComponentId TEXT, Dimension TEXT,
      Level INTEGER, Notes TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_inform_tenant ON INFORMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_informscore_assess ON INFORMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_informscore ON INFORMSCORE(AssessmentID, ComponentId);
    """)


def _next_id(cur: sqlite3.Cursor, table: str, col: str) -> int:
    return int(cur.execute(f"SELECT COALESCE(MAX({col}),0) FROM {table}").fetchone()[0] or 0) + 1


def _jitter(seed: str, comp_id: str) -> int:
    """Deterministic value in {-1,0,+1} from a stable hash of the seed + component id."""
    h = hashlib.md5(f"{seed}:{comp_id}".encode()).digest()[0]
    return (h % 3) - 1


def _level(profile: str, max_level: int, comp_id: str, seed: str, demote: int = 0) -> int:
    """Assign an achieved level (0..max_level) for one component under the chosen profile.

    `demote` subtracts levels for older snapshots in a --count series (improving-trend ramp).
    """
    if profile == "baseline":
        base = 1
    elif profile == "target":
        base = max_level - 1
    elif profile == "leading":
        base = max_level
    else:  # realistic
        base = (max_level - 1) + _jitter(seed, comp_id)
    return max(0, min(max_level, base - demote))


def _quarter_label(dt: datetime) -> str:
    return f"{dt.year}-Q{(dt.month - 1) // 3 + 1}"


def _populate(cur: sqlite3.Cursor, args, name: str, created_iso: str, demote: int, dims: list) -> tuple:
    """Create or (idempotently) refresh one assessment + its scores. Returns a summary tuple."""
    row = cur.execute(
        "SELECT AssessmentID FROM INFORMASSESSMENT WHERE Name=? AND TenantID IS ?",
        (name, args.tenant)).fetchone()
    note = f"Auto-populated ({args.profile} profile)"
    if row:
        aid = int(row[0])
        cur.execute("DELETE FROM INFORMSCORE WHERE AssessmentID=?", (aid,))
        cur.execute("UPDATE INFORMASSESSMENT SET OrgName=?, Assessor=?, Notes=?, CreatedDate=?, UpdatedDate=? "
                    "WHERE AssessmentID=?", (args.org, args.assessor, note, created_iso, created_iso, aid))
        action = "refreshed"
    else:
        aid = _next_id(cur, "INFORMASSESSMENT", "AssessmentID")
        cur.execute(
            "INSERT INTO INFORMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, "
            "Assessor, Status, Score, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (aid, str(uuid.uuid4()), args.tenant, name, args.org, args.assessor,
             "draft", 0, note, created_iso, created_iso))
        action = "created"

    sid = _next_id(cur, "INFORMSCORE", "ScoreID")
    scored = 0
    total = 0
    weighted = 0.0
    for d in dims:
        earned = possible = 0
        for c in d["components"]:
            total += 1
            max_level = max(1, len(c["levels"]) - 1)
            lvl = _level(args.profile, max_level, c["id"], name, demote)
            cur.execute(
                "INSERT INTO INFORMSCORE (ScoreID, AssessmentID, ComponentId, Dimension, Level, Notes, UpdatedDate) "
                "VALUES (?,?,?,?,?,?,?)",
                (sid, aid, c["id"], d["code"], lvl, "", created_iso))
            sid += 1
            scored += 1
            earned += lvl
            possible += max_level
        dim_pct = (earned / possible * 100) if possible else 0.0
        weighted += dim_pct * float(d["weight"])

    overall = round(weighted, 1)
    status = "draft" if scored == 0 else ("completed" if scored >= total else "in-progress")
    cur.execute("UPDATE INFORMASSESSMENT SET Score=?, Status=?, UpdatedDate=? WHERE AssessmentID=?",
                (overall, status, created_iso, aid))
    return (action, aid, name, scored, total, overall, status)


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-populate MITRE INFORM assessment(s) in XORCISM.")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID (default 3 = demo)")
    ap.add_argument("--name", default="INFORM threat-informed defense assessment (auto)",
                    help="assessment name (idempotency key)")
    ap.add_argument("--org", default="Enterprise SOC", help="organisation name")
    ap.add_argument("--assessor", default="Detection lead", help="assessor name")
    ap.add_argument("--profile", default="realistic", choices=PROFILES, help="scoring profile")
    ap.add_argument("--count", type=int, default=1,
                    help="generate N backdated quarterly snapshots with an improving-maturity trend (default 1)")
    ap.add_argument("--db-dir", default=None, help="override DB directory")
    args = ap.parse_args()

    cat = json.load(open(DATA, encoding="utf-8"))
    dims = cat["dimensions"]

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
        results.append(_populate(cur, args, name, dt.isoformat(), demote, dims))

    con.commit()
    con.close()
    for action, aid, name, scored, total, overall, status in results:
        print(f"[inform] {action} #{aid} '{name}' (tenant {args.tenant}, {args.profile}): "
              f"{scored}/{total} components, overall TID {overall}%, {status}.")
    if count > 1:
        trend = " -> ".join(str(r[5]) for r in results)
        print(f"[inform] {count} quarterly snapshots - TID trend (oldest->newest): {trend}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
