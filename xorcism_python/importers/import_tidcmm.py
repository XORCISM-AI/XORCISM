"""import_tidcmm.py - auto-populate a TID-CMM assessment in XORCISM (XCOMPLIANCE), and/or refresh the
canonical TID-CMM model from tid-cmm.com.

TID-CMM (Threat-Informed Detection Capability Maturity Model, tid-cmm.com, author Reza Adineh, v1.5.0,
CC BY 4.0) is the DETECTION companion to TIR-CMM: whether detection is driven by adversary behaviour,
whether the telemetry exists to see it, and whether it has been proven to work. Eight weighted domains
(TI/TM/DC/DE/AV/AA/IR/GV) hold 58 sub-capabilities scored 0-5 (or NA = scoped out); domain score =
weighted mean of in-scope sub-caps, overall = domain-weighted mean -> band L0-L5. Assessment tiers cap
the ceiling (rapid->L3, structured/evidence uncapped). The XORCISM cockpit at /tid-cmm reads
XCOMPLIANCE.TIDCMMASSESSMENT + TIDCMMSCORE.

    python xorcism_python/importers/import_tidcmm.py --tenant 3 --tier structured --profile realistic
    python xorcism_python/importers/import_tidcmm.py --name "ACME TID 2026" --profile target --count 4
    python xorcism_python/importers/import_tidcmm.py --refresh-model     # re-pull the model from tid-cmm.com

Profiles: baseline (mostly L2), target (one below L-target), leading (at target), realistic. Deterministic
+ idempotent by (Name, TenantID). Stdlib only. DB dir = --db-dir or $XORCISM_DB_DIR or the default.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "tid_cmm_model.json")
MODEL_URL = "https://tid-cmm.com/api/model.json"
TS_OUT = os.path.normpath(os.path.join(HERE, "..", "..", "xorcism_ts", "server", "data", "tidCmmModel.ts"))
PROFILES = ("baseline", "target", "leading", "realistic")
TIER_CEILING = {"rapid": 3, "structured": 6, "evidence": 6}


def _db(name: str, db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _ensure_tables(cur: sqlite3.Cursor) -> None:
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS TIDCMMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, Assessor TEXT, Tier TEXT, TargetLevel INTEGER DEFAULT 3, Status TEXT,
      Score REAL, Band TEXT, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS TIDCMMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, SubCapId TEXT, Domain TEXT,
      Level REAL, NA INTEGER DEFAULT 0, Notes TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_tidcmm_tenant ON TIDCMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_tidcmmscore_assess ON TIDCMMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_tidcmmscore ON TIDCMMSCORE(AssessmentID, SubCapId);
    """)


def _next_id(cur: sqlite3.Cursor, table: str, col: str) -> int:
    return int(cur.execute(f"SELECT COALESCE(MAX({col}),0) FROM {table}").fetchone()[0] or 0) + 1


def _refresh_model() -> int:
    req = urllib.request.Request(MODEL_URL, headers={"User-Agent": "XORCISM-tidcmm-importer"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
        model = json.loads(r.read().decode("utf-8"))
    subs = sum(len(d["subcapabilities"]) for d in model["domains"])
    json.dump(model, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    header = ("/**\n * tidCmmModel.ts - canonical TID-CMM (Threat-Informed Detection Capability Maturity Model) v"
              + str(model["model"].get("version")) + "\n * model, fetched from https://tid-cmm.com/api/model.json. "
              "Author: Reza Adineh. Licence: " + str(model["model"].get("licence")) + ".\n"
              " * Refresh with import_tidcmm.py --refresh-model\n */\n")
    body = "export const TID_CMM_MODEL = " + json.dumps(model, ensure_ascii=False, indent=1) + ";\nexport type TidModel = typeof TID_CMM_MODEL;\n"
    open(TS_OUT, "w", encoding="utf-8").write(header + body)
    print(f"[tid-cmm] refreshed model v{model['model'].get('version')}: {len(model['domains'])} domains, {subs} sub-capabilities "
          f"-> {DATA} + {os.path.relpath(TS_OUT, os.path.join(HERE, '..', '..'))} (rebuild the server to pick it up)")
    return 0


def _band(model: dict, score: float) -> str:
    for b in model["scoring"]["maturity_band"]:
        if b["min"] <= score <= b["max"]:
            return "L" + str(int(b["min"]))
    return "L5"


def _jit(seed: str, sub_id: str) -> int:
    return (hashlib.md5(f"{seed}:{sub_id}".encode()).digest()[0] % 3) - 1


def _level(profile: str, target: int, sub_id: str, seed: str, demote: int) -> int:
    if profile == "baseline":
        base = 2
    elif profile == "target":
        base = target - 1
    elif profile == "leading":
        base = target
    else:
        base = (target - 1) + _jit(seed, sub_id)
    return max(0, min(5, base - demote))


def _populate(cur: sqlite3.Cursor, args, model: dict, name: str, created_iso: str, demote: int) -> tuple:
    ceil = TIER_CEILING.get(args.tier, 6)
    note = f"Auto-populated ({args.profile} profile, {args.tier} tier)"
    row = cur.execute("SELECT AssessmentID FROM TIDCMMASSESSMENT WHERE Name=? AND TenantID IS ?", (name, args.tenant)).fetchone()
    if row:
        aid = int(row[0])
        cur.execute("DELETE FROM TIDCMMSCORE WHERE AssessmentID=?", (aid,))
        cur.execute("UPDATE TIDCMMASSESSMENT SET OrgName=?, Assessor=?, Tier=?, TargetLevel=?, Notes=?, CreatedDate=?, UpdatedDate=? WHERE AssessmentID=?",
                    (args.org, args.assessor, args.tier, args.target, note, created_iso, created_iso, aid))
        action = "refreshed"
    else:
        aid = _next_id(cur, "TIDCMMASSESSMENT", "AssessmentID")
        cur.execute("INSERT INTO TIDCMMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, Assessor, Tier, "
                    "TargetLevel, Status, Score, Band, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (aid, str(uuid.uuid4()), args.tenant, name, args.org, args.assessor, args.tier, args.target,
                     "draft", 0, "L0", note, created_iso, created_iso))
        action = "created"

    sid = _next_id(cur, "TIDCMMSCORE", "ScoreID")
    scored = 0
    total = 0
    na = 0
    dom_acc: dict[str, list] = {}
    i = 0
    for d in model["domains"]:
        for s in d["subcapabilities"]:
            total += 1
            if i % 11 == 10:                      # occasionally scope out (NA)
                cur.execute("INSERT INTO TIDCMMSCORE (ScoreID, AssessmentID, SubCapId, Domain, Level, NA, Notes, UpdatedDate) "
                            "VALUES (?,?,?,?,?,?,?,?)", (sid, aid, s["id"], d["id"], None, 1, "", created_iso))
                na += 1
            else:
                lvl = _level(args.profile, args.target, s["id"], name, demote)
                cur.execute("INSERT INTO TIDCMMSCORE (ScoreID, AssessmentID, SubCapId, Domain, Level, NA, Notes, UpdatedDate) "
                            "VALUES (?,?,?,?,?,?,?,?)", (sid, aid, s["id"], d["id"], lvl, 0, "", created_iso))
                scored += 1
                dom_acc.setdefault(d["id"], []).append((min(lvl, ceil), s["weight"], d["weight"]))
            sid += 1
            i += 1

    dom_scores = []
    for did, rows in dom_acc.items():
        wsum = sum(w for _, w, _ in rows)
        dom_scores.append((sum(e * w for e, w, _ in rows) / wsum, rows[0][2]))
    if dom_scores:
        dw = sum(w for _, w in dom_scores)
        overall = round(min(ceil, sum(sc * w for sc, w in dom_scores) / dw), 1)
    else:
        overall = 0.0
    band_id = _band(model, overall)
    addressed = scored + na
    status = "completed" if addressed >= total else ("in-progress" if addressed else "draft")
    cur.execute("UPDATE TIDCMMASSESSMENT SET Score=?, Band=?, Status=?, UpdatedDate=? WHERE AssessmentID=?",
                (overall, band_id, status, created_iso, aid))
    return (action, aid, name, scored, na, total, overall, band_id, status)


def _quarter_label(dt: datetime) -> str:
    return f"{dt.year}-Q{(dt.month - 1) // 3 + 1}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-populate a TID-CMM assessment (or refresh the model) in XORCISM.")
    ap.add_argument("--refresh-model", action="store_true", help="re-fetch the canonical model from tid-cmm.com and rewrite the bundled data")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID (default 3 = demo)")
    ap.add_argument("--name", default="TID-CMM assessment (auto)", help="assessment name (idempotency key)")
    ap.add_argument("--org", default="Enterprise SOC", help="organisation name")
    ap.add_argument("--assessor", default="Head of detection", help="assessor name")
    ap.add_argument("--tier", default="structured", choices=("rapid", "structured", "evidence"), help="assessment tier (sets ceiling)")
    ap.add_argument("--target", type=int, default=3, choices=(3, 4, 5), help="target level (default 3 = threat-informed)")
    ap.add_argument("--profile", default="realistic", choices=PROFILES, help="scoring profile")
    ap.add_argument("--count", type=int, default=1, help="generate N backdated quarterly snapshots with an improving trend")
    ap.add_argument("--db-dir", default=None, help="override DB directory")
    args = ap.parse_args()

    if args.refresh_model:
        return _refresh_model()

    model = json.load(open(DATA, encoding="utf-8"))
    count = max(1, args.count)
    now = datetime.now(timezone.utc)
    con = sqlite3.connect(_db("XCOMPLIANCE", args.db_dir))
    con.execute("PRAGMA busy_timeout=20000")
    cur = con.cursor()
    _ensure_tables(cur)

    results = []
    for i in range(count):
        offset_q = count - 1 - i
        dt = now - timedelta(days=91 * offset_q)
        demote = round(offset_q / (count - 1) * 2) if count > 1 else 0
        name = args.name if count == 1 else f"{args.name} - {_quarter_label(dt)}"
        results.append(_populate(cur, args, model, name, dt.isoformat(), demote))

    con.commit()
    con.close()
    for action, aid, name, scored, na, total, overall, band, status in results:
        print(f"[tid-cmm] {action} #{aid} '{name}' (tenant {args.tenant}, {args.tier}/{args.profile}): "
              f"{scored}/{total} scored ({na} NA), overall {overall}/5 band {band}, {status}.")
    if count > 1:
        print(f"[tid-cmm] {count} quarterly snapshots - maturity trend (oldest->newest): "
              + " -> ".join(str(r[6]) for r in results) + "/5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
