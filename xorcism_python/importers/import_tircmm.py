"""import_tircmm.py - auto-populate a TIR-CMM assessment in XORCISM (XCOMPLIANCE), and/or refresh the
canonical TIR-CMM model from tir-cmm.com.

TIR-CMM (Threat-Informed Response Capability Maturity Model, tir-cmm.com, author Reza Adineh, model
CC BY-ND 4.0 / schemas CC BY 4.0) scores whether an organisation can contain a detected attack inside
the adversary's breakout window - and prove it. Eight weighted domains hold 58 sub-capabilities scored
0-5; every score is CAPPED by an evidence grade (VC0->1, VC1->2, VC2->4, VC3->5) and the assessment
tier (pulse->L3, baseline->L4, assurance->uncapped) sets the ceiling. The XORCISM cockpit at /tir-cmm
reads XCOMPLIANCE.TIRCMMASSESSMENT + TIRCMMSCORE.

This creates (or refreshes, in place) a fully-scored assessment so the cockpit populates immediately -
the Python equivalent of the built-in demo seed, runnable against any DB / tenant / tier / profile. The
model structure is read from data/tir_cmm_model.json (a snapshot of tir-cmm.com/data/tir-cmm-model.json).

    python xorcism_python/importers/import_tircmm.py
    python xorcism_python/importers/import_tircmm.py --tenant 3 --tier baseline --profile realistic
    python xorcism_python/importers/import_tircmm.py --name "ACME TIR 2026" --profile target --count 4
    python xorcism_python/importers/import_tircmm.py --refresh-model     # re-pull the model from tir-cmm.com

Profiles: baseline (mostly L2), target (one below L-target), leading (at target), realistic
(deterministic spread). Evidence grade is auto-set to the smallest grade whose cap allows the level, so
scores are meaningful (not evidence-crushed). Deterministic + idempotent by (Name, TenantID). Stdlib
only. DB dir = --db-dir or $XORCISM_DB_DIR or the default XORCISM_databases path.
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
DATA = os.path.join(HERE, "data", "tir_cmm_model.json")
MODEL_URL = "https://tir-cmm.com/data/tir-cmm-model.json"
TS_OUT = os.path.normpath(os.path.join(HERE, "..", "..", "xorcism_ts", "server", "data", "tirCmmModel.ts"))
PROFILES = ("baseline", "target", "leading", "realistic")
# level -> smallest evidence grade whose cap (VC0=1,VC1=2,VC2=4,VC3=5) allows it
EV_FOR_LEVEL = {0: "VC0", 1: "VC0", 2: "VC1", 3: "VC2", 4: "VC2", 5: "VC3"}


def _db(name: str, db_dir: str | None) -> str:
    d = db_dir or os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, f"{name}.db")


def _ensure_tables(cur: sqlite3.Cursor) -> None:
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS TIRCMMASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, OrgName TEXT, Assessor TEXT, Tier TEXT, TargetLevel INTEGER DEFAULT 3, Status TEXT,
      Score REAL, Band TEXT, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS TIRCMMSCORE(
      ScoreID INTEGER PRIMARY KEY, AssessmentID INTEGER, SubCapId TEXT, Domain TEXT,
      Level REAL, Evidence TEXT, Notes TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_tircmm_tenant ON TIRCMMASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_tircmmscore_assess ON TIRCMMSCORE(AssessmentID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_tircmmscore ON TIRCMMSCORE(AssessmentID, SubCapId);
    """)


def _next_id(cur: sqlite3.Cursor, table: str, col: str) -> int:
    return int(cur.execute(f"SELECT COALESCE(MAX({col}),0) FROM {table}").fetchone()[0] or 0) + 1


def _refresh_model() -> int:
    req = urllib.request.Request(MODEL_URL, headers={"User-Agent": "XORCISM-tircmm-importer"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (https, our constant)
        model = json.loads(r.read().decode("utf-8"))
    subs = sum(len(d["sub_capabilities"]) for d in model["domains"])
    json.dump(model, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    header = ("/**\n * tirCmmModel.ts - canonical TIR-CMM (Threat-Informed Response Capability Maturity Model) v"
              + str(model.get("version")) + "\n * model, fetched from https://tir-cmm.com/data/tir-cmm-model.json. Author: Reza Adineh.\n"
              " * Model (c) CC BY-ND 4.0; schemas CC BY 4.0. Refresh with import_tircmm.py --refresh-model\n */\n")
    body = "export const TIR_CMM_MODEL = " + json.dumps(model, ensure_ascii=False, indent=1) + ";\nexport type TirModel = typeof TIR_CMM_MODEL;\n"
    open(TS_OUT, "w", encoding="utf-8").write(header + body)
    print(f"[tir-cmm] refreshed model v{model.get('version')}: {len(model['domains'])} domains, {subs} sub-capabilities "
          f"-> {DATA} + {os.path.relpath(TS_OUT, os.path.join(HERE, '..', '..'))} (rebuild the server to pick it up)")
    return 0


def _ev_cap(model: dict) -> dict:
    return {e["vc"]: e["cap"] for e in model["evidence"]}


def _tier_ceiling(model: dict, tier: str) -> int:
    t = next((x for x in model["assessment_tiers"] if x["id"] == tier), None)
    if t and t.get("ceiling"):
        digits = "".join(ch for ch in str(t["ceiling"]) if ch.isdigit())
        return int(digits) if digits else 6
    return 6


def _band(model: dict, score: float) -> tuple[str, str]:
    for b in model["bands"]:
        if b["min"] <= score <= b["max"]:
            return b["id"], b["name"]
    last = model["bands"][-1]
    return last["id"], last["name"]


def _jit(seed: str, sub_id: str) -> int:
    return (hashlib.md5(f"{seed}:{sub_id}".encode()).digest()[0] % 3) - 1


def _level(profile: str, target: int, sub_id: str, seed: str, demote: int) -> int:
    if profile == "baseline":
        base = 2
    elif profile == "target":
        base = target - 1
    elif profile == "leading":
        base = target
    else:  # realistic
        base = (target - 1) + _jit(seed, sub_id)
    return max(0, min(5, base - demote))


def _populate(cur: sqlite3.Cursor, args, model: dict, name: str, created_iso: str, demote: int) -> tuple:
    ceil = _tier_ceiling(model, args.tier)
    caps = _ev_cap(model)
    note = f"Auto-populated ({args.profile} profile, {args.tier} tier)"
    row = cur.execute("SELECT AssessmentID FROM TIRCMMASSESSMENT WHERE Name=? AND TenantID IS ?", (name, args.tenant)).fetchone()
    if row:
        aid = int(row[0])
        cur.execute("DELETE FROM TIRCMMSCORE WHERE AssessmentID=?", (aid,))
        cur.execute("UPDATE TIRCMMASSESSMENT SET OrgName=?, Assessor=?, Tier=?, TargetLevel=?, Notes=?, CreatedDate=?, UpdatedDate=? WHERE AssessmentID=?",
                    (args.org, args.assessor, args.tier, args.target, note, created_iso, created_iso, aid))
        action = "refreshed"
    else:
        aid = _next_id(cur, "TIRCMMASSESSMENT", "AssessmentID")
        cur.execute("INSERT INTO TIRCMMASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, OrgName, Assessor, Tier, "
                    "TargetLevel, Status, Score, Band, Notes, CreatedDate, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (aid, str(uuid.uuid4()), args.tenant, name, args.org, args.assessor, args.tier, args.target,
                     "draft", 0, "L0", note, created_iso, created_iso))
        action = "created"

    sid = _next_id(cur, "TIRCMMSCORE", "ScoreID")
    scored = 0
    total = 0
    dom_acc: dict[str, list] = {}
    for d in model["domains"]:
        for s in d["sub_capabilities"]:
            total += 1
            lvl = _level(args.profile, args.target, s["id"], name, demote)
            ev = EV_FOR_LEVEL.get(lvl, "VC2")
            cur.execute("INSERT INTO TIRCMMSCORE (ScoreID, AssessmentID, SubCapId, Domain, Level, Evidence, Notes, UpdatedDate) "
                        "VALUES (?,?,?,?,?,?,?,?)", (sid, aid, s["id"], d["id"], lvl, ev, "", created_iso))
            sid += 1
            scored += 1
            eff = min(lvl, caps.get(ev, 1), ceil)
            dom_acc.setdefault(d["id"], []).append((eff, s["weight"], d["weight"]))

    # weighted overall (mirrors server scoreAssessment)
    dom_scores = []
    for did, rows in dom_acc.items():
        wsum = sum(w for _, w, _ in rows)
        dom_scores.append((sum(e * w for e, w, _ in rows) / wsum, rows[0][2]))
    if dom_scores:
        dw = sum(w for _, w in dom_scores)
        overall = round(min(ceil, sum(sc * w for sc, w in dom_scores) / dw), 1)
    else:
        overall = 0.0
    band_id, _ = _band(model, overall)
    status = "completed" if scored >= total else ("in-progress" if scored else "draft")
    cur.execute("UPDATE TIRCMMASSESSMENT SET Score=?, Band=?, Status=?, UpdatedDate=? WHERE AssessmentID=?",
                (overall, band_id, status, created_iso, aid))
    return (action, aid, name, scored, total, overall, band_id, status)


def _quarter_label(dt: datetime) -> str:
    return f"{dt.year}-Q{(dt.month - 1) // 3 + 1}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-populate a TIR-CMM assessment (or refresh the model) in XORCISM.")
    ap.add_argument("--refresh-model", action="store_true", help="re-fetch the canonical model from tir-cmm.com and rewrite the bundled data")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID (default 3 = demo)")
    ap.add_argument("--name", default="TIR-CMM assessment (auto)", help="assessment name (idempotency key)")
    ap.add_argument("--org", default="Enterprise SOC", help="organisation name")
    ap.add_argument("--assessor", default="Head of IR", help="assessor name")
    ap.add_argument("--tier", default="baseline", choices=("pulse", "baseline", "assurance"), help="assessment tier (sets score ceiling)")
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
    for action, aid, name, scored, total, overall, band, status in results:
        print(f"[tir-cmm] {action} #{aid} '{name}' (tenant {args.tenant}, {args.tier}/{args.profile}): "
              f"{scored}/{total} sub-caps, overall {overall}/5 band {band}, {status}.")
    if count > 1:
        print(f"[tir-cmm] {count} quarterly snapshots - maturity trend (oldest->newest): "
              + " -> ".join(str(r[5]) for r in results) + "/5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
