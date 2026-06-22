"""
seed_security_awareness.py — seed a KnowBe4-style Security Awareness program for the demo tenant:
a training catalogue (XORCISM.TRAINING), per-person enrollment + completion
(XORCISM.TRAININGFORPERSON), phishing-simulation campaigns (XORCISM.PHISHINGSIMULATION) and their
per-recipient outcomes (XORCISM.PHISHINGRESULT: sent/opened/clicked/submitted/reported).

Drives the /security-awareness cockpit: training-completion rate, Phish-Prone %, repeat clickers,
per-user human-risk score and the remediation worklist.

Idempotent: trainings keyed on (TrainingName, TenantID); campaigns on (Name, TenantID). Enrollments
and results for a seeded training/campaign are deleted and re-inserted on re-run rather than
duplicated. Self-contained schema-ensure mirrors db.ts ensureAwarenessTables.

    python seed_security_awareness.py                # tenant 3 (default)
    python seed_security_awareness.py --tenant 3
    python seed_security_awareness.py --list         # show what would be written
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sqlite3
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from xorcism_python import config
    _DB_DIR = config.DB_DIR
except Exception:
    _DB_DIR = os.environ.get("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

SOURCE = "SeedSecurityAwareness"

# ── training catalogue (KnowBe4-style) ────────────────────────────────────────
# (name, category, provider, minutes, required, description)
TRAININGS = [
    ("Security Awareness Fundamentals", "Foundational", "XORCISM Academy", 30, True,
     "The baseline new-hire course: the threat landscape, your role in defense, acceptable use, clean desk and how to report something suspicious."),
    ("Phishing & Social Engineering Defense", "Phishing", "XORCISM Academy", 20, True,
     "Recognize phishing, spear-phishing, smishing and vishing; spot lookalike domains and urgency/authority pressure; report with one click."),
    ("Password Security & Passkeys", "Passwords", "XORCISM Academy", 15, True,
     "Strong unique passwords, password managers, MFA and the move to phishing-resistant passkeys (WebAuthn/FIDO2)."),
    ("Data Protection & GDPR Essentials", "Data Protection", "XORCISM Academy", 25, True,
     "Handling personal and confidential data, classification labels, lawful basis, data-subject rights and breach reporting duties."),
    ("Incident Reporting: Spot & Report", "Incident Response", "XORCISM Academy", 15, True,
     "What an incident looks like, when and how to report, preserving evidence, and why fast reporting beats a perfect report."),
    ("Safe Remote Work & Mobile Security", "Remote Work", "XORCISM Academy", 20, False,
     "Securing home networks and mobile devices, public Wi-Fi and VPN, BYOD hygiene and physical security on the road."),
    ("AI & Deepfake Threat Awareness", "Emerging Threats", "XORCISM Academy", 20, False,
     "AI-assisted phishing, voice/video deepfakes and CEO-fraud, prompt-injection basics and verifying out-of-band before you act."),
]
REQUIRED_NAMES = [t[0] for t in TRAININGS if t[4]]

# ── phishing-simulation campaigns ─────────────────────────────────────────────
# (name, theme, difficulty, days_ago, description)
CAMPAIGNS = [
    ("Q1 Password Reset Lure", "IT — forced password reset", "Medium", 84,
     "Spoofed IT helpdesk email warning the account will be locked unless the password is reset via the (fake) portal."),
    ("Invoice Payment Update", "Finance / BEC — vendor bank-detail change", "Hard", 49,
     "A look-alike-domain email from a 'supplier' asking to update bank details for an outstanding invoice."),
    ("HR Benefits Enrollment", "HR — open-enrollment deadline", "Easy", 21,
     "An HR-themed email pushing staff to log in to a benefits portal before a fake deadline."),
]

# per-campaign outcomes by PersonID: 'c'=clicked, 's'=clicked+submitted credentials, 'r'=reported.
# Everyone in the org is a recipient (opened); unlisted = opened, no action.
OUTCOMES = {
    "Q1 Password Reset Lure": {6: "c", 7: "s", 4: "r", 5: "r", 9: "r", 8: "r"},
    "Invoice Payment Update": {6: "c", 8: "c", 3: "r", 4: "r", 5: "r", 2: "r"},
    "HR Benefits Enrollment": {10: "c", 11: "c", 4: "r", 5: "r", 9: "r", 6: "r"},
}

# enrollment completion plan: PersonID -> set of training names NOT completed (still in progress).
# A PersonID absent from ENROLL_SKIP completes all required courses; PersonID in NEVER_TRAINED gets
# no enrollment at all (drives the "never trained" worklist item).
INCOMPLETE = {
    6: {"Password Security & Passkeys", "Data Protection & GDPR Essentials", "Incident Reporting: Spot & Report"},
    7: {"Data Protection & GDPR Essentials", "Incident Reporting: Spot & Report"},
    10: {"Incident Reporting: Spot & Report"},
}
NEVER_TRAINED = {11}
# a few people also take the optional courses (all completed)
OPTIONAL_TAKERS = {
    "Safe Remote Work & Mobile Security": {2, 3, 10, 11},
    "AI & Deepfake Threat Awareness": {2, 4, 5, 8},
}


def _ensure_schema(cur):
    cur.executescript("""
      CREATE TABLE IF NOT EXISTS PHISHINGSIMULATION (
        PhishingSimulationID INTEGER PRIMARY KEY, PhishingSimulationGUID TEXT,
        Name TEXT, Theme TEXT, Template TEXT, Difficulty TEXT, Status TEXT, Description TEXT,
        LandingPageURL TEXT, SentDate TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS PHISHINGRESULT (
        PhishingResultID INTEGER PRIMARY KEY, PhishingSimulationID INTEGER, PersonID INTEGER,
        Sent INTEGER DEFAULT 1, Opened INTEGER DEFAULT 0, Clicked INTEGER DEFAULT 0,
        SubmittedData INTEGER DEFAULT 0, ReportedPhish INTEGER DEFAULT 0,
        DateSent TEXT, DateClicked TEXT, DateReported TEXT, TenantID INTEGER, CreatedDate TEXT);
      CREATE INDEX IF NOT EXISTS ix_phishresult_sim ON PHISHINGRESULT(PhishingSimulationID);
      CREATE INDEX IF NOT EXISTS ix_phishresult_person ON PHISHINGRESULT(PersonID);
      CREATE INDEX IF NOT EXISTS ix_phishsim_tenant ON PHISHINGSIMULATION(TenantID);""")

    def addcols(table, cols):
        if not cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            return
        have = {r[1] for r in cur.execute(f'PRAGMA table_info("{table}")').fetchall()}
        for n, t in cols.items():
            if n not in have:
                cur.execute(f'ALTER TABLE "{table}" ADD COLUMN "{n}" {t}')

    addcols("TRAINING", {"Category": "TEXT", "DurationMinutes": "INTEGER", "Provider": "TEXT",
                         "ContentURL": "TEXT", "Required": "INTEGER DEFAULT 0", "PassingScore": "INTEGER",
                         "TenantID": "INTEGER", "CreatedDate": "TEXT"})
    addcols("TRAININGFORPERSON", {"Score": "INTEGER", "DueDate": "TEXT", "AssignedDate": "TEXT"})


def _cols(cur, table):
    return {r[1] for r in cur.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _nextid(cur, table, pk):
    return (cur.execute(f"SELECT COALESCE(MAX({pk}),0)+1 FROM {table}").fetchone()[0])


def _days_ago(n):
    return (_dt.datetime.now() - _dt.timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def seed(tenant: int, list_only: bool = False) -> None:
    if list_only:
        print("Training catalogue:")
        for name, cat, prov, mins, req, _ in TRAININGS:
            print(f"  [{'REQ' if req else 'opt'}] {name}  ({cat}, {mins} min)")
        print("\nPhishing campaigns:")
        for name, theme, diff, days, _ in CAMPAIGNS:
            print(f"  [{diff:6}] {name}  ({theme}, sent {days}d ago)")
        print(f"\n{len(TRAININGS)} trainings, {len(CAMPAIGNS)} campaigns — tenant {tenant}")
        return

    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(os.path.join(_DB_DIR, "XORCISM.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    _ensure_schema(cur)

    persons = [r[0] for r in cur.execute("SELECT PersonID FROM PERSON ORDER BY PersonID").fetchall()]
    if not persons:
        print("[%s] no PERSON rows — nothing to enroll. Seed the org chart first." % SOURCE)
        con.close()
        return

    tcols = _cols(cur, "TRAINING")
    ecols = _cols(cur, "TRAININGFORPERSON")
    n_t = n_e = n_c = n_r = 0

    # ── trainings + enrollment ────────────────────────────────────────────────
    name_to_id = {}
    for name, cat, prov, mins, req, desc in TRAININGS:
        row = cur.execute("SELECT TrainingID FROM TRAINING WHERE TrainingName=? AND IFNULL(TenantID,-1)=IFNULL(?,-1)",
                          (name, tenant)).fetchone()
        rec = {"TrainingGUID": str(uuid.uuid4()), "TrainingName": name, "TrainingDescription": desc,
               "Status": "Active", "Category": cat, "DurationMinutes": mins, "Provider": prov,
               "Required": 1 if req else 0, "PassingScore": 80, "TenantID": tenant, "CreatedDate": now}
        if row:
            tid = row[0]
            sets = {k: v for k, v in rec.items() if k in tcols and k not in ("TrainingGUID", "CreatedDate")}
            cur.execute(f"UPDATE TRAINING SET {','.join(k+'=?' for k in sets)} WHERE TrainingID=?",
                        (*sets.values(), tid))
        else:
            tid = _nextid(cur, "TRAINING", "TrainingID")
            rec2 = {"TrainingID": tid, **{k: v for k, v in rec.items() if k in tcols}}
            cur.execute(f"INSERT INTO TRAINING ({','.join(rec2)}) VALUES ({','.join('?' for _ in rec2)})",
                        tuple(rec2.values()))
            n_t += 1
        name_to_id[name] = tid

    # wipe seeded enrollments for these trainings, then re-create
    tids = tuple(name_to_id.values())
    cur.execute(f"DELETE FROM TRAININGFORPERSON WHERE TrainingID IN ({','.join('?' for _ in tids)})", tids)

    def enroll(pid, tname, completed, days_enrolled):
        eid = _nextid(cur, "TRAININGFORPERSON", "TrainingPersonID")
        enrolled_at = _days_ago(days_enrolled)
        completed_at = _days_ago(max(0, days_enrolled - 5)) if completed else None
        rec = {"TrainingPersonID": eid, "PersonID": pid, "TrainingID": name_to_id[tname],
               "DateEnrolled": enrolled_at, "AssignedDate": enrolled_at,
               "DateCompleted": completed_at, "Status": "Completed" if completed else "In Progress",
               "Score": (85 + (pid * 3) % 15) if completed else None,
               "DueDate": _days_ago(days_enrolled - 30), "TenantID": tenant}
        rec = {k: v for k, v in rec.items() if k in ecols or k == "TrainingPersonID"}
        cur.execute(f"INSERT INTO TRAININGFORPERSON ({','.join(rec)}) VALUES ({','.join('?' for _ in rec)})",
                    tuple(rec.values()))

    for pid in persons:
        if pid in NEVER_TRAINED:
            continue
        incomplete = INCOMPLETE.get(pid, set())
        for rname in REQUIRED_NAMES:
            enroll(pid, rname, completed=(rname not in incomplete), days_enrolled=70)
            n_e += 1
    for oname, takers in OPTIONAL_TAKERS.items():
        for pid in takers:
            if pid in NEVER_TRAINED:
                continue
            enroll(pid, oname, completed=True, days_enrolled=40)
            n_e += 1

    # ── phishing campaigns + results ──────────────────────────────────────────
    scols = _cols(cur, "PHISHINGSIMULATION")
    for name, theme, diff, days, desc in CAMPAIGNS:
        sent_date = _days_ago(days)
        row = cur.execute("SELECT PhishingSimulationID FROM PHISHINGSIMULATION WHERE Name=? AND IFNULL(TenantID,-1)=IFNULL(?,-1)",
                          (name, tenant)).fetchone()
        rec = {"PhishingSimulationGUID": str(uuid.uuid4()), "Name": name, "Theme": theme,
               "Template": name, "Difficulty": diff, "Status": "Completed", "Description": desc,
               "LandingPageURL": "", "SentDate": sent_date, "TenantID": tenant, "CreatedDate": now}
        if row:
            sid = row[0]
            sets = {k: v for k, v in rec.items() if k in scols and k not in ("PhishingSimulationGUID", "CreatedDate")}
            cur.execute(f"UPDATE PHISHINGSIMULATION SET {','.join(k+'=?' for k in sets)} WHERE PhishingSimulationID=?",
                        (*sets.values(), sid))
        else:
            sid = _nextid(cur, "PHISHINGSIMULATION", "PhishingSimulationID")
            rec2 = {"PhishingSimulationID": sid, **{k: v for k, v in rec.items() if k in scols}}
            cur.execute(f"INSERT INTO PHISHINGSIMULATION ({','.join(rec2)}) VALUES ({','.join('?' for _ in rec2)})",
                        tuple(rec2.values()))
            n_c += 1

        cur.execute("DELETE FROM PHISHINGRESULT WHERE PhishingSimulationID=?", (sid,))
        outcomes = OUTCOMES.get(name, {})
        for pid in persons:
            o = outcomes.get(pid, "")
            clicked = 1 if o in ("c", "s") else 0
            submitted = 1 if o == "s" else 0
            reported = 1 if o == "r" else 0
            # reporters tend to report fast; clickers click within a day; everyone opened
            date_clicked = _days_ago(days) if clicked else None
            date_reported = _days_ago(days) if reported else None
            rid = _nextid(cur, "PHISHINGRESULT", "PhishingResultID")
            cur.execute(
                "INSERT INTO PHISHINGRESULT (PhishingResultID, PhishingSimulationID, PersonID, Sent, Opened, "
                "Clicked, SubmittedData, ReportedPhish, DateSent, DateClicked, DateReported, TenantID, CreatedDate) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, sid, pid, 1, 1, clicked, submitted, reported, sent_date, date_clicked, date_reported, tenant, now))
            n_r += 1

    con.commit()
    con.close()
    print("[%s] tenant %d: %d new trainings, %d enrollments; %d new campaigns, %d phishing results."
          % (SOURCE, tenant, n_t, n_e, n_c, n_r))


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed a KnowBe4-style Security Awareness demo program")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID to stamp (default 3 = demo account)")
    ap.add_argument("--list", action="store_true", help="show what would be written, write nothing")
    a = ap.parse_args()
    seed(a.tenant, a.list)


if __name__ == "__main__":
    main()
