"""
seed_crisis_scenarios.py — seed a baseline library of crisis-management scenario templates
(XCOMPLIANCE.CRISISSCENARIO) with their tabletop-exercise injects (XCOMPLIANCE.EXERCISEINJECT,
template rows = AuditID NULL), for the Crisis Management view (/crisis-management).
Jerome Athias - XORCISM

Each scenario is a ready-to-run tabletop exercise (TTX): a realistic crisis narrative plus a
timed sequence of injects (events / decisions / escalations) and the expected response for each.
From the Crisis Management page you "Run exercise" on a scenario → it creates an audit of type
'Tabletop Exercise' and copies these injects into it.

Idempotent: keyed on (ScenarioName, TenantID) — re-running updates the scenario and replaces its
template injects rather than duplicating.

    python seed_crisis_scenarios.py                # tenant 3 (default)
    python seed_crisis_scenarios.py --tenant 3
    python seed_crisis_scenarios.py --list         # show what would be written
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

SOURCE = "SeedCrisisScenarios"


def _inj(time, title, description, expected, itype="Event"):
    return {"time": time, "title": title, "description": description, "expected": expected, "type": itype}


# ── the scenario library ──────────────────────────────────────────────────────
SCENARIOS = [
    {
        "name": "Ransomware Outbreak — enterprise-wide encryption",
        "type": "Ransomware",
        "severity": "Critical",
        "actor": "Big-game ransomware affiliate (e.g. LockBit / BlackCat)",
        "techniques": "T1566, T1078, T1486, T1490, T1489",
        "objectives": "Test detection-to-containment time, the decision to isolate, backup-restore readiness, "
                      "ransom-payment decision authority, and regulator/customer communications.",
        "injects": [
            _inj("T+0:00", "EDR alerts on mass file renames", "The SOC receives EDR alerts: thousands of files renamed with a '.locked' extension across two file servers.", "SOC triages, declares a suspected ransomware incident, activates the IR plan and notifies the on-call crisis manager.", "Event"),
            _inj("T+0:20", "Shares unreachable; ransom note found", "Users report network shares are unreachable; a ransom note 'RESTORE-FILES.txt' demands 30 BTC within 72h.", "Crisis team convenes; decide whether to isolate affected segments and disable VPN/RDP.", "Decision"),
            _inj("T+0:45", "Spread to a second site", "Telemetry shows encryption starting at a second site via a domain admin account.", "Contain: disable the compromised account, isolate the second site, preserve forensic evidence.", "Escalation"),
            _inj("T+1:30", "Backups partially encrypted", "The backup team reports the last two daily backups are also encrypted; the most recent clean restore point is 4 days old.", "Assess data-loss impact (RPO), decide restore vs. rebuild, brief executives on options.", "Decision"),
            _inj("T+3:00", "Media enquiry + regulator clock", "A journalist emails asking about an outage; legal flags a potential personal-data breach (72h GDPR clock).", "Approve holding statement, start the breach-notification assessment, assign a single spokesperson.", "Media"),
            _inj("T+6:00", "Ransom deadline pressure", "The actor threatens to leak exfiltrated data unless paid. Decision required on negotiation/payment.", "Executive + legal decide on the payment stance (and OFAC/sanctions check); document the rationale.", "Decision"),
        ],
    },
    {
        "name": "Major Data Breach — customer PII exfiltration",
        "type": "Data Breach",
        "severity": "Critical",
        "actor": "Financially-motivated intrusion set",
        "techniques": "T1190, T1530, T1048, T1567",
        "objectives": "Validate breach confirmation, scoping of affected records, 72h regulator notification, "
                      "customer comms, and credential-reset orchestration.",
        "injects": [
            _inj("T+0:00", "Data-for-sale post discovered", "Threat-intel flags a forum post offering 2M customer records allegedly from your company.", "Verify authenticity against a sample; convene the breach response team.", "Event"),
            _inj("T+0:30", "Exfil path confirmed", "Logs confirm bulk export from a reporting database via a compromised service account two weeks ago.", "Contain the account/path, preserve evidence, begin scoping which records and fields were taken.", "Escalation"),
            _inj("T+1:00", "Scope: PII + payment tokens", "Scoping shows names, emails, hashed passwords and payment tokens are in scope.", "Engage legal/DPO on notification obligations (GDPR/CCPA/PCI); start the 72h clock.", "Decision"),
            _inj("T+2:00", "Customer & regulator comms", "Comms drafts customer notification; the regulator portal requires a preliminary filing.", "Approve customer notice + regulator filing; stand up a support/FAQ and forced password reset.", "Media"),
            _inj("T+4:00", "Class-action & board briefing", "Outside counsel warns of class-action exposure; the board requests a briefing.", "Deliver an executive brief: impact, actions, residual risk, and remediation roadmap.", "Decision"),
        ],
    },
    {
        "name": "Distributed Denial of Service — public services down",
        "type": "DDoS",
        "severity": "High",
        "actor": "Hacktivist collective / booter service",
        "techniques": "T1498, T1499",
        "objectives": "Test traffic-scrubbing activation, ISP/CDN escalation, status-page comms and the "
                      "extortion-DDoS decision.",
        "injects": [
            _inj("T+0:00", "Latency + 5xx spike", "Monitoring shows the public website latency spiking and a surge of 5xx errors.", "NOC confirms a volumetric attack, engages the DDoS runbook, notifies the crisis lead.", "Event"),
            _inj("T+0:15", "Site effectively offline", "The site is effectively offline; checkout and login fail for customers.", "Activate CDN/scrubbing, enable rate-limiting/WAF rules, post a status-page update.", "Decision"),
            _inj("T+0:40", "Extortion note", "An email demands payment to stop the attack and threatens a larger follow-up.", "Decide on the non-payment stance, engage ISP/upstream for filtering, keep customers informed.", "Decision"),
            _inj("T+1:30", "Attack shifts to API", "The attacker pivots to the API/DNS layer to evade the CDN.", "Adapt mitigations (Anycast DNS, API rate limits); reassess capacity and business impact.", "Escalation"),
        ],
    },
    {
        "name": "Malicious Insider — privileged data theft",
        "type": "Insider Threat",
        "severity": "High",
        "actor": "Departing privileged employee",
        "techniques": "T1078, T1530, T1052, T1567.002",
        "objectives": "Test DLP/insider-risk detection, HR/Legal coordination, access revocation, and evidence "
                      "handling for a potential prosecution.",
        "injects": [
            _inj("T+0:00", "DLP alert: bulk download", "Insider-risk tooling flags an engineer downloading the entire source repo and a customer list to a USB drive.", "Triage with HR/Legal before acting; preserve logs; avoid tipping off the subject prematurely.", "Event"),
            _inj("T+0:45", "Resignation + cloud copy", "HR reveals the employee resigned yesterday; logs show a copy to a personal cloud account.", "Decide on immediate access revocation timing vs. evidence collection; involve legal counsel.", "Decision"),
            _inj("T+1:30", "Access revoked, device held", "Access is revoked and the device secured; forensics begins.", "Chain-of-custody the device, scope what left, assess trade-secret/PII exposure.", "Escalation"),
            _inj("T+3:00", "Decision: law enforcement?", "Counsel asks whether to refer to law enforcement and notify affected customers.", "Executive/legal decide on referral and notifications; document the rationale.", "Decision"),
        ],
    },
    {
        "name": "Software Supply-Chain Compromise — poisoned dependency",
        "type": "Supply Chain",
        "severity": "Critical",
        "actor": "Sophisticated supply-chain actor",
        "techniques": "T1195.002, T1199, T1059",
        "objectives": "Test third-party/SBOM response, blast-radius scoping, customer notification as a vendor, "
                      "and rebuild-from-trusted-source readiness.",
        "injects": [
            _inj("T+0:00", "Upstream advisory", "A widely-used dependency you ship publishes an advisory: recent versions contain a backdoor.", "Confirm whether affected versions are in your build; convene the response team.", "Event"),
            _inj("T+0:40", "Backdoor in a release", "SBOM analysis confirms the malicious version shipped in your last two product releases.", "Scope customers affected, pull the releases, prepare a customer advisory (you are now the vendor).", "Escalation"),
            _inj("T+1:30", "Beaconing in the field", "A customer reports outbound beaconing from your product in their environment.", "Provide IOCs + mitigations, coordinate patched build from a verified-clean toolchain.", "Decision"),
            _inj("T+3:00", "Coordinated disclosure", "A researcher and a CERT request coordinated disclosure timing.", "Agree a disclosure timeline; align customer comms and the public advisory.", "Media"),
        ],
    },
    {
        "name": "Cloud Identity Compromise — admin account takeover",
        "type": "Cloud Account Compromise",
        "severity": "High",
        "actor": "Access broker / phishing crew",
        "techniques": "T1078.004, T1528, T1556, T1098",
        "objectives": "Test cloud-IdP detection, MFA/session revocation, persistence hunting (OAuth grants, "
                      "inbox rules) and blast-radius assessment across SaaS.",
        "injects": [
            _inj("T+0:00", "Impossible-travel sign-in", "The IdP flags an impossible-travel sign-in to a Global Admin account from a new country.", "Confirm compromise; force sign-out and password reset; require MFA re-registration.", "Event"),
            _inj("T+0:30", "Persistence found", "Investigation finds a new OAuth app grant and an inbox-forwarding rule exfiltrating mail.", "Revoke tokens/app grants, remove the rule, hunt for other admin changes.", "Escalation"),
            _inj("T+1:00", "Lateral SaaS access", "The account had SSO into finance and HR SaaS; suspicious access is seen there too.", "Assess blast radius across federated apps; reset affected sessions; notify app owners.", "Decision"),
            _inj("T+2:30", "Wire-fraud attempt", "Finance reports a fraudulent payment-change request that originated from the mailbox.", "Block the payment, engage fraud/bank, brief executives, decide on customer/partner notice.", "Decision"),
        ],
    },
    {
        "name": "Business Email Compromise — CEO fraud / invoice redirect",
        "type": "Business Email Compromise",
        "severity": "High",
        "actor": "BEC fraud group",
        "techniques": "T1566, T1534, T1114, T1656",
        "objectives": "Test out-of-band payment verification, fund-recall procedures, bank/law-enforcement "
                      "engagement and finance-team awareness.",
        "injects": [
            _inj("T+0:00", "Urgent CEO wire request", "Finance receives an urgent 'CEO' email requesting a confidential wire transfer for an acquisition.", "Apply out-of-band verification policy; do NOT act on email alone; flag to security.", "Event"),
            _inj("T+0:20", "Spoofed domain + lookalike", "Security finds the email came from a look-alike domain; a real invoice was also altered to a new account.", "Quarantine, hunt for other recipients, check whether any payment already went out.", "Escalation"),
            _inj("T+0:45", "A payment already sent", "Finance reveals a €240k payment was sent this morning to the fraudulent account.", "Initiate bank recall/SWIFT recall, file with law enforcement (IC3/local), preserve evidence.", "Decision"),
            _inj("T+2:00", "Lessons & comms", "Leadership asks how this happened and what to tell staff and the auditor.", "Brief leadership, reinforce verification controls, plan staff awareness, document for audit.", "Decision"),
        ],
    },
]


def _ensure_schema(cur):
    cur.execute("""CREATE TABLE IF NOT EXISTS CRISISSCENARIO (
      ScenarioID INTEGER PRIMARY KEY, ScenarioGUID TEXT, ScenarioName TEXT, ScenarioType TEXT,
      Description TEXT, Severity TEXT, Objectives TEXT, ThreatActor TEXT, AttackTechniques TEXT,
      Refs TEXT, IsTemplate INTEGER DEFAULT 1, Source TEXT, CreatedDate TEXT, TenantID INTEGER)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS EXERCISEINJECT (
      InjectID INTEGER PRIMARY KEY, InjectGUID TEXT, AuditID INTEGER, ScenarioID INTEGER, StepOrder INTEGER,
      InjectTime TEXT, Title TEXT, Description TEXT, InjectType TEXT, ExpectedAction TEXT,
      ActualResponse TEXT, Status TEXT, CreatedDate TEXT, TenantID INTEGER)""")


def seed(tenant: int, list_only: bool = False) -> None:
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if list_only:
        for s in SCENARIOS:
            print(f"  [{s['severity']:8}] {s['name']}  ({s['type']}, {len(s['injects'])} injects)")
        print(f"\n{len(SCENARIOS)} scenario(s) — tenant {tenant}")
        return
    con = sqlite3.connect(os.path.join(_DB_DIR, "XCOMPLIANCE.db"), timeout=15)
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    _ensure_schema(cur)
    n_new = n_upd = n_inj = 0
    for s in SCENARIOS:
        row = cur.execute(
            "SELECT ScenarioID FROM CRISISSCENARIO WHERE ScenarioName=? AND IFNULL(TenantID,-1)=IFNULL(?,-1)",
            (s["name"], tenant),
        ).fetchone()
        vals = (s["name"], s["type"], s["objectives"][:200] + ("…" if len(s["objectives"]) > 200 else ""),
                s["severity"], s["objectives"], s["actor"], s["techniques"])
        if row:
            sid = row[0]
            cur.execute(
                "UPDATE CRISISSCENARIO SET ScenarioName=?, ScenarioType=?, Description=?, Severity=?, "
                "Objectives=?, ThreatActor=?, AttackTechniques=? WHERE ScenarioID=?",
                (*vals, sid),
            )
            n_upd += 1
        else:
            cur.execute(
                "INSERT INTO CRISISSCENARIO (ScenarioGUID, ScenarioName, ScenarioType, Description, Severity, "
                "Objectives, ThreatActor, AttackTechniques, IsTemplate, Source, CreatedDate, TenantID) "
                "VALUES (?,?,?,?,?,?,?,?,1,?,?,?)",
                (str(uuid.uuid4()), *vals, SOURCE, now, tenant),
            )
            sid = cur.lastrowid
            n_new += 1
        # replace template injects (AuditID NULL) for this scenario
        cur.execute("DELETE FROM EXERCISEINJECT WHERE ScenarioID=? AND AuditID IS NULL", (sid,))
        for i, inj in enumerate(s["injects"], 1):
            cur.execute(
                "INSERT INTO EXERCISEINJECT (InjectGUID, AuditID, ScenarioID, StepOrder, InjectTime, Title, "
                "Description, InjectType, ExpectedAction, Status, CreatedDate, TenantID) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), None, sid, i, inj["time"], inj["title"], inj["description"],
                 inj["type"], inj["expected"], "Template", now, tenant),
            )
            n_inj += 1
    con.commit()
    con.close()
    print(f"[{SOURCE}] scenarios: {n_new} new, {n_upd} updated; {n_inj} template injects (tenant {tenant}).")


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed crisis-management scenario templates + tabletop injects")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID to stamp (default 3)")
    ap.add_argument("--list", action="store_true", help="show what would be written, write nothing")
    a = ap.parse_args()
    seed(a.tenant, a.list)


if __name__ == "__main__":
    main()
