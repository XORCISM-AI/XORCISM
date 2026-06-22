"""seed_iso27031_dora.py — seed the ISO/IEC 27031 IRBC catalogue into XORCISM.CONTROL,
with a crosswalk to DORA (Regulation (EU) 2022/2554) in CONTROLMAPPING.

ISO/IEC 27031 — "Guidelines for information and communication technology readiness for
business continuity" (IRBC) — is the bridge between ICT/DR and Business Continuity
Management. It is the natural standard backing DORA's digital-operational-resilience and
ICT-continuity requirements. This seeder:

  * registers the VOCABULARY entry "ISO/IEC 27031" (and "DORA");
  * inserts ~30 IRBC requirements as CONTROL rows (VocabularyID = the 27031 vocab id),
    organised by the IRBC lifecycle (Plan-Do-Check-Act) and the prevention / detection /
    response / recovery outcomes, with clause refs in CONTROL.ISO + Statement/Guidance;
  * inserts CONTROLMAPPING rows (Framework = "DORA") mapping each requirement to the
    relevant DORA article(s), so ISO 27031 readiness is expressed in DORA terms.

Idempotent: re-running deletes the 27031 controls + their DORA mappings and re-inserts.
No SQLAlchemy model change needed (raw SQL). DB path = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/seed_iso27031_dora.py
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone

VOCAB_27031 = "ISO/IEC 27031"
VOCAB_DORA = "DORA"

# (clause ref, IRBC phase, title, statement, [ (DORA article, article title) ... ])
CATALOGUE = [
    # ── Establish / govern (IRBC framework) ────────────────────────────────────
    ("27031:5.1", "Establish", "IRBC policy & objectives",
     "Establish, document and approve an ICT-readiness-for-business-continuity (IRBC) policy, scope and objectives aligned with the organisation's BCM and ICT strategy.",
     [("DORA Art. 5", "ICT risk management framework — governance"), ("DORA Art. 6", "ICT risk management framework")]),
    ("27031:5.2", "Establish", "IRBC roles & responsibilities",
     "Define and assign IRBC roles, responsibilities and authorities, including top-management accountability and an IRBC response structure.",
     [("DORA Art. 5", "Governance and organisation"), ("DORA Art. 13", "Communication")]),
    ("27031:5.3", "Establish", "Competence, awareness & training",
     "Ensure personnel with IRBC responsibilities are competent, and run awareness and training so staff can fulfil their role during ICT disruption.",
     [("DORA Art. 13", "Learning and evolving"), ("DORA Art. 5(4)", "ICT awareness and training")]),
    ("27031:5.4", "Establish", "Resources for IRBC",
     "Determine and provide the resources (people, facilities, technology, information, suppliers) needed to establish, maintain and improve IRBC.",
     [("DORA Art. 6", "ICT risk management framework — resources")]),
    # ── Plan (risk, BIA, strategy) ─────────────────────────────────────────────
    ("27031:6.1", "Plan", "ICT risk assessment",
     "Assess threats to and vulnerabilities of ICT services that support critical business functions, and the likelihood and impact of their disruption.",
     [("DORA Art. 8", "Identification"), ("DORA Art. 6(2)", "ICT risk management")]),
    ("27031:6.2", "Plan", "Business impact analysis for ICT (RTO/RPO/MTPD)",
     "Conduct a BIA to determine, per ICT service, the Maximum Tolerable Period of Disruption (MTPD), Recovery Time Objective (RTO) and Recovery Point Objective (RPO).",
     [("DORA Art. 11", "Response and recovery — BIA"), ("DORA Art. 11(6)", "Recovery time and point objectives")]),
    ("27031:6.3", "Plan", "IRBC strategy & options",
     "Select IRBC strategies (redundancy, alternate sites/capacity, alternative suppliers, manual workarounds) that meet the RTO/RPO derived from the BIA.",
     [("DORA Art. 11(1)", "ICT business continuity policy"), ("DORA Art. 12", "Backup, restoration and recovery")]),
    ("27031:6.4", "Plan", "ICT continuity & response plans",
     "Develop documented ICT continuity, response and recovery plans with activation criteria, procedures, contacts and resource requirements.",
     [("DORA Art. 11(1)", "ICT business continuity policy"), ("DORA Art. 11(3)", "Business continuity plans")]),
    ("27031:6.5", "Plan", "Crisis communication & escalation",
     "Define internal and external communication, notification and escalation arrangements for ICT disruptions, including to stakeholders and authorities.",
     [("DORA Art. 13", "Communication"), ("DORA Art. 14", "Communication plans"), ("DORA Art. 19", "Reporting of major ICT-related incidents")]),
    # ── Do — Prevention ────────────────────────────────────────────────────────
    ("27031:7.1", "Do/Prevent", "Prevention & protection controls",
     "Implement preventive controls (resilience, redundancy, hardening, capacity, environmental and physical protection) that reduce the likelihood of ICT disruption.",
     [("DORA Art. 9", "Protection and prevention")]),
    ("27031:7.2", "Do/Prevent", "Backup & secure storage",
     "Maintain backups of data, configurations and system images with secure, segregated and tested restoration capability meeting the RPO.",
     [("DORA Art. 12", "Backup policies and procedures, restoration and recovery")]),
    ("27031:7.3", "Do/Prevent", "Redundancy of ICT resources",
     "Provide redundant ICT components, network paths, power and alternate processing capacity proportionate to the criticality of the service.",
     [("DORA Art. 9(3)", "Resilience of ICT systems"), ("DORA Art. 12(3)", "Redundant ICT capacities")]),
    # ── Do — Detection ─────────────────────────────────────────────────────────
    ("27031:7.4", "Do/Detect", "Detection & early warning",
     "Implement monitoring, alerting and anomaly-detection to identify ICT incidents and conditions that could lead to disruption as early as possible.",
     [("DORA Art. 10", "Detection")]),
    ("27031:7.5", "Do/Detect", "Incident classification & triggers",
     "Classify ICT incidents by severity/impact and define the triggers that activate the IRBC response and the incident-reporting process.",
     [("DORA Art. 18", "Classification of ICT-related incidents"), ("DORA Art. 17", "ICT-related incident management process")]),
    # ── Do — Response ──────────────────────────────────────────────────────────
    ("27031:7.6", "Do/Respond", "IRBC response activation",
     "Activate the IRBC response structure and plans on detection of a qualifying ICT disruption, mobilising teams and resources.",
     [("DORA Art. 17", "ICT-related incident management process"), ("DORA Art. 11(2)", "Continuity of critical functions")]),
    ("27031:7.7", "Do/Respond", "Incident handling & containment",
     "Contain, analyse and handle the ICT incident to limit impact and preserve evidence while restoring critical services.",
     [("DORA Art. 17", "ICT-related incident management process")]),
    ("27031:7.8", "Do/Respond", "Major-incident reporting",
     "Report major ICT-related incidents and significant cyber threats to the competent authority within the regulatory timelines.",
     [("DORA Art. 19", "Reporting of major ICT-related incidents and voluntary notification"), ("DORA Art. 20", "Harmonisation of reporting content and templates")]),
    # ── Do — Recovery ──────────────────────────────────────────────────────────
    ("27031:7.9", "Do/Recover", "Recovery & restoration",
     "Execute recovery and restoration procedures to bring ICT services back within the RTO and verify data integrity against the RPO.",
     [("DORA Art. 11", "Response and recovery"), ("DORA Art. 12", "Restoration and recovery")]),
    ("27031:7.10", "Do/Recover", "Return to normal operations",
     "Confirm full restoration of ICT services and an orderly return to normal (business-as-usual) operations, including stand-down of the response.",
     [("DORA Art. 11(2)", "Restoration of ICT systems"), ("DORA Art. 12(2)", "Recovery and restoration procedures")]),
    ("27031:7.11", "Do/Recover", "Alternate/recovery site readiness",
     "Maintain and keep ready the alternate processing or recovery sites and the third-party recovery services on which continuity depends.",
     [("DORA Art. 12(3)", "Redundant ICT capacities"), ("DORA Art. 28", "General principles — ICT third-party risk")]),
    # ── Third-party (ICT supply chain) ─────────────────────────────────────────
    ("27031:7.12", "Do", "ICT third-party & supply-chain continuity",
     "Ensure ICT third-party providers supporting critical services have continuity, recovery and exit arrangements consistent with the organisation's RTO/RPO.",
     [("DORA Art. 28", "General principles — ICT third-party risk"), ("DORA Art. 30", "Key contractual provisions"), ("DORA Art. 11(7)", "Third-party continuity")]),
    # ── Check — Test / measure / review ────────────────────────────────────────
    ("27031:8.1", "Check", "Testing & exercising of IRBC plans",
     "Test and exercise ICT continuity and recovery plans at planned intervals (and after significant change) to validate they meet RTO/RPO; record and act on results.",
     [("DORA Art. 24", "General requirements for digital operational resilience testing"), ("DORA Art. 25", "Testing of ICT tools and systems"), ("DORA Art. 11(6)", "Periodic testing of BC plans")]),
    ("27031:8.2", "Check", "Advanced/threat-led testing",
     "Where required, conduct advanced testing such as threat-led penetration testing (TLPT) of the ICT systems supporting critical functions.",
     [("DORA Art. 26", "Advanced testing of ICT tools — threat-led penetration testing"), ("DORA Art. 27", "Requirements for testers")]),
    ("27031:8.3", "Check", "Performance measurement & metrics",
     "Define and monitor IRBC performance metrics (achieved RTO/RPO, exercise success, detection time) against objectives.",
     [("DORA Art. 13", "Learning and evolving"), ("DORA Art. 6(5)", "Review of the ICT risk management framework")]),
    ("27031:8.4", "Check", "Internal audit of IRBC",
     "Audit the IRBC arrangements at planned intervals to confirm conformity with the policy, this standard and regulatory obligations.",
     [("DORA Art. 6(5)", "Internal audit"), ("DORA Art. 5(2)", "Governance and oversight")]),
    ("27031:8.5", "Check", "Management review",
     "Review IRBC suitability, adequacy and effectiveness at top-management level, considering audit results, tests, incidents and changes.",
     [("DORA Art. 5", "Management body responsibility"), ("DORA Art. 6(5)", "Review of the framework")]),
    # ── Act — Maintain / improve ───────────────────────────────────────────────
    ("27031:9.1", "Act", "Post-incident review & lessons learned",
     "Conduct post-incident and post-exercise reviews, capture lessons learned and feed improvements back into the IRBC arrangements.",
     [("DORA Art. 13", "Learning and evolving"), ("DORA Art. 17(3)", "Root-cause analysis")]),
    ("27031:9.2", "Act", "Corrective action & continual improvement",
     "Take corrective and preventive action on nonconformities and weaknesses, and continually improve the IRBC capability.",
     [("DORA Art. 6(5)", "Continuous improvement of the framework"), ("DORA Art. 13", "Learning and evolving")]),
    ("27031:9.3", "Act", "Maintenance & change management",
     "Keep IRBC documentation, contacts, dependencies and recovery configurations current through change management and regular maintenance.",
     [("DORA Art. 8(6)", "Maintaining the ICT asset inventory"), ("DORA Art. 6(2)", "Documentation and review")]),
    ("27031:9.4", "Act", "Information sharing on threats",
     "Participate, where appropriate, in trusted information-sharing on cyber threats and vulnerabilities to strengthen ICT readiness.",
     [("DORA Art. 45", "Information-sharing arrangements on cyber threat information")]),
]


def _db_path() -> str:
    d = os.environ.get("XORCISM_DB_DIR") or r"C:/Users/jerom/XORCISM_databases"
    return os.path.join(d, "XORCISM.db")


def _ensure_vocab(cur: sqlite3.Cursor, name: str) -> int:
    cols = {r[1] for r in cur.execute("PRAGMA table_info(VOCABULARY)").fetchall()}
    namecol = "VocabularyName" if "VocabularyName" in cols else ("Name" if "Name" in cols else None)
    if namecol:
        row = cur.execute(f"SELECT VocabularyID FROM VOCABULARY WHERE {namecol}=?", (name,)).fetchone()
        if row:
            return int(row[0])
    nid = (cur.execute("SELECT COALESCE(MAX(VocabularyID),0) FROM VOCABULARY").fetchone()[0] or 0) + 1
    rec = {"VocabularyID": nid}
    if namecol:
        rec[namecol] = name
    if "VocabularyGUID" in cols:
        rec["VocabularyGUID"] = str(uuid.uuid4())
    if "CreatedDate" in cols:
        rec["CreatedDate"] = datetime.now(timezone.utc).isoformat()
    keys = list(rec)
    cur.execute(f"INSERT INTO VOCABULARY ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
    return nid


def main() -> int:
    con = sqlite3.connect(_db_path())
    con.execute("PRAGMA busy_timeout=15000")
    cur = con.cursor()
    now = datetime.now(timezone.utc).isoformat()

    vocab_id = _ensure_vocab(cur, VOCAB_27031)
    _ensure_vocab(cur, VOCAB_DORA)

    ccols = {r[1] for r in cur.execute("PRAGMA table_info(CONTROL)").fetchall()}
    has_mapping = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").fetchone() is not None

    # idempotent: drop previous 27031 controls + their DORA mappings
    old_ids = [r[0] for r in cur.execute("SELECT ControlID FROM CONTROL WHERE VocabularyID=?", (vocab_id,)).fetchall()]
    if old_ids and has_mapping:
        cur.execute(f"DELETE FROM CONTROLMAPPING WHERE Framework='DORA' AND ControlID IN ({','.join('?'*len(old_ids))})", old_ids)
    cur.execute("DELETE FROM CONTROL WHERE VocabularyID=?", (vocab_id,))

    next_cid = (cur.execute("SELECT COALESCE(MAX(ControlID),0) FROM CONTROL").fetchone()[0] or 0) + 1
    next_mid = 1
    if has_mapping:
        next_mid = (cur.execute("SELECT COALESCE(MAX(MappingID),0) FROM CONTROLMAPPING").fetchone()[0] or 0) + 1

    n_ctrl = n_map = 0
    for ref, phase, title, statement, doras in CATALOGUE:
        cid = next_cid; next_cid += 1
        rec = {
            "ControlID": cid, "ControlGUID": str(uuid.uuid4()),
            "ControlName": f"{ref} {title}",
            "ControlDescription": f"ISO/IEC 27031 IRBC — {phase}",
            "VocabularyID": vocab_id, "ISO": ref,
            "Statement": statement, "Guidance": f"IRBC lifecycle phase: {phase}.",
            "CreatedDate": now, "ValidFromDate": now[:10], "isEncrypted": 0,
        }
        keys = [k for k in rec if k in ccols]
        cur.execute(f"INSERT INTO CONTROL ({','.join(keys)}) VALUES ({','.join('?'*len(keys))})", [rec[k] for k in keys])
        n_ctrl += 1
        if has_mapping:
            for art, atitle in doras:
                cur.execute(
                    "INSERT INTO CONTROLMAPPING (MappingID, MappingGUID, ControlID, Framework, ExternalID, ExternalName, Relationship, Source, CreatedDate) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (next_mid, str(uuid.uuid4()), cid, "DORA", art, atitle, "supports",
                     "ISO/IEC 27031 ↔ DORA (Reg. (EU) 2022/2554) mapping", now))
                next_mid += 1; n_map += 1

    con.commit()
    con.close()
    print(f"[seed] ISO/IEC 27031 (VocabularyID={vocab_id}): {n_ctrl} controls, {n_map} DORA mappings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
