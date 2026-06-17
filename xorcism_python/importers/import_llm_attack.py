"""
import_llm_attack.py — Import the LLM ATT&CK Navigator (Anthropic, 2026) as an
AI-enablement *layer* over MITRE ATT&CK, into XTHREAT.LLMATTACKTECHNIQUE.
Jerome Athias - XORCISM

Source: https://red.anthropic.com/2026/attack-navigator/
Anthropic mapped AI-enabled malicious activity (832 banned accounts, Mar 2025 –
Mar 2026; 13,873 observations) onto the MITRE ATT&CK framework that was live at
the time (v18, Enterprise + Mobile). It scores techniques with an AI Risk
Enablement Score (ARiES, 0–100 = Threat 0–35 + Vulnerability 0–35 + Impact 0–30)
and reports prevalence (% of banned accounts). The Navigator itself is a
JS-rendered ATT&CK Navigator; no static layer JSON is published, so this importer
seeds the *documented* high-prevalence techniques with their published figures —
clearly attributed. Each row joins to XTHREAT.ATTACKTECHNIQUE by AttackID, so the
/attack matrix can overlay it as a heatmap. Idempotent (ON CONFLICT AttackID).

    python import_llm_attack.py
"""
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
SOURCE = "https://red.anthropic.com/2026/attack-navigator/"
ACCOUNTS = 832  # banned accounts analysed (denominator for prevalence)

# Documented high-prevalence techniques from the Anthropic LLM ATT&CK Navigator.
# (AttackID, technique name, ATT&CK tactic, actor_count|None, prevalence_pct|None)
# prevalence = % of the 832 banned accounts; actor_count given where published.
TECHNIQUES = [
    ("T1587.001", "Develop Capabilities: Malware",            "Resource Development", 560, round(560 / ACCOUNTS * 100, 1)),
    ("T1027",     "Obfuscated Files or Information",          "Defense Evasion",      None, 64.7),
    ("T1005",     "Data from Local System",                   "Collection",           None, 55.9),
    ("T1562",     "Impair Defenses",                          "Defense Evasion",      None, 54.9),
    ("T1087",     "Account Discovery",                        "Discovery",            None, None),
    ("T1020",     "Automated Exfiltration",                   "Exfiltration",         None, None),
    ("T1055",     "Process Injection",                        "Defense Evasion",      None, None),
    ("T1021",     "Remote Services",                          "Lateral Movement",     None, None),
    ("T1078.003", "Valid Accounts: Local Accounts",           "Defense Evasion",      None, None),
    ("T1003",     "OS Credential Dumping",                    "Credential Access",    None, None),
    ("T1560",     "Archive Collected Data",                   "Collection",           None, None),
    ("T1505.003", "Server Software Component: Web Shell",     "Persistence",          None, None),
    ("T1210",     "Exploitation of Remote Services",          "Lateral Movement",     None, None),
]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(m: str) -> None:
    print(f"[ImportLLMAttack] {m}", flush=True)


def main() -> int:
    if not os.path.exists(DB_PATH):
        log(f"XTHREAT.db not found: {DB_PATH}")
        return 1
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=10000")
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS LLMATTACKTECHNIQUE (
        LLMAttackTechniqueID INTEGER PRIMARY KEY,
        AttackID TEXT UNIQUE, Name TEXT, TacticName TEXT,
        ActorCount INTEGER, PrevalencePct REAL, AriesMean REAL,
        Observed INTEGER DEFAULT 1, Notes TEXT, Source TEXT, CreatedDate TEXT)""")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_llmattack_attackid ON LLMATTACKTECHNIQUE(AttackID)")

    # Enrich the display name from the local ATT&CK import when available (keeps it
    # consistent with the rest of the matrix); fall back to the documented name.
    have_attack = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").fetchone() is not None

    ts = now()
    n = 0
    for aid, name, tactic, actors, prev in TECHNIQUES:
        if have_attack:
            row = cur.execute("SELECT Name FROM ATTACKTECHNIQUE WHERE AttackID=?", (aid,)).fetchone()
            if row and row[0]:
                name = row[0]
        cur.execute(
            """INSERT INTO LLMATTACKTECHNIQUE
                 (AttackID, Name, TacticName, ActorCount, PrevalencePct, Observed, Notes, Source, CreatedDate)
               VALUES (?,?,?,?,?,1,?,?,?)
               ON CONFLICT(AttackID) DO UPDATE SET
                 Name=excluded.Name, TacticName=excluded.TacticName,
                 ActorCount=excluded.ActorCount, PrevalencePct=excluded.PrevalencePct""",
            (aid, name, tactic, actors, prev,
             "AI-enabled threat-actor technique (Anthropic LLM ATT&CK Navigator, 832 accounts).",
             SOURCE, ts))
        n += 1

    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM LLMATTACKTECHNIQUE").fetchone()[0]
    withp = cur.execute("SELECT COUNT(*) FROM LLMATTACKTECHNIQUE WHERE PrevalencePct IS NOT NULL").fetchone()[0]
    conn.close()
    log(f"OK ({now()}) — {n} techniques upserted, {total} total ({withp} with published prevalence) in XTHREAT.LLMATTACKTECHNIQUE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
