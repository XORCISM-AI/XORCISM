"""
import_saif.py — Import Google's SAIF (Secure AI Framework) risk map into XTHREAT.

Source: https://saif.google/secure-ai-framework/risks  (the risk map / taxonomy)

The SAIF site is a JavaScript single-page app, so rather than scrape it this importer
embeds the SAIF taxonomy itself: the 15 risks (with their short codes, responsible
party and lifecycle component), the 5 lifecycle components, and the control catalogue.
The risk/component/control NAMES and codes are SAIF's factual taxonomy; the
descriptions here are short ORIGINAL paraphrases (Google's wording is not reproduced).

Mirrors import_a3m.py: idempotent upsert keyed by Name, optional XTHREAT.db schema
creation, runs against config.DB_DIR. Re-runnable.

    python import_saif.py            # import / refresh
    python import_saif.py --dry-run  # print what would be imported, touch no DB
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
SOURCE_URL = "https://saif.google/secure-ai-framework/risks"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportSAIF] {msg}", flush=True)


# ── SAIF taxonomy (names/codes = SAIF; descriptions = original paraphrases) ────

# (order, name, description)
COMPONENTS = [
    (1, "Data", "Data sourcing, filtering, processing and storage across the ML lifecycle."),
    (2, "Infrastructure", "Model serving and deployment systems and the platforms that run models."),
    (3, "Model", "Training, tuning, evaluation and inference of the model itself."),
    (4, "Application", "Integration of the model into applications, incl. access control and I/O handling."),
    (5, "Agent", "Agentic orchestration: tool access, reasoning and autonomous actions."),
]

# (name, category, description)
CONTROLS = [
    ("Training Data Sanitization", "Data Security",
     "Detect and remove poisoned, malicious or low-quality records from training data."),
    ("Training Data Management", "Data Security",
     "Govern the provenance, lineage and authorization of training data."),
    ("User Data Management", "Data Security",
     "Minimize, govern and protect user data handled by the model."),
    ("Model and Data Integrity Management", "Model Protection",
     "Protect model code, weights and data from unauthorized modification (signing/verification)."),
    ("Model and Data Access Control", "Model Protection",
     "Restrict who and what can access models and data, with least privilege."),
    ("Model and Data Inventory Management", "Model Protection",
     "Maintain an inventory of models, datasets and their metadata."),
    ("Secure-by-Default ML Tooling", "Model Protection",
     "Use ML frameworks and tooling that are hardened and secure by default."),
    ("Input Validation and Sanitization", "Operational Security",
     "Validate and sanitize prompts and inputs before they reach the model."),
    ("Output Validation and Sanitization", "Operational Security",
     "Validate and sanitize model output before it is used by downstream systems or users."),
    ("Adversarial Training and Testing", "Operational Security",
     "Harden models with adversarial examples and red-team testing."),
    ("Application Access Management", "Operational Security",
     "Authentication and authorization controls around the application fronting the model."),
    ("Privacy Enhancing Technologies", "Operational Security",
     "Apply PETs (e.g. differential privacy) to limit sensitive-data exposure."),
    ("Agent Permissions", "Agent Security",
     "Constrain the actions and tools an agent may invoke (least privilege)."),
    ("Agent User Control", "Agent Security",
     "Keep the user in control: confirmation/approval for sensitive agent actions."),
    ("Agent Observability", "Agent Security",
     "Log and monitor agent reasoning and actions for oversight."),
]

# (order, code, name, component, responsible_party, description, [controls])
RISKS = [
    (1, "DP", "Data Poisoning", "Data", "Model Creators",
     "Tampering with training or retraining data to degrade model quality or implant hidden behaviour.",
     ["Training Data Sanitization", "Training Data Management"]),
    (2, "UTD", "Unauthorized Training Data", "Data", "Model Creators",
     "Training on data collected or used without the proper authorization or consent.",
     ["Training Data Management", "User Data Management"]),
    (3, "MST", "Model Source Tampering", "Model", "Model Creators",
     "Compromising model code, dependencies or weights through the build/supply chain.",
     ["Model and Data Integrity Management", "Secure-by-Default ML Tooling"]),
    (4, "EDH", "Excessive Data Handling", "Data", "Model Creators",
     "Collecting, retaining, processing or sharing user data beyond what is permitted.",
     ["User Data Management", "Privacy Enhancing Technologies"]),
    (5, "MXF", "Model Exfiltration", "Model", "Both",
     "Stealing trained model weights or artifacts to replicate or misuse the model.",
     ["Model and Data Access Control", "Model and Data Inventory Management"]),
    (6, "MDT", "Model Deployment Tampering", "Infrastructure", "Both",
     "Unauthorized changes to the model's deployment infrastructure or serving components.",
     ["Model and Data Integrity Management", "Model and Data Access Control"]),
    (7, "DMS", "Denial of ML Service", "Infrastructure", "Model Consumers",
     "Exhausting model or serving resources with costly queries to reduce availability.",
     ["Application Access Management"]),
    (8, "MRE", "Model Reverse Engineering", "Model", "Model Consumers",
     "Reconstructing a model's behaviour or parameters via crafted inputs and output analysis.",
     ["Application Access Management", "Privacy Enhancing Technologies"]),
    (9, "IIC", "Insecure Integrated Component", "Application", "Model Consumers",
     "Vulnerable plugins, tools or libraries that grant unauthorized access to the model or its data.",
     ["Secure-by-Default ML Tooling", "Application Access Management"]),
    (10, "PIJ", "Prompt Injection", "Application", "Both",
     "Embedding adversarial instructions in a prompt or content so the model executes unintended commands.",
     ["Input Validation and Sanitization", "Adversarial Training and Testing"]),
    (11, "MEV", "Model Evasion", "Model", "Both",
     "Perturbing inputs so the model produces incorrect or attacker-chosen inferences.",
     ["Adversarial Training and Testing", "Input Validation and Sanitization"]),
    (12, "SDD", "Sensitive Data Disclosure", "Application", "Both",
     "Leaking confidential or private data through model responses or agent actions.",
     ["Output Validation and Sanitization", "Privacy Enhancing Technologies"]),
    (13, "ISD", "Inferred Sensitive Data", "Model", "Both",
     "Model inferring or revealing sensitive information that was not explicitly in its inputs.",
     ["Privacy Enhancing Technologies"]),
    (14, "IMO", "Insecure Model Output", "Application", "Model Consumers",
     "Passing unvalidated model output to downstream systems or users, enabling injection or abuse.",
     ["Output Validation and Sanitization"]),
    (15, "RA", "Rogue Actions", "Agent", "Model Consumers",
     "An AI agent taking unintended or unsafe actions (e.g. via tools) beyond the user's intent.",
     ["Agent Permissions", "Agent User Control", "Agent Observability"]),
]


def ensure_schema(cur: sqlite3.Cursor) -> None:
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS SAIFCOMPONENT (
          SaifComponentID INTEGER PRIMARY KEY, Name TEXT UNIQUE, Description TEXT,
          MatrixOrder INTEGER, CreatedDate TEXT);
        CREATE TABLE IF NOT EXISTS SAIFCONTROL (
          SaifControlID INTEGER PRIMARY KEY, Name TEXT UNIQUE, Category TEXT, Description TEXT,
          CreatedDate TEXT);
        CREATE TABLE IF NOT EXISTS SAIFRISK (
          SaifRiskID INTEGER PRIMARY KEY, SaifID TEXT, Name TEXT UNIQUE, Description TEXT,
          Component TEXT, ResponsibleParty TEXT, Controls TEXT, MatrixOrder INTEGER, URL TEXT,
          CreatedDate TEXT);
        CREATE INDEX IF NOT EXISTS ix_saifrisk_component ON SAIFRISK(Component);
        """
    )


def upsert(cur: sqlite3.Cursor, table: str, pk: str, name: str, cols: dict) -> bool:
    """Idempotent upsert keyed by the UNIQUE Name column. Returns True if newly inserted."""
    row = cur.execute(f"SELECT {pk} FROM {table} WHERE Name=?", (name,)).fetchone()
    if row:
        sets = ", ".join(f"{c}=?" for c in cols)
        cur.execute(f"UPDATE {table} SET {sets} WHERE {pk}=?", (*cols.values(), row[0]))
        return False
    nid = cur.execute(f"SELECT COALESCE(MAX({pk}),0)+1 FROM {table}").fetchone()[0]
    allcols = [pk, "Name", *cols.keys()]
    ph = ",".join("?" for _ in allcols)
    cur.execute(f"INSERT INTO {table} ({','.join(allcols)}) VALUES ({ph})",
                (nid, name, *cols.values()))
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Import the Google SAIF risk map into XTHREAT")
    ap.add_argument("--dry-run", action="store_true", help="Print the taxonomy, write nothing")
    args = ap.parse_args()

    log(f"{len(COMPONENTS)} components, {len(CONTROLS)} controls, {len(RISKS)} risks "
        f"(source: {SOURCE_URL})")
    if args.dry_run:
        for _, code, name, comp, party, *_ in RISKS:
            log(f"  {code:4} {name:30} [{comp} · {party}]")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=15000")
    cur = conn.cursor()
    ensure_schema(cur)

    new_c = new_ctl = new_r = 0
    for order, name, desc in COMPONENTS:
        new_c += upsert(cur, "SAIFCOMPONENT", "SaifComponentID", name,
                        {"Description": desc, "MatrixOrder": order, "CreatedDate": now()})
    for name, cat, desc in CONTROLS:
        new_ctl += upsert(cur, "SAIFCONTROL", "SaifControlID", name,
                          {"Category": cat, "Description": desc, "CreatedDate": now()})
    for order, code, name, comp, party, desc, controls in RISKS:
        new_r += upsert(cur, "SAIFRISK", "SaifRiskID", name, {
            "SaifID": code, "Description": desc, "Component": comp, "ResponsibleParty": party,
            "Controls": ", ".join(controls), "MatrixOrder": order, "URL": SOURCE_URL,
            "CreatedDate": now(),
        })
    conn.commit()
    conn.close()
    log(f"Done ({now()}): components {new_c} new / {len(COMPONENTS)-new_c} updated, "
        f"controls {new_ctl} new / {len(CONTROLS)-new_ctl} updated, "
        f"risks {new_r} new / {len(RISKS)-new_r} updated.")


if __name__ == "__main__":
    main()
