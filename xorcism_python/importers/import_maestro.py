"""
import_maestro.py — Import the MAESTRO agentic-AI threat-modeling framework into XTHREAT.
Jerome Athias - XORCISM

MAESTRO (Multi-Agent Environment, Security, Threat, Risk & Outcome) is the Cloud Security
Alliance's threat-modeling framework for agentic AI. It decomposes an agentic system into a
seven-layer reference architecture, then enumerates layer-specific and cross-layer threats.

Source: https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro
(CSA blog by Ken Huang). MAESTRO ships no downloadable data file, so the layer/threat catalogue
is embedded below verbatim from the framework; the one-line threat descriptions summarise each
well-known threat class for the matrix tooltips.

Target: XTHREAT.db — MAESTROLAYER (7 layers, matrix order) + MAESTROTHREAT (MaestroID UNIQUE,
LayerName='Cross-Layer' for the cross-layer threats). Idempotent (upsert by MaestroID).

Usage:
    python import_maestro.py
"""
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
URL = "https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro"

# (number, name, is_vertical, description)
LAYERS = [
    (1, "Foundation Models", 0,
     "The core AI model on which the agent is built - a large language model (LLM) or other AI."),
    (2, "Data Operations", 0,
     "Data processing, preparation and storage supporting the agent: databases, vector stores and RAG pipelines."),
    (3, "Agent Frameworks", 0,
     "The frameworks and toolkits used to build agents and integrate tools and data."),
    (4, "Deployment and Infrastructure", 0,
     "The infrastructure the agent executes on: cloud or on-premise environments, containers and orchestration."),
    (5, "Evaluation and Observability", 0,
     "Tools and processes for tracking agent performance and detecting anomalies."),
    (6, "Security and Compliance", 1,
     "A vertical layer cutting across all others, embedding security and compliance controls into every agent operation."),
    (7, "Agent Ecosystem", 0,
     "The marketplace where agents interface with real-world applications, users and other agents."),
]

# layer_name -> [(maestro_id, threat_name, description), ...] verbatim threat names from the framework
THREATS = {
    "Foundation Models": [
        ("M1.1", "Adversarial Examples", "Crafted inputs that make the model produce incorrect or attacker-chosen outputs."),
        ("M1.2", "Model Stealing", "Extracting a functional copy of the model through query access."),
        ("M1.3", "Backdoor Attacks", "Hidden triggers implanted in the model that activate malicious behaviour."),
        ("M1.4", "Membership Inference Attacks", "Inferring whether specific data was in the training set, leaking privacy."),
        ("M1.5", "Data Poisoning (Training Phase)", "Corrupting training data to degrade or bias the model."),
        ("M1.6", "Reprogramming Attacks", "Repurposing the model to perform a task the attacker chooses."),
        ("M1.7", "Denial of Service (DoS) Attacks", "Overloading the model to exhaust resources and deny availability."),
    ],
    "Data Operations": [
        ("M2.1", "Data Poisoning", "Injecting malicious data into stores or RAG corpora to manipulate agent behaviour."),
        ("M2.2", "Data Exfiltration", "Unauthorised extraction of sensitive data from data stores."),
        ("M2.3", "Denial of Service on Data Infrastructure", "Overwhelming databases or vector stores to deny access."),
        ("M2.4", "Data Tampering", "Unauthorised modification of stored data affecting agent decisions."),
        ("M2.5", "Compromised RAG Pipelines", "Manipulating retrieval-augmented-generation pipelines to feed poisoned context."),
    ],
    "Agent Frameworks": [
        ("M3.1", "Compromised Framework Components", "Malicious or vulnerable components within the agent framework."),
        ("M3.2", "Backdoor Attacks", "Hidden malicious functionality embedded in the framework."),
        ("M3.3", "Input Validation Attacks", "Exploiting weak input validation (e.g. prompt or tool-argument injection)."),
        ("M3.4", "Supply Chain Attacks", "Compromise of third-party libraries or dependencies the framework relies on."),
        ("M3.5", "Denial of Service on Framework APIs", "Flooding framework APIs to deny agent operation."),
        ("M3.6", "Framework Evasion", "Bypassing framework-level guardrails and controls."),
    ],
    "Deployment and Infrastructure": [
        ("M4.1", "Compromised Container Images", "Malicious or vulnerable container images used to deploy agents."),
        ("M4.2", "Orchestration Attacks", "Abusing orchestration (e.g. Kubernetes) to control or disrupt workloads."),
        ("M4.3", "Infrastructure-as-Code (IaC) Manipulation", "Tampering with IaC to introduce insecure configuration."),
        ("M4.4", "Denial of Service (DoS) Attacks", "Exhausting infrastructure resources to deny availability."),
        ("M4.5", "Resource Hijacking", "Stealing compute (e.g. cryptomining) from agent infrastructure."),
        ("M4.6", "Lateral Movement", "Pivoting from a compromised agent host to other systems."),
    ],
    "Evaluation and Observability": [
        ("M5.1", "Manipulation of Evaluation Metrics", "Falsifying metrics to hide malfunction or malicious behaviour."),
        ("M5.2", "Compromised Observability Tools", "Subverting monitoring tools to blind defenders."),
        ("M5.3", "Denial of Service on Evaluation Infrastructure", "Disrupting evaluation and monitoring systems."),
        ("M5.4", "Evasion of Detection", "Behaving so as to avoid triggering monitoring and alerts."),
        ("M5.5", "Data Leakage through Observability", "Sensitive data exposed via logs, traces or dashboards."),
        ("M5.6", "Poisoning Observability Data", "Injecting false telemetry to mislead operators."),
    ],
    "Security and Compliance": [
        ("M6.1", "Security Agent Data Poisoning", "Poisoning the data that security AI agents rely on."),
        ("M6.2", "Evasion of Security AI Agents", "Crafting activity that evades AI-driven security controls."),
        ("M6.3", "Compromised Security AI Agents", "Taking control of the agents meant to provide defence."),
        ("M6.4", "Regulatory Non-Compliance by AI Security Agents", "Security agents violating legal or regulatory requirements."),
        ("M6.5", "Bias in Security AI Agents", "Biased security agents producing unfair or blind-spot decisions."),
        ("M6.6", "Lack of Explainability in Security AI Agents", "Opaque security decisions that cannot be audited."),
        ("M6.7", "Model Extraction of AI Security Agents", "Stealing the security agent's model to learn its detection logic."),
    ],
    "Agent Ecosystem": [
        ("M7.1", "Compromised Agents", "Ecosystem agents taken over by an attacker."),
        ("M7.2", "Agent Impersonation", "An attacker masquerading as a legitimate agent."),
        ("M7.3", "Agent Identity Attack", "Forging or abusing agent identities and credentials."),
        ("M7.4", "Agent Tool Misuse", "Abusing an agent's tools or integrations to cause harm."),
        ("M7.5", "Agent Goal Manipulation", "Steering an agent's goals toward attacker objectives."),
        ("M7.6", "Marketplace Manipulation", "Gaming the agent marketplace (ratings, ranking, discovery)."),
        ("M7.7", "Integration Risks", "Vulnerabilities introduced when agents integrate with external applications."),
        ("M7.8", "Horizontal/Vertical Solution Vulnerabilities", "Flaws in cross-domain or domain-specific agent solutions."),
        ("M7.9", "Repudiation", "Inability to attribute actions to an agent, enabling deniability."),
        ("M7.10", "Compromised Agent Registry", "Subverting the registry agents are published to or discovered from."),
        ("M7.11", "Malicious Agent Discovery", "Luring users or agents into discovering and using malicious agents."),
        ("M7.12", "Agent Pricing Model Manipulation", "Manipulating usage or pricing to cause financial harm."),
        ("M7.13", "Inaccurate Agent Capability Description", "Misrepresenting agent capabilities to mislead consumers."),
    ],
    "Cross-Layer": [
        ("MX.1", "Supply Chain Attacks", "Compromise propagating through shared dependencies across layers."),
        ("MX.2", "Lateral Movement", "An attacker moving between layers or components after an initial foothold."),
        ("MX.3", "Privilege Escalation", "Gaining higher privileges spanning multiple layers."),
        ("MX.4", "Data Leakage", "Sensitive data crossing trust boundaries between layers."),
        ("MX.5", "Goal Misalignment Cascades", "Misaligned goals in one layer cascading into failures across others."),
    ],
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportMAESTRO] {msg}", flush=True)


def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS MAESTROLAYER (
        MaestroLayerID INTEGER PRIMARY KEY, LayerNumber INTEGER, Name TEXT UNIQUE, Description TEXT,
        IsVertical INTEGER, MatrixOrder INTEGER, URL TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS MAESTROTHREAT (
        MaestroThreatID INTEGER PRIMARY KEY, MaestroID TEXT UNIQUE, Name TEXT, Description TEXT,
        LayerName TEXT, IsCrossLayer INTEGER, MatrixOrder INTEGER, URL TEXT)""")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_maestrothreat_layer ON MAESTROTHREAT(LayerName)")

    for order, (num, name, vert, desc) in enumerate(LAYERS, start=1):
        cur.execute(
            """INSERT INTO MAESTROLAYER (LayerNumber, Name, Description, IsVertical, MatrixOrder, URL)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(Name) DO UPDATE SET LayerNumber=excluded.LayerNumber,
                 Description=excluded.Description, IsVertical=excluded.IsVertical,
                 MatrixOrder=excluded.MatrixOrder, URL=excluded.URL""",
            (num, name, desc, vert, order, URL),
        )

    order = 0
    for layer_name, threats in THREATS.items():
        is_cross = 1 if layer_name == "Cross-Layer" else 0
        for mid, tname, tdesc in threats:
            order += 1
            cur.execute(
                """INSERT INTO MAESTROTHREAT (MaestroID, Name, Description, LayerName, IsCrossLayer, MatrixOrder, URL)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(MaestroID) DO UPDATE SET Name=excluded.Name, Description=excluded.Description,
                     LayerName=excluded.LayerName, IsCrossLayer=excluded.IsCrossLayer,
                     MatrixOrder=excluded.MatrixOrder, URL=excluded.URL""",
                (mid, tname, tdesc, layer_name, is_cross, order, URL),
            )
    conn.commit()
    nl = cur.execute("SELECT COUNT(*) FROM MAESTROLAYER").fetchone()[0]
    nt = cur.execute("SELECT COUNT(*) FROM MAESTROTHREAT WHERE IsCrossLayer=0").fetchone()[0]
    nx = cur.execute("SELECT COUNT(*) FROM MAESTROTHREAT WHERE IsCrossLayer=1").fetchone()[0]
    conn.close()
    log(f"Done ({now()}) — {nl} layers, {nt} layer threats, {nx} cross-layer threats in XTHREAT.MAESTRO*.")


if __name__ == "__main__":
    main()
