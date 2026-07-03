# Microsoft Agent Governance Toolkit connector

Imports a **[Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)**
(AGT, MIT) export bundle into XORCISM.

AGT is a middleware framework that enforces **deterministic governance** for autonomous AI agents:
a policy engine (allow / deny / require‑approval / transform / log), zero‑trust agent identity
(SPIFFE/DID/mTLS), execution sandboxing (privilege rings), **tamper‑evident decision records**
(Merkle audit) and **OWASP Agentic Top 10 verification** (`agt verify`) — mapped to NIST AI RMF,
EU AI Act and SOC 2.

## What it does

Parses an AGT export bundle (JSON) and normalises it to XORCISM findings:

| AGT artifact | → XORCISM |
|---|---|
| governed agent / registration | **ASSET** (an AI‑agent asset) |
| failing OWASP Agentic Top 10 category (`agt verify`) | **VULNERABILITY** tagged `ASI‑T#` (severity from grade/severity) |
| MCP‑gateway / tool finding (poisoning · drift · typosquatting) | **VULNERABILITY** |
| blocked policy violations (deny / require‑approval decision records) | one per‑agent **VULNERABILITY** summarising the denials (T8) |

Findings feed the exposure / vulnerability views, the **Agent Policy Firewall** (`/agent-firewall`)
and AI‑guardrails. XORCISM's Agent Policy Firewall then **replicates the same OWASP Agentic Top 10
verification** from its own deterministic controls (deny‑by‑default, approval gates, SoD, replay‑block,
blast‑radius gate, signed receipt chain) — see `GET /api/agent-firewall/owasp-agentic`.

## Usage

Worker‑safe & read‑only — this connector never runs AGT or any agent; the operator runs AGT and feeds
the export here.

```bash
# 1) Produce an AGT bundle (on the operator side)
agt verify --evidence ./evidence.json          # OWASP Agentic verification evidence
#   …or a decision-records / registry export.

# 2) Offline dry run of the connector (built-in sample if no --file)
python connectors/agent-governance-toolkit/run.py --file ./evidence.json --agent invoice-agent

# 3) In XORCISM: /connectors → "Microsoft Agent Governance Toolkit" → upload the bundle.
```

### Parameters

- `file` (required) — an AGT export bundle JSON (an object, or an array of findings; the parser is
  defensive about the exact shape).
- `agent` — override the agent/asset name (default: read from the bundle's `agent` / `name` / `target`).
- `min_severity` — `info|low|medium|high|critical`, minimum severity to import (default `low`).

Normalized result: `{assets, vulns, intel, source:"agent-governance-toolkit"}`.

## OWASP Agentic Top 10 (ASI T1–T10)

T1 Memory Poisoning · T2 Tool Misuse · T3 Privilege Compromise · T4 Resource Overload ·
T5 Cascading Hallucination · T6 Intent Breaking & Goal Manipulation · T7 Misaligned & Deceptive
Behaviors · T8 Repudiation & Untraceability · T9 Identity Spoofing & Impersonation ·
T10 Overwhelming Human‑in‑the‑Loop.

## License

The connector code is part of XORCISM. Microsoft Agent Governance Toolkit is MIT‑licensed; this
connector only **parses its exported JSON** (no AGT code is copied or vendored).
