# AWARE connector

Imports from [**AWARE**](https://github.com/GoodCISO/aware) (by GoodCISO, Apache-2.0) — open-source
**autonomous-compliance infrastructure for AI agent systems**. AWARE governs autonomous agents with a
cryptographic non-human identity, audit trails, a parent→child **revocation cascade** (kill-switch),
**constraint-enforcement tiers T0–T4**, and compliance mapping to CSA AICM / NIST AI RMF / ISO 27001 /
DORA / OWASP-LLM.

XORCISM natively models the AWARE concepts (tiers, cryptographic identity, hierarchy + cascade) on its
discovered AI agents — see the **/aware** governance cockpit. This connector brings an external AWARE
deployment's state into XORCISM.

## What it maps

| AWARE export | Normalized as | XORCISM |
| :--- | :--- | :--- |
| Governed agents (tier, identity, parent) | `aware_agents` | **XAGENT.AIAGENT** (constraint tier T0–T4, identity fingerprint, parent agent) → `/aware` + AI Guardrails |
| Policy / guardrail enforcement violations | `guardrail_violations` | **XAGENT.AIGUARDRAILVIOLATION** (blocked/flagged events) → AI Guardrails cockpit |

Constraint tiers are normalized from any of `4` / `"T4"` / `"autonomous"` → `T4`, etc.

## Read-only & worker-safe

Parses an exported AWARE JSON only — it never calls AWARE or any live endpoint, and writes nothing back.

### Parameters

| Param | Required | Description |
| :--- | :--- | :--- |
| `file` | yes | An AWARE export JSON: `{agents:[…], violations:[…]}` (or a bare array of agents). |
| `limit` | no | Max agents to import (default 1000). |

## Offline dry run

```bash
python run.py                    # built-in sample (4 governed agents + 2 violations)
python run.py --file export.json # parse a real AWARE export
```

## Note

This connector imports AWARE's *state*. The native AWARE governance — assigning tiers, minting
cryptographic identities, the revocation cascade kill-switch, and the AICM/NIST-AI-RMF/ISO-27001/DORA/
OWASP-LLM mapping — is managed in the **/aware** cockpit over XORCISM's own discovered AI agents.
Enforcement of the T2/T3 policy constraints runs in the **Agent Policy Firewall** (`/agent-firewall`).
