# Praxen connector (AI agent behavior verification)

Imports a [Praxen](https://open-agent-ai-security.github.io/praxen/) report into XORCISM. Praxen (by
**Exabeam** / the Open Agent AI Security community, Apache-2.0) verifies that an AI agent **does its job
— and only its job**: it compares the agent's declared **Worker Remit** (mission, authorized tools,
channels, counterparties, forbidden actions) against the agent's actual **source code, deployment config
and conversation logs**, like an auditor reading the workspace.

## What it flags
- **Policy-implementation divergence** — code behaviour that contradicts the declared policy
- **Credential / secret exposure** in the workspace
- **Missing controls** — no rate limit, no loop detection, …
- **Capability drift** — unauthorized tools or outbound destinations
- **Hidden secondary prompts** (e.g. a `SOUL.md`)
- **Compound attack paths** — chained findings (credential + outbound = exfiltration)

Findings map to the **OWASP Top 10 for LLM Applications (2025)** and the **OWASP Top 10 for Agentic AI
(2026)**, with a **RAISE** 0–5 maturity score.

## Mapping
- the analyzed agent → an **`ASSET`** (tags `praxen, ai-agent`)
- each finding → a **`VULNERABILITY`** on the agent (severity from the finding), **and** an OWASP-LLM
  `fail` result for the LLM red-team / AI-BAS module. Praxen finding categories are mapped to OWASP-LLM:

| Praxen finding | OWASP-LLM |
|---|---|
| Credential / secret exposure, exfiltration | LLM02 Sensitive information disclosure |
| Capability drift, unauthorized tool/destination, policy divergence | LLM06 Excessive agency |
| Hidden / secondary system prompt | LLM07 System prompt leakage |
| Missing rate limit / loop detection | LLM10 Unbounded consumption |
| Improper output handling (SQLi/XSS/SSRF/cmd via output) | LLM05 Improper output handling |
| Unverified model / dependency | LLM03 Supply chain |
| Prompt injection | LLM01 Prompt injection |

(an explicit `owasp` id on the finding always wins over the keyword inference).

## Usage
Run Praxen on your agent (plugin for Claude Code & compatible agents), then import its JSON report:
```bash
claude plugin marketplace add open-agent-ai-security/praxen
claude plugin install praxen@open-agent-ai-security
# "Run a Praxen behavior analysis on ./my-agent"  → writes ./reports/<run>.json
# then import that JSON via the connector (file param), or:
python run.py                                       # demo (bundled FinBot sample)
```

The normalized `{assets, vulns}` is consumed by `runner.import_findings` (so it rolls into engagements
and **attack chains** — it seeds the *AI agent assessment* playbook in `chain.ts`), and the
`{aibas:{results}}` list is POSTed to `POST /api/ai-redteam/import/<aiSystemId>` to auto-fill the
**LLM Pentest Methodology** (`/llm-pentest`). Worker-safe: stdlib only, ASCII-only output, no DB access.
