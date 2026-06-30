# offsec-ai connector

Imports an [**offsec-ai**](https://github.com/Htunn/offsec-ai) (by Htunn, MIT) JSON report into XORCISM.

**offsec-ai** is an offensive-security toolkit (Python library + CLI) that pairs classic network
reconnaissance with **AI/LLM security testing** for authorized red-team engagements:

- **OWASP LLM Top 10 scanner** — probes live LLM/chat endpoints for prompt injection, insecure output
  handling, sensitive-information disclosure, etc. (rule-based + optional LLM judge).
- **MCP (Model Context Protocol) security** — scans **and actively attacks** MCP servers for known CVEs,
  auth bypass, path traversal and tool/command injection. The active attack is gated behind
  `--i-have-authorization`.
- **Infrastructure checks** — async port scan, L7 WAF/CDN detection, mTLS verification, certificate-chain
  analysis, Azure AD/ADFS hybrid-identity discovery, web OWASP Top 10 (2021 & 2025) and security-header
  grading. Exports PDF / JSON / CSV.

This connector is **import-type and worker-safe**: it parses a JSON report that *you* produced by running
offsec-ai yourself. It never runs offsec-ai, never touches the target, and never performs the active
(authorized) MCP attack — so it is safe to run from the XORCISM worker. All offensive activity stays in
your hands and under your authorization.

## What it maps

| offsec-ai | XORCISM |
| :--- | :--- |
| scanned endpoint / host (`target` / `host` / `url` / `endpoint`) | **ASSET** |
| open ports / services | **CPEs** linked to the asset (feeds the CVE matcher) |
| each OWASP-LLM / MCP / web / TLS / header finding | **VULNERABILITY** (ref + severity + name; any embedded `CVE-…` becomes the ref) |

Findings that *pass* (grade A / `status: pass`) are ignored; only failing/vulnerable items are imported.

## Usage

1. Run offsec-ai and export JSON, e.g.:
   ```bash
   offsec-ai ai-owasp-scan https://api.example.com/v1/chat/completions --output json > report.json
   # or: offsec-ai mcp-scan … / owasp-scan … / scan … / cert-check …
   ```
2. In XORCISM → **Connectors → offsec-ai**, upload `report.json`.

### Parameters

| Param | Required | Description |
| :--- | :--- | :--- |
| `file` | yes | The offsec-ai JSON report (an object, or an array of findings). |
| `target` | no | Override the asset name (default: read from the report). |
| `min_severity` | no | `info\|low\|medium\|high\|critical` — minimum severity to import (default `low`). |

## Offline dry run

```bash
python run.py                       # uses a built-in sample report
python run.py --file report.json    # parse a real offsec-ai report
python run.py --file report.json --min-severity high
```

The connector understands several offsec-ai report shapes defensively (flat `findings`/`vulnerabilities`
lists, OWASP `categories` maps with grades, MCP `tools`/`cves`, and nested `scan`/`web`/`infra`/`mcp`
blocks), so it works across the `ai-owasp-scan`, `mcp-scan`, `owasp-scan`, `scan` and `cert-check`
report variants.

## Attack-chain playbook

Seeding `offsec-ai` drives the **"AI/LLM & MCP red-team (offsec-ai)"** playbook (`/attack-chain`):
every imported finding is escalated to **CyberSentinel AI** for deep analysis (AI triage + MITRE ATT&CK
mapping), and the results feed the exposure, attack-path, AI-guardrails and vulnerability views.
