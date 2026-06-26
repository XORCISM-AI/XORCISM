# Strix connector (autonomous AI pentest)

Imports findings from [Strix](https://github.com/usestrix/strix) — the open-source **autonomous AI
hacking agent** by usestrix (Apache-2.0). Strix runs AI agents that act like real pentesters: they
dynamically test a codebase, GitHub repo, web app or API, **exploit** issues and **validate** them with a
proof-of-concept.

## What it finds
IDOR / auth bypass / privilege escalation · SQL/NoSQL/command injection · SSRF / XXE / insecure
deserialization · XSS / prototype pollution / DOM flaws · business-logic & race conditions ·
JWT / session weaknesses · infrastructure misconfigurations — each with a **PoC and reproduction steps**.

## Mapping
The assessed target → an `ASSET` (tags `strix, ai-pentest`); each validated finding → a
`VULNERABILITY / ASSETVULNERABILITY` (severity from the finding, the vuln class / **CWE** and the PoC in
the description, ref `CWE-NNN-<id>`). Consumed by `runner.import_findings`, so it rolls into engagements
and **attack chains** (it seeds the *Autonomous AI pentest (Strix)* playbook in `chain.ts`).

## Usage
```bash
pip install strix-agent        # (or the curl installer); requires Docker + an LLM API key
export STRIX_LLM="openai/gpt-5.4"; export LLM_API_KEY="..."
strix --target https://your-app.com        # or ./code-dir, or a GitHub repo URL
# Strix writes results to strix_runs/<run-name>/ — import its findings JSON via the connector (file param), or:
python run.py                               # demo (bundled sample, 5 findings)
```
Worker-safe: stdlib only, ASCII-only output, no DB access. Returns `{project, assets, vulns}`.
