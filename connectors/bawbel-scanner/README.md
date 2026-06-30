# bawbel-scanner connector

Imports the output of the **bawbel-scanner** — the reference scanner for **AVE** (Agentic Vulnerability Enumeration, [github.com/bawbel/ave](https://github.com/bawbel/ave), Apache-2.0) — into XORCISM's `AVESCANFINDING`, surfaced in the **Scan findings** view of **`/ave`**.

## What it does

`pip install bawbel-scanner` scans agentic-AI components — **skill files, MCP server manifests, system prompts, agent components** — for behavioral vulnerability classes and prints / emits findings like:

```
CRITICAL  bawbel-confused-deputy       AVE-2026-00007  mcp/payments-server.json:42  AIVSS 9.1
HIGH      bawbel-external-fetch        AVE-2026-00001  skills/data-fetcher.md:14    AIVSS 8.0
HIGH      bawbel-indirect-injection    AVE-2026-00015  prompts/agent-system.txt:7   AIVSS 7.4
```

For machine ingestion it emits **AVE-in-SARIF 2.1.0**: each `result` references an `AVE-2026-#####` rule (carrying the AIVSS score + OWASP MCP / MITRE ATLAS mappings), with a `file:line` location, a `confidence` float and the detection engine. This connector parses that.

This is the **per-artifact detection** path — real findings located in your components — and complements the inferred **Agent exposure** assessment on `/ave` (which maps the AVE catalogue onto discovered agents). Together: the catalogue (what AVE classes exist) → the scan findings (what was actually detected in your code) → the agent exposure (what your live agents are exposed to).

## How it works

Import-type, worker-safe, read-only — it parses an exported report and performs **no scanning or code execution**. It accepts:

- **AVE-in-SARIF 2.1.0** (`bawbel-scanner --sarif out.sarif`) — recommended,
- a flat `{ "findings": [...] }` / top-level array JSON.

Each finding → `XVULNERABILITY.AVESCANFINDING` (via the runner's `import_ave_scan_findings`), cross-linked to the AVE catalogue by `ave_id`. A scan run is a **snapshot**: re-importing the same `source` replaces its previous findings.

## Producing the input

```bash
pip install bawbel-scanner
bawbel-scanner scan ./my-agent-repo --sarif scan.sarif        # AVE-in-SARIF (recommended)
bawbel-scanner scan ./my-agent-repo --json findings.json      # flat JSON findings
```

## Parameters

| name | type | required | notes |
|------|------|----------|-------|
| `file` | file | no | A bawbel-scanner report (AVE-in-SARIF or flat findings). Defaults to the bundled `sample.sarif.json`. |
| `source` | string | no | Source label (default `bawbel-scanner`). Re-importing the same source replaces its snapshot. |
| `scan_ref` | string | no | Optional scan reference (repo / branch / commit / run id). |

## Dry-run

```bash
python run.py                      # bundled sample SARIF
python run.py scan.sarif           # your own bawbel-scanner SARIF
```
