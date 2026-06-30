# AVE connector

Imports the **AVE catalogue** ([github.com/bawbel/ave](https://github.com/bawbel/ave), Apache-2.0, by bawbel) — *Agentic Vulnerability Enumeration*, the behavioral-classification standard for agentic-AI components — into XORCISM's reference store (`XVULNERABILITY.AVERECORD`), surfaced at **`/ave`**.

## Why AVE

CVE / OSV describe vulnerabilities in *packages with versions*. They can't describe prompt injection, tool-allowlist breaches, metamorphic supply-chain payloads, memory poisoning or denial-of-wallet in **AI agents, skill files, MCP servers and system prompts** — there is no package version to track. AVE fills that gap: it assigns stable **AVE-2026-#####** ids and **AIVSS** scores (OWASP AIVSS v0.8 — a CVSS base amplified by agentic factors: autonomy, tool-use, self-modification, multi-agent, non-determinism, …) to *behavioral* vulnerability classes, and maps each to the **OWASP Agentic Top 10**, **OWASP MCP Top 10**, **MITRE ATLAS** and **NIST AI RMF**.

## How it works

Import-type, worker-safe, read-only — it parses an exported AVE catalogue and performs no scanning. It accepts:

- a `records.json` / `{ "records": [...] }` / top-level array export,
- a single `AVE-####.json` record file, or
- (via `dir`) a directory of `AVE-####.json` files — e.g. the `records/` folder of the AVE repo.

Each record → `XVULNERABILITY.AVERECORD` (via the runner's `import_ave_records`), idempotent by `ave_id`. Severity is taken from the record (or derived from the AIVSS score: CRITICAL ≥9.0 / HIGH ≥7.0 / MEDIUM ≥4.0 / LOW). The catalogue then shows in `/ave` and can be mapped from AI Guardrails / AWARE / the LLM-pentest module onto a stable taxonomy.

## Parameters

| name | type | required | notes |
|------|------|----------|-------|
| `file` | file | no | An AVE records export (records.json / `{records:[]}` / array / single record). Defaults to the bundled `sample.json`. |
| `dir` | string | no | A directory of `AVE-####.json` files (the AVE repo's `records/` folder). |
| `source` | string | no | Source label stamped on imported records (default `AVE`). |

## Dry-run

```bash
python run.py                 # bundled sample
python run.py records.json    # your own AVE export
```

The bundled `sample.json` is a representative subset authored to the AVE record schema. To load the full registry, clone the AVE repo and point `dir` at its `records/` folder.
