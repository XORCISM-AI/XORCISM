# RedAmon

`redamon` · **import** connector · category **Exploitation**

Imports findings from RedAmon (https://github.com/samugit83/redamon), an autonomous AI red-team framework (recon + exploitation + post-exploitation) that builds a Neo4j attack-surface graph and exports JSON scan results. This connector parses RedAmon's exports and maps them into XORCISM: discovered hosts / domains / subdomains / IPs become ASSETs; open ports / services / detected technologies become services & CPEs on those assets; vulnerability findings (Nuclei templates, GVM/OpenVAS NVTs, CVEs) become VULNERABILITYs (CVE/template ref + severity). Reads a single JSON/JSONL export ('file'), a directory of exports ('dir'), or pulls JSON from a RedAmon backend export URL ('endpoint', authenticated with the REDAMON_API_KEY worker env var). Defensive multi-shape parser (findings lists, Nuclei JSONL, host/port records, Neo4j node exports). Import-only — it does NOT run the RedAmon framework or any LLM. No XORCISM DB access in run.py (worker-safe). Secrets via worker env only (REDAMON_API_KEY), never in the manifest or UI.

**Upstream:** https://github.com/samugit83/redamon

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a RedAmon JSON / JSON-lines export to import. |
| `dir` | string | no | — | Path to a directory of RedAmon exports — every *.json / *.jsonl inside is imported. |
| `endpoint` | url | no | — | Optional RedAmon backend export URL returning JSON findings; sent with 'Authorization: Bearer <REDAMON_API_KEY>' (worker env). |
| `target` | target | no | — | Default engagement target (host or URL) for findings that don't carry their own; must be within the engagement scope. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *RedAmon*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:redamon`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
