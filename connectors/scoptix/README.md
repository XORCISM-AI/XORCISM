# SCOPTIX — passive attack-surface recon

`scoptix` · **import** connector · category **Recon**

Imports passive attack-surface findings from SCOPTIX (https://github.com/Omnitarium/scoptix). Discovered subdomains / IPs become ASSETs (and host facts for the tool-chaining engine), URLs become web SERVICEs, and exposed secrets / API keys / credentials become VULNERABILITY findings — the secret value/snippet is REDACTED; only its type and location are recorded. SCOPTIX is a web dashboard with no CLI, so this connector is import-only: export a scan from SCOPTIX (CSV per type — findings / subdomains / urls / ips — or the 'all' ZIP) and pass the file. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/Omnitarium/scoptix

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a SCOPTIX CSV export (findings/subdomains/urls/ips.csv) or the 'all' ZIP. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *SCOPTIX — passive attack-surface recon*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:scoptix`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
