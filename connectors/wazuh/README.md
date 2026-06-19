# Wazuh

`wazuh` · **import** connector · category **SIEM**

Imports endpoint inventory and vulnerability findings from Wazuh (https://wazuh.com), the open-source XDR/SIEM. Each Wazuh agent becomes an ASSET (name + IP + OS); syscollector packages become components/CPEs; vulnerability-detector findings become VULNERABILITIES (CVE + severity) attached to their agent. Offline mode: parse a saved Wazuh API JSON (an /agents or /vulnerability/{agent} response, shape {data:{affected_items:[...]}}, or a {agents,vulnerabilities,packages} bundle). Live mode: if `manager` (or WAZUH_API_URL) is set and WAZUH_API_USER/WAZUH_API_PASSWORD are in the worker env, authenticates (JWT) and pulls agents + per-agent vulnerabilities (needs `pip install requests`). Read-only API queries (non-intrusive). No DB access in run.py (worker-safe).

**Upstream:** https://wazuh.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a saved Wazuh API JSON (/agents, /vulnerability/{agent}, or a {agents,vulnerabilities,packages} bundle) to import. |
| `manager` | string | no | — | Live mode: Wazuh server API base URL, e.g. https://wazuh.example:55000 (else WAZUH_API_URL in the worker env). Credentials come from WAZUH_API_USER/WAZUH_API_PASSWORD. |
| `agent` | string | no | — | Optional: agent name to attribute vulnerabilities to when an offline vulnerability export lacks the agent context. |
| `limit` | int | no | `200` | Live mode: maximum number of agents to enrich with vulnerabilities/packages. (range 1–5000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Wazuh*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:wazuh`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
