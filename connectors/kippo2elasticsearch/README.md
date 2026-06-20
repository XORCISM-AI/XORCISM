# Kippo2ElasticSearch

`kippo2elasticsearch` · **import** connector · category **Honeypot**

Python script to transfer data from a Kippo SSH honeypot MySQL database to an ElasticSearch instance (server or cluster). Tool: https://bruteforcelab.com/kippo2elasticsearch. [SCAFFOLD generated from XORCISM.TOOL #462 by tool_to_connector.py — implement run() in run.py to map Kippo2ElasticSearch output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://bruteforcelab.com/kippo2elasticsearch

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved Kippo2ElasticSearch output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Kippo2ElasticSearch*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:kippo2elasticsearch`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
