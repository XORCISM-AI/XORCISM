# DShield docker

`dshield-docker` · **import** connector · category **Honeypot**

Docker container running cowrie with DShield output enabled. Tool: https://github.com/xme/dshield-docker. [SCAFFOLD generated from XORCISM.TOOL #540 by tool_to_connector.py — implement run() in run.py to map DShield docker output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/xme/dshield-docker

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved DShield docker output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *DShield docker*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:dshield-docker`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
