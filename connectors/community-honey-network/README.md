# Community Honey Network

`community-honey-network` · **import** connector · category **Honeypot**

CHN aims to make deployments honeypots and honeypot management tools easy and flexible. The default deployment method uses Docker Compose and Docker to deploy with a few simple commands. Tool: https://communityhoneynetwork.readthedocs.io/en/stable/. [SCAFFOLD generated from XORCISM.TOOL #450 by tool_to_connector.py — implement run() in run.py to map Community Honey Network output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://communityhoneynetwork.readthedocs.io/en/stable/

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved Community Honey Network output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Community Honey Network*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:community-honey-network`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
