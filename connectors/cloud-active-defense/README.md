# Cloud Active Defense

`cloud-active-defense` · **import** connector · category **Honeypot**

Cloud active defense lets you deploy decoys right into your cloud applications, putting adversaries into a dilemma: to hack or not to hack? Tool: https://github.com/SAP/cloud-active-defense?tab=readme-ov-file. [SCAFFOLD generated from XORCISM.TOOL #351 by tool_to_connector.py — implement run() in run.py to map Cloud Active Defense output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/SAP/cloud-active-defense?tab=readme-ov-file

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved Cloud Active Defense output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Cloud Active Defense*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:cloud-active-defense`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
