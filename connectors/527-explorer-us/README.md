# 527 Explorer (US)

`527-explorer-us` · **import** connector · category **Public Records OSINT**

Public Records OSINT. OSINT tool from the OSINT Newsletter tools library (https://tools.osintnewsletter.com/). Tool: https://tools.osintnewsletter.com/osint-tools/527-explorer. [SCAFFOLD generated from XORCISM.TOOL #248 by tool_to_connector.py — implement run() in run.py to map 527 Explorer (US) output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://tools.osintnewsletter.com/

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved 527 Explorer (US) output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *527 Explorer (US)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:527-explorer-us`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
