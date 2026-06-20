# Google Guide Advanced Operators

`google-guide-advanced-operators` · **import** connector · category **OSINT**

Reference for Google search operators Tool: http://www.googleguide.com/advanced_operators_reference.html. [SCAFFOLD generated from XORCISM.TOOL #1094 by tool_to_connector.py — implement run() in run.py to map Google Guide Advanced Operators output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** http://www.googleguide.com/advanced_operators_reference.html

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved Google Guide Advanced Operators output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Google Guide Advanced Operators*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:google-guide-advanced-operators`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
