# NetExec

`netexec` · **import** connector · category **Credential Access** · ⚠️ **intrusive** (engagement scope enforced)

Maintained successor to CrackMapExec for network exploitation. Tool: https://github.com/Pennyw0rth/NetExec. [SCAFFOLD generated from XORCISM.TOOL #75 by tool_to_connector.py — implement run() in run.py to map NetExec output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/Pennyw0rth/NetExec

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved NetExec output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *NetExec*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:netexec`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
