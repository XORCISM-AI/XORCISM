# Ncrack

`ncrack` · **import** connector · category **Password Cracking** · ⚠️ **intrusive** (engagement scope enforced)

High-speed network authentication cracking tool from the Nmap project. Tool: https://nmap.org/ncrack/. [SCAFFOLD generated from XORCISM.TOOL #71 by tool_to_connector.py — implement run() in run.py to map Ncrack output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://nmap.org/ncrack/

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved Ncrack output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Ncrack*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:ncrack`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
