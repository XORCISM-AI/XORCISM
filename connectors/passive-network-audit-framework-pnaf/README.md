# Passive Network Audit Framework (pnaf)

`passive-network-audit-framework-pnaf` · **import** connector · category **Honeypot**

Framework that combines multiple passive and automated analysis techniques in order to provide a security assessment of network platforms. Tool: https://github.com/jusafing/pnaf. [SCAFFOLD generated from XORCISM.TOOL #463 by tool_to_connector.py — implement run() in run.py to map Passive Network Audit Framework (pnaf) output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/jusafing/pnaf

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved Passive Network Audit Framework (pnaf) output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Passive Network Audit Framework (pnaf)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:passive-network-audit-framework-pnaf`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
