# EyeWitness

`eyewitness` · **import** connector · category **Recon** · ⚠️ **intrusive** (engagement scope enforced)

Captures screenshots of websites and fingerprints services. Tool: https://github.com/RedSiege/EyeWitness. [SCAFFOLD generated from XORCISM.TOOL #54 by tool_to_connector.py — implement run() in run.py to map EyeWitness output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/RedSiege/EyeWitness

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved EyeWitness output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *EyeWitness*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:eyewitness`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
