# FCaptcha

`fcaptcha` · **import** connector · category **Honeypot**

Self-hosted CAPTCHA that acts as an inline honeypot, detecting bots and vision AI agents through 40+ behavioral signals, headless browser fingerprinting, and SHA-256 proof of work. Tool: https://github.com/WebDecoy/FCaptcha. [SCAFFOLD generated from XORCISM.TOOL #354 by tool_to_connector.py — implement run() in run.py to map FCaptcha output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/WebDecoy/FCaptcha

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved FCaptcha output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *FCaptcha*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:fcaptcha`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
