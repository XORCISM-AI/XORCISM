# django-admin-honeypot

`django-admin-honeypot` · **import** connector · category **Honeypot**

Fake Django admin login screen to notify admins of attempted unauthorized access. Tool: https://github.com/dmpayton/django-admin-honeypot. [SCAFFOLD generated from XORCISM.TOOL #368 by tool_to_connector.py — implement run() in run.py to map django-admin-honeypot output to the XORCISM findings model {assets, services, cpes, vulns}.]

**Upstream:** https://github.com/dmpayton/django-admin-honeypot

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | string | no | — | Host, URL or path the tool acts on. When implementing, consider type 'target' or 'url' so the runner enforces the engagement scope. |
| `file` | file | no | — | Offline mode: a saved django-admin-honeypot output file to parse instead of running it live. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *django-admin-honeypot*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:django-admin-honeypot`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
