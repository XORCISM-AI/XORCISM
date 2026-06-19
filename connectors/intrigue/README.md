# Intrigue Core — attack surface / OSINT discovery

`intrigue` · **import** connector · category **recon**

Imports discovered entities from a running Intrigue Core instance (attack-surface mapping / OSINT) via its REST API. Domains / DNS records / hosts / IP addresses become ASSETs; URIs become assets with a service. Read-only API import (non-intrusive). Configure via worker environment variables (never in the UI): INTRIGUE_CORE_URL (e.g. http://127.0.0.1:7777), INTRIGUE_CORE_API_KEY, INTRIGUE_VERIFY_TLS (0 to skip). Requires `pip install requests` on the worker.

**Upstream:** http://127.0.0.1:7777

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `project` | string | yes | — | Intrigue Core project name to import entities from. |
| `limit` | int | no | `2000` | Maximum number of entities to import. (range 1–50000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Intrigue Core — attack surface / OSINT discovery*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:intrigue`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/intrigue/sample.json --connector intrigue
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
