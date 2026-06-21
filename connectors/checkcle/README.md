# CheckCle

`checkcle` · **import** connector · category **Monitoring**

CheckCle — open-source full-stack monitoring (uptime HTTP/DNS/Ping/TCP, server CPU/RAM/disk, SSL/domain expiry, incidents, status pages). Imports CheckCle's monitored services / servers / SSL certificates into XORCISM Asset Monitoring (MONITORINGCHECK) and its incidents (MONITORINGINCIDENT). Tool: https://github.com/operacle/checkcle. Parses an exported JSON, or pulls live from CheckCle's PocketBase API — CHECKCLE_URL + CHECKCLE_TOKEN, or CHECKCLE_USER + CHECKCLE_PASSWORD (PocketBase auth).

**Upstream:** https://github.com/operacle/checkcle

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline: a CheckCle JSON export — {services,servers,ssl,incidents}, a PocketBase {items:[…]} page, or a flat list of records (type auto-detected). |
| `base` | string | no | — | CheckCle base URL (PocketBase, e.g. http://host:8090). Overrides CHECKCLE_URL. Live mode needs CHECKCLE_TOKEN or CHECKCLE_USER + CHECKCLE_PASSWORD. |
| `collections` | string | no | — | Comma-separated PocketBase collections to pull (default: services,servers,ssl_certificates,incident). |
| `max_items` | int | no | `1000` | Maximum records to import per collection. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *CheckCle*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:checkcle`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/checkcle/sample.json --connector checkcle
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
