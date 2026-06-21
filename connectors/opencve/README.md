# OpenCVE

`opencve` · **import** connector · category **Threat Intelligence**

OpenCVE — CVE monitoring & alerting platform (self-hosted or app.opencve.io). Pulls CVEs from the OpenCVE REST API (filtered by vendor / product / keyword / CVSS severity / tag) and imports them as vulnerabilities (XVULNERABILITY). Tool: https://www.opencve.io. Auth from the worker environment: OPENCVE_API_TOKEN (Bearer org token) OR OPENCVE_USERNAME + OPENCVE_PASSWORD (Basic, legacy v1); base URL via OPENCVE_URL or the 'base' parameter.

**Upstream:** https://www.opencve.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `base` | string | no | — | OpenCVE base URL (e.g. https://app.opencve.io or your self-hosted instance). Overrides OPENCVE_URL. Default: https://app.opencve.io. |
| `vendor` | string | no | — | Filter CVEs by vendor name (OpenCVE slug, e.g. 'microsoft'). |
| `product` | string | no | — | Filter CVEs by product name (used with vendor). |
| `search` | string | no | — | Keyword filter on CVE id or description. |
| `cvss` | enum | no | — | Filter by CVSS 3.1 severity. When set, it also sets each imported finding's severity. (one of: ``, `low`, `medium`, `high`, `critical`) |
| `tag` | string | no | — | Filter by an OpenCVE user tag. |
| `details` | bool | no | `False` | Fetch each CVE's detail to populate the exact CVSS score & CWE (one extra request per CVE — slower; bounded by max_items). |
| `max_items` | int | no | `200` | Maximum CVEs to import (paginated). |
| `project` | string | no | — | Optional asset name to attach the CVEs to (creates ASSETVULNERABILITY links). Omit to only enrich the CVE database. |
| `file` | file | no | — | Offline mode: a saved OpenCVE JSON response to parse instead of calling the API ({results:[...]}, a bare list, or a single CVE). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *OpenCVE*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:opencve`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/opencve/sample.json --connector opencve
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
