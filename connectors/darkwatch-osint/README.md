# DARKWATCH-OSINT — dark-web asset monitoring

`darkwatch-osint` · **import** connector · category **monitoring**

Imports dark-web monitoring alerts from DARKWATCH-OSINT (defensive .onion crawling / digital-risk-protection platform by K3lgy, https://github.com/K3lgy/DARKWATCH-OSINT). Monitored assets that surface in data leaks, ransomware posts or exploit sales become ASSETs, and each alert becomes a finding (data-leak / ransomware / exploit exposure). Extracted entities (domains, IPs, emails, file hashes) are mapped to assets where possible. Read-only import (non-intrusive): DARKWATCH-OSINT itself runs on YOUR infrastructure (Tor + crawler + Elasticsearch); this connector only ingests its output. Config via worker environment variables (NEVER in the UI): DARKWATCH_API_URL (optional, e.g. http://127.0.0.1:8080), DARKWATCH_API_KEY (optional), DARKWATCH_VERIFY_TLS (0 to skip TLS verification). Offline mode: supply a saved alerts/entities JSON export through the 'file' parameter. The API mode needs `pip install requests` on the worker.

**Upstream:** https://github.com/K3lgy/DARKWATCH-OSINT

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `brand` | string | yes | — | Organisation / brand / asset under monitoring (e.g. example.com). Labels the findings and is the fallback asset for alerts with no extractable host. |
| `file` | file | no | — | Path on the worker to a DARKWATCH-OSINT export (JSON: alerts and/or monitored entities). If omitted, DARKWATCH_API_URL is queried. |
| `limit` | int | no | `2000` | Maximum number of alerts/entities to import. (range 1–50000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *DARKWATCH-OSINT — dark-web asset monitoring*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:darkwatch-osint`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/darkwatch-osint/sample.json --connector darkwatch-osint
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
