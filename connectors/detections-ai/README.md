# detections.ai — Intel Exchange (threat intel)

`detections-ai` · **import** connector · category **threat-intel**

Gathers community threat-intelligence reports from the detections.ai Intel Exchange (https://detections.ai/intel-exchange) using a REAL headless browser (Playwright/Chromium), capturing the JSON its single-page app loads from the BFF API (/bff/api/v1/intel). Each report (title, summary, author, date, MITRE ATT&CK techniques, adversary groups, malware/tools, CVE references, views) is imported into XTHREAT.INTELEXCHANGE — idempotent by source URL — and its ATT&CK techniques are cross-linked into INTELEXCHANGEATTACK so they appear in the ATT&CK matrix coverage. Read-only, non-intrusive, no authentication. Worker setup: pip install playwright && playwright install chromium. Offline/air-gapped import is possible via the 'file' parameter (a saved BFF JSON payload).

**Upstream:** https://detections.ai/intel-exchange

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max_items` | int | no | `60` | Maximum number of intel-exchange items to import (most recent first). (range 1–500) |
| `headful` | bool | no | `False` | Run the browser with a visible window (debugging). Default: headless. |
| `file` | file | no | — | Offline mode: import from a saved JSON payload (the BFF /bff/api/v1/intel response, or a JSON list of items) instead of scraping. Mainly for testing / air-gapped use. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *detections.ai — Intel Exchange (threat intel)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:detections-ai`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/detections-ai/sample.json --connector detections-ai
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
