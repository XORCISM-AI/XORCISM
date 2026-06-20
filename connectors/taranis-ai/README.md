# Taranis AI

`taranis-ai` · **import** connector · category **OSINT**

Imports OSINT / threat intelligence from Taranis AI (https://github.com/taranis-ai/taranis-ai), an AI-powered Open-Source Intelligence tool (Python, EUPL-1.2) that collects unstructured news from web/RSS sources, enriches them with NLP/AI, and lets analysts refine them into structured reports. This connector turns Taranis news items / reports into XORCISM threat-intel items in XTHREAT.INTELEXCHANGE — extracting CVE, MITRE ATT&CK and threat-actor tags (idempotent by reference, with ATT&CK cross-links). Offline mode: import a Taranis JSON export (news items / reports) via `file`. Live mode: set env TARANIS_URL (the Taranis Core base URL) and TARANIS_API_KEY (Bearer/JWT) and the connector fetches recent news items from the REST API (best-effort across versions). No DB access in run.py (worker-safe).

**Upstream:** https://github.com/taranis-ai/taranis-ai

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Taranis AI JSON export (news items / reports) to import. |
| `max_items` | int | no | `100` | Live mode: maximum number of news items to fetch from the Taranis API. (range 1–1000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Taranis AI*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:taranis-ai`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/taranis-ai/sample.json --connector taranis-ai
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
