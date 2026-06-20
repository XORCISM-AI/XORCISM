# MISP — Threat Intelligence Sharing

`misp` · **import** connector · category **threat-intel**

Pulls events from a MISP instance (open-source threat-intelligence sharing platform, https://www.misp-project.org) via its REST API (/events/restSearch) and imports each event into XTHREAT.INTELEXCHANGE — idempotent by event reference. MITRE ATT&CK techniques (from MISP galaxy clusters and tags), threat-actor / intrusion-set galaxies, malware/tool galaxies, CVE references and an IOC summary (IP / domain / URL / hash / email counts) are extracted as tags, and ATT&CK techniques are cross-linked into INTELEXCHANGEATTACK so they count toward the ATT&CK coverage. Read-only, non-intrusive, Python stdlib only (no PyMISP needed). Live mode needs the worker env vars MISP_URL + MISP_KEY (set MISP_VERIFY_SSL=0 for a self-signed instance, MISP_DAYS for the look-back window). Offline / air-gapped import is possible via the 'file' parameter (a saved /events/restSearch response, a single event export, or a JSON list of events).

**Upstream:** https://www.misp-project.org

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max_items` | int | no | `100` | Maximum number of MISP events to import (most recent first). (range 1–2000) |
| `days` | int | no | `30` | Live mode: look-back window (in days) for published events. Overrides MISP_DAYS. (range 1–3650) |
| `file` | file | no | — | Offline mode: import from a saved MISP JSON (a /events/restSearch response, a single /events/view export, or a JSON list of events) instead of querying live. Mainly for testing / air-gapped use. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *MISP — Threat Intelligence Sharing*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:misp`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/misp/sample.json --connector misp
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
