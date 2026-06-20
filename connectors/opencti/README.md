# OpenCTI — Cyber Threat Intelligence

`opencti` · **import** connector · category **threat-intel**

Pulls Reports from an OpenCTI platform (open cyber-threat-intelligence platform built on STIX 2.1, https://www.opencti.io) via its GraphQL API and imports each report into XTHREAT.INTELEXCHANGE — idempotent by report reference. The report's contained objects are resolved into tags: MITRE ATT&CK techniques (attack-pattern → x_mitre_id) are cross-linked into INTELEXCHANGEATTACK for ATT&CK coverage; intrusion-sets / threat actors, malware / tools and CVE vulnerabilities become actor / malware / CVE tags; report labels become free tags. Read-only, non-intrusive, Python stdlib only (no pycti SDK needed). Live mode needs the worker env vars OPENCTI_URL + OPENCTI_TOKEN. Offline / air-gapped import is possible via the 'file' parameter — either a STIX 2.1 bundle (a JSON {"objects": [...]} export, the universal format) or a saved OpenCTI GraphQL response.

**Upstream:** https://www.opencti.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max_items` | int | no | `60` | Maximum number of OpenCTI reports to import (most recent first). (range 1–1000) |
| `file` | file | no | — | Offline mode: import from a STIX 2.1 bundle (JSON with an 'objects' array) or a saved OpenCTI GraphQL response, instead of querying live. Mainly for testing / air-gapped use. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *OpenCTI — Cyber Threat Intelligence*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:opencti`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/opencti/sample.json --connector opencti
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
