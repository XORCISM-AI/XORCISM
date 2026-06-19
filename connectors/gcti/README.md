# Google Threat Intelligence (GTIG/Mandiant) blog

`gcti` · **import** connector · category **threat-intel**

Imports the latest posts from Google's Threat Intelligence blog (Google Threat Intelligence Group / Mandiant, https://cloud.google.com/blog/topics/threat-intelligence) via its RSS feed (https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/). Each post (title, summary, author, date) becomes an XTHREAT.INTELEXCHANGE item, idempotent by post URL; MITRE ATT&CK technique IDs, CVEs and adversary group codes (APT##, UNC####, FIN##, TEMP.*, UTA-###) found in the text are extracted as tags, and ATT&CK techniques are cross-linked into INTELEXCHANGEATTACK so they count toward the ATT&CK coverage. Read-only, non-intrusive, no authentication, Python stdlib only (no extra worker packages). Override the feed with the GCTI_FEED_URL worker env var. Offline import via the 'file' parameter (a saved RSS XML).

**Upstream:** https://cloud.google.com/blog/topics/threat-intelligence

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max_items` | int | no | `40` | Maximum number of blog posts to import (most recent first). (range 1–200) |
| `file` | file | no | — | Offline mode: parse a saved RSS XML file instead of fetching the live feed. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Google Threat Intelligence (GTIG/Mandiant) blog*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:gcti`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/gcti/sample.xml --connector gcti
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
