# VoidAccess

`voidaccess` · **import** connector · category **OSINT**

Imports dark-web OSINT / threat intelligence from VoidAccess (https://github.com/KatrielMoses/voidaccess), a self-hosted dark-web OSINT platform (Python, MIT) — a free alternative to Recorded Future / DarkOwl / Flare. It runs autonomous investigations across Tor search engines and clearnet sources, extracts entities (CVEs, threat actors, domains, IPs, emails, hashes, crypto wallets, paste links) and builds relationship graphs. This connector turns a VoidAccess investigation/findings export (JSON) into XORCISM threat-intel items in XTHREAT.INTELEXCHANGE — each finding becomes an intel item with CVE / MITRE ATT&CK / threat-actor tags and an indicator summary (idempotent by reference, with ATT&CK cross-links). Import-only via `file` (its REST API *triggers* live dark-web crawls, which is intentionally NOT exposed here). VoidAccess can also export STIX 2.1 bundles and MISP JSON events, which you can import via the opencti / misp connectors. Privacy: emails / wallets / hashes are summarised as counts, not dumped verbatim. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/KatrielMoses/voidaccess

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to a VoidAccess investigation/findings export (JSON) to import. |
| `max_items` | int | no | `200` | Maximum number of findings to import. (range 1–2000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *VoidAccess*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:voidaccess`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/voidaccess/sample.json --connector voidaccess
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
