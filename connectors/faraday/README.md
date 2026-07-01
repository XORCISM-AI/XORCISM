# Faraday — vulnerability management import

`faraday` · **import** connector · category **Vulnerability Scanner**

Imports from Faraday (github.com/infobyte/faraday, by Faraday Security / Infobyte, GPL-3.0) — the open-source collaborative vulnerability manager. Faraday's strength is normalization: ~90 console/report plugins ingest Nessus, Nmap, Burp, OpenVAS, Qualys, Nuclei, ZAP and more into one Workspace → Host → Service → Vulnerability model (severity, CVE/refs, CVSS, status, confirmed flag), deduplicated across tools. This connector consumes that aggregated output — a Faraday workspace export (faraday-cli / the REST-GraphQL API's hosts + vulns) — and maps it into XORCISM: Hosts → ASSET, Vulnerabilities → XVULNERABILITY.VULNERABILITY (CVE ref + CVSS preserved) linked via ASSETVULNERABILITY, so Faraday-aggregated findings feed the exposure-fusion score, VPR, the Unified Exposure queue and the Enterprise Risk Score. Use Faraday as the multi-scanner pentest front-end, XORCISM as the exposure/risk brain. Worker-safe & read-only: parses an exported JSON only (no scanning). Open vulns are imported by default (set include_closed to import the rest).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | A Faraday workspace export JSON (faraday-cli 'vuln list'/'host list' or the REST/GraphQL API). Defaults to the bundled sample. |
| `workspace` | string | no | — | Workspace label to stamp on imported findings (defaults to the workspace in the export). |
| `include_closed` | bool | no | `False` | Also import vulnerabilities whose Faraday status is closed / risk-accepted (default: open + re-opened only). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Faraday — vulnerability management import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:faraday`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/faraday/sample.json --connector faraday
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
