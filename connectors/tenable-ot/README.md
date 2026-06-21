# Tenable OT Security

`tenable-ot` · **import** connector · category **OT/IoT**

Tenable OT Security (formerly Tenable.ot / Indegy) OT vulnerability management & asset inventory. Parses an exported assets + findings report (JSON or CSV) and maps each OT asset to an ASSET and each finding/CVE to a vulnerability on that asset. Tool: https://www.tenable.com/products/tenable-ot-security. Offline export parser (live API via TENABLE_OT_URL + access/secret keys is a future enhancement).

**Upstream:** https://www.tenable.com/products/tenable-ot-security

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Tenable OT export to parse: JSON ({assets:[…], findings:[…]} or a list) or a CSV of assets or of findings (auto-detected by columns). |
| `project` | string | no | — | Optional asset-name override applied to all findings (otherwise each asset's name / IP is used). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Tenable OT Security*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:tenable-ot`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/tenable-ot/sample.json --connector tenable-ot
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
