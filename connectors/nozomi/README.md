# Nozomi Networks

`nozomi` · **import** connector · category **OT/IoT**

Nozomi Networks (Guardian / Vantage) OT/IoT visibility & detection. Parses an exported assets + vulnerabilities report (JSON or CSV) and maps each node to an ASSET and each vulnerability/CVE to a finding on that asset. Tool: https://www.nozominetworks.com. Offline export parser (live Vantage/Guardian API via NOZOMI_URL + NOZOMI_API_KEY is a future enhancement).

**Upstream:** https://www.nozominetworks.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Nozomi export to parse: JSON ({nodes:[…], vulnerabilities:[…]} or a list), or a CSV of assets or of vulnerabilities (auto-detected by columns). |
| `project` | string | no | — | Optional asset-name override applied to all findings (otherwise each node's label / IP is used). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Nozomi Networks*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:nozomi`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/nozomi/sample.json --connector nozomi
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
