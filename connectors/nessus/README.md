# Tenable Nessus — import .nessus

`nessus` · **import** connector · category **vuln-scanner**

Importe un fichier .nessus (NessusClientData_v2). Hôtes → ASSET, findings → VULNERABILITY (CVE ou Nessus:pluginID) + liens.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Chemin du fichier .nessus (sur le worker) |
| `min_severity` | enum | no | `1` | Severité minimale (0=info … 4=critique) (one of: `0`, `1`, `2`, `3`, `4`) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Tenable Nessus — import .nessus*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:nessus`.
- **Self-test** — parse **and import** the bundled `sample.nessus` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/nessus/sample.nessus --connector nessus
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
