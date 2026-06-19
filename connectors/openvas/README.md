# OpenVAS / Greenbone — import rapport GMP

`openvas` · **import** connector · category **vuln-scanner**

Importe un rapport XML Greenbone (GMP <report>). Résultats → VULNERABILITY (CVE ou NVT OID) liés à l'asset hôte.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Chemin du rapport XML Greenbone (sur le worker) |
| `min_cvss` | string | no | `0.1` | Severité CVSS minimale |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *OpenVAS / Greenbone — import rapport GMP*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:openvas`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/openvas/sample.xml --connector openvas
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
