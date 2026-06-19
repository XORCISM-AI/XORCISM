# SAINT — import rapport XML

`saint` · **import** connector · category **vuln-scanner**

Importe un rapport XML SAINT (vulnérabilités par hôte). Best-effort : adapter le mapping si votre schéma SAINT diffère.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Chemin du rapport XML SAINT (sur le worker) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *SAINT — import rapport XML*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:saint`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/saint/sample.xml --connector saint
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
