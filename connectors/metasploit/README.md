# Metasploit Framework — import db_export

`metasploit` · **import** connector · category **exploitation**

Importe un export Metasploit (msfconsole : db_export -f xml). Hôtes → ASSET, services → CPE/services, vulns → VULNERABILITY (CVE) + liens. Mode RPC optionnel (MSF_RPC_*).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Chemin de l'export XML Metasploit (db_export -f xml) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Metasploit Framework — import db_export*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:metasploit`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/metasploit/sample.xml --connector metasploit
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
