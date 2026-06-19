# Rudder — nodes & compliance import

`rudder` · **import** connector · category **compliance**

Imports managed nodes and configuration-compliance state from a Rudder server (https://www.rudder.io) via its REST API (X-API-Token). Each managed node becomes an ASSET (hostname, IP, OS); installed software (opt-in) becomes a CPE linked to the node; each rule a node is not fully compliant with becomes a finding (ref RUDDER-<ruleId>, severity from the compliance %). Read-only, non-intrusive. Configuration via worker environment variables (never entered in the UI): RUDDER_URL (e.g. https://rudder.example.com — the /rudder/api/latest path is appended automatically), RUDDER_API_TOKEN, RUDDER_VERIFY_TLS (set 0 to skip TLS verification for self-signed servers). Requires `pip install requests` on the worker.

**Upstream:** https://www.rudder.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `scope` | enum | no | `all` | Import inventory only (nodes), compliance findings only, or both (all). (one of: `all`, `nodes`, `compliance`) |
| `limit` | int | no | `1000` | Maximum number of nodes to import. (range 1–20000) |
| `min_compliance` | int | no | `100` | Flag a node↔rule as a finding when its compliance %% is below this threshold (default 100 = any rule not fully compliant). (range 0–100) |
| `include_software` | bool | no | `False` | Also import each node's installed software as CPEs (can be large). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Rudder — nodes & compliance import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:rudder`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/rudder/sample.json --connector rudder
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
