# Rustinel

`rustinel` · **import** connector · category **Endpoint**

Open-source cross-platform endpoint detection engine (EDR). Collects native host telemetry via ETW (Windows), eBPF (Linux) and Endpoint Security (macOS), normalizes it into a shared event model, and evaluates it against Sigma rules, YARA signatures and atomic IOCs — emitting ECS-compatible NDJSON alerts for SIEM pipelines. Tool: https://github.com/Karib0u/rustinel. This connector parses Rustinel's ECS NDJSON alert log (logs/alerts.json.<date>) and maps each detection to a finding on the originating host asset.

**Upstream:** https://github.com/Karib0u/rustinel

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Rustinel ECS NDJSON alert log to parse (e.g. logs/alerts.json.2026-06-21). One JSON alert per line. |
| `project` | string | no | — | Optional host/asset name override. By default each alert's host.name is used as the asset, so a single file can fan out to several hosts. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Rustinel*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:rustinel`.
- **Self-test** — parse **and import** the bundled `sample.ndjson` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/rustinel/sample.ndjson --connector rustinel
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
