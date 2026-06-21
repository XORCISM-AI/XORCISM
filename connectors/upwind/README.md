# Upwind

`upwind` · **import** connector · category **Cloud Security**

Imports cloud-security findings from Upwind (https://www.upwind.io), a runtime-powered CNAPP (cloud-native application protection: vulnerabilities, misconfigurations, runtime threats, identity & posture). Each affected cloud resource / host / image becomes an ASSET and every finding a VULNERABILITY / ASSETVULNERABILITY (ref = CVE when present, else UPWIND-<hash>; severity from the finding's risk level). Offline mode: export findings to JSON and import via `file` (accepts a findings array or a {findings|vulnerabilities|issues|results|data:[...]} object). Live mode: set env UPWIND_API_URL + UPWIND_CLIENT_ID + UPWIND_CLIENT_SECRET (OAuth2 client-credentials, best-effort) to pull findings from the API. No DB access in run.py (worker-safe).

**Upstream:** https://www.upwind.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to an Upwind findings export (JSON) to import. |
| `project` | string | no | — | Default asset name for findings whose record carries no resource/host/image. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Upwind*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:upwind`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/upwind/sample.json --connector upwind
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
