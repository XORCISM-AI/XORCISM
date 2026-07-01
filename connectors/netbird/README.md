# NetBird

`netbird` · **import** connector · category **Asset Management**

Imports the device inventory from NetBird, the open-source WireGuard-based zero-trust mesh network (https://netbird.io). Each NetBird peer becomes an ASSET — its DNS label / hostname, overlay IP, operating system, agent version, connectivity and groups. Offline mode: parse a `GET /api/peers` JSON export saved from the NetBird Management API. Live mode: if `api_token` is set, the worker calls the NetBird Management API (self-hosted `management_url` or the NetBird cloud) read-only to list peers. No DB access in run.py (worker-safe); the runner performs the ASSET writes. Feeds Asset Management with the mesh-connected endpoints.

**Upstream:** https://netbird.io

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline mode: a NetBird `GET /api/peers` JSON response (array, or an object with a `data`/`peers` array) to import. |
| `api_token` | string | no | — | Live mode: a NetBird Management API personal access token / service-user token (sent as `Authorization: Token …`). Read-only peer listing. |
| `management_url` | string | no | `https://api.netbird.io` | NetBird Management API base URL (self-hosted, e.g. https://netbird.example.com). Defaults to the NetBird cloud API. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *NetBird*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:netbird`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/netbird/sample.json --connector netbird
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
