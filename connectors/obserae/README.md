# Obserae — NDR (Network Detection & Response)

`obserae` · **import** connector · category **Network Monitoring**

Integrates [Obserae](https://obserae.com), a **self-hosted Network Detection & Response** platform — a NetFlow/IPFIX collector that reconstructs sessions, builds a cartography of hosts & services, and raises detection alerts. The connector brings all three into XORCISM around **ASSET**, **NETWORKSESSION** and the SOC **ALERT** layer.

## Two modes

### 1. Live REST API (recommended)
Talks to the Obserae REST API ([docs](https://obserae.com/docs/api-reference/)) using an `obs_…` **Bearer** token:

| Obserae endpoint | → XORCISM |
|---|---|
| `GET /api/carto/graph` | host nodes → **ASSET** (name, IP, OS, zone); their listening services → **ASSETSERVICE** (protocol/port/service) |
| `GET /api/sessions/riverview` | reconstructed flows → **NETWORKSESSION** (src↔dst asset/IP/port, bytes/packets, first/last seen) |
| `GET /api/alerts` | detection alerts → **XINCIDENT.ALERT** (title, severity, ATT&CK, impacted asset), idempotent by source + external id, surfaced in **/soc** |
| `GET /api/status` | Obserae version / health (summary) |

Set in the **worker environment**:
```bash
OBSERAE_URL=http://127.0.0.1:8080      # or pass the base_url param
OBSERAE_API_TOKEN=obs_xxxxxxxxxxxxxxxx # an obs_ Bearer token (mint one in Obserae → tokens)
```
Non-host cartography nodes (networks/groups) are ignored; alert severities (`critical/high/medium/low/info`) and field names are parsed tolerantly.

### 2. Offline export (file)
Point `file` at an Obserae cartography + sessions (+ optional `alerts`) export (YAML or JSON) — e.g. an air-gapped or lab export. Same normalization, no network.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `base_url` | string | no | — | Live API mode: Obserae base URL (or set `OBSERAE_URL`). Needs `OBSERAE_API_TOKEN` in the worker env. |
| `file` | file | no | — | Offline mode: an Obserae cartography + sessions (+ alerts) export (YAML/JSON). Used when no `base_url` is given. |
| `max_alerts` | int | no | `500` | Live mode: max detection alerts to pull from `/api/alerts`. |
| `default_protocol` | string | no | `tcp` | Protocol assumed when a session/service omits it. |

Provide **either** `base_url`/`OBSERAE_URL` (live) **or** `file` (offline).

## Output → XORCISM

`run(params, workdir)` returns:
```jsonc
{
  "source": "Obserae NDR",
  "netflow": { "assets": [...], "services": [...], "sessions": [...] },  // → import_netflow
  "alerts":  [ { "external_id", "name", "severity", "attack", "asset", "created", ... } ],  // → import_incidents
  "summary": { "assets", "services", "sessions", "alerts", "mode", "obserae_version" }
}
```
The connector performs **no database access** (runs on a remote worker); the XORCISM runner imports the normalized result. Required permission: `connector:obserae`.

## Running it

- **From XORCISM** — **Connectors → Obserae**, fill parameters, run (admin only; creates a job for `connectors/runner.py`).
- **Offline self-test** — parse & import the bundled `sample.yaml` (no live tool):
  ```bash
  python connectors/runner.py --selftest connectors/obserae/sample.yaml --connector obserae
  ```
  > `--selftest` writes to the DB — use a throwaway `XORCISM_DB_DIR` to avoid touching live data.
- **Live CLI test** — `OBSERAE_URL=… OBSERAE_API_TOKEN=obs_… python connectors/obserae/run.py` prints the normalized JSON.

---
<sub>Obserae REST API integration — cartography, sessions and detection alerts. Set `OBSERAE_URL` + `OBSERAE_API_TOKEN` for live mode.</sub>
