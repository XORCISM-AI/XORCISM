# Google SecOps (Chronicle) — SIEM detections import

`google-secops` · **import** connector · category **SIEM**

Imports rule detections / curated alerts from Google Security Operations (formerly Chronicle, Google Cloud's cloud-native SIEM) via the v1alpha legacy alerts API into XORCISM as security alerts (XINCIDENT.ALERT). Each detection becomes an ALERT (idempotent by its detection id), rule severity maps to XORCISM severity, MITRE ATT&CK techniques carried on the rule are attached, and the matched UDM host is linked to its ASSET. Config (worker environment variables): GOOGLE_SECOPS_TOKEN (OAuth2 Bearer access token), GOOGLE_SECOPS_REGION (default us), GOOGLE_SECOPS_PROJECT, GOOGLE_SECOPS_INSTANCE; optional GOOGLE_SECOPS_LOCATION and GOOGLE_SECOPS_ENDPOINT (full URL override). Offline: pass `file` = a saved detections/alerts export JSON, or run with no config for the bundled sample.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | int | no | `200` | Maximum number of detections to import (range 1–1000) |
| `file` | file | no | — | Offline: a saved Google SecOps detections/alerts export JSON to parse instead of the live API |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns a normalized `{"source": "Google SecOps", "alerts": [...]}`. The XORCISM runner imports it via `import_incidents` — each detection becomes an **ALERT** in `XINCIDENT.ALERT` (idempotent by `DetectionSource` + `ExternalID`), and the matched host is linked to its **ASSET** through `ALERTFORASSET`. The connector performs **no database access** itself, so it is safe to run on a remote worker.

### Live mode (Google SecOps API)

The connector calls the Chronicle **v1alpha** legacy alerts endpoint on the region-scoped host:

```
https://{region}-chronicle.googleapis.com/v1alpha/projects/{project}/locations/{location}/instances/{instance}/legacy:legacyFetchAlertsView
```

Authentication is an OAuth2 **Bearer** access token (`GOOGLE_SECOPS_TOKEN`). Obtain one with a service account granted the *Chronicle API Viewer* role, e.g.:

```bash
export GOOGLE_SECOPS_TOKEN="$(gcloud auth print-access-token)"
export GOOGLE_SECOPS_REGION="us"          # or europe, asia-southeast1, ...
export GOOGLE_SECOPS_PROJECT="my-gcp-project"
export GOOGLE_SECOPS_INSTANCE="0000-1111-2222-3333"   # Chronicle customer id
```

Chronicle alert/detection payloads are deeply nested and vary by endpoint, so parsing is **tolerant**: the connector walks several known shapes (`detections`/`alerts`/`rulesAlerts` arrays, `alertGroups[].alertInfos`, or a bare list) and extracts sensible defaults. If your deployment uses a different endpoint, set `GOOGLE_SECOPS_ENDPOINT` to the full URL and it will be used verbatim.

## Running it

- **From XORCISM** — open **Connectors**, choose *Google SecOps (Chronicle) — SIEM detections import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:google-secops`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/google-secops/sample.json --connector google-secops
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
