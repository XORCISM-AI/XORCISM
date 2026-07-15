# MITRE TRAM — Threat Report ATT&CK Mapper import

`tram` · **import** connector · category **Threat Intelligence**

Imports **MITRE TRAM** ([Threat Report ATT&CK Mapper](https://github.com/center-for-threat-informed-defense/tram)) results into XORCISM. TRAM uses NLP (a SciBERT model) to map the individual sentences of a finished CTI report to MITRE ATT&CK techniques, each with a confidence score. This connector ingests TRAM's **report-export JSON** and turns each report into a `XTHREAT.THREATREPORT` plus its sentence-level technique mappings (`REPORTMAPPING`), cross-linked to `ATTACKTECHNIQUE` so the mappings feed XORCISM's ATT&CK coverage and CTI.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | int | no | `50` | Maximum number of reports to import (range 1–500) |
| `min_confidence` | float | no | `0` | Drop technique mappings below this confidence (0–1) |
| `only_accepted` | bool | no | `false` | Keep only sentences the analyst accepted in TRAM |
| `file` | file | no | — | Offline: a saved TRAM report-export JSON to parse instead of the live API |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns a normalized `{"source": "TRAM", "reportmappings": [...]}`. The XORCISM runner imports it via `import_report_mappings` — each report becomes a **THREATREPORT** (idempotent by TRAM source + report id) and every sentence→technique mapping becomes a **REPORTMAPPING** row (technique id, name, confidence, the evidence sentence, and the analyst disposition), cross-linked into `ATTACKTECHNIQUE`. The connector performs **no database access** itself, so it is safe to run on a remote worker.

### Live mode (TRAM API)

```
export TRAM_URL="http://localhost:8000"     # your TRAM instance
export TRAM_TOKEN="…"                        # API token (Authorization: Token …)
export TRAM_REPORT_ID="42"                   # optional — export just one report
```

Without `TRAM_REPORT_ID` the connector lists `/api/reports/` and exports up to `limit` reports from `/api/report-export/{id}/`. Parsing is tolerant of the export shape (`sentences[].mappings[]` with `attack_id` / `name` / `confidence`).

> **Don't have a TRAM deployment?** XORCISM ships a native equivalent at **`/report-mapper`** — paste report text and it maps sentences to ATT&CK techniques with confidence + evidence (local-AI engine, or a deterministic keyword engine over the ATT&CK catalogue offline), then saves to THREATREPORT + REPORTMAPPING and exports an ATT&CK Navigator layer.

## Running it

- **From XORCISM** — open **Connectors**, choose *MITRE TRAM — Threat Report ATT&CK Mapper import*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:tram`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/tram/sample.json --connector tram
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
