# Vigil SOC connector

Imports detection rules and AI-agent cases from [Vigil SOC](https://vigilsoc.org)
([github.com/Vigil-SOC/vigil](https://github.com/Vigil-SOC/vigil), Apache-2.0) into XORCISM.

Vigil is an open-source, local-first AI-SOC: a FastAPI backend on `:6987` with PostgreSQL/pgvector,
built on Bifrost + MCP and sponsored by DeepTempo. It runs 13 coordinated agents — Triage,
Investigator, Threat Hunter, Correlator, Responder, Reporter, MITRE Analyst, Forensics, Threat
Intel, Compliance, Malware Analyst, Network Analyst, Auto Responder — over 30+ MCP integrations,
and ships a detection library of **7,200+ rules across Sigma, Splunk, Elastic and KQL**.

## What it maps to

| Vigil | XORCISM | Path |
|---|---|---|
| Detection rules (Sigma + Splunk/Elastic/KQL variants) | `XTHREAT.SIGMARULE` (`SigmaYaml`, `SplQuery`, `EqlQuery`, `KqlQuery`) | runner `detections` → `import_sigma_rules` |
| Cases (agent output: MITRE tags, confidence, containment) | `XINCIDENT.ALERT` | runner `alerts` → `import_incidents` |

No new tables. Rules are idempotent by `SigmaReference` (`vigilsoc:<rule id>`); cases are idempotent
by (`DetectionSource`, `ExternalID`). Once imported, the rules feed `/detection-engineering`,
`/purple-team` and `/threat-informed-defense`; the cases show up at `/incident-management` and
`/soc`.

Because a Vigil rule usually ships as Sigma **plus** a backend-specific query, all four query
columns are carried on the one row rather than creating a rule per platform — that keeps ATT&CK
coverage counts honest.

## Configuration

Secrets come from the worker environment, never from UI parameters:

| Variable | Purpose |
|---|---|
| `VIGILSOC_URL` | Base URL of a Vigil instance, e.g. `http://localhost:6987`. Set it to enable live mode. |
| `VIGILSOC_API_KEY` | Optional; sent as `Authorization: Bearer <key>`. |
| `VIGILSOC_RULES_PATH` | Optional override for the rules endpoint path. |
| `VIGILSOC_CASES_PATH` | Optional override for the cases endpoint path. |

Vigil publishes the port and its FastAPI `/docs`, but not a frozen public path list. Live mode
therefore probes the plausible paths (`/api/detections/rules`, `/api/rules`, `/api/v1/detections`,
… and `/api/cases`, `/api/v1/cases`, …) and parses tolerantly — a response may be a bare list, or
wrapped in `rules` / `cases` / `items` / `results` / `data`. Pin it to your deployment with the
`*_PATH` overrides once you have checked `/docs`.

## Parameters

| Name | Default | Meaning |
|---|---|---|
| `import` | `both` | `rules`, `cases` or `both` |
| `limit` | `500` | Max rules and cases per run |
| `file` | — | Offline: a saved Vigil export JSON |

## Modes

1. **Live** — `VIGILSOC_URL` set → the Vigil REST API.
2. **Offline** — `file` param → a saved export (same JSON shape as `sample.json`).
3. **Demo** — neither → the bundled `sample.json` (3 multi-platform rules, 2 cases).

```bash
python connectors/vigilsoc/run.py          # demo
VIGILSOC_URL=http://localhost:6987 python connectors/runner.py vigilsoc
```
