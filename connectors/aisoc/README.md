# AiSOC connector

Imports from [**AiSOC**](https://github.com/beenuar/AiSOC) (by beenuar, MIT) — an open-source,
self-hostable **AI Security Operations Center**: alert fusion, four LangGraph agents
(Detect / Triage / Hunt / Respond), OCSF-normalized alerts, cases, MITRE ATT&CK investigation,
risk-based alerting, UEBA, detection-as-code (Sigma) and a replayable investigation ledger.

XORCISM is itself an AI-assisted SOC, so this connector treats AiSOC as a **feeding source**: one import
fans AiSOC's outputs into three XORCISM cockpits at once.

## What it maps

| AiSOC output | Normalized as | XORCISM cockpit |
| :--- | :--- | :--- |
| Cases & alerts (OCSF) | `alerts` | **XINCIDENT.ALERT** → Incident Management / SOC Operations (idempotent by `aisoc:<id>`; impacted host linked to its ASSET) |
| IOCs + threat-actor attributions | `intel` | **XTHREAT.INTELEXCHANGE** → CTI; the MITRE technique ids carried in `attack_tags` cross-link into the **ATT&CK coverage matrix** |
| Detection rules (Sigma) | `detections` | **XTHREAT.SIGMARULE** → Purple-Team / Threat-Informed Defense |

MITRE ATT&CK technique ids (`T####[.###]`) and CVEs are harvested from every item (dedicated fields or
free text), so AiSOC's investigation context shows up on the alert, the intel item and the Sigma rule.

## Read-only & worker-safe

The connector only **reads**. It never sends actions back to AiSOC. It works two ways:

1. **File (recommended / offline)** — export AiSOC JSON and pass it as `file`.
2. **Live read-only API** — set `AISOC_URL` + `AISOC_API_KEY` (Bearer); the connector does best-effort
   `GET` requests against the AiSOC API (`/api/cases`, `/api/alerts`, `/api/intel/iocs`, `/api/detections`)
   and falls back to the file/sample on any error.

### Parameters

| Param | Required | Description |
| :--- | :--- | :--- |
| `file` | no | An AiSOC export JSON (object with `cases`/`alerts`/`iocs`/`detections`/`actors`, or a bare array of alerts). |
| `kind` | no | `all` (default) \| `cases` \| `alerts` \| `iocs` \| `detections`. |
| `limit` | no | Max items per category (default 500). |
| `min_severity` | no | `info\|low\|medium\|high\|critical` — minimum severity for alerts/IOCs (default `info`). |

### Environment

| Var | Purpose |
| :--- | :--- |
| `AISOC_URL` | Base URL of your AiSOC instance (optional live pull). |
| `AISOC_API_KEY` | AiSOC API key, sent as `Authorization: Bearer …` (read-only). |

## Offline dry run

```bash
python run.py                       # built-in sample (1 case + 2 alerts, 2 IOCs, 1 actor, 1 detection)
python run.py --file export.json    # parse a real AiSOC export
python run.py --kind iocs --min-severity high
```

The parser is defensive about AiSOC's export shapes (`cases`/`investigations`, `alerts`/`events`,
`iocs`/`intel`/`indicators`/`observables`, `actors`/`threat_actors`/`attribution`, `detections`/`rules`/`sigma`),
so it works across exports from different AiSOC versions.

## Why this integration

AiSOC and XORCISM overlap a lot (both are AI SOCs). Rather than duplicate AiSOC's agents, this connector
makes AiSOC's *results* first-class XORCISM data: its cases feed your incident queue and SLA/MTTR metrics,
its IOCs and attributions enrich CTI and the ATT&CK matrix, and its detections land in the Sigma library
that powers Purple-Team coverage and Threat-Informed Defense — so the two platforms compound instead of
competing.
