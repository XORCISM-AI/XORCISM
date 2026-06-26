# SentinelOne connector (EDR)

Imports [SentinelOne](https://www.sentinelone.com) (Singularity) EDR/XDR threats into XORCISM as security
alerts, unifying endpoint detections with the rest of the incident layer.

## Mapping
SentinelOne threat → an `ALERT` (XINCIDENT, via `runner.import_incidents`), idempotent by source + threat
id; the impacted endpoint (`agentRealtimeInfo.agentComputerName`) is linked as an `ASSET`; the threat
classification / MITRE tactic is the alert classification; the confidence level **malicious / suspicious**
maps to **high / medium**. Parsing via the shared `connectors/_edr.py` normalizer.

## Usage
```bash
# Export threats (Singularity API GET /web/api/v2.1/threats) to threats.json, then:
python run.py --file threats.json     # or: python run.py  (bundled sample)
```
Worker-safe: stdlib only, ASCII-only output, no DB access. Returns `{source, alerts:[...]}`.
