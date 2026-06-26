# Palo Alto Cortex XDR connector (EDR/XDR)

Imports [Palo Alto Cortex XDR](https://www.paloaltonetworks.com/cortex/cortex-xdr) alerts into XORCISM as
security alerts, unifying endpoint/XDR detections with the rest of the incident layer.

## Mapping
Cortex XDR alert → an `ALERT` (XINCIDENT, via `runner.import_incidents`), idempotent by source + alert id;
the impacted endpoint (`host_name`) is linked as an `ASSET`; the MITRE tactic/technique
(`mitre_tactic_id_and_name` / `mitre_technique_id_and_name`) is the classification; severity is
normalized from low/medium/high/critical. The Cortex API nests alerts under `reply.alerts.data` — the
shared `connectors/_edr.py` normalizer locates it automatically.

## Usage
```bash
# Export alerts (XDR API POST /public_api/v1/alerts/get_alerts) to alerts.json, then:
python run.py --file alerts.json     # or: python run.py  (bundled sample)
```
Worker-safe: stdlib only, ASCII-only output, no DB access. Returns `{source, alerts:[...]}`.
