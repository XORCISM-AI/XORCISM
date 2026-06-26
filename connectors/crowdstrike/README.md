# CrowdStrike Falcon connector (EDR)

Imports [CrowdStrike Falcon](https://www.crowdstrike.com) endpoint detections / alerts into XORCISM as
security alerts. Falcon is the market-leading EDR/XDR; bringing its detections in unifies them with the
rest of the incident layer.

## Mapping
Falcon detection → an `ALERT` (XINCIDENT, via `runner.import_incidents`), idempotent by source + detection
id; the impacted endpoint (`device.hostname`) is linked as an `ASSET`; the ATT&CK tactic/technique is kept
as the alert classification; severity is normalized from Falcon's 0-100 / Low–Critical scale. Parsing is
delegated to the shared `connectors/_edr.py` normalizer.

## Usage
```bash
# Export detections from the Falcon API (/detects or /alerts) to detections.json, then:
python run.py --file detections.json     # or: python run.py  (bundled sample)
```
Worker-safe: stdlib only, ASCII-only output, no DB access. Returns `{source, alerts:[...]}`. One of the
EDR connectors built on `_edr.py` (CrowdStrike, Defender for Endpoint, SentinelOne, Cortex XDR, Carbon Black).
