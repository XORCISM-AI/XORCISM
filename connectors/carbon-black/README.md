# VMware Carbon Black Cloud connector (EDR)

Imports [VMware Carbon Black Cloud](https://www.vmware.com/products/carbon-black-cloud.html) (CBC) EDR
alerts into XORCISM as security alerts, unifying endpoint detections with the rest of the incident layer.

## Mapping
Carbon Black alert → an `ALERT` (XINCIDENT, via `runner.import_incidents`), idempotent by source + alert
id; the impacted device (`device_name`) is linked as an `ASSET`; the threat category / TTPs are the alert
classification; severity is normalized from the CBC **1–10** scale. Parsing via the shared
`connectors/_edr.py` normalizer.

## Usage
```bash
# Export alerts (CBC API POST /api/alerts/v7/orgs/{org}/alerts/_search) to alerts.json, then:
python run.py --file alerts.json     # or: python run.py  (bundled sample)
```
Worker-safe: stdlib only, ASCII-only output, no DB access. Returns `{source, alerts:[...]}`.
