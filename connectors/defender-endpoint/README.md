# Microsoft Defender for Endpoint connector (EDR)

Imports [Microsoft Defender for Endpoint](https://www.microsoft.com/security/business/endpoint-security/microsoft-defender-endpoint)
(MDE) alerts into XORCISM as security alerts. Complements the Defender XDR incident alignment already in
XORCISM by bringing the endpoint-detection layer into the unified alert/incident view.

## Mapping
MDE alert → an `ALERT` (XINCIDENT, via `runner.import_incidents`), idempotent by source + alert id; the
impacted device (`computerDnsName`) is linked as an `ASSET`; the ATT&CK category/technique is the alert
classification; severity is normalized from Informational/Low/Medium/High. Parsing via the shared
`connectors/_edr.py` normalizer.

## Usage
```bash
# Export alerts (Defender API GET /api/alerts or Microsoft Graph /security/alerts) to alerts.json, then:
python run.py --file alerts.json     # or: python run.py  (bundled sample)
```
Worker-safe: stdlib only, ASCII-only output, no DB access. Returns `{source, alerts:[...]}`.
