# GraphSpy connector

Imports a [GraphSpy](https://github.com/RedByte1337/GraphSpy) engagement export into XORCISM. GraphSpy is
an **initial-access & post-exploitation tool for Entra ID / Microsoft 365** (device-code phishing,
access/refresh/PRT token abuse, OneDrive/SharePoint/Outlook/Teams exfiltration, MFA-method persistence).

## Mapping
- tenant / users / devices → **ASSET** (tags `m365` / `entra` / `identity` / `user` / `device`)
- captured access/refresh token → **VULN** `GRAPHSPY-TOKEN-*` (ATT&CK **T1528**; a PRT → **T1550**, critical)
- successful device-code phish → **VULN** `GRAPHSPY-DEVICECODE-*` (T1528 / T1078)
- over-privileged user with weak/no MFA → **VULN** `GRAPHSPY-MFA-*` (T1078)
- explicit `findings[]` → **VULN** `GRAPHSPY-*` (severity + ATT&CK from the finding)

## Export schema (all sections optional)
```json
{
  "tenant": "contoso.onmicrosoft.com",
  "users":   [ { "upn": "alice@contoso.com", "roles": ["Global Administrator"], "mfa": ["sms"], "enabled": true } ],
  "devices": [ { "name": "DESKTOP-1", "trust": "AzureAD", "compliant": false } ],
  "tokens":  [ { "user": "alice@contoso.com", "type": "refresh", "scope": ".default", "source": "device_code", "prt": true } ],
  "device_codes": [ { "user": "bob@contoso.com", "status": "authenticated" } ],
  "findings":[ { "title": "Mailbox exfiltrated via Graph", "severity": "high", "user": "alice@contoso.com", "attck": "T1114" } ]
}
```

## Run
- **Connector**: `python connectors/runner.py --connector graphspy --file graphspy-export.json`
- **Attack chain**: the **Microsoft 365 / Entra ID attack (GraphSpy)** playbook (Tool-chaining / `/chain`)
  seeds `graphspy` and escalates any finding to CyberSentinel AI for ATT&CK mapping. Simulate or live, under ROE.

`run.py` does no DB access (worker-safe). GraphSpy itself is an offensive tool — only use exports from an
**authorized** engagement.
