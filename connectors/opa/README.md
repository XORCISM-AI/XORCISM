# Open Policy Agent (OPA) connector

Imports an [OPA](https://www.openpolicyagent.org) authorization inventory into XORCISM's **API
Authorization Governance** (`/authz-governance`):

- the OPA instance → a **Policy Decision Point (PDP)** (`engine=opa`)
- each Rego module → a **policy** (`language=rego`), with **default-deny** auto-detected from the module
  text (`default allow := false`) and `versioned` / `tested` flags when provided
- any API gateways that delegate to OPA → a **gateway (PEP)** referencing the PDP

The imported inventory feeds the authorization posture score (OWASP API Top 10 / NIST CSF PR.AA /
NIST 800-207 PE-PA-PEP).

## Usage

Worker-safe and **offline** — no live access, stdlib only.

- **Export from OPA**: `curl localhost:8181/v1/policies > policies.json`, then run the connector with
  `file = policies.json` (the `{result:[{id,raw}]}` shape is parsed; Rego text is hashed, not stored).
- **Inventory JSON**: pass a `{pdps, gateways, policies}` document directly.
- **Demo**: run with no `file` to import the bundled `sample.json`.

```bash
python run.py            # prints the normalized sample result
```

Result keys: `authz_pdps`, `authz_gateways`, `authz_policies` → `runner.import_authz` →
`XORCISM.AUTHZPDP / AUTHZGATEWAY / AUTHZPOLICY`.
