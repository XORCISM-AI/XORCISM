# Cedar / Amazon Verified Permissions connector

Imports a [Cedar](https://www.cedarpolicy.com) authorization inventory into XORCISM's **API
Authorization Governance** (`/authz-governance`):

- the policy store / Amazon Verified Permissions (AVP) → a **Policy Decision Point (PDP)** (`engine=cedar`)
- each Cedar policy → a **policy** (`language=cedar`). Cedar is **deny-by-default by design** — access is
  granted only by an explicit `permit` — so imported policies are marked `default_deny=true`
- any API gateways that delegate to it → a **gateway (PEP)** referencing the PDP

Cedar evaluates **Principal-Action-Resource-Context (PARC)**, which maps directly to object-level (BOLA)
and function-level (BFLA) authorization in the posture score.

## Usage

Worker-safe and **offline** — no live access, stdlib only.

- **AVP export**: an `ListPolicies` response (`{policies:[{policyId,description,...}]}`) via `file`.
- **Inventory JSON**: a `{pdps, gateways, policies}` document.
- **Demo**: no `file` → bundled `sample.json`.

```bash
python run.py
```

Result keys: `authz_pdps`, `authz_gateways`, `authz_policies` → `runner.import_authz`.
