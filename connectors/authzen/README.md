# AuthZEN PDP connector

Imports an [AuthZEN](https://openid.net/wg/authzen/)-conformant authorization inventory into XORCISM's
**API Authorization Governance** (`/authz-governance`).

AuthZEN is the OpenID Foundation's vendor-neutral **Authorization API 1.0**: a standardized
`POST /access/v1/evaluation` with `{subject, action, resource, context}` returning `{decision: true|false}`.
Because it is the interop standard, any enforcement point (PEP) can talk to any decision point (PDP) — so
PDPs imported by this connector are marked **AuthZEN-conformant** (which the posture score rewards).

- the PDP → a **Policy Decision Point** (`engine=authzen`, `authzen_compliant=true`)
- each policy → a **policy**
- any API gateways calling it → a **gateway (PEP)** referencing the PDP

The bundled sample also shows an **ungoverned** legacy gateway (static API key, no PDP) so the posture
score's coverage/edge-auth findings are demonstrable.

## Usage

Worker-safe and **offline** — no live access, stdlib only. Pass `file` = a `{pdps, gateways, policies}`
inventory JSON, or run with no `file` for the bundled `sample.json`.

```bash
python run.py
```

XORCISM can also act as an AuthZEN **PEP test harness**: the `/authz-governance` decision evaluator builds
the exact AuthZEN evaluation payload and (optionally) calls a live PDP, normalizing the decision.

Result keys: `authz_pdps`, `authz_gateways`, `authz_policies` → `runner.import_authz`.
