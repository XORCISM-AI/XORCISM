# XORCISM REST API

A read-only, tenant-scoped REST API over the XORCISM platform. It exposes the
same data the UI shows — assets, incidents, exposures, SLA/RTO posture, the
enterprise risk score, and the **asset & identity governance** inventories — for
integration with SIEMs, dashboards, CI pipelines and automation.

- **Base URL:** `/api/v1` (e.g. `https://your-host/api/v1`)
- **Format:** JSON
- **Spec:** OpenAPI 3 at `GET /api/v1/openapi.json`
- **Interactive docs:** `/api-docs` (in-app)
- **Status:** v1 (reads + scoped writes)

---

## Authentication

Create a key on the **`/api-keys`** page (or `POST /api/apikeys` from a logged-in
session). The raw key (`xor_…`) is shown **once** — store it securely; only its
SHA-256 is kept server-side.

Send it on every request, either way:

```
Authorization: Bearer xor_xxxxxxxxxxxxxxxxxxxxxxxx
X-API-Key: xor_xxxxxxxxxxxxxxxxxxxxxxxx
```

A key acts as its owning **user**: it inherits that user's role-based permissions
and tenant scope. Revoke a key any time on the same page; revoked keys return
`401` immediately. Keys can only be created/revoked from a logged-in session — a
leaked key cannot mint more keys.

**Scopes & expiry.** Each key holds scopes — the presets **read-only** /
**read+write**, or fine-grained tokens (`assets:read`, `assets:write`,
`incidents:read`, `incidents:write`, `exposure:read`, `risk:read`,
`identities:read`, `compliance:read`, `policies:read`, `configuration:read`, `tid:read`). An endpoint
returns `403` if the key lacks its scope (e.g. `POST /incidents` needs
`incidents:write`). Rules: `write` grants everything; `read` grants all `*:read`;
`<res>:write` implies `<res>:read`. Writes are *also* governed by the user's RBAC.
Keys may be given an **expiry** (30 / 90 / 365 days); an expired key returns `401`.

```bash
export XORCISM_API_KEY=xor_xxxxxxxxxxxxxxxxxxxxxxxx
curl -s https://your-host/api/v1/me -H "Authorization: Bearer $XORCISM_API_KEY"
```

### Errors

| Status | Meaning |
|---|---|
| `200` | Success |
| `401` | Missing/invalid/revoked key (`{"error":"…"}`) |
| `403` | Authenticated, but the user lacks read permission on that resource |
| `404` | Resource not found (or outside your tenant) |

---

## Endpoints

### Meta

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Liveness probe: `{status,name,version,time}` |
| `GET` | `/me` | key | Identity behind the key (user, tenant, roles) |
| `GET` | `/openapi.json` | key | The OpenAPI 3 document |

### Assets

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/assets?limit=&offset=` | key | Paginated asset list (tenant-scoped) |
| `GET` | `/assets/{id}` | key | One asset |
| `PATCH` | `/assets/{id}` | **write** | Set `slaResponseHours`, `slaResolutionHours`, `businessValue`, `financialValue` |

Asset fields: `assetId, name, criticality, businessValue, financialValue, riskScore, slaResolutionHours`.

### Incidents

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/incidents?limit=&offset=` | key | Paginated incident list |
| `POST` | `/incidents` | **write** | Create an incident (`name` required; `severity`, `status`, `synopsis`, `durationHours`) |
| `PATCH` | `/incidents/{id}` | **write** | Update `durationHours`, `status`, `severity` |
| `GET` | `/incident-sla` | key | Incident durations vs **asset SLAs** and **BIA RTOs** (breach analysis) |

The `incident-sla` response: each row carries `duration`, `slaHours`/`slaStatus`
and `rtoHours`/`rtoStatus` (`met` \| `breached` \| `no-target` \| `no-duration`),
plus a `summary` with per-target breach rates.

### Exposure & risk

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/exposures?limit=` | key | Top vulnerabilities by fusion exploitability score |
| `GET` | `/risk` | key | Enterprise risk score for the caller's tenant |

### Governance

Inventory + worklist views with a derived 0–100 score per item — the same data
behind the in-app **Asset Management**, **Identities & IAM**, **Incident
Management**, **Compliance & GRC** and **Policies & Documents** pages.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/asset-management` | `assets:read` | Asset inventory + governance findings (owner / Internet exposure / backup / controls / BIA / KEV-critical vulns) |
| `GET` | `/identities` | `identities:read` | Identity inventory (human + non-human) + findings (orphaned NHI / privileged / stale / expiring credentials / missing MFA) |
| `GET` | `/incident-management` | `incidents:read` | Incident inventory + response worklist (open critical / SLA-RTO breach / unassigned / stale / compromise) + MTTR |
| `GET` | `/compliance-management` | `compliance:read` | Audit inventory + remediation worklist (open findings by severity / overdue / unassigned / policies past review) + posture score |
| `GET` | `/policy-management` | `policies:read` | Policy lifecycle inventory + document register + worklist (overdue reviews / unpublished / unowned / missing version / expired documents) + per-policy governance score |
| `GET` | `/configuration-management` | `configuration:read` | Secure-configuration content library (OVAL hardening baselines) + verification worklist (deprecated / unverified by scan / interim status / no CCE) + per-baseline health score |
| `GET` | `/crisis-management` | `crisis:read` | Crisis-management & tabletop-exercise readiness: exercises (inject progress, participants, improvement actions) + the crisis-scenario library + a worklist (overdue actions, scenarios never exercised, no after-action report) + a 0-100 readiness score |
| `GET` | `/threat-informed-defense` | `tid:read` | Threat-Informed Defense scorecard: per ATT&CK technique, adversary use (groups) vs detect (Sigma) / mitigate (D3FEND + ATT&CK) / test (Atomic) coverage + prioritised gap worklist + a threat-weighted program score |
| `GET` | `/threat-informed-defense/navigator-layer` | `tid:read` | Export the program as a MITRE ATT&CK Navigator layer (v4.5 JSON): score = adversary prevalence, colour = defence status. Opens in the official ATT&CK Navigator |

Each returns `{ rows, findings, summary }` (policy adds a `documents` array):
`rows` is the scored inventory, `findings` is the severity-sorted worklist, and
`summary` holds the headline counters (e.g. `crownJewels`, `internetFacing`,
`withCriticalVulns` for assets; `nonHuman`, `privileged`, `orphaned`, `mfaGaps`
for identities; `published`, `overdueReview`, `noOwner`, `expiredDocs`,
`byFramework`, `byLanguage` for policies).

---

## Examples

```bash
# Liveness (no auth)
curl -s https://your-host/api/v1/health

# Top 10 assets
curl -s "https://your-host/api/v1/assets?limit=10" \
  -H "Authorization: Bearer $XORCISM_API_KEY"

# SLA / RTO breach posture
curl -s https://your-host/api/v1/incident-sla \
  -H "X-API-Key: $XORCISM_API_KEY" | jq '.summary'

# Highest-priority exposures
curl -s "https://your-host/api/v1/exposures?limit=5" \
  -H "Authorization: Bearer $XORCISM_API_KEY" | jq '.items[].cve'

# Asset governance worklist (top findings + headline counters)
curl -s https://your-host/api/v1/asset-management \
  -H "X-API-Key: $XORCISM_API_KEY" | jq '{summary, top: .findings[:5]}'

# Identity inventory summary (needs identities:read)
curl -s https://your-host/api/v1/identities \
  -H "Authorization: Bearer $XORCISM_API_KEY" | jq '.summary'

# Create an incident (needs a write-scoped key)
curl -s -X POST https://your-host/api/v1/incidents \
  -H "Authorization: Bearer $XORCISM_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"Phishing wave","severity":"High","durationHours":6}'

# Set an asset's resolution SLA (hours)
curl -s -X PATCH https://your-host/api/v1/assets/42 \
  -H "Authorization: Bearer $XORCISM_API_KEY" -H "Content-Type: application/json" \
  -d '{"slaResolutionHours":4}'
```

```python
import os, requests
H = {"Authorization": f"Bearer {os.environ['XORCISM_API_KEY']}"}
base = "https://your-host/api/v1"
risk = requests.get(f"{base}/risk", headers=H).json()
print("Enterprise risk score:", risk["enterpriseRiskScore"])
```

---

## Webhooks

Register HTTPS endpoints on the **`/webhooks`** page to receive a signed JSON
`POST` when events fire:

| Event | Fired by |
|---|---|
| `incident.created` | `POST /api/v1/incidents` |
| `incident.updated` | `PATCH /api/v1/incidents/{id}` |
| `asset.updated` | `PATCH /api/v1/assets/{id}` |

Each delivery carries:

```
X-XORCISM-Event: incident.created
X-XORCISM-Signature: sha256=<hex HMAC-SHA256(secret, rawBody)>
Content-Type: application/json
```

Body: `{ "event": "...", "sentAt": "<iso8601>", "data": { ... } }`. Verify the
signature with the per-hook secret (shown once at creation):

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-XORCISM-Signature"])
```

Endpoints must be **public** (localhost / private / link-local addresses are
rejected). Use **Test** on the `/webhooks` page to send a `test.ping`. Tenant
webhooks only receive their own tenant's events.

---

## Notes & roadmap

- **Pagination:** `limit` (default 50, max 500) + `offset`; list responses include `total`.
- **Tenancy:** non-super-admin keys only see (and write) their tenant's rows.
- **Writes:** `POST`/`PATCH` need a write-scoped key **and** the user's RBAC permission; they reuse the same insert/update path as the UI (PK assignment, tenant guard, validation).
- **Versioning:** breaking changes ship under a new prefix (`/api/v2`).
- **Planned:** delivery retries/replay for webhooks, and per-field scopes.
