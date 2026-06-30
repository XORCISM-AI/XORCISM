# Saviynt connector

Imports identities and accounts from **Saviynt Enterprise Identity Cloud (EIC)** — the cloud-native
**IGA + PAM** platform — into XORCISM's identity registry (`XORCISM.IDENTITY`), idempotent by
`Provider` + `ExternalID` (runner `import_identities`, same path as the SailPoint / CyberArk / Entra
connectors).

| Saviynt object | XORCISM identity |
| :--- | :--- |
| User (`getUser`) | **Human** identity (`user`); `service`-type employees → Non-Human |
| Account (`getAccounts`) | **Non-Human / NHI** (`account`, or `privileged-account` for admin accounts); uncorrelated/orphaned accounts flagged High risk |

It feeds the identity **inventory** (`/identities`), **certification** (`/identity-governance`), and the
Saviynt-style **Access Governance** cockpit (`/access-governance`: entitlements, Segregation-of-Duties,
access requests, JIT).

## Read-only & worker-safe

Two modes (it never writes back to Saviynt):

1. **Live** — set `SAVIYNT_BASE_URL`, `SAVIYNT_USERNAME`, `SAVIYNT_PASSWORD` (worker env). The connector
   logs in (`/ECM/api/login` → bearer token) and best-effort fetches users + accounts; any error falls
   back to the file/sample.
2. **File (offline)** — pass `file` = a Saviynt user/account export JSON.

### Parameters

| Param | Default | Description |
| :--- | :--- | :--- |
| `limit` | 500 | Max identities to import. |
| `include` | `users,accounts` | `users` \| `accounts` \| `users,accounts`. |
| `file` | — | Offline: a saved Saviynt export JSON. |

## Offline dry run

```bash
python run.py                       # built-in sample (3 users + 2 accounts)
python run.py --file export.json    # parse a real Saviynt export
python run.py --include accounts
```

## Note on Access Governance

This connector brings the **identities** into XORCISM. The entitlement catalogue, Segregation-of-Duties
rules and violations, access requests and JIT grants are managed natively in the **/access-governance**
module (XORCISM's Saviynt-equivalent IGA layer) — seed a demo there, or build the entitlement model via the
explorer.
