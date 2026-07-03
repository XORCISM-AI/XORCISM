# XOR agent — token management

How the XOR endpoint agent (`xor_agent.py`) authenticates to the XORCISM server: how the
agent token is **issued, stored, used, rotated and revoked**, and how to operate it safely.

---

## 1. What the token is

Every enrolled agent holds **one bearer token** — a 192‑bit random secret (`24` bytes → 48 hex
characters). The agent presents it on every request:

```
Authorization: Bearer <token>
```

The token *is* the agent's identity and its authorization. Anyone holding it can act as that
agent (report inventory, push events, pull threat intel / OVAL content). Treat it like a password.

**Server never stores the raw token.** Enrollment returns the token once; the server keeps only its
`SHA‑256` hash in `XAGENT.token_hash`. A stolen database therefore does not leak usable tokens, but a
leaked `xor_agent.conf` (see §4) does — so protect the file, not just the DB.

---

## 2. Lifecycle at a glance

```
  enroll ──▶ issue ──▶ store ──▶ use ──▶ rotate / revoke
  (key)     (server)  (agent)  (Bearer)  (re-enroll / delete)
```

| Phase | Where | What happens |
|---|---|---|
| **Enroll** | agent → `POST /api/agent/enroll` | gated by the shared enrollment key (`X-Enroll-Key`) |
| **Issue** | server `enrollAgent()` | `token = randomBytes(24).hex`; server stores only `sha256(token)` |
| **Store** | agent `xor_agent.conf` | token saved **in clear text** (JSON) next to the script |
| **Use** | agent → every endpoint | `Authorization: Bearer <token>` → server `agentByToken()` |
| **Rotate** | re-enroll same agent name | new token issued; old `token_hash` overwritten → old token dead |
| **Revoke** | delete the `XAGENT` row | `token_hash` gone → all requests with that token get `401` |

There is **no token TTL** — a token is valid until it is rotated (re-enroll) or revoked (delete the
agent). Rotate on a schedule and on any suspected compromise (§7).

---

## 3. Enrollment — the enrollment key

Enrollment is the only unauthenticated endpoint, so it is protected by a **shared enrollment key**
set on the server as an environment variable:

```bash
# On the XORCISM server:
export XOR_ENROLL_KEY="<a long random secret>"
```

- If `XOR_ENROLL_KEY` is **set**, `POST /api/agent/enroll` requires a matching `X-Enroll-Key` header,
  else it returns `403`.
- If `XOR_ENROLL_KEY` is **unset** *and* no managed keys exist (see below), enrollment is **open** —
  dev/lab only. **Always require a key in production.**

### Managed enrollment keys (admin UI)

Instead of (or in addition to) the single `XOR_ENROLL_KEY` env var, a super-admin can manage
**multiple named enrollment keys** from **Administration → “Agent enrollment keys”**
(`/api/admin/enroll-keys`). Each key:

- is created with a **label**, an optional **tenant** scope and an optional **expiry** (days);
- is shown **once** at creation (raw value prefixed `xen_…`) — only its `SHA-256` is stored, in
  `XID.XENROLLKEY.KeyHash`, exactly like an API key;
- can be **revoked** at any time (soft delete → `Revoked = 1`); revoked/expired keys are refused.

At enrollment the presented `X-Enroll-Key` is accepted if it matches **either** the `XOR_ENROLL_KEY`
env var **or** any active managed key. A key becomes **required** as soon as the env var is set *or*
at least one active managed key exists. Each successful use bumps the key’s `UseCount` / `LastUsedDate`
for visibility. Rotating a managed key = create a new one and revoke the old.

Enroll an endpoint (the agent sends `X-Enroll-Key` for you via `--enroll-key`):

```bash
python xor_agent.py --enroll --server https://xorcism.example:9292 --enroll-key "<XOR_ENROLL_KEY>"
```

On success the agent prints `enroll OK — asset «…», token saved in xor_agent.conf` and the endpoint
appears as an **ASSET** in XORCISM (and under `/agents`). The enrollment key is a *bootstrap* secret —
it is **not** stored in `xor_agent.conf`; only the per‑agent token is.

---

## 4. Where the token lives

| Side | Location | Form |
|---|---|---|
| **Server** | `XAGENT.token_hash` (XAGENT DB) | `SHA‑256(token)` — never the raw token |
| **Agent** | `xor_agent.conf` (next to the script, or `--conf <path>`) | raw token, **clear‑text JSON** |

`xor_agent.conf` also holds `server`, `name` and `insecure`. Because the token is in clear text,
**restrict the file's permissions** on the endpoint:

```bash
# Linux / macOS
chmod 600 xor_agent.conf && chown root:root xor_agent.conf
```
```powershell
# Windows — remove inherited ACLs, grant only SYSTEM + Administrators
icacls xor_agent.conf /inheritance:r /grant:r "SYSTEM:F" "Administrators:F"
```

Run the agent as a dedicated service account with least privilege; the config file should be readable
only by that account.

---

## 5. Authentication — how the token is used

The agent's token endpoints are mounted **before** the web session gate (they use bearer‑token auth
only — no cookie, no CSRF). The middleware reads `Authorization: Bearer <token>`, looks up
`agentByToken(token)` = `WHERE token_hash = sha256(token)`, and returns `401` if there is no match.

Token‑authenticated endpoints (all under `/api/agent/…`):
`checkin` · `inventory` · `vulnerabilities` · `events` · `honeypot` · `memdump` · `loghunt` ·
`aiguard` · `query` · `oval` · `oval-content` · `match` · `intel` · `yara-rules` · `emulation`.

The token authorizes **only** these agent endpoints — it is **not** a XORCISM user session and grants
no access to the web UI or the REST API (`/api/v1`, which uses separate `XAPIKEY` keys).

---

## 6. Rotation

Rotating a token = **re-enrolling the same agent name**:

```bash
python xor_agent.py --enroll --server https://xorcism.example:9292 --enroll-key "<XOR_ENROLL_KEY>"
```

`enrollAgent()` finds the existing `XAGENT` row by `name`, generates a fresh token and **overwrites**
`token_hash`. The previous token is invalid immediately (its hash no longer matches). The agent writes
the new token to `xor_agent.conf`. No asset/history is lost — the same `AgentID`/ASSET is reused.

Rotate: on a schedule (e.g. every 90 days), when staff leave, or on any suspected leak.

---

## 7. Revocation

There is no separate "revoke" flag — revocation is removing the credential:

- **Rotate** (preferred if the endpoint is still trusted): re-enroll (§6) — the old token dies at once.
- **Hard revoke** (endpoint decommissioned or compromised): delete the agent's `XAGENT` row in the
  schema explorer → `/?db=XAGENT&table=XAGENT` → filter by `name` → delete. Once the row (and its
  `token_hash`) is gone, every request with that token returns `401`. Also delete `xor_agent.conf`
  on the endpoint so the secret is not left on disk.

The `XAGENT.status` / `last_seen` columns are for fleet visibility (online / stale), **not** an auth
gate — setting `status` does not disable a token; only rotating or deleting does.

---

## 8. Hardening checklist

- [ ] Set a long, random `XOR_ENROLL_KEY` on the server; never leave enrollment open in production.
- [ ] Enroll over **HTTPS** with a valid certificate. Do **not** use `--insecure` in production — it
      disables TLS verification (`ssl._create_unverified_context()`) and exposes the token to MITM.
- [ ] `chmod 600` / tight ACLs on `xor_agent.conf`; run the agent as a least‑privilege service account.
- [ ] **One token per endpoint** — never copy `xor_agent.conf` between hosts (a shared token cannot be
      attributed or revoked per host).
- [ ] Rotate tokens on a schedule and on staff changes; rotate the **enrollment key** periodically too.
- [ ] Monitor `/agents` (and `XAGENT.last_seen` / events) for stale or unexpected agents; revoke unknown ones.
- [ ] Keep server↔agent traffic on a trusted network/VPN where possible.

---

## 9. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `enroll` returns `403` | `X-Enroll-Key` missing/wrong → pass a correct `--enroll-key` matching the server's `XOR_ENROLL_KEY` **or** an active managed key (Administration → Agent enrollment keys). |
| Endpoints return `401` after enroll | token in `xor_agent.conf` doesn't match `token_hash` (rotated/revoked elsewhere) → re-enroll. |
| TLS / certificate error on enroll | use a valid cert; only as a last resort in a lab, `--insecure` (never in prod). |
| Agent not visible in `/agents` | enrollment failed (check the `enroll` output) or a different `--server` was used. |
| Want to move an agent to a new server | re-enroll against the new `--server` (writes a new token for that server into the conf). |

---

## 10. Reference

**Environment (server):** `XOR_ENROLL_KEY` — shared enrollment secret (unset *and* no managed keys =
open enrollment, dev only). Managed alternative: Administration → Agent enrollment keys (`XID.XENROLLKEY`).

**Agent flags:** `--enroll`, `--server <url>`, `--enroll-key <KEY>`, `--conf <path>`, `--insecure`.

**Files:** agent `xor_agent.conf` (raw token, clear‑text JSON) · server `XAGENT.token_hash` (SHA‑256).

**Code:** issue/verify in [`xorcism_ts/server/agents.ts`](../xorcism_ts/server/agents.ts)
(`enrollAgent` / `agentByToken`, `randomBytes(24).hex` + `sha256`); routing + enroll gate in
[`xorcism_ts/server/routes/agent.ts`](../xorcism_ts/server/routes/agent.ts) (`agentTokenRouter`,
`tokenAuth`, `XOR_ENROLL_KEY`); agent client in [`xor_agent.py`](xor_agent.py) (`enroll`, `save_conf`).

**`XAGENT` columns:** `AgentID, name, token_hash, asset_name, os, platform, version, ip, fqdn, status,
enrolled_at, last_seen, intel_seen`.

*See also: [README.md](README.md) (agent overview) · [SETUP.md](SETUP.md) (deployment).*
