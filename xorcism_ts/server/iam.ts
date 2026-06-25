/**
 * iam.ts — outbound IAM enforcement for the CROC loop's `constrain` action (Microsoft Entra ID / Graph).
 *
 * When a `constrain` policy fires on an over-scoped / high-risk (non-human) identity, the loop already
 * opens an internal Identity ticket. This module is the *teeth*: it can actually disable the principal
 * or revoke its sessions in Entra ID — the real least-privilege enforcement that closes the loop.
 *
 * Because this is a hard-to-reverse, outward-facing security action, it is deliberately conservative:
 *   • DRY-RUN BY DEFAULT — it only ever *recommends* the Graph action unless BOTH (a) the global arm
 *     switch `XOR_ALLOW_IAM_ENFORCE=1` is set, AND (b) the target's Mode is an actionable one.
 *   • SCOPED — it acts only on the named identity, only the configured action, and NEVER deletes.
 *   • AUDITED — every attempt is recorded on the loop event + the route audit log.
 *   • Best-effort — never throws (it runs inside emitLoopEvent).
 *
 * Auth reuses the Entra connector's app-only client-credentials (ENTRA_TENANT_ID / ENTRA_CLIENT_ID /
 * ENTRA_CLIENT_SECRET). LoginBase/GraphBase are overridable (per-target columns or ENTRA_LOGIN_BASE /
 * ENTRA_GRAPH_BASE) so the real Microsoft endpoints can be swapped for a mock in verification — in
 * production they default to the live endpoints. Requires app permissions to PATCH the principal
 * (Application.ReadWrite.All / User.ReadWrite.All) when armed.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();
const DEFAULT_LOGIN = "https://login.microsoftonline.com";
const DEFAULT_GRAPH = "https://graph.microsoft.com/v1.0";
export type IamMode = "recommend" | "disable" | "revoke-sessions" | "revoke-roles";

/** The global arm switch — no real Graph write happens unless this is explicitly set. */
export function iamEnforceArmed(): boolean { return String(process.env.XOR_ALLOW_IAM_ENFORCE || "") === "1"; }

interface IamConfig { name: string; tenantRef: string; clientId: string; clientSecret: string; mode: IamMode; loginBase: string; graphBase: string }
export interface IamConstraint { identityName: string; externalId?: string | null; kind?: "user" | "servicePrincipal" | null; reason?: string | null }

// ── target store ─────────────────────────────────────────────────────────────────────────
export function ensureIamTargets(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS IAMTARGET (
      TargetID INTEGER PRIMARY KEY,
      TargetGUID TEXT, Name TEXT, TenantRef TEXT, ClientId TEXT, ClientSecret TEXT,
      Mode TEXT DEFAULT 'recommend', LoginBase TEXT, GraphBase TEXT,
      EventFilter TEXT, Enabled INTEGER DEFAULT 1, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_iamtarget_tenant ON IAMTARGET(TenantID);
  `);
}

interface IamRow {
  TargetID: number; Name: string; TenantRef: string; ClientId: string; ClientSecret: string | null;
  Mode: string; LoginBase: string | null; GraphBase: string | null; EventFilter: string | null; Enabled: number; TenantID: number | null;
}

function listRows(tenant: number | null): IamRow[] {
  try {
    ensureIamTargets();
    return getDb("XORCISM").prepare("SELECT * FROM IAMTARGET WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY TargetID").all(tenant) as IamRow[];
  } catch { return []; }
}

const normMode = (m: string | null | undefined): IamMode =>
  m === "disable" || m === "revoke-sessions" || m === "revoke-roles" ? m : "recommend";

/** Client-safe view (secret masked, plus the live arm state). */
export function redactIamTargets(tenant: number | null): any[] {
  return listRows(tenant).map((r) => ({
    id: r.TargetID, name: r.Name, tenantRef: r.TenantRef, clientId: r.ClientId, mode: normMode(r.Mode),
    eventFilter: r.EventFilter, enabled: !!r.Enabled, hasSecret: !!r.ClientSecret,
    graphBase: r.GraphBase || DEFAULT_GRAPH,
  }));
}

export function addIamTarget(tenant: number | null, p: {
  name?: string; tenantRef: string; clientId: string; clientSecret: string; mode?: string;
  loginBase?: string; graphBase?: string; eventFilter?: string;
}): { id: number } {
  ensureIamTargets();
  const db = getDb("XORCISM");
  const id = allocId(db, "IAMTARGET", "TargetID");
  db.prepare(
    `INSERT INTO IAMTARGET (TargetID, TargetGUID, Name, TenantRef, ClientId, ClientSecret, Mode, LoginBase, GraphBase, EventFilter, Enabled, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)`
  ).run(id, randomUUID(), (p.name || "Entra ID").slice(0, 120), String(p.tenantRef || "").slice(0, 200),
    String(p.clientId || "").slice(0, 200), String(p.clientSecret || ""), normMode(p.mode),
    (p.loginBase || "").slice(0, 200) || null, (p.graphBase || "").slice(0, 200) || null, p.eventFilter || null, now(), tenant);
  return { id };
}

export function setIamTarget(tenant: number | null, id: number, patch: {
  enabled?: boolean; mode?: string; eventFilter?: string | null; name?: string;
  tenantRef?: string; clientId?: string; clientSecret?: string; loginBase?: string; graphBase?: string;
}): boolean {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM IAMTARGET WHERE TargetID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant)) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.enabled != null) { sets.push("Enabled=?"); vals.push(patch.enabled ? 1 : 0); }
  if (patch.mode) { sets.push("Mode=?"); vals.push(normMode(patch.mode)); }
  if (patch.eventFilter !== undefined) { sets.push("EventFilter=?"); vals.push(patch.eventFilter || null); }
  if (patch.name) { sets.push("Name=?"); vals.push(patch.name.slice(0, 120)); }
  if (patch.tenantRef) { sets.push("TenantRef=?"); vals.push(patch.tenantRef.slice(0, 200)); }
  if (patch.clientId) { sets.push("ClientId=?"); vals.push(patch.clientId.slice(0, 200)); }
  if (patch.clientSecret) { sets.push("ClientSecret=?"); vals.push(String(patch.clientSecret)); }
  if (patch.loginBase) { sets.push("LoginBase=?"); vals.push(patch.loginBase.slice(0, 200)); }
  if (patch.graphBase) { sets.push("GraphBase=?"); vals.push(patch.graphBase.slice(0, 200)); }
  if (sets.length) db.prepare(`UPDATE IAMTARGET SET ${sets.join(", ")} WHERE TargetID=?`).run(...vals, id);
  return true;
}

export function deleteIamTarget(tenant: number | null, id: number): boolean {
  return getDb("XORCISM").prepare("DELETE FROM IAMTARGET WHERE TargetID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant).changes > 0;
}

// ── target resolution (DB rows + env fallback) ─────────────────────────────────────────────
function envTarget(): IamConfig | null {
  const t = (process.env.ENTRA_TENANT_ID || "").trim();
  const c = (process.env.ENTRA_CLIENT_ID || "").trim();
  const s = process.env.ENTRA_CLIENT_SECRET || "";
  if (!t || !c || !s) return null;
  return {
    name: "Entra (env)", tenantRef: t, clientId: c, clientSecret: s,
    mode: normMode(process.env.IAM_ENFORCE_MODE), loginBase: (process.env.ENTRA_LOGIN_BASE || DEFAULT_LOGIN).replace(/\/$/, ""),
    graphBase: (process.env.ENTRA_GRAPH_BASE || DEFAULT_GRAPH).replace(/\/$/, ""),
  };
}

function resolveIamTargets(tenant: number | null, eventType?: string | null): IamConfig[] {
  const out: IamConfig[] = [];
  for (const r of listRows(tenant)) {
    if (!r.Enabled || !r.TenantRef || !r.ClientId || !r.ClientSecret) continue;
    if (r.EventFilter && eventType && !r.EventFilter.split(",").some((f) => String(eventType).toLowerCase().includes(f.trim().toLowerCase()))) continue;
    out.push({
      name: r.Name, tenantRef: r.TenantRef, clientId: r.ClientId, clientSecret: r.ClientSecret, mode: normMode(r.Mode),
      loginBase: (r.LoginBase || DEFAULT_LOGIN).replace(/\/$/, ""), graphBase: (r.GraphBase || DEFAULT_GRAPH).replace(/\/$/, ""),
    });
  }
  const env = envTarget();
  if (env) out.push(env);
  return out;
}

export function externalIamConfigured(tenant: number | null): boolean { return resolveIamTargets(tenant).length > 0; }

// ── Microsoft Graph calls ──────────────────────────────────────────────────────────────────
async function acquireGraphToken(cfg: IamConfig, timeoutMs = 15000): Promise<string | null> {
  try {
    const body = new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" });
    const r = await fetch(`${cfg.loginBase}/${encodeURIComponent(cfg.tenantRef)}/oauth2/v2.0/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString(), signal: AbortSignal.timeout(timeoutMs),
    });
    const j: any = await r.json().catch(() => null);
    return j && j.access_token ? String(j.access_token) : null;
  } catch { return null; }
}

async function graphGet(cfg: IamConfig, token: string, path: string): Promise<any> {
  try {
    const r = await fetch(`${cfg.graphBase}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" }, signal: AbortSignal.timeout(15000) });
    return r.ok ? await r.json().catch(() => null) : null;
  } catch { return null; }
}
async function graphWrite(cfg: IamConfig, token: string, path: string, method: "PATCH" | "POST" | "DELETE", payload?: unknown): Promise<boolean> {
  try {
    const r = await fetch(`${cfg.graphBase}${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: payload != null ? JSON.stringify(payload) : undefined, signal: AbortSignal.timeout(15000),
    });
    return r.ok; // Graph returns 204 for PATCH / DELETE / revokeSignInSessions
  } catch { return false; }
}

const odataLit = (s: string): string => `'${String(s).replace(/'/g, "''")}'`;

type Principal = { id: string; kind: "user" | "servicePrincipal" };

/**
 * Resolve a principal from XORCISM's own IDENTITY inventory by name (preferred — reliable, no Graph
 * search): returns the stored Entra object id (ExternalID) + kind from IdentityClass. Best-effort.
 */
function resolveFromInventory(tenant: number | null, name: string): Principal | null {
  try {
    const row = getDb("XORCISM").prepare(
      `SELECT ExternalID, IdentityClass FROM "IDENTITY"
       WHERE (TenantID = ? OR TenantID IS NULL) AND ExternalID IS NOT NULL AND ExternalID <> ''
         AND lower(IdentityName) = lower(?)
       ORDER BY CASE WHEN IdentityType='non-human' THEN 0 ELSE 1 END, IdentityID LIMIT 1`
    ).get(tenant, name) as { ExternalID: string; IdentityClass: string | null } | undefined;
    if (!row || !row.ExternalID) return null;
    return { id: String(row.ExternalID), kind: String(row.IdentityClass || "").toLowerCase() === "user" ? "user" : "servicePrincipal" };
  } catch { return null; }
}

/** Resolve a principal by display name via Graph (fallback when the inventory has no ExternalID). */
async function resolveByGraph(cfg: IamConfig, token: string, name: string): Promise<Principal | null> {
  const sp = await graphGet(cfg, token, `/servicePrincipals?$filter=displayName eq ${encodeURIComponent(odataLit(name))}&$select=id,displayName`);
  if (sp && sp.value && sp.value[0] && sp.value[0].id) return { id: String(sp.value[0].id), kind: "servicePrincipal" };
  const u = await graphGet(cfg, token, `/users?$filter=displayName eq ${encodeURIComponent(odataLit(name))} or userPrincipalName eq ${encodeURIComponent(odataLit(name))}&$select=id,displayName`);
  if (u && u.value && u.value[0] && u.value[0].id) return { id: String(u.value[0].id), kind: "user" };
  return null;
}

/**
 * Surgical least-privilege: strip the principal's standing privilege without disabling the account —
 * remove its app-role assignments (API permissions / app access) and its directory (RBAC) role
 * assignments. Returns the count removed. Best-effort.
 */
async function revokeRoles(cfg: IamConfig, token: string, obj: Principal, name: string): Promise<{ ok: boolean; ref: string }> {
  const kindPath = obj.kind === "user" ? "users" : "servicePrincipals";
  let removed = 0, listed = false;
  const ara = await graphGet(cfg, token, `/${kindPath}/${obj.id}/appRoleAssignments?$select=id`);
  if (ara && Array.isArray(ara.value)) { listed = true; for (const a of ara.value) { if (a && a.id && await graphWrite(cfg, token, `/${kindPath}/${obj.id}/appRoleAssignments/${a.id}`, "DELETE")) removed++; } }
  const dra = await graphGet(cfg, token, `/roleManagement/directory/roleAssignments?$filter=principalId eq ${encodeURIComponent(odataLit(obj.id))}&$select=id`);
  if (dra && Array.isArray(dra.value)) { listed = true; for (const a of dra.value) { if (a && a.id && await graphWrite(cfg, token, `/roleManagement/directory/roleAssignments/${a.id}`, "DELETE")) removed++; } }
  return { ok: listed, ref: `iam:revoked-roles ${name} (${removed})` };
}

/**
 * Take a noisy event summary and extract the most likely identity name (text before the first
 * separator). Splits on ':' / '(' / em- & en-dash / ',' — but NOT on a plain hyphen, since hyphens
 * are ubiquitous in principal names (svc-deploy-bot, app-prod-01).
 */
function cleanName(s: string): string {
  const first = String(s || "").split(/[:(,—–]/)[0].trim();
  return (first || String(s || "").trim()).slice(0, 120);
}

/**
 * Apply (or, by default, only recommend) the least-privilege constraint. Best-effort; never throws.
 * Returns the concrete refs to record on the loop event (e.g. "iam:disabled svc-deploy-bot" when armed,
 * or "iam:recommend disable(svc-deploy-bot)" in dry-run).
 */
export async function pushIamConstraint(tenant: number | null, c: IamConstraint): Promise<{ enforced: boolean; dryRun: boolean; refs: string[] }> {
  const armed = iamEnforceArmed();
  const refs: string[] = [];
  let enforced = false;
  try {
    const name = cleanName(c.identityName);
    for (const cfg of resolveIamTargets(tenant, c.reason)) {
      // recommend mode (or globally disarmed) → dry-run only; surgical revoke-roles is the suggestion.
      const intended: IamMode = cfg.mode === "recommend" ? "revoke-roles" : cfg.mode;
      if (!armed || cfg.mode === "recommend") { refs.push(`iam:recommend ${intended}(${name})`); continue; }
      try {
        const token = await acquireGraphToken(cfg);
        if (!token) { refs.push(`iam:auth-failed(${name})`); continue; }
        // Resolve the principal: explicit id → IDENTITY inventory (ExternalID) → Graph displayName.
        const obj: Principal | null = c.externalId
          ? { id: String(c.externalId), kind: (c.kind || "servicePrincipal") }
          : (resolveFromInventory(tenant, name) || await resolveByGraph(cfg, token, name));
        if (!obj) { refs.push(`iam:not-found(${name})`); continue; }
        let ok = false, ref = "";
        if (cfg.mode === "revoke-sessions") {
          ok = await graphWrite(cfg, token, `/users/${obj.id}/revokeSignInSessions`, "POST");
          ref = ok ? `iam:sessions-revoked ${name}` : `iam:action-failed(${name})`;
        } else if (cfg.mode === "revoke-roles") {
          const r = await revokeRoles(cfg, token, obj, name);
          ok = r.ok; ref = r.ok ? r.ref : `iam:action-failed(${name})`;
        } else { // disable
          ok = await graphWrite(cfg, token, `/${obj.kind === "user" ? "users" : "servicePrincipals"}/${obj.id}`, "PATCH", { accountEnabled: false });
          ref = ok ? `iam:disabled ${name}` : `iam:action-failed(${name})`;
        }
        if (ok) enforced = true;
        refs.push(ref);
      } catch { refs.push(`iam:error(${name})`); }
    }
  } catch { /* never throw */ }
  return { enforced, dryRun: !enforced, refs };
}

/** Non-destructive credential check for the Settings "Test" button: token + a single read. */
export async function testIamTarget(tenant: number | null, id: number): Promise<{ ok: boolean; armed: boolean; mode?: IamMode; note?: string } | null> {
  const row = listRows(tenant).find((r) => r.TargetID === id);
  if (!row) return null;
  const cfg: IamConfig = {
    name: row.Name, tenantRef: row.TenantRef, clientId: row.ClientId, clientSecret: row.ClientSecret || "", mode: normMode(row.Mode),
    loginBase: (row.LoginBase || DEFAULT_LOGIN).replace(/\/$/, ""), graphBase: (row.GraphBase || DEFAULT_GRAPH).replace(/\/$/, ""),
  };
  const token = await acquireGraphToken(cfg);
  if (!token) return { ok: false, armed: iamEnforceArmed(), mode: cfg.mode, note: "token request failed" };
  const probe = await graphGet(cfg, token, "/servicePrincipals?$top=1&$select=id");
  return { ok: !!probe, armed: iamEnforceArmed(), mode: cfg.mode, note: probe ? "authenticated (read-only probe)" : "token ok but read failed" };
}
