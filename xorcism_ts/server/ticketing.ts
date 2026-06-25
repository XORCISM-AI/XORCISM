/**
 * ticketing.ts — outbound ticket creation in external ITSM systems (Jira / ServiceNow).
 *
 * The CROC loop's `ticket` / `constrain` enforcement already opens an internal XTICKET work item.
 * This module is the *outbound bridge*: when an external Jira or ServiceNow destination is
 * configured, the same action also POSTs a real ticket into that system, at machine speed.
 *
 * Configuration mirrors teams.ts — a per-tenant DB table (TICKETINGTARGET) **plus an env fallback**
 * that reuses the very same secrets the inbound Jira/ServiceNow connectors already use, so a single
 * configuration enables both directions:
 *   Jira:        JIRA_URL + (JIRA_USER for Cloud) + JIRA_TOKEN + JIRA_PROJECT [+ JIRA_ISSUETYPE]
 *   ServiceNow:  SERVICENOW_INSTANCE + SERVICENOW_USER + SERVICENOW_PASSWORD [+ SERVICENOW_TABLE]
 *   gate:        TICKETING_MIN_SEVERITY (default "high") — only high/critical events push outbound.
 *
 * Worker-free (the Node server posts directly). Best-effort: every call is fire-and-forget and never
 * throws — nothing is posted unless a destination is configured. Credentials are never returned to
 * the client (redactTargets masks them).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();

// 5-level severity scale (+ notification-level aliases) used to gate which events push outbound.
const SEV_RANK: Record<string, number> = {
  info: 0, informational: 0, success: 0,
  low: 1,
  medium: 2, moderate: 2, warning: 2,
  high: 3, error: 3,
  critical: 4,
};
const srank = (s: string | null | undefined): number => SEV_RANK[String(s || "info").toLowerCase()] ?? 0;

export type TicketSystem = "jira" | "servicenow";
export interface OutboundTicket { subject: string; body: string; severity?: string | null; eventType?: string | null }
interface TargetConfig { system: TicketSystem; name: string; baseUrl: string; authUser: string; authSecret: string; project: string; issueType: string }

// ── target store ─────────────────────────────────────────────────────────────────────────
export function ensureTicketingTargets(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS TICKETINGTARGET (
      TargetID INTEGER PRIMARY KEY,
      TargetGUID TEXT, System TEXT, Name TEXT, BaseUrl TEXT,
      AuthUser TEXT, AuthSecret TEXT, Project TEXT, IssueType TEXT,
      MinSeverity TEXT DEFAULT 'high', EventFilter TEXT, Enabled INTEGER DEFAULT 1,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_ticketingtarget_tenant ON TICKETINGTARGET(TenantID);
  `);
}

interface TargetRow {
  TargetID: number; System: string; Name: string; BaseUrl: string; AuthUser: string | null; AuthSecret: string | null;
  Project: string | null; IssueType: string | null; MinSeverity: string; EventFilter: string | null; Enabled: number; TenantID: number | null;
}

function listRows(tenant: number | null): TargetRow[] {
  try {
    ensureTicketingTargets();
    return getDb("XORCISM").prepare(
      "SELECT * FROM TICKETINGTARGET WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY TargetID"
    ).all(tenant) as TargetRow[];
  } catch { return []; }
}

function hostOf(u: string): string { try { return new URL(/^https?:\/\//.test(u) ? u : "https://" + u).host; } catch { return "…"; } }

/** Client-safe view of the configured targets (secrets masked). */
export function redactTargets(tenant: number | null): any[] {
  return listRows(tenant).map((r) => ({
    id: r.TargetID, system: r.System, name: r.Name, host: hostOf(r.BaseUrl || ""),
    project: r.Project, issueType: r.IssueType, minSeverity: r.MinSeverity,
    eventFilter: r.EventFilter, enabled: !!r.Enabled, authUser: r.AuthUser || "", hasSecret: !!r.AuthSecret,
  }));
}

export function addTarget(tenant: number | null, p: {
  system: string; name?: string; baseUrl: string; authUser?: string; authSecret: string;
  project?: string; issueType?: string; minSeverity?: string; eventFilter?: string;
}): { id: number } {
  ensureTicketingTargets();
  const db = getDb("XORCISM");
  const id = allocId(db, "TICKETINGTARGET", "TargetID");
  const system: TicketSystem = p.system === "servicenow" ? "servicenow" : "jira";
  const minSev = p.minSeverity && SEV_RANK[String(p.minSeverity).toLowerCase()] != null ? String(p.minSeverity).toLowerCase() : "high";
  db.prepare(
    `INSERT INTO TICKETINGTARGET (TargetID, TargetGUID, System, Name, BaseUrl, AuthUser, AuthSecret, Project, IssueType, MinSeverity, EventFilter, Enabled, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)`
  ).run(id, randomUUID(), system, (p.name || (system === "jira" ? "Jira" : "ServiceNow")).slice(0, 120),
    String(p.baseUrl || "").slice(0, 300), (p.authUser || "").slice(0, 200), String(p.authSecret || ""),
    (p.project || (system === "servicenow" ? "incident" : "")).slice(0, 120),
    (p.issueType || (system === "jira" ? "Task" : "")).slice(0, 60), minSev, p.eventFilter || null, now(), tenant);
  return { id };
}

export function setTarget(tenant: number | null, id: number, patch: {
  enabled?: boolean; minSeverity?: string; eventFilter?: string | null; name?: string;
  project?: string; issueType?: string; baseUrl?: string; authUser?: string; authSecret?: string;
}): boolean {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM TICKETINGTARGET WHERE TargetID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant)) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.enabled != null) { sets.push("Enabled=?"); vals.push(patch.enabled ? 1 : 0); }
  if (patch.minSeverity && SEV_RANK[patch.minSeverity.toLowerCase()] != null) { sets.push("MinSeverity=?"); vals.push(patch.minSeverity.toLowerCase()); }
  if (patch.eventFilter !== undefined) { sets.push("EventFilter=?"); vals.push(patch.eventFilter || null); }
  if (patch.name) { sets.push("Name=?"); vals.push(patch.name.slice(0, 120)); }
  if (patch.project) { sets.push("Project=?"); vals.push(patch.project.slice(0, 120)); }
  if (patch.issueType) { sets.push("IssueType=?"); vals.push(patch.issueType.slice(0, 60)); }
  if (patch.baseUrl) { sets.push("BaseUrl=?"); vals.push(patch.baseUrl.slice(0, 300)); }
  if (patch.authUser !== undefined) { sets.push("AuthUser=?"); vals.push((patch.authUser || "").slice(0, 200)); }
  if (patch.authSecret) { sets.push("AuthSecret=?"); vals.push(String(patch.authSecret)); }
  if (sets.length) db.prepare(`UPDATE TICKETINGTARGET SET ${sets.join(", ")} WHERE TargetID=?`).run(...vals, id);
  return true;
}

export function deleteTarget(tenant: number | null, id: number): boolean {
  return getDb("XORCISM").prepare("DELETE FROM TICKETINGTARGET WHERE TargetID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant).changes > 0;
}

// ── target resolution (DB rows + env fallback) ─────────────────────────────────────────────
function envTargets(severity: string): TargetConfig[] {
  const out: TargetConfig[] = [];
  if (srank(severity) < srank(process.env.TICKETING_MIN_SEVERITY || "high")) return out;
  const jiraUrl = (process.env.JIRA_URL || "").trim();
  const jiraTok = (process.env.JIRA_TOKEN || process.env.JIRA_PAT || "").trim();
  const jiraProj = (process.env.JIRA_PROJECT || "").trim();
  if (jiraUrl && jiraTok && jiraProj) out.push({
    system: "jira", name: "Jira (env)", baseUrl: jiraUrl, authUser: (process.env.JIRA_USER || "").trim(),
    authSecret: jiraTok, project: jiraProj, issueType: (process.env.JIRA_ISSUETYPE || "Task").trim(),
  });
  const snInst = (process.env.SERVICENOW_INSTANCE || "").trim();
  const snUser = (process.env.SERVICENOW_USER || "").trim();
  const snPwd = process.env.SERVICENOW_PASSWORD || "";
  if (snInst && snUser && snPwd) out.push({
    system: "servicenow", name: "ServiceNow (env)", baseUrl: snInst, authUser: snUser,
    authSecret: snPwd, project: (process.env.SERVICENOW_TABLE || "incident").trim(), issueType: "",
  });
  return out;
}

function resolveTicketTargets(tenant: number | null, severity: string, eventType?: string | null): TargetConfig[] {
  const out: TargetConfig[] = [];
  for (const r of listRows(tenant)) {
    if (!r.Enabled || !r.BaseUrl || !r.AuthSecret) continue;
    if (srank(severity) < srank(r.MinSeverity)) continue;
    if (r.EventFilter && eventType && !r.EventFilter.split(",").some((f) => String(eventType).toLowerCase().includes(f.trim().toLowerCase()))) continue;
    out.push({
      system: r.System === "servicenow" ? "servicenow" : "jira", name: r.Name, baseUrl: r.BaseUrl,
      authUser: r.AuthUser || "", authSecret: r.AuthSecret, project: r.Project || (r.System === "servicenow" ? "incident" : ""),
      issueType: r.IssueType || (r.System === "jira" ? "Task" : ""),
    });
  }
  out.push(...envTargets(severity));
  return out;
}

/** Sync check: is at least one external ticketing destination configured for this tenant? */
export function externalTicketingConfigured(tenant: number | null): boolean {
  return resolveTicketTargets(tenant, "critical").length > 0;
}

// ── system-specific POSTs ─────────────────────────────────────────────────────────────────
async function postJson(url: string, headers: Record<string, string>, payload: unknown, timeoutMs = 15000): Promise<{ ok: boolean; status: number; json: any }> {
  try {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", ...headers }, body: JSON.stringify(payload), signal: AbortSignal.timeout(timeoutMs) });
    const text = await r.text().catch(() => "");
    let json: any = null; try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
    return { ok: r.ok, status: r.status, json };
  } catch { return { ok: false, status: 0, json: null }; }
}

async function createJira(cfg: TargetConfig, t: OutboundTicket): Promise<string | null> {
  const base = cfg.baseUrl.replace(/\/$/, "");
  const auth = cfg.authUser
    ? "Basic " + Buffer.from(`${cfg.authUser}:${cfg.authSecret}`).toString("base64") // Cloud
    : "Bearer " + cfg.authSecret;                                                     // Server/DC PAT
  const payload = { fields: {
    project: { key: cfg.project }, summary: (t.subject || "XORCISM CROC ticket").slice(0, 250),
    description: t.body || "", issuetype: { name: cfg.issueType || "Task" }, labels: ["xorcism", "croc"],
  } };
  const r = await postJson(`${base}/rest/api/2/issue`, { Authorization: auth }, payload);
  if (!r.ok || !r.json) return null;
  return r.json.key ? `jira:${r.json.key}` : (r.json.id ? `jira:${r.json.id}` : null);
}

async function createSnow(cfg: TargetConfig, t: OutboundTicket): Promise<string | null> {
  const raw = String(cfg.baseUrl || "").trim().replace(/\/$/, "");
  const base = /^https?:\/\//.test(raw) ? raw : "https://" + raw; // bare hostname → https (ServiceNow default)
  const auth = "Basic " + Buffer.from(`${cfg.authUser}:${cfg.authSecret}`).toString("base64");
  const sev = srank(t.severity);
  const u = sev >= 3 ? "1" : sev === 2 ? "2" : "3"; // urgency/impact: high/crit→1, med→2, else→3
  const payload = { short_description: (t.subject || "XORCISM CROC ticket").slice(0, 160), description: t.body || "", urgency: u, impact: u };
  const r = await postJson(`${base}/api/now/table/${cfg.project || "incident"}`, { Authorization: auth }, payload);
  if (!r.ok || !r.json) return null;
  const num = r.json.result && r.json.result.number;
  return num ? `snow:${num}` : null;
}

/** Push the ticket into every configured external destination. Best-effort; never throws. */
export async function pushExternalTicket(tenant: number | null, t: OutboundTicket): Promise<{ created: number; failed: number; refs: string[] }> {
  let created = 0, failed = 0; const refs: string[] = [];
  try {
    for (const cfg of resolveTicketTargets(tenant, t.severity || "high", t.eventType)) {
      let ref: string | null = null;
      try { ref = cfg.system === "jira" ? await createJira(cfg, t) : await createSnow(cfg, t); } catch { ref = null; }
      if (ref) { created++; refs.push(ref); } else failed++;
    }
  } catch { /* never throw */ }
  return { created, failed, refs };
}

/** Push a one-off test ticket to a single stored target (Settings "Test" button). */
export async function testTarget(tenant: number | null, id: number): Promise<{ ok: boolean; ref?: string } | null> {
  const row = listRows(tenant).find((r) => r.TargetID === id);
  if (!row) return null;
  const cfg: TargetConfig = {
    system: row.System === "servicenow" ? "servicenow" : "jira", name: row.Name, baseUrl: row.BaseUrl,
    authUser: row.AuthUser || "", authSecret: row.AuthSecret || "", project: row.Project || "incident", issueType: row.IssueType || "Task",
  };
  const t: OutboundTicket = { subject: "XORCISM CROC — test ticket", body: "If you can read this, outbound ticketing from the CROC loop is working.", severity: "high", eventType: "test" };
  const ref = cfg.system === "jira" ? await createJira(cfg, t) : await createSnow(cfg, t);
  return { ok: !!ref, ref: ref || undefined };
}
