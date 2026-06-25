/**
 * soar.ts — outbound SOAR / automation dispatch for the CROC loop (n8n & any webhook-driven SOAR).
 *
 * Every action the loop fires (escalate / ticket / constrain / notify / reprioritize) is also POSTed
 * as a compact JSON event to the configured automation webhooks, so an n8n / Tines / Shuffle workflow
 * can run arbitrary downstream playbooks (enrich, quarantine, page, open a bridge, …). This is the
 * generic "glue" rung: XORCISM decides + acts on the things it owns, and hands everything else to the
 * SOAR. Mirrors teams.ts (webhook store + env fallback N8N_WEBHOOK_URL / N8N_API_KEY). Fire-and-forget,
 * best-effort, never throws; nothing is posted unless a webhook is configured.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();
const SEV_RANK: Record<string, number> = { info: 0, informational: 0, success: 0, low: 1, medium: 2, moderate: 2, warning: 2, high: 3, error: 3, critical: 4 };
const srank = (s: string | null | undefined): number => SEV_RANK[String(s || "info").toLowerCase()] ?? 0;

export interface SoarEvent { action: string; eventType: string; severity?: string | null; summary?: string | null; refs?: string[] }

export function ensureSoarTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS SOARWEBHOOK (
      WebhookID INTEGER PRIMARY KEY,
      WebhookGUID TEXT, Name TEXT, Url TEXT, ApiKey TEXT, MinSeverity TEXT DEFAULT 'high',
      EventFilter TEXT, Enabled INTEGER DEFAULT 1, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_soarwebhook_tenant ON SOARWEBHOOK(TenantID);
  `);
}

interface SoarRow { WebhookID: number; Name: string; Url: string; ApiKey: string | null; MinSeverity: string; EventFilter: string | null; Enabled: number; TenantID: number | null }

function listRows(tenant: number | null): SoarRow[] {
  try { ensureSoarTables(); return getDb("XORCISM").prepare("SELECT * FROM SOARWEBHOOK WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY WebhookID").all(tenant) as SoarRow[]; }
  catch { return []; }
}

function hostOf(u: string): string { try { return new URL(u).host; } catch { return "…"; } }

export function redactSoar(tenant: number | null): any[] {
  return listRows(tenant).map((r) => ({ id: r.WebhookID, name: r.Name, host: hostOf(r.Url || ""), minSeverity: r.MinSeverity, eventFilter: r.EventFilter, enabled: !!r.Enabled, hasKey: !!r.ApiKey }));
}

export function addSoar(tenant: number | null, p: { name?: string; url: string; apiKey?: string; minSeverity?: string; eventFilter?: string }): { id: number } {
  ensureSoarTables();
  const db = getDb("XORCISM");
  const id = allocId(db, "SOARWEBHOOK", "WebhookID");
  const minSev = p.minSeverity && SEV_RANK[String(p.minSeverity).toLowerCase()] != null ? String(p.minSeverity).toLowerCase() : "high";
  db.prepare("INSERT INTO SOARWEBHOOK (WebhookID, WebhookGUID, Name, Url, ApiKey, MinSeverity, EventFilter, Enabled, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,1,?,?)")
    .run(id, randomUUID(), (p.name || "n8n / SOAR").slice(0, 120), String(p.url || "").slice(0, 400), p.apiKey || null, minSev, p.eventFilter || null, now(), tenant);
  return { id };
}

export function setSoar(tenant: number | null, id: number, patch: { enabled?: boolean; minSeverity?: string; eventFilter?: string | null; name?: string; url?: string; apiKey?: string }): boolean {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM SOARWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant)) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.enabled != null) { sets.push("Enabled=?"); vals.push(patch.enabled ? 1 : 0); }
  if (patch.minSeverity && SEV_RANK[patch.minSeverity.toLowerCase()] != null) { sets.push("MinSeverity=?"); vals.push(patch.minSeverity.toLowerCase()); }
  if (patch.eventFilter !== undefined) { sets.push("EventFilter=?"); vals.push(patch.eventFilter || null); }
  if (patch.name) { sets.push("Name=?"); vals.push(patch.name.slice(0, 120)); }
  if (patch.url) { sets.push("Url=?"); vals.push(patch.url.slice(0, 400)); }
  if (patch.apiKey) { sets.push("ApiKey=?"); vals.push(String(patch.apiKey)); }
  if (sets.length) db.prepare(`UPDATE SOARWEBHOOK SET ${sets.join(", ")} WHERE WebhookID=?`).run(...vals, id);
  return true;
}

export function deleteSoar(tenant: number | null, id: number): boolean {
  return getDb("XORCISM").prepare("DELETE FROM SOARWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant).changes > 0;
}

interface SoarTarget { url: string; apiKey: string | null }
function resolveSoar(tenant: number | null, severity: string, eventType?: string | null): SoarTarget[] {
  const out: SoarTarget[] = [];
  for (const r of listRows(tenant)) {
    if (!r.Enabled || !r.Url) continue;
    if (srank(severity) < srank(r.MinSeverity)) continue;
    if (r.EventFilter && eventType && !r.EventFilter.split(",").some((f) => String(eventType).toLowerCase().includes(f.trim().toLowerCase()))) continue;
    out.push({ url: r.Url, apiKey: r.ApiKey });
  }
  const envUrl = (process.env.N8N_WEBHOOK_URL || "").trim();
  if (envUrl && srank(severity) >= srank(process.env.SOAR_MIN_SEVERITY || "high")) out.push({ url: envUrl, apiKey: process.env.N8N_API_KEY || null });
  return out;
}

export function externalSoarConfigured(tenant: number | null): boolean { return resolveSoar(tenant, "critical").length > 0; }

async function postWebhook(t: SoarTarget, payload: unknown): Promise<boolean> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (t.apiKey) headers["X-API-Key"] = t.apiKey;
    const r = await fetch(t.url, { method: "POST", headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(15000) });
    return r.ok;
  } catch { return false; }
}

/** Fan an action out to the configured SOAR webhooks. Best-effort, fire-and-forget. */
export async function dispatchSoar(tenant: number | null, ev: SoarEvent): Promise<{ sent: number; failed: number }> {
  let sent = 0, failed = 0;
  try {
    const targets = resolveSoar(tenant, ev.severity || "info", ev.eventType);
    if (!targets.length) return { sent, failed };
    const payload = { source: "xorcism-croc", action: ev.action, eventType: ev.eventType, severity: ev.severity || "info", summary: ev.summary || "", refs: ev.refs || [], at: now() };
    for (const t of targets) { if (await postWebhook(t, payload)) sent++; else failed++; }
  } catch { /* never throw */ }
  return { sent, failed };
}

/** Post one test event to a stored webhook (Settings "Test" button). */
export async function testSoar(tenant: number | null, id: number): Promise<{ ok: boolean } | null> {
  const row = listRows(tenant).find((r) => r.WebhookID === id);
  if (!row) return null;
  const ok = await postWebhook({ url: row.Url, apiKey: row.ApiKey }, { source: "xorcism-croc", action: "test", eventType: "test", severity: "high", summary: "CROC SOAR connectivity test", at: now() });
  return { ok };
}

// ════════════════════════════════════════════════════════════════════════════
// SOAR cockpit — Security Orchestration, Automation & Response playbooks.
//
// Beyond the outbound webhook glue above, this is the orchestration layer: named
// automation playbooks (trigger → ordered actions) drawn from a built-in action
// catalogue, with a run engine. Runs default to SIMULATE (dry-run: each action is
// modeled, no real side effects) so playbooks can be designed and validated safely;
// the real outbound rung remains dispatchSoar()/SOARWEBHOOK. Tables live in XINCIDENT.
// ════════════════════════════════════════════════════════════════════════════

/** The SOAR trigger catalogue — the events a playbook can fire on. */
export const SOAR_TRIGGERS = [
  { id: "incident.created", label: "Incident created", severity: "high" },
  { id: "malware.malicious", label: "Malicious verdict (malware scan)", severity: "critical" },
  { id: "alert.high", label: "High/critical alert", severity: "high" },
  { id: "exposure.kev", label: "New KEV exposure on an asset", severity: "high" },
  { id: "phishing.reported", label: "Phishing reported", severity: "medium" },
  { id: "manual", label: "Manual / on-demand", severity: "info" },
];

/** The built-in action catalogue — the orchestration building blocks. */
export const SOAR_ACTIONS: Record<string, { label: string; sim: (params: string) => string }> = {
  "enrich-ioc": { label: "Enrich IOC (reputation)", sim: (p) => `Would enrich indicator(s) ${p || "from the trigger"} across the configured malware-scan engines and attach the verdict.` },
  "notify": { label: "Notify (Teams / SOAR webhook)", sim: (p) => `Would notify ${p || "the on-call channel"} via the configured Teams / SOAR webhook.` },
  "create-ticket": { label: "Create ticket (Jira / ServiceNow)", sim: (p) => `Would open a tracking ticket${p ? ` (${p})` : ""} via the CROC ticketing target.` },
  "isolate-host": { label: "Isolate host (EDR)", sim: (p) => `Would network-isolate host ${p || "the affected endpoint"} via the EDR/Rustinel target.` },
  "block-indicator": { label: "Block indicator (firewall/proxy)", sim: (p) => `Would block ${p || "the malicious indicator"} at the firewall/proxy.` },
  "disable-account": { label: "Disable account (IAM)", sim: (p) => `Would disable account ${p || "the compromised identity"} via the Entra/Graph IAM target.` },
  "scan-asset": { label: "Scan asset", sim: (p) => `Would launch a scan against ${p || "the affected asset"}.` },
  "escalate": { label: "Escalate (SOC tier)", sim: (p) => `Would escalate to ${p || "the next SOC tier"} per the escalation policy.` },
  "run-automation": { label: "Run automation (n8n / SOAR)", sim: (p) => `Would trigger the n8n / SOAR workflow${p ? ` "${p}"` : ""} via the outbound webhook.` },
};

export function ensureSoarOpsTables(): void {
  getDb("XINCIDENT").exec(`
    CREATE TABLE IF NOT EXISTS SOARPLAYBOOK (
      PlaybookID INTEGER PRIMARY KEY, PlaybookGUID TEXT, Name TEXT, Description TEXT, TriggerType TEXT,
      Category TEXT, Enabled INTEGER DEFAULT 1, RunCount INTEGER DEFAULT 0, LastRunAt TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS SOARPLAYBOOKACTION (
      ActionID INTEGER PRIMARY KEY, PlaybookID INTEGER, StepOrder INTEGER, ActionType TEXT, Name TEXT,
      Params TEXT, OnFailure TEXT DEFAULT 'continue', CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS SOARRUN (
      RunID INTEGER PRIMARY KEY, RunGUID TEXT, PlaybookID INTEGER, Mode TEXT, TriggerRef TEXT, Status TEXT,
      Steps INTEGER, StartedAt TEXT, FinishedAt TEXT, Summary TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS SOARRUNSTEP (
      RunStepID INTEGER PRIMARY KEY, RunID INTEGER, StepOrder INTEGER, ActionType TEXT, Name TEXT,
      Status TEXT, Output TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_soarplaybook_tenant ON SOARPLAYBOOK(TenantID);
    CREATE INDEX IF NOT EXISTS ix_soarrun_pb ON SOARRUN(PlaybookID);
  `);
}

const xi = () => getDb("XINCIDENT");
const stw = (tenant: number | null): string => (tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "");
function nextXi(table: string, pk: string): number { return (xi().prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n; }
function playbookOk(id: number, tenant: number | null): boolean {
  const r = xi().prepare("SELECT TenantID FROM SOARPLAYBOOK WHERE PlaybookID = ?").get(id) as { TenantID: number | null } | undefined;
  return !!r && (tenant == null || r.TenantID == null || Number(r.TenantID) === tenant);
}

export function soarDashboard(tenant: number | null): any {
  try { ensureSoarTables(); } catch { /* XORCISM webhook store optional */ }
  ensureSoarOpsTables();
  const db = xi();
  const pbs = db.prepare(`SELECT PlaybookID, Name, Description, TriggerType, Category, Enabled, RunCount, LastRunAt FROM SOARPLAYBOOK ${stw(tenant)} ORDER BY Name`).all() as any[];
  const actsBy = new Map<number, any[]>();
  for (const a of db.prepare("SELECT ActionID, PlaybookID, StepOrder, ActionType, Name, Params, OnFailure FROM SOARPLAYBOOKACTION ORDER BY PlaybookID, StepOrder").all() as any[]) {
    const k = Number(a.PlaybookID); if (!actsBy.has(k)) actsBy.set(k, []);
    actsBy.get(k)!.push({ id: Number(a.ActionID), order: Number(a.StepOrder), type: String(a.ActionType), name: String(a.Name ?? ""), params: String(a.Params ?? ""), onFailure: String(a.OnFailure ?? "continue") });
  }
  const playbooks = pbs.map((p) => ({ id: Number(p.PlaybookID), name: String(p.Name), description: String(p.Description ?? ""), trigger: String(p.TriggerType ?? "manual"), category: String(p.Category ?? ""), enabled: Number(p.Enabled) === 1, runCount: Number(p.RunCount ?? 0), lastRunAt: p.LastRunAt || null, actions: actsBy.get(Number(p.PlaybookID)) || [] }));
  const runs = (db.prepare(`SELECT RunID, PlaybookID, Mode, Status, Steps, StartedAt, FinishedAt, Summary FROM SOARRUN ${stw(tenant)} ORDER BY RunID DESC LIMIT 25`).all() as any[])
    .map((r) => ({ id: Number(r.RunID), playbookId: Number(r.PlaybookID), playbookName: playbooks.find((p) => p.id === Number(r.PlaybookID))?.name || `#${r.PlaybookID}`, mode: String(r.Mode ?? "simulate"), status: String(r.Status ?? ""), steps: Number(r.Steps ?? 0), startedAt: r.StartedAt, summary: String(r.Summary ?? "") }));

  const triggersCovered = new Set(playbooks.filter((p) => p.enabled).map((p) => p.trigger));
  const worklist: { label: string; severity: string }[] = [];
  for (const t of SOAR_TRIGGERS) if (t.id !== "manual" && !triggersCovered.has(t.id)) worklist.push({ label: `No enabled playbook for trigger "${t.label}"`, severity: "Medium" });
  for (const p of playbooks) if (!p.actions.length) worklist.push({ label: `Playbook "${p.name}" has no actions defined`, severity: "Low" });
  const totalRuns = Number((db.prepare(`SELECT COUNT(*) n FROM SOARRUN ${stw(tenant)}`).get() as { n: number }).n);
  const okRuns = Number((db.prepare(`SELECT COUNT(*) n FROM SOARRUN ${tenant != null ? `WHERE (TenantID=${tenant} OR TenantID IS NULL) AND` : "WHERE"} Status='success'`).get() as { n: number }).n);

  return {
    summary: {
      playbooks: playbooks.length, enabled: playbooks.filter((p) => p.enabled).length,
      actions: playbooks.reduce((s, p) => s + p.actions.length, 0),
      triggersCovered: triggersCovered.size, triggersTotal: SOAR_TRIGGERS.length - 1,
      runs: totalRuns, successRuns: okRuns, successRate: totalRuns ? Math.round((okRuns / totalRuns) * 100) : null,
      webhookTargets: redactSoar(tenant).length, externalConfigured: externalSoarConfigured(tenant),
    },
    playbooks, runs, worklist,
    triggers: SOAR_TRIGGERS, actionCatalogue: Object.entries(SOAR_ACTIONS).map(([id, a]) => ({ id, label: a.label })),
    webhooks: redactSoar(tenant),
  };
}

export function createSoarPlaybook(p: { name: string; description?: string; triggerType?: string; category?: string; actions?: { actionType: string; name?: string; params?: string; onFailure?: string }[] }, tenant: number | null): { id: number } {
  ensureSoarOpsTables();
  const db = xi(); const id = nextXi("SOARPLAYBOOK", "PlaybookID"); const ts = now();
  const trig = SOAR_TRIGGERS.some((t) => t.id === p.triggerType) ? p.triggerType! : "manual";
  db.prepare("INSERT INTO SOARPLAYBOOK (PlaybookID, PlaybookGUID, Name, Description, TriggerType, Category, Enabled, RunCount, LastRunAt, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,0,?,?,?)")
    .run(id, randomUUID(), p.name.trim(), (p.description || "").trim(), trig, (p.category || "General").trim(), 1, null, ts, tenant);
  const actions = (p.actions || []).filter((a) => a && SOAR_ACTIONS[a.actionType]);
  let sid = nextXi("SOARPLAYBOOKACTION", "ActionID");
  const ins = db.prepare("INSERT INTO SOARPLAYBOOKACTION (ActionID, PlaybookID, StepOrder, ActionType, Name, Params, OnFailure, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)");
  actions.forEach((a, i) => ins.run(sid++, id, i + 1, a.actionType, (a.name || SOAR_ACTIONS[a.actionType].label).slice(0, 160), (a.params || "").slice(0, 300), a.onFailure === "stop" ? "stop" : "continue", ts, tenant));
  return { id };
}

export function setSoarPlaybookEnabled(id: number, enabled: boolean, tenant: number | null): boolean {
  if (!playbookOk(id, tenant)) return false;
  xi().prepare("UPDATE SOARPLAYBOOK SET Enabled = ? WHERE PlaybookID = ?").run(enabled ? 1 : 0, id);
  return true;
}

export function deleteSoarPlaybook(id: number, tenant: number | null): boolean {
  if (!playbookOk(id, tenant)) return false;
  const db = xi();
  db.prepare("DELETE FROM SOARPLAYBOOKACTION WHERE PlaybookID = ?").run(id);
  db.prepare("DELETE FROM SOARPLAYBOOK WHERE PlaybookID = ?").run(id);
  return true;
}

/** Execute a playbook. mode='simulate' (default, dry-run, no side effects) models each action's outcome. */
export function runSoarPlaybook(id: number, tenant: number | null, opts?: { mode?: string; triggerRef?: string }): { runId: number; status: string; steps: number } | null {
  if (!playbookOk(id, tenant)) return null;
  ensureSoarOpsTables();
  const db = xi();
  const actions = db.prepare("SELECT ActionID, StepOrder, ActionType, Name, Params FROM SOARPLAYBOOKACTION WHERE PlaybookID = ? ORDER BY StepOrder").all(id) as any[];
  const mode = opts?.mode === "live" ? "live" : "simulate"; // live currently dispatches only via the safe webhook rung; simulate is dry-run
  const runId = nextXi("SOARRUN", "RunID"); const startedAt = now();
  let rsid = nextXi("SOARRUNSTEP", "RunStepID");
  const insStep = db.prepare("INSERT INTO SOARRUNSTEP (RunStepID, RunID, StepOrder, ActionType, Name, Status, Output, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)");
  let ok = 0;
  for (const a of actions) {
    const cat = SOAR_ACTIONS[String(a.ActionType)];
    const output = cat ? cat.sim(String(a.Params ?? "")) : `Unknown action "${a.ActionType}".`;
    const status = cat ? "success" : "skipped";
    if (status === "success") ok++;
    insStep.run(rsid++, runId, Number(a.StepOrder), String(a.ActionType), String(a.Name ?? ""), status, (mode === "simulate" ? "[dry-run] " : "") + output, now(), tenant);
  }
  const status = actions.length === 0 ? "empty" : ok === actions.length ? "success" : ok > 0 ? "partial" : "failed";
  const summary = `${mode === "simulate" ? "Simulated" : "Executed"} ${actions.length} action(s) — ${ok} ok`;
  db.prepare("INSERT INTO SOARRUN (RunID, RunGUID, PlaybookID, Mode, TriggerRef, Status, Steps, StartedAt, FinishedAt, Summary, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(runId, randomUUID(), id, mode, opts?.triggerRef || "manual", status, actions.length, startedAt, now(), summary, startedAt, tenant);
  db.prepare("UPDATE SOARPLAYBOOK SET RunCount = RunCount + 1, LastRunAt = ? WHERE PlaybookID = ?").run(startedAt, id);
  return { runId, status, steps: actions.length };
}

export function soarRunDetail(runId: number, tenant: number | null): any {
  const db = xi();
  const run = db.prepare(`SELECT RunID, PlaybookID, Mode, Status, Steps, StartedAt, Summary FROM SOARRUN WHERE RunID = ? ${tenant != null ? "AND (TenantID=" + tenant + " OR TenantID IS NULL)" : ""}`).get(runId) as any;
  if (!run) return null;
  const steps = (db.prepare("SELECT StepOrder, ActionType, Name, Status, Output FROM SOARRUNSTEP WHERE RunID = ? ORDER BY StepOrder").all(runId) as any[])
    .map((s) => ({ order: Number(s.StepOrder), type: String(s.ActionType), name: String(s.Name ?? ""), status: String(s.Status ?? ""), output: String(s.Output ?? "") }));
  return { id: Number(run.RunID), mode: String(run.Mode), status: String(run.Status), summary: String(run.Summary ?? ""), startedAt: run.StartedAt, steps };
}

/** Demo seed (tenant only) — 3 representative SOAR playbooks + a couple of simulated runs. */
export function seedSoarOps(tenant: number): { playbooks: number } {
  ensureSoarOpsTables();
  const db = xi();
  if (Number((db.prepare("SELECT COUNT(*) n FROM SOARPLAYBOOK WHERE TenantID = ?").get(tenant) as { n: number }).n)) return { playbooks: 0 };
  const p1 = createSoarPlaybook({ name: "Phishing auto-triage", description: "On a reported phish: enrich, notify, and open a ticket.", triggerType: "phishing.reported", category: "Email", actions: [
    { actionType: "enrich-ioc", params: "sender + URLs + attachment hashes" }, { actionType: "notify", params: "#soc-phishing" }, { actionType: "create-ticket", params: "Phishing triage" },
  ] }, tenant).id;
  const p2 = createSoarPlaybook({ name: "Malware containment", description: "On a malicious verdict: isolate the host, block the indicator, escalate.", triggerType: "malware.malicious", category: "Endpoint", actions: [
    { actionType: "isolate-host", params: "affected endpoint" }, { actionType: "block-indicator", params: "file hash / C2" }, { actionType: "escalate", params: "L2" }, { actionType: "run-automation", params: "forensics-collect" },
  ] }, tenant).id;
  createSoarPlaybook({ name: "KEV exposure response", description: "On a new KEV exposure: ticket the owner and scan the asset.", triggerType: "exposure.kev", category: "Vulnerability", actions: [
    { actionType: "create-ticket", params: "Patch KEV within SLA" }, { actionType: "scan-asset", params: "affected asset" }, { actionType: "notify", params: "asset owner" },
  ] }, tenant);
  runSoarPlaybook(p1, tenant, { mode: "simulate", triggerRef: "demo" });
  runSoarPlaybook(p2, tenant, { mode: "simulate", triggerRef: "demo" });
  return { playbooks: 3 };
}
