/**
 * teams.ts — Microsoft Teams alert/notification distribution.
 *
 * A Teams channel becomes an outbound delivery target for XORCISM alerts & notifications. Admins
 * register one or more **incoming-webhook** URLs per tenant (TEAMSWEBHOOK); every dispatchEvent()
 * (the central notification engine — incidents, alerts, malware verdicts, …) then fans the event
 * out to the matching webhooks, gated by a per-webhook minimum level + optional event filter.
 * Supports both Teams payloads: a modern **Adaptive Card** (Power Automate / Workflows webhooks)
 * and the legacy **MessageCard** (Office 365 "Incoming Webhook" connector, `*.webhook.office.com`),
 * auto-detected from the URL host. Worker-free (the Node server posts directly); also exposed as
 * the `teams` connector for manual / attack-chain distribution. Nothing is posted unless a webhook
 * is configured (table row or the TEAMS_WEBHOOK_URL env fallback).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();
type Level = "info" | "success" | "warning" | "error";
const LEVEL_RANK: Record<string, number> = { info: 0, success: 1, warning: 2, error: 3 };
const rank = (l: string | null | undefined): number => LEVEL_RANK[String(l || "info").toLowerCase()] ?? 0;
// Normalize alert severities (Critical/High/Medium/Low/Informational) → notification levels.
function normLevel(l: string | null | undefined): Level {
  const v = String(l || "info").toLowerCase();
  if (v in LEVEL_RANK) return v as Level;
  if (v.startsWith("crit") || v.startsWith("high") || v === "error") return "error";
  if (v.startsWith("med") || v === "warn" || v.startsWith("warning")) return "warning";
  if (v.startsWith("low") || v === "ok" || v === "success") return v === "low" ? "warning" : "success";
  return "info";
}
const ADAPTIVE_COLOR: Record<Level, string> = { error: "Attention", warning: "Warning", success: "Good", info: "Accent" };
const THEME_HEX: Record<Level, string> = { error: "b91c1c", warning: "ea580c", success: "16a34a", info: "2563eb" };
const EMOJI: Record<Level, string> = { error: "🔴", warning: "🟠", success: "🟢", info: "🔵" };

export interface TeamsMessage { title: string; message?: string | null; level?: string | null; link?: string | null; source?: string | null; facts?: { name: string; value: string }[] }

/** Prefix a relative XORCISM link with the configured public base URL (Teams needs an absolute URL). */
function absLink(link?: string | null): string | null {
  if (!link) return null;
  if (/^https?:\/\//i.test(link)) return link;
  const base = (process.env.XORCISM_BASE_URL || process.env.TEAMS_BASE_URL || "").replace(/\/$/, "");
  return base ? base + (link.startsWith("/") ? link : "/" + link) : null;
}

export function detectFormat(url: string, explicit?: string | null): "adaptivecard" | "messagecard" {
  const f = String(explicit || "").toLowerCase();
  if (f === "adaptivecard" || f === "messagecard") return f;
  // legacy O365 "Incoming Webhook" connector hosts expect MessageCard; Workflows expect Adaptive Cards
  return /webhook\.office\.com|outlook\.office\.com|office365\.com/i.test(url) ? "messagecard" : "adaptivecard";
}

export function buildCard(m: TeamsMessage, format: "adaptivecard" | "messagecard"): unknown {
  const lvl = normLevel(m.level);
  const title = `${EMOJI[lvl]} ${m.title}`.slice(0, 300);
  const text = (m.message || "").slice(0, 4000);
  const url = absLink(m.link);
  const facts = [
    ...(m.level ? [{ name: "Severity", value: String(m.level) }] : []),
    ...(m.source ? [{ name: "Event", value: String(m.source) }] : []),
    ...(m.facts || []),
  ];
  if (format === "messagecard") {
    return {
      "@type": "MessageCard", "@context": "http://schema.org/extensions",
      themeColor: THEME_HEX[lvl], summary: m.title.slice(0, 250), title,
      sections: [{ text, facts: facts.map((f) => ({ name: f.name, value: f.value })) }],
      ...(url ? { potentialAction: [{ "@type": "OpenUri", name: "Open in XORCISM", targets: [{ os: "default", uri: url }] }] } : {}),
    };
  }
  const body: unknown[] = [
    { type: "TextBlock", text: title, weight: "Bolder", size: "Large", color: ADAPTIVE_COLOR[lvl], wrap: true },
  ];
  if (text) body.push({ type: "TextBlock", text, wrap: true });
  if (facts.length) body.push({ type: "FactSet", facts: facts.map((f) => ({ title: f.name, value: f.value })) });
  return {
    type: "message",
    attachments: [{
      contentType: "application/vnd.microsoft.card.adaptive",
      content: {
        $schema: "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4",
        body,
        ...(url ? { actions: [{ type: "Action.OpenUrl", title: "Open in XORCISM", url }] } : {}),
        msteams: { width: "Full" },
      },
    }],
  };
}

export async function postTeams(url: string, payload: unknown, timeoutMs = 15000): Promise<{ ok: boolean; status: number; body?: string }> {
  try {
    const r = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(timeoutMs),
    });
    const body = await r.text().catch(() => "");
    return { ok: r.ok, status: r.status, body: body.slice(0, 200) };
  } catch (e) {
    return { ok: false, status: 0, body: (e as Error).message };
  }
}

// ── webhook store ──────────────────────────────────────────────────────────────────────
export function ensureTeamsTables(): void {
  const db = getDb("XORCISM");
  db.exec(`
    CREATE TABLE IF NOT EXISTS TEAMSWEBHOOK (
      WebhookID INTEGER PRIMARY KEY,
      WebhookGUID TEXT, Name TEXT, WebhookUrl TEXT, Format TEXT DEFAULT 'auto',
      MinLevel TEXT DEFAULT 'info', EventFilter TEXT, Enabled INTEGER DEFAULT 1,
      CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_teamswebhook_tenant ON TEAMSWEBHOOK(TenantID);
  `);
}

interface WebhookRow { WebhookID: number; Name: string; WebhookUrl: string; Format: string; MinLevel: string; EventFilter: string | null; Enabled: number; TenantID: number | null; CreatedDate: string }

export function listWebhooks(tenant: number | null): WebhookRow[] {
  ensureTeamsTables();
  return getDb("XORCISM").prepare(
    "SELECT * FROM TEAMSWEBHOOK WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY WebhookID"
  ).all(tenant) as WebhookRow[];
}

/** Redact a webhook URL for display (keep host, mask the secret path). */
export function redactUrl(u: string): string {
  try { const x = new URL(u); return `${x.protocol}//${x.host}/…`; } catch { return "…"; }
}

export function addWebhook(tenant: number | null, p: { name?: string; url: string; format?: string; minLevel?: string; eventFilter?: string }): { id: number } {
  ensureTeamsTables();
  const db = getDb("XORCISM");
  const id = allocId(db, "TEAMSWEBHOOK", "WebhookID");
  const fmt = ["auto", "adaptivecard", "messagecard"].includes(String(p.format)) ? p.format : "auto";
  const minLevel = p.minLevel && LEVEL_RANK[String(p.minLevel)] != null ? p.minLevel : "info";
  db.prepare(
    "INSERT INTO TEAMSWEBHOOK (WebhookID, WebhookGUID, Name, WebhookUrl, Format, MinLevel, EventFilter, Enabled, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,1,?,?)"
  ).run(id, randomUUID(), (p.name || "Teams channel").slice(0, 120), p.url, fmt, minLevel, p.eventFilter || null, now(), tenant);
  return { id };
}

export function setWebhook(tenant: number | null, id: number, patch: { enabled?: boolean; minLevel?: string; format?: string; eventFilter?: string | null; name?: string }): boolean {
  const db = getDb("XORCISM");
  const row = db.prepare("SELECT WebhookID FROM TEAMSWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant);
  if (!row) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.enabled != null) { sets.push("Enabled=?"); vals.push(patch.enabled ? 1 : 0); }
  if (patch.minLevel && LEVEL_RANK[patch.minLevel] != null) { sets.push("MinLevel=?"); vals.push(patch.minLevel); }
  if (patch.format && ["auto", "adaptivecard", "messagecard"].includes(patch.format)) { sets.push("Format=?"); vals.push(patch.format); }
  if (patch.eventFilter !== undefined) { sets.push("EventFilter=?"); vals.push(patch.eventFilter || null); }
  if (patch.name) { sets.push("Name=?"); vals.push(patch.name.slice(0, 120)); }
  if (!sets.length) return true;
  db.prepare(`UPDATE TEAMSWEBHOOK SET ${sets.join(", ")} WHERE WebhookID=?`).run(...vals, id);
  return true;
}

export function deleteWebhook(tenant: number | null, id: number): boolean {
  const db = getDb("XORCISM");
  const r = db.prepare("DELETE FROM TEAMSWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant);
  return r.changes > 0;
}

/** Resolve all webhooks that should receive an event of `level`/`eventKey` for this tenant (+ env fallback). */
function resolveTargets(tenant: number | null, level: string, eventKey?: string): { url: string; format: "adaptivecard" | "messagecard" }[] {
  const out: { url: string; format: "adaptivecard" | "messagecard" }[] = [];
  const lvl = rank(normLevel(level));
  let rows: WebhookRow[] = [];
  try { rows = listWebhooks(tenant); } catch { /* table missing */ }
  for (const w of rows) {
    if (!w.Enabled || !w.WebhookUrl) continue;
    if (lvl < rank(w.MinLevel)) continue;
    if (w.EventFilter && eventKey && !w.EventFilter.split(",").map((s) => s.trim()).includes(eventKey)) continue;
    out.push({ url: w.WebhookUrl, format: detectFormat(w.WebhookUrl, w.Format) });
  }
  const envUrl = (process.env.TEAMS_WEBHOOK_URL || "").trim();
  if (envUrl && lvl >= rank(process.env.TEAMS_MIN_LEVEL || "info")) {
    out.push({ url: envUrl, format: detectFormat(envUrl, process.env.TEAMS_WEBHOOK_FORMAT) });
  }
  return out;
}

/** Fan an event/notification out to the tenant's Teams channels. Best-effort, fire-and-forget. */
export async function notifyTeams(eventKey: string, m: TeamsMessage & { tenant?: number | null }): Promise<{ sent: number; failed: number }> {
  const targets = resolveTargets(m.tenant ?? null, String(m.level ?? "info"), eventKey);
  let sent = 0, failed = 0;
  for (const t of targets) {
    const res = await postTeams(t.url, buildCard({ ...m, source: m.source ?? eventKey }, t.format));
    if (res.ok) sent++; else failed++;
  }
  return { sent, failed };
}

/** Post a one-off test card to a specific URL (used by the Settings "Test" button). */
export async function testWebhook(url: string, format?: string): Promise<{ ok: boolean; status: number; body?: string }> {
  return postTeams(url, buildCard(
    { title: "XORCISM test notification", message: "If you can read this in Teams, alert & notification distribution is working. ✅", level: "success", source: "teams.test" },
    detectFormat(url, format),
  ));
}

export function configured(tenant: number | null): boolean {
  return resolveTargets(tenant, "error").length > 0;
}

/** Test an already-stored webhook by id (its real URL is never exposed to the client). */
export async function testWebhookById(tenant: number | null, id: number): Promise<{ ok: boolean; status: number; body?: string } | null> {
  const row = getDb("XORCISM").prepare(
    "SELECT WebhookUrl, Format FROM TEAMSWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)"
  ).get(id, tenant) as { WebhookUrl: string; Format: string } | undefined;
  if (!row) return null;
  return testWebhook(row.WebhookUrl, row.Format);
}
