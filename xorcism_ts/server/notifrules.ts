/**
 * notifrules.ts — Event → notification rule engine.
 *
 * Users manage, from the Settings panel, WHICH events automatically create a notification for them
 * (XORCISM.NOTIFICATIONRULE, one row per user+event with an Enabled toggle and a minimum-severity
 * threshold). This module owns the catalogue of subscribable events and the dispatch primitive that
 * the rest of the app calls when one of those events fires:
 *
 *     dispatchEvent("malware.malicious", { userId, tenant, title, message, link });
 *
 * For each target user it consults their rule (falling back to the event's catalogue default) and a
 * severity threshold, then creates the notification via createNotification(). Adding a new auto-
 * notification anywhere in the app is now: declare the event here, then call dispatchEvent().
 */
import { randomUUID } from "crypto";
import { allocId, getDb, createNotification } from "./db";
import { notifyTeams } from "./teams";
import { emitLoopEvent } from "./croc";

export type Level = "info" | "success" | "warning" | "error";
const LEVEL_RANK: Record<string, number> = { info: 0, success: 1, warning: 2, error: 3 };
const rank = (l: string | null | undefined): number => LEVEL_RANK[String(l || "info")] ?? 0;

export interface EventType {
  key: string; label: string; description: string;
  level: Level;          // default severity of the event
  default: boolean;      // auto-create for users who have not configured a rule
  category: string;      // grouping for the Settings UI
}

/** The catalogue of events a user can subscribe to. */
export const EVENT_TYPES: EventType[] = [
  { key: "kev.new", category: "Vulnerabilities", level: "warning", default: true,
    label: "New KEV vulnerability on an asset", description: "A CISA Known-Exploited vulnerability now affects one of your assets." },
  { key: "cve.asset_match", category: "Vulnerabilities", level: "warning", default: true,
    label: "New CVE matched to your assets", description: "A newly imported CVE matches the technology of one of your assets." },
  { key: "vuln.exploit_available", category: "Vulnerabilities", level: "warning", default: false,
    label: "Public exploit available", description: "A public exploit was found for a CVE you track." },
  { key: "patch.sla_breach", category: "Vulnerabilities", level: "error", default: false,
    label: "Patch SLA breached", description: "A vulnerability passed its risk-based patch SLA without being remediated." },
  { key: "incident.created", category: "Incidents", level: "warning", default: true,
    label: "New incident / alert", description: "A new incident or alert was created in your tenant." },
  { key: "incident.sla_breach", category: "Incidents", level: "error", default: true,
    label: "Incident SLA breach", description: "An incident exceeded its response or resolution SLA." },
  { key: "malware.malicious", category: "Threats", level: "error", default: true,
    label: "Malicious malware-scan verdict", description: "A multi-engine malware scan returned a malicious verdict." },
  { key: "threatfeed.match", category: "Threats", level: "info", default: false,
    label: "Threat report matches your watchlist", description: "A CTI feed item matches a watched keyword or asset." },
  { key: "phishing.clicked", category: "Awareness", level: "warning", default: false,
    label: "Phishing simulation clicked", description: "A user clicked a link in a phishing-simulation campaign." },
  { key: "monitoring.down", category: "Operations", level: "error", default: true,
    label: "Monitored asset down", description: "An uptime/health monitor detected that an asset is down." },
  { key: "croc.resilience_degraded", category: "Operations", level: "warning", default: true,
    label: "CROC loop resilience degraded", description: "The continuous defense loop regressed vs its baseline or breached its resilience SLA (machine-speed dropped, backlog ballooned, latency spiked, or the loop went still)." },
  { key: "croc.loop_digest", category: "Operations", level: "info", default: false,
    label: "CROC daily loop digest (AI)", description: "A scheduled local-AI read across the continuous defense loop (detect→decide→act→learn): the dominant cross-stage story and the single next move." },
  { key: "journey.step_overdue", category: "Compliance", level: "warning", default: false,
    label: "Compliance journey step overdue", description: "A step in a compliance journey passed its target date." },
  { key: "compliance.audit_due", category: "Compliance", level: "info", default: false,
    label: "Audit / assessment due", description: "A scheduled audit or assessment is approaching its due date." },
  { key: "policy.regression", category: "Compliance", level: "warning", default: true,
    label: "Policy control regressed", description: "A policy requirement that previously passed now fails on-prem/cloud/hybrid evidence." },
  { key: "authz.regression", category: "Compliance", level: "warning", default: true,
    label: "Authorization regression", description: "A scheduled BOLA/BFLA authorization test that previously passed is now allowed by the PDP." },
];
const BY_KEY = new Map(EVENT_TYPES.map((e) => [e.key, e]));
export function isEvent(key: string): boolean { return BY_KEY.has(key); }

interface RuleRow { Enabled: number; MinLevel: string }

/** The effective rule for a user+event (null = no explicit rule → use catalogue default). */
function getRule(userId: number, eventKey: string): RuleRow | null {
  try {
    return (getDb("XORCISM").prepare("SELECT Enabled, MinLevel FROM NOTIFICATIONRULE WHERE UserID = ? AND EventKey = ?").get(userId, eventKey) as RuleRow | undefined) ?? null;
  } catch { return null; }
}

/** Would this event (at this severity) notify the user given their rule / the default? */
export function ruleAllows(userId: number, eventKey: string, level: string): boolean {
  const def = BY_KEY.get(eventKey);
  const r = getRule(userId, eventKey);
  if (!r) return def ? def.default : true;
  if (!r.Enabled) return false;
  return rank(level) >= rank(r.MinLevel);
}

/** Catalogue merged with the user's current rules (for the Settings UI). */
export function listRulesForUser(userId: number): { events: any[] } {
  const events = EVENT_TYPES.map((e) => {
    const r = getRule(userId, e.key);
    return {
      key: e.key, label: e.label, description: e.description, category: e.category, level: e.level,
      defaultEnabled: e.default,
      enabled: r ? !!r.Enabled : e.default,
      minLevel: r ? (r.MinLevel || "info") : "info",
      configured: !!r,
    };
  });
  return { events };
}

/** Upsert a user's rule for an event. */
export function upsertRule(userId: number, eventKey: string, patch: { enabled?: boolean; minLevel?: string }, tenant: number | null): boolean {
  if (!BY_KEY.has(eventKey)) return false;
  const db = getDb("XORCISM");
  const now = new Date().toISOString();
  const minLevel = patch.minLevel && LEVEL_RANK[patch.minLevel] != null ? patch.minLevel : null;
  const existing = db.prepare("SELECT RuleID, Enabled, MinLevel FROM NOTIFICATIONRULE WHERE UserID = ? AND EventKey = ?").get(userId, eventKey) as { RuleID: number; Enabled: number; MinLevel: string } | undefined;
  if (existing) {
    const enabled = patch.enabled != null ? (patch.enabled ? 1 : 0) : existing.Enabled;
    db.prepare("UPDATE NOTIFICATIONRULE SET Enabled = ?, MinLevel = ?, UpdatedDate = ? WHERE RuleID = ?")
      .run(enabled, minLevel ?? existing.MinLevel ?? "info", now, existing.RuleID);
  } else {
    const def = BY_KEY.get(eventKey)!;
    const id = allocId(db, "NOTIFICATIONRULE", "RuleID");
    db.prepare("INSERT INTO NOTIFICATIONRULE (RuleID, RuleGUID, UserID, EventKey, Enabled, MinLevel, CreatedDate, UpdatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(id, randomUUID(), userId, eventKey, patch.enabled != null ? (patch.enabled ? 1 : 0) : (def.default ? 1 : 0), minLevel ?? "info", now, now, tenant);
  }
  return true;
}

/** Reset a user's rule for an event back to the catalogue default (deletes the row). */
export function resetRule(userId: number, eventKey: string): boolean {
  getDb("XORCISM").prepare("DELETE FROM NOTIFICATIONRULE WHERE UserID = ? AND EventKey = ?").run(userId, eventKey);
  return true;
}

export interface DispatchOpts {
  userId?: number; userIds?: number[]; tenant?: number | null;
  title: string; message?: string | null; level?: Level | string; link?: string | null;
  dedupeByLink?: boolean; force?: boolean;
}

/** Fire an event: create a notification for each target user whose rule (or the default) allows it. */
export function dispatchEvent(eventKey: string, opts: DispatchOpts): { created: number; skipped: number } {
  const def = BY_KEY.get(eventKey);
  const level = String(opts.level ?? def?.level ?? "info");
  const targets = (opts.userIds && opts.userIds.length ? opts.userIds : (opts.userId != null ? [opts.userId] : []))
    .filter((u) => Number.isInteger(u) && u > 0);
  let created = 0, skipped = 0;
  const xo = getDb("XORCISM");
  const seen = opts.dedupeByLink && opts.link ? xo.prepare("SELECT 1 FROM NOTIFICATION WHERE UserID = ? AND Link = ? LIMIT 1") : null;
  for (const uid of new Set(targets)) {
    if (!opts.force && !ruleAllows(uid, eventKey, level)) { skipped++; continue; }
    if (seen && opts.link && seen.get(uid, opts.link)) { skipped++; continue; }
    createNotification({ userId: uid, title: opts.title.slice(0, 300), message: opts.message ?? null, level, link: opts.link ?? null, source: eventKey, tenantId: opts.tenant ?? null });
    created++;
  }
  // Fan the same event out to the tenant's Microsoft Teams channel(s) — independent of the per-user
  // in-app rules (a Teams channel is an org-level delivery target). Best-effort, never blocks/throws.
  void notifyTeams(eventKey, { tenant: opts.tenant ?? null, title: opts.title, message: opts.message ?? null, level, link: opts.link ?? null, source: eventKey })
    .catch(() => { /* distribution is best-effort */ });
  // Record the event on the Continuous Defense Loop (CROC) so it can move + trigger pre-authorized
  // policies at machine speed. Synchronous + best-effort (emitLoopEvent never throws).
  emitLoopEvent({ type: eventKey, source: "dispatchEvent", summary: opts.title, severity: level, tenant: opts.tenant ?? null });
  return { created, skipped };
}
