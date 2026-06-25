/**
 * trustcenter.ts — a Drata-style Trust Center: a public-facing security-posture page driven by live
 * XORCISM data, shareable read-only at /trust/<slug>.
 *
 * The admin view (/trust-center) edits one config row per tenant (XCOMPLIANCE.TRUSTCENTER) — branding,
 * sub-processors, the published frameworks list, and which live panels to show. The public view only
 * ever exposes AGGREGATE posture (NIST 800-53 coverage %, framework status, monitoring uptime, policy
 * count) — never asset, control or finding detail.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { controlManagementInventory } from "./control53";
import { monitoringInventory } from "./monitoring";

export interface TrustConfig {
  slug: string; enabled: boolean; companyName: string; title: string; intro: string; contactEmail: string;
  subprocessors: { name: string; purpose: string; location: string }[];
  frameworks: { name: string; status: string }[];
  showControls: boolean; showUptime: boolean; showPolicies: boolean; updatedAt: string | null;
}

const DEFAULTS: TrustConfig = {
  slug: "", enabled: false, companyName: "", title: "Trust Center", intro: "", contactEmail: "",
  subprocessors: [], frameworks: [], showControls: true, showUptime: true, showPolicies: true, updatedAt: null,
};

function slugify(s: string): string {
  return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "trust";
}
function parseJson<T>(s: unknown, fallback: T): T { try { return s ? JSON.parse(String(s)) : fallback; } catch { return fallback; } }
function rowToConfig(r: Record<string, any>): TrustConfig {
  return {
    slug: r.Slug || "", enabled: !!Number(r.Enabled), companyName: r.CompanyName || "", title: r.Title || "Trust Center",
    intro: r.Intro || "", contactEmail: r.ContactEmail || "",
    subprocessors: parseJson(r.Subprocessors, []), frameworks: parseJson(r.Frameworks, []),
    showControls: r.ShowControls == null ? true : !!Number(r.ShowControls),
    showUptime: r.ShowUptime == null ? true : !!Number(r.ShowUptime),
    showPolicies: r.ShowPolicies == null ? true : !!Number(r.ShowPolicies),
    updatedAt: r.UpdatedAt || null,
  };
}

export function getTrustCenterConfig(tenant: number | null): TrustConfig {
  try {
    const cc = getDb("XCOMPLIANCE");
    if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='TRUSTCENTER'").get()) return { ...DEFAULTS };
    const where = tenant != null ? "WHERE TenantID = ?" : "WHERE TenantID IS NULL";
    const r = cc.prepare(`SELECT * FROM TRUSTCENTER ${where} LIMIT 1`).get(...(tenant != null ? [tenant] : [])) as Record<string, any> | undefined;
    return r ? rowToConfig(r) : { ...DEFAULTS };
  } catch { return { ...DEFAULTS }; }
}

export function setTrustCenterConfig(tenant: number | null, p: Partial<TrustConfig>): TrustConfig {
  const cc = getDb("XCOMPLIANCE");
  const cur = getTrustCenterConfig(tenant);
  const next: TrustConfig = {
    ...cur,
    slug: p.slug != null ? slugify(p.slug) : (cur.slug || slugify(p.companyName || cur.companyName || `tenant-${tenant ?? "x"}`)),
    enabled: p.enabled != null ? !!p.enabled : cur.enabled,
    companyName: p.companyName != null ? String(p.companyName).slice(0, 200) : cur.companyName,
    title: p.title != null ? String(p.title).slice(0, 200) : cur.title,
    intro: p.intro != null ? String(p.intro).slice(0, 2000) : cur.intro,
    contactEmail: p.contactEmail != null ? String(p.contactEmail).slice(0, 200) : cur.contactEmail,
    subprocessors: p.subprocessors != null ? p.subprocessors.slice(0, 100) : cur.subprocessors,
    frameworks: p.frameworks != null ? p.frameworks.slice(0, 50) : cur.frameworks,
    showControls: p.showControls != null ? !!p.showControls : cur.showControls,
    showUptime: p.showUptime != null ? !!p.showUptime : cur.showUptime,
    showPolicies: p.showPolicies != null ? !!p.showPolicies : cur.showPolicies,
    updatedAt: new Date().toISOString(),
  };
  // Slug must be unique across tenants.
  const clash = cc.prepare("SELECT TenantID FROM TRUSTCENTER WHERE Slug = ? AND " + (tenant != null ? "TenantID <> ?" : "TenantID IS NOT NULL")).get(...(tenant != null ? [next.slug, tenant] : [next.slug]));
  if (clash) next.slug = `${next.slug}-${Math.random().toString(36).slice(2, 6)}`;

  const where = tenant != null ? "WHERE TenantID = ?" : "WHERE TenantID IS NULL";
  const existing = cc.prepare(`SELECT TrustCenterID FROM TRUSTCENTER ${where}`).get(...(tenant != null ? [tenant] : [])) as { TrustCenterID: number } | undefined;
  const vals = [next.slug, next.enabled ? 1 : 0, next.companyName, next.title, next.intro, next.contactEmail,
    JSON.stringify(next.subprocessors), JSON.stringify(next.frameworks), next.showControls ? 1 : 0, next.showUptime ? 1 : 0, next.showPolicies ? 1 : 0, next.updatedAt];
  if (existing) {
    cc.prepare(`UPDATE TRUSTCENTER SET Slug=?, Enabled=?, CompanyName=?, Title=?, Intro=?, ContactEmail=?, Subprocessors=?, Frameworks=?, ShowControls=?, ShowUptime=?, ShowPolicies=?, UpdatedAt=? WHERE TrustCenterID=?`).run(...vals, existing.TrustCenterID);
  } else {
    const id = allocId(cc, "TRUSTCENTER", "TrustCenterID");
    cc.prepare(`INSERT INTO TRUSTCENTER (TrustCenterID, TenantID, Slug, Enabled, CompanyName, Title, Intro, ContactEmail, Subprocessors, Frameworks, ShowControls, ShowUptime, ShowPolicies, UpdatedAt, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, tenant, ...vals, new Date().toISOString());
  }
  return next;
}

/** Aggregate, public-safe posture for a tenant (no asset/control detail). */
export function trustCenterPosture(tenant: number | null): Record<string, unknown> {
  const safe = <T>(fn: () => T, fb: T): T => { try { return fn(); } catch { return fb; } };
  // NIST 800-53 control coverage
  const ctl = safe(() => controlManagementInventory(tenant).summary, null as any);
  // monitoring uptime
  const mon = safe(() => monitoringInventory(tenant).summary, null as any);
  // policies (published count) + audits/frameworks (XCOMPLIANCE)
  let policies = 0; let frameworks: { name: string; status: string }[] = []; let audits = 0;
  safe(() => {
    const cc = getDb("XCOMPLIANCE");
    if (cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='POLICY'").get()) {
      const pc = new Set((cc.prepare(`PRAGMA table_info("POLICY")`).all() as { name: string }[]).map((c) => c.name));
      const tw = tenant != null && pc.has("TenantID") ? "WHERE TenantID = ?" : "";
      policies = (cc.prepare(`SELECT COUNT(*) n FROM POLICY ${tw}`).get(...(tenant != null && pc.has("TenantID") ? [tenant] : [])) as { n: number }).n;
    }
    if (cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='AUDIT'").get()) {
      const ac = new Set((cc.prepare(`PRAGMA table_info("AUDIT")`).all() as { name: string }[]).map((c) => c.name));
      const tw = tenant != null && ac.has("TenantID") ? "WHERE TenantID = ?" : "";
      const rows = cc.prepare(`SELECT AuditCategory cat, AuditStatus st FROM AUDIT ${tw}`).all(...(tenant != null && ac.has("TenantID") ? [tenant] : [])) as { cat: string; st: string }[];
      audits = rows.length;
      const byCat = new Map<string, string>();
      for (const r of rows) { const c = (r.cat || "").trim(); if (c) byCat.set(c, /complet|clos|certif|pass/i.test(String(r.st || "")) ? "Compliant" : "In progress"); }
      frameworks = [...byCat.entries()].slice(0, 20).map(([name, status]) => ({ name, status }));
    }
    return null;
  }, null);

  return {
    controls: ctl ? { coveragePct: ctl.coveragePct, implemented: ctl.implemented, total: ctl.total, assessed: ctl.assessed } : null,
    uptime: mon && mon.avgUptime != null ? { avgUptime: mon.avgUptime, monitors: mon.total, up: mon.up } : null,
    policies, audits, frameworksLive: frameworks,
  };
}

/** Resolve a public slug → tenant (only if enabled). */
export function resolveSlug(slug: string): { tenant: number | null; config: TrustConfig } | null {
  try {
    const cc = getDb("XCOMPLIANCE");
    if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='TRUSTCENTER'").get()) return null;
    const r = cc.prepare("SELECT * FROM TRUSTCENTER WHERE Slug = ? AND Enabled = 1 LIMIT 1").get(slugify(slug)) as Record<string, any> | undefined;
    if (!r) return null;
    return { tenant: r.TenantID != null ? Number(r.TenantID) : null, config: rowToConfig(r) };
  } catch { return null; }
}

/** Public read-only Trust Center payload for a slug (or null if not found / disabled). */
export function publicTrustCenter(slug: string): Record<string, unknown> | null {
  const resolved = resolveSlug(slug);
  if (!resolved) return null;
  const { tenant, config } = resolved;
  const posture = trustCenterPosture(tenant);
  // public config — drop nothing sensitive (all config fields are intentionally public)
  return {
    companyName: config.companyName, title: config.title, intro: config.intro, contactEmail: config.contactEmail,
    subprocessors: config.subprocessors, frameworks: config.frameworks,
    showControls: config.showControls, showUptime: config.showUptime, showPolicies: config.showPolicies,
    updatedAt: config.updatedAt, posture,
  };
}

export const _trustInternal = { slugify, randomUUID };
