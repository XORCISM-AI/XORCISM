/**
 * landingaccess.ts — NICE-profile filtering + per-group/card access control for the landing menu.
 *
 * The main-menu cards can be (1) FILTERED by the viewer to the modules relevant to a NICE work-role
 * profile, and (2) ACCESS-CONTROLLED by an admin: each group/card may be restricted to one or more
 * NICE profiles, and a non-admin user only sees it if their own assigned workforce role(s) match.
 *
 * A user's profile is derived from the workforce module: XUSER.Email → PERSON → PERSONWORKROLE →
 * WORKROLE.Category (the NICE category is the "profile"). Admins/super-admins always see everything.
 * Restrictions live per-tenant in LANDINGACCESS; absence of a row means "open to everyone".
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { userCanPage } from "./auth";

/** The canonical NICE Workforce Framework (SP 800-181 rev1, 2025) categories used as profiles. */
export const NICE_PROFILES: string[] = [
  "Oversight & Governance",
  "Design & Development",
  "Implementation & Operation",
  "Protection & Defense",
  "Investigation",
  "Cyberspace Intelligence",
  "Cyberspace Effects",
];

/** Default NICE relevance per approach group (used by the filter when a card has no override). */
const GROUP_RELEVANCE: Record<string, string[]> = {
  asset: ["Implementation & Operation", "Oversight & Governance"],
  exposure: ["Protection & Defense", "Cyberspace Intelligence"],
  threat: ["Cyberspace Intelligence", "Protection & Defense"],
  risk: ["Oversight & Governance", "Protection & Defense"],
  compliance: ["Oversight & Governance"],
  operations: ["Protection & Defense", "Investigation"],
  platform: ["Implementation & Operation"],
};

/** Per-card NICE relevance overrides (for the filter) where a card serves a different role than its group. */
const CARD_RELEVANCE: Record<string, string[]> = {
  "/workforce": ["Oversight & Governance"],
  "/org-chart": ["Oversight & Governance"],
  "/sca": ["Design & Development"],
  "/devsecops": ["Design & Development"],
  "/threat-model": ["Design & Development", "Protection & Defense"],
  "/attack-tree": ["Design & Development", "Cyberspace Intelligence"],
  "/cert-ops": ["Investigation"],
  "/malware-scan": ["Investigation", "Cyberspace Intelligence"],
  "/hunting": ["Cyberspace Intelligence"],
  "/cti-watch": ["Cyberspace Intelligence"],
  "/cti-expert": ["Cyberspace Intelligence"],
  "/pir": ["Cyberspace Intelligence"],
  "/osint-graph": ["Cyberspace Intelligence"],
  "/ai-threat-advisor": ["Cyberspace Intelligence"],
  "/threat-informed-defense": ["Cyberspace Intelligence", "Protection & Defense"],
  "/pentest": ["Cyberspace Effects", "Protection & Defense"],
  "/team-ops": ["Cyberspace Effects", "Protection & Defense"],
  "/ransomware": ["Cyberspace Effects", "Protection & Defense"],
  "/attack-path": ["Cyberspace Effects", "Protection & Defense"],
  "/soc": ["Protection & Defense"],
  "/soc-cmm": ["Protection & Defense"],
  "/crisis-management": ["Protection & Defense", "Oversight & Governance"],
};

/** The approach groups (mirrors client/index.html). */
export const GROUPS: { id: string; label: string }[] = [
  { id: "asset", label: "Asset-Based" },
  { id: "exposure", label: "Vulnerability & Exposure" },
  { id: "threat", label: "Threat" },
  { id: "risk", label: "Risk-Based" },
  { id: "compliance", label: "Compliance" },
  { id: "operations", label: "Response & Operations" },
  { id: "platform", label: "Platform" },
];

/** The card catalogue (href + group) — mirrors client/index.html (hrefs decoded). */
export const CARDS: { href: string; group: string }[] = [
  ...["/asset-management", "/network-sessions", "/cloud-security", "/identities", "/workforce", "/org-chart", "/bia", "/sca", "/configuration-management", "/oval-scan", "/connectors?connector=darkwatch-osint"].map((href) => ({ href, group: "asset" })),
  ...["/voc", "/vm-report", "/ctem", "/easm", "/bug-bounty", "/vulnerability-management", "/exposure", "/exploitdb", "/attack-path", "/drift", "/pqcmm", "/?db=XVULNERABILITY&table=BUGBOUNTYPROGRAM"].map((href) => ({ href, group: "exposure" })),
  ...["/?db=XTHREAT&table=THREAT", "/cti-expert", "/threat-informed-defense", "/hunting", "/pir", "/cti-watch", "/kill-chain", "/threat-model", "/attack-tree", "/ransomware", "/tools?category=OSINT", "/osint-graph", "/team-ops", "/ai-threat-advisor", "/malware-scan"].map((href) => ({ href, group: "threat" })),
  ...["/croc", "/cyber-risk-hunting", "/investment-advisor", "/risk-register", "/fair-mam", "/fair-tef", "/ebios", "/asset-monitoring", "/patch-management", "/ot-security", "/nist-800-30", "/tprm"].map((href) => ({ href, group: "risk" })),
  ...["/governance", "/compliance-journeys", "/control-management", "/frameworks", "/compliance-management", "/policy-management", "/privacy", "/trust-center", "/assurance"].map((href) => ({ href, group: "compliance" })),
  ...["/agents", "/ai-guardrails", "/endpoint-query", "/devsecops", "/soc-cmm", "/cert-ops", "/soc", "/soar", "/incident-management", "/incident-sla", "/crisis-management", "/pentest", "/?db=XTICKET&table=TICKET", "/content", "/security-awareness"].map((href) => ({ href, group: "operations" })),
  ...["/connectors", "/api-docs", "/tools"].map((href) => ({ href, group: "platform" })),
];

/** Prettify an href into a human label for the admin UI. */
export function cardLabel(href: string): string {
  if (href.includes("db=")) { const m = href.match(/table=([A-Z_]+)/i); return m ? m[1] : href; }
  const base = href.replace(/^\//, "").split("?")[0] || href;
  return base.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * The feature PAGES governed by RBAC = the cards that map to a real page route (drop the explorer
 * deep-links with a query string). Each is an XPERMISSION resource (ResourceType='page', ResourceKey=path)
 * so a role can be granted/denied it, enforced by the feature middleware in index.ts.
 */
export const FEATURE_PAGES: { path: string; label: string; group: string }[] =
  CARDS.filter((c) => !c.href.includes("?")).map((c) => ({ path: c.href, label: cardLabel(c.href), group: c.group }));
export const FEATURE_PAGE_PATHS: Set<string> = new Set(FEATURE_PAGES.map((f) => f.path));
const GROUP_LABEL: Record<string, string> = Object.fromEntries(GROUPS.map((g) => [g.id, g.label]));

// ── access-control store ───────────────────────────────────────────────────────────────────
export function ensureLandingAccessTable(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS LANDINGACCESS (
      AccessID INTEGER PRIMARY KEY, AccessGUID TEXT,
      ItemType TEXT, ItemKey TEXT, AllowedProfiles TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_landingaccess_tenant ON LANDINGACCESS(TenantID);
  `);
}

export interface AccessRestriction { itemType: "group" | "card"; itemKey: string; profiles: string[] }

export function listAccess(tenant: number | null): AccessRestriction[] {
  try {
    ensureLandingAccessTable();
    return (getDb("XORCISM").prepare(
      "SELECT ItemType, ItemKey, AllowedProfiles FROM LANDINGACCESS WHERE (TenantID = ? OR (TenantID IS NULL AND ? IS NULL))"
    ).all(tenant, tenant) as { ItemType: string; ItemKey: string; AllowedProfiles: string }[])
      .map((r) => ({ itemType: r.ItemType === "group" ? "group" : "card", itemKey: r.ItemKey, profiles: String(r.AllowedProfiles || "").split(",").map((s) => s.trim()).filter(Boolean) }));
  } catch { return []; }
}

/** Upsert a restriction; an empty profile list removes it (item becomes open to everyone). */
export function setAccess(tenant: number | null, itemType: string, itemKey: string, profiles: string[]): void {
  ensureLandingAccessTable();
  const db = getDb("XORCISM");
  const type = itemType === "group" ? "group" : "card";
  const clean = [...new Set((profiles || []).map((p) => String(p).trim()).filter((p) => NICE_PROFILES.includes(p)))];
  db.prepare("DELETE FROM LANDINGACCESS WHERE ItemType=? AND ItemKey=? AND (TenantID = ? OR (TenantID IS NULL AND ? IS NULL))").run(type, itemKey, tenant, tenant);
  if (clean.length) {
    const id = allocId(db, "LANDINGACCESS", "AccessID");
    db.prepare("INSERT INTO LANDINGACCESS (AccessID, AccessGUID, ItemType, ItemKey, AllowedProfiles, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?)")
      .run(id, randomUUID(), type, itemKey, clean.join(","), new Date().toISOString(), tenant);
  }
}

/** Derive the viewer's NICE profile(s) from their assigned workforce role(s). */
export function userNiceProfiles(user: { Email?: string | null } | null | undefined): string[] {
  try {
    const email = String(user?.Email || "").trim();
    if (!email) return [];
    const xo = getDb("XORCISM");
    const p = xo.prepare("SELECT PersonID FROM PERSON WHERE Email = ? LIMIT 1").get(email) as { PersonID: number } | undefined;
    if (!p) return [];
    const cats = xo.prepare(
      "SELECT DISTINCT w.Category c FROM PERSONWORKROLE pwr JOIN WORKROLE w ON w.WorkRoleID = pwr.WorkRoleID WHERE pwr.PersonID = ?"
    ).all(p.PersonID) as { c: string }[];
    return [...new Set(cats.map((x) => String(x.c || "").trim()).filter(Boolean))];
  } catch { return []; }
}

/** Everything the landing client needs for both the NICE filter and access enforcement. */
export function landingConfig(user: { Email?: string | null; isAdmin?: boolean; isSuperAdmin?: boolean; tenantId?: number | null } | null): any {
  const isAdmin = !!(user && (user.isAdmin || user.isSuperAdmin));
  const tenant = user?.isSuperAdmin ? null : (user?.tenantId ?? null);
  // RBAC: feature pages this (non-admin) user's role(s) are NOT granted — the landing hides those cards.
  let rbacDenied: string[] = [];
  if (!isAdmin) { try { rbacDenied = FEATURE_PAGES.filter((f) => !userCanPage(user as any, f.path)).map((f) => f.path); } catch { /* */ } }
  return {
    profiles: NICE_PROFILES,
    groupRelevance: GROUP_RELEVANCE,
    cardRelevance: CARD_RELEVANCE,
    restrictions: listAccess(tenant),
    userProfiles: userNiceProfiles(user),
    rbacDenied,
    isAdmin,
  };
}

/**
 * Does the NICE-profile access control (LANDINGACCESS) allow this user to reach a feature page?
 * Server-side mirror of the landing's applyAccess: a card/group restricted to NICE profiles is denied
 * unless the user's assigned workforce profile matches (admins bypass; an unrestricted page is allowed).
 */
export function niceAllowsPage(user: { Email?: string | null; isAdmin?: boolean; isSuperAdmin?: boolean; tenantId?: number | null } | null, path: string): boolean {
  if (user && (user.isAdmin || user.isSuperAdmin)) return true;
  try {
    const tenant = user?.isSuperAdmin ? null : (user?.tenantId ?? null);
    const card = CARDS.find((c) => c.href === path);
    const restr = listAccess(tenant);
    const up = new Set(userNiceProfiles(user));
    const ok = (profiles: string[]): boolean => profiles.length === 0 || profiles.some((p) => up.has(p));
    if (card) { const gr = restr.find((r) => r.itemType === "group" && r.itemKey === card.group); if (gr && !ok(gr.profiles)) return false; }
    const cr = restr.find((r) => r.itemType === "card" && r.itemKey === path);
    if (cr && !ok(cr.profiles)) return false;
    return true;
  } catch { return true; } // never harden on an error
}

/** Unified feature-page gate: RBAC role grant AND NICE-profile access control must both permit. */
export function canAccessFeaturePage(user: any, path: string): boolean {
  return userCanPage(user, path) && niceAllowsPage(user, path);
}

/** The catalogue + current restrictions for the admin management UI. */
export function accessCatalogue(tenant: number | null): any {
  return {
    profiles: NICE_PROFILES,
    groups: GROUPS,
    cards: CARDS.map((c) => ({ href: c.href, group: c.group, label: cardLabel(c.href) })),
    restrictions: listAccess(tenant),
  };
}
