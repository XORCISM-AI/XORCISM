/**
 * identitygov.ts — Identity Governance & Administration (IGA / IDMS).
 *
 * The access-review / recertification layer over the IAM inventory ([[identity-iam]] is the inventory,
 * itdr is detection & response). Reviewers periodically attest that each in-scope identity still needs
 * its access (certify) or no longer does (revoke / delegate) — the SailPoint/Saviynt access-certification
 * capability. Plus identity-lifecycle (JML) posture and a certification-coverage KPI (% of privileged
 * identities recertified within the window) and a revocation worklist (the de-provisioning queue).
 *
 * Campaigns snapshot the matching identities at creation, so a review reflects access as it was when
 * the campaign opened. Read paths tolerate a partially-seeded instance.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { identityInventory } from "./identities";

const COVERAGE_WINDOW_DAYS = 90; // a privileged identity is "covered" if recertified within this window
const PRIVILEGED = new Set(["privileged", "admin", "administrator", "root", "owner", "superuser"]);
const mfaOn = (s: string): boolean => /^(y|yes|true|enabled|on|1)$/i.test(String(s || "").trim());

export type CampaignScope = "all" | "privileged" | "non-human" | "stale-privileged" | "no-mfa-privileged" | "orphaned";
export const CAMPAIGN_SCOPES: { key: CampaignScope; label: string; desc: string }[] = [
  { key: "privileged", label: "Privileged access", desc: "All identities with an admin/root/owner privilege level." },
  { key: "no-mfa-privileged", label: "Privileged · no MFA", desc: "Privileged identities without MFA — single-factor admin paths." },
  { key: "non-human", label: "Non-human identities", desc: "Service accounts, agents, API keys, machine identities." },
  { key: "stale-privileged", label: "Stale privileged", desc: "Privileged identities unused for 90+ days." },
  { key: "orphaned", label: "Orphaned (no owner)", desc: "Identities with no accountable owner." },
  { key: "all", label: "All identities", desc: "Every identity in scope (full recertification)." },
];

function tableCols(db: ReturnType<typeof getDb>, table: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
const STALE_DAYS = 90;
function daysSince(d: string | null): number | null {
  if (!d) return null; const t = Date.parse(String(d)); if (!Number.isFinite(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

interface IdRow { IdentityID: number; IdentityName: string | null; IdentityClass: string | null; IdentityType: string | null; Status: string | null; PrivilegeLevel: string | null; MFAEnabled: string | null; OwnerPersonID: number | null; LastUsedDate: string | null; CredentialType: string | null; }

/** Select the identities that match a campaign scope (the population put up for review). */
function selectScope(tenant: number | null, scope: CampaignScope): IdRow[] {
  const db = getDb("XORCISM");
  if (!tableCols(db, "IDENTITY").size) return [];
  const w = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  let rows: IdRow[] = [];
  try { rows = db.prepare(`SELECT IdentityID, IdentityName, IdentityClass, IdentityType, Status, PrivilegeLevel, MFAEnabled, OwnerPersonID, LastUsedDate, CredentialType FROM IDENTITY ${w}`).all(...(tenant != null ? [tenant] : [])) as IdRow[]; }
  catch { return []; }
  const isPriv = (r: IdRow) => PRIVILEGED.has(String(r.PrivilegeLevel || "").trim().toLowerCase());
  const isNH = (r: IdRow) => { const c = String(r.IdentityClass || "").trim(); return c ? /non/i.test(c) || !/human/i.test(c) : !/^(user|employee|person|human|staff)$/i.test(String(r.IdentityType || "")); };
  switch (scope) {
    case "privileged": return rows.filter(isPriv);
    case "no-mfa-privileged": return rows.filter((r) => isPriv(r) && String(r.MFAEnabled || "").trim() !== "" && !mfaOn(String(r.MFAEnabled)));
    case "non-human": return rows.filter(isNH);
    case "stale-privileged": return rows.filter((r) => isPriv(r) && (daysSince(r.LastUsedDate) ?? 0) > STALE_DAYS);
    case "orphaned": return rows.filter((r) => r.OwnerPersonID == null);
    case "all": default: return rows;
  }
}

function ownerName(db: ReturnType<typeof getDb>, ownerId: number | null): string | null {
  if (ownerId == null) return null;
  try { const p = db.prepare("SELECT FullName FROM PERSON WHERE PersonID = ?").get(ownerId) as { FullName?: string } | undefined; return p?.FullName || `#${ownerId}`; }
  catch { return `#${ownerId}`; }
}

export interface CreateCampaignInput { name?: string; description?: string; scope?: CampaignScope; dueDate?: string; }
export function createCampaign(input: CreateCampaignInput, tenant: number | null, createdBy: string): { id: number; items: number } {
  const db = getDb("XORCISM");
  const scope = (CAMPAIGN_SCOPES.find((s) => s.key === input.scope)?.key ?? "privileged") as CampaignScope;
  const pop = selectScope(tenant, scope);
  const now = new Date().toISOString();
  const name = (input.name || `${CAMPAIGN_SCOPES.find((s) => s.key === scope)!.label} recertification`).slice(0, 200);
  const cid = allocId(db, "ACCESSCAMPAIGN", "CampaignID");
  const ins = db.prepare(`INSERT INTO ACCESSCAMPAIGN (CampaignID, CampaignGUID, Name, Description, Scope, Status, DueDate, ItemCount, CreatedBy, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
  const insItem = db.prepare(`INSERT INTO ACCESSREVIEWITEM (ItemGUID, CampaignID, IdentityID, IdentityName, Snapshot, Decision, Actioned, TenantID, CreatedDate)
    VALUES (?,?,?,?,?,'pending',0,?,?)`);
  const tx = db.transaction(() => {
    ins.run(cid, randomUUID(), name, (input.description || "").slice(0, 1000) || null, scope, "active",
      input.dueDate || null, pop.length, createdBy, now, tenant ?? null);
    for (const r of pop) {
      const snap = {
        class: r.IdentityClass || "", type: r.IdentityType || "", privilege: r.PrivilegeLevel || "",
        mfa: r.MFAEnabled || "", owner: ownerName(db, r.OwnerPersonID), status: r.Status || "",
        lastUsed: r.LastUsedDate || null, staleDays: daysSince(r.LastUsedDate),
      };
      insItem.run(randomUUID(), cid, r.IdentityID, r.IdentityName || `Identity #${r.IdentityID}`, JSON.stringify(snap), tenant ?? null, now);
    }
  });
  tx();
  return { id: cid, items: pop.length };
}

const DECISIONS = new Set(["pending", "certify", "revoke", "delegate"]);
export function reviewItem(itemId: number, decision: string, comment: string | undefined, tenant: number | null, reviewer: string): boolean {
  if (!DECISIONS.has(decision)) return false;
  const db = getDb("XORCISM");
  const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const now = new Date().toISOString();
  const args: any[] = [decision, decision === "pending" ? null : reviewer, decision === "pending" ? null : now, comment ?? null, itemId];
  if (tenant != null) args.push(tenant);
  let ok = false;
  try { ok = db.prepare(`UPDATE ACCESSREVIEWITEM SET Decision=?, Reviewer=?, DecidedDate=?, Comment=COALESCE(?, Comment) WHERE ItemID=? ${w}`).run(...args).changes > 0; }
  catch { return false; }
  if (ok) maybeCompleteCampaignFor(itemId, tenant);
  return ok;
}

/** Mark a 'revoke' decision as actioned (de-provisioning done) — closes the revocation worklist item. */
export function markActioned(itemId: number, tenant: number | null): boolean {
  const db = getDb("XORCISM");
  const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  try { return db.prepare(`UPDATE ACCESSREVIEWITEM SET Actioned=1 WHERE ItemID=? AND Decision='revoke' ${w}`).run(...[itemId, ...(tenant != null ? [tenant] : [])]).changes > 0; }
  catch { return false; }
}

function maybeCompleteCampaignFor(itemId: number, tenant: number | null): void {
  const db = getDb("XORCISM");
  try {
    const row = db.prepare("SELECT CampaignID FROM ACCESSREVIEWITEM WHERE ItemID=?").get(itemId) as { CampaignID: number } | undefined;
    if (!row) return;
    const pending = (db.prepare("SELECT COUNT(*) n FROM ACCESSREVIEWITEM WHERE CampaignID=? AND Decision='pending'").get(row.CampaignID) as { n: number }).n;
    const status = pending === 0 ? "completed" : "active";
    db.prepare("UPDATE ACCESSCAMPAIGN SET Status=?, CompletedDate=CASE WHEN ? = 'completed' THEN COALESCE(CompletedDate, ?) ELSE NULL END WHERE CampaignID=?")
      .run(status, status, new Date().toISOString(), row.CampaignID);
  } catch { /* best-effort */ }
}

interface CampaignRow { CampaignID: number; Name: string; Scope: string; Status: string; DueDate: string | null; ItemCount: number; CreatedBy: string; CreatedDate: string; CompletedDate: string | null; }
function campaignProgress(db: ReturnType<typeof getDb>, campaignId: number): { total: number; certified: number; revoked: number; delegated: number; pending: number; pct: number } {
  const rows = db.prepare("SELECT Decision, COUNT(*) n FROM ACCESSREVIEWITEM WHERE CampaignID=? GROUP BY Decision").all(campaignId) as { Decision: string; n: number }[];
  const m: Record<string, number> = {}; let total = 0;
  for (const r of rows) { m[r.Decision] = r.n; total += r.n; }
  const pending = m.pending || 0;
  return { total, certified: m.certify || 0, revoked: m.revoke || 0, delegated: m.delegate || 0, pending, pct: total ? Math.round(((total - pending) / total) * 100) : 0 };
}

export function listCampaigns(tenant: number | null): any[] {
  const db = getDb("XORCISM");
  if (!tableCols(db, "ACCESSCAMPAIGN").size) return [];
  const w = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = db.prepare(`SELECT * FROM ACCESSCAMPAIGN ${w} ORDER BY CampaignID DESC`).all(...(tenant != null ? [tenant] : [])) as CampaignRow[];
  return rows.map((c) => ({ ...c, progress: campaignProgress(db, c.CampaignID), overdue: !!(c.DueDate && c.Status !== "completed" && c.DueDate < new Date().toISOString().slice(0, 10)) }));
}

export function getCampaign(id: number, tenant: number | null): any | null {
  const db = getDb("XORCISM");
  const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const c = db.prepare(`SELECT * FROM ACCESSCAMPAIGN WHERE CampaignID=? ${w}`).get(...[id, ...(tenant != null ? [tenant] : [])]) as CampaignRow | undefined;
  if (!c) return null;
  const items = db.prepare("SELECT ItemID, IdentityID, IdentityName, Snapshot, Decision, Reviewer, DecidedDate, Comment, Actioned FROM ACCESSREVIEWITEM WHERE CampaignID=? ORDER BY (Decision='pending') DESC, IdentityName").all(id) as any[];
  return { ...c, progress: campaignProgress(db, id), items: items.map((it) => ({ ...it, snapshot: safeJson(it.Snapshot) })) };
}

function safeJson(s: string): any { try { return JSON.parse(s); } catch { return {}; } }

/** Cockpit dashboard: campaigns + lifecycle (JML) posture + certification coverage + revocation worklist. */
export function idgovDashboard(tenant: number | null): any {
  const db = getDb("XORCISM");
  const campaigns = listCampaigns(tenant);

  // Lifecycle (JML) posture from the live inventory.
  let inv: any = { total: 0, human: 0, nonHuman: 0, privileged: 0, orphaned: 0, stale: 0, mfaGaps: 0 };
  try { inv = identityInventory(tenant).summary; } catch { /* tolerate */ }

  // Certification coverage: of the privileged population, how many were certified/revoked within the window.
  const priv = selectScope(tenant, "privileged");
  const privIds = new Set(priv.map((r) => r.IdentityID));
  let recentlyReviewed = new Set<number>();
  if (tableCols(db, "ACCESSREVIEWITEM").size && privIds.size) {
    const since = new Date(Date.now() - COVERAGE_WINDOW_DAYS * 86_400_000).toISOString();
    const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
    const rows = db.prepare(`SELECT DISTINCT IdentityID FROM ACCESSREVIEWITEM WHERE Decision IN ('certify','revoke') AND DecidedDate >= ? ${w}`)
      .all(...[since, ...(tenant != null ? [tenant] : [])]) as { IdentityID: number }[];
    recentlyReviewed = new Set(rows.map((r) => r.IdentityID).filter((id) => privIds.has(id)));
  }
  const coveragePct = privIds.size ? Math.round((recentlyReviewed.size / privIds.size) * 100) : null;

  // Revocation worklist: items decided 'revoke' but not yet de-provisioned (Actioned=0).
  let revocations: any[] = [];
  if (tableCols(db, "ACCESSREVIEWITEM").size) {
    const w = tenant != null ? "AND (i.TenantID = ? OR i.TenantID IS NULL)" : "";
    revocations = db.prepare(`SELECT i.ItemID, i.IdentityName, i.Comment, i.Reviewer, i.DecidedDate, c.Name campaign, c.CampaignID
      FROM ACCESSREVIEWITEM i JOIN ACCESSCAMPAIGN c ON c.CampaignID = i.CampaignID
      WHERE i.Decision='revoke' AND COALESCE(i.Actioned,0)=0 ${w} ORDER BY i.DecidedDate DESC LIMIT 100`)
      .all(...(tenant != null ? [tenant] : [])) as any[];
  }

  const active = campaigns.filter((c) => c.Status !== "completed");
  const pendingItems = active.reduce((s, c) => s + c.progress.pending, 0);
  return {
    summary: {
      campaigns: campaigns.length, activeCampaigns: active.length,
      overdueCampaigns: campaigns.filter((c) => c.overdue).length,
      pendingReviews: pendingItems, openRevocations: revocations.length,
      coveragePct, privilegedTotal: privIds.size, privilegedReviewed: recentlyReviewed.size,
    },
    lifecycle: {
      total: inv.total || 0, human: inv.human || 0, nonHuman: inv.nonHuman || 0,
      privileged: inv.privileged || 0, orphaned: inv.orphaned || 0, stale: inv.stale || 0, mfaGaps: inv.mfaGaps || 0,
    },
    scopes: CAMPAIGN_SCOPES,
    campaigns, revocations,
  };
}

// ── Demo seed (tenant 3) ─────────────────────────────────────────────────────
/** Create a privileged-access recertification campaign and partially review it, so the cockpit shows
 * progress, coverage and a revocation worklist. Idempotent (skips if a demo campaign already exists). */
export function seedIdGovDemo(tenant: number): void {
  try {
    const db = getDb("XORCISM");
    if (!tableCols(db, "ACCESSCAMPAIGN").size || !tableCols(db, "IDENTITY").size) return;
    if (db.prepare("SELECT 1 FROM ACCESSCAMPAIGN WHERE CreatedBy='demo-seed' AND TenantID=? LIMIT 1").get(tenant)) return;
    if (!selectScope(tenant, "privileged").length) return; // nothing to review
    const { id } = createCampaign({ name: "Quarterly privileged-access recertification", scope: "privileged",
      dueDate: new Date(Date.now() + 14 * 86_400_000).toISOString().slice(0, 10) }, tenant, "demo-seed");
    db.prepare("UPDATE ACCESSCAMPAIGN SET CreatedBy='demo-seed' WHERE CampaignID=?").run(id);
    // review the first few: mostly certify, one revoke (an over-privileged stale account)
    const items = db.prepare("SELECT ItemID, Snapshot FROM ACCESSREVIEWITEM WHERE CampaignID=? ORDER BY ItemID").all(id) as { ItemID: number; Snapshot: string }[];
    items.slice(0, Math.max(1, Math.ceil(items.length * 0.6))).forEach((it, i) => {
      const snap = safeJson(it.Snapshot);
      const revoke = i === 0 && (snap.staleDays > 90 || !snap.owner);
      reviewItem(it.ItemID, revoke ? "revoke" : "certify", revoke ? "No longer required — dormant standing privilege; deprovision." : "Access confirmed by owner.", tenant, "demo-seed");
    });
  } catch { /* best-effort demo */ }
}
