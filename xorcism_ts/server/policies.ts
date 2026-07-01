/**
 * policies.ts — Policy & document management inventory + governance worklist.
 *
 * The documented-information counterpart of compliance.ts / assets.ts: one pane over the
 * controlled-document estate — policies (XORCISM.POLICY) with their lifecycle (draft →
 * in review → approved → published → retired), and the supporting document register
 * (XCOMPLIANCE.DOCUMENT, records/evidence). Each policy carries a 0-100 governance score
 * (higher = worse) and the worklist surfaces the gaps that matter: overdue reviews,
 * unpublished/unowned policies, missing version/effective date, and expired documents.
 * Read-only; CRUD stays in the schema-driven explorer. Cross-DB (policies XORCISM,
 * documents XCOMPLIANCE), owners resolved against XORCISM.PERSON.
 */
import { allocId, getDb, ensurePolicyAckTable, ensurePolicyVersionTable, ensureLegalReviewTable } from "./db";
import { listUsers } from "./xid";
import { legalRollup } from "./legalreview";
import { randomUUID } from "crypto";

export interface PolicyRow {
  id: number;
  name: string;
  reference: string;
  docType: string;               // ISO documentation pyramid: Policy / Standard / Procedure / Guideline
  parentId: number | null;       // the parent governed document this implements (Procedure → Standard → Policy)
  category: string;
  framework: string;
  language: string;
  status: string;
  version: string;
  owner: string | null;
  effectiveDate: string | null;
  reviewDate: string | null;
  reviewInDays: number | null;   // <0 = overdue
  published: boolean;
  retired: boolean;
  publishedDate: string | null;
  requiresAck: boolean;
  accepted: number;              // distinct users who acknowledged the current version
  ackTarget: number;             // users expected to acknowledge (tenant population)
  ackRate: number | null;        // accepted / target (%), null if not applicable
  versions: number;              // number of snapshots in the version history
  score: number;                 // 0-100 (higher = worse)
  issues: string[];
  legalStatus: string | null;    // latest legal-counsel review status
  validationStatus: string | null; // latest validation / sign-off status
  legallyCleared: boolean;       // legal approved AND validated
  legalOverdue: boolean;         // a legal review/validation is past its re-review date
}
export interface DocumentRow {
  id: number;
  name: string;
  type: string;
  category: string;
  status: string;
  version: string;
  language: string;
  owner: string | null;
  reviewDate: string | null;
  validUntil: string | null;
  expired: boolean;
  issues: string[];
  classification: string;
  tlp: string;
  legalStatus: string | null;
  validationStatus: string | null;
  legallyCleared: boolean;
  legalOverdue: boolean;
}
export interface PolicyFinding {
  id: number;
  name: string;
  kind: "policy" | "document";
  severity: "High" | "Medium" | "Low";
  reason: string;
  label: string;
}
export interface PolicyInventory {
  rows: PolicyRow[];
  documents: DocumentRow[];
  findings: PolicyFinding[];
  summary: {
    policies: number; published: number; draft: number; inReview: number; approved: number; retired: number;
    overdueReview: number; dueSoon: number; noOwner: number; noVersion: number; notEffective: number;
    documents: number; expiredDocs: number; docsNoOwner: number;
    frameworks: number; languages: number; avgScore: number;
    // publication + user-acceptance KPIs
    requiringAck: number;        // published policies that require acknowledgement
    ackTarget: number;           // users expected to acknowledge (tenant population)
    requiredAcks: number;        // requiringAck × ackTarget
    completedAcks: number;       // acknowledgements actually recorded (current versions)
    ackCoverage: number;         // completedAcks / requiredAcks (%)
    pendingAcks: number;         // requiredAcks − completedAcks
    fullyAcknowledged: number;   // published+requiresAck policies at 100% acceptance
    standards: number; procedures: number; guidelines: number;  // ISO documentation pyramid counts
    // legal review & validation roll-up (across policies + documents)
    legalReviewed: number;       // targets with at least one legal review or validation
    legalCleared: number;        // legal approved AND validated
    legalPendingLegal: number;   // awaiting legal-counsel approval
    legalPendingValidation: number; // awaiting validation / sign-off
    legalRejected: number;       // a legal review or validation was rejected
    legalOverdue: number;        // a review/validation past its re-review date
    byStatus: Record<string, number>; byFramework: Record<string, number>;
    byCategory: Record<string, number>; byLanguage: Record<string, number>; byType: Record<string, number>;
  };
}

const EMPTY: PolicyInventory = {
  rows: [], documents: [], findings: [],
  summary: {
    policies: 0, published: 0, draft: 0, inReview: 0, approved: 0, retired: 0,
    overdueReview: 0, dueSoon: 0, noOwner: 0, noVersion: 0, notEffective: 0,
    documents: 0, expiredDocs: 0, docsNoOwner: 0, frameworks: 0, languages: 0, avgScore: 0,
    requiringAck: 0, ackTarget: 0, requiredAcks: 0, completedAcks: 0, ackCoverage: 0, pendingAcks: 0, fullyAcknowledged: 0,
    standards: 0, procedures: 0, guidelines: 0,
    legalReviewed: 0, legalCleared: 0, legalPendingLegal: 0, legalPendingValidation: 0, legalRejected: 0, legalOverdue: 0,
    byStatus: {}, byFramework: {}, byCategory: {}, byLanguage: {}, byType: {},
  },
};

const SEV_RANK: Record<string, number> = { High: 0, Medium: 1, Low: 2 };
const DUE_SOON_DAYS = 90;
const PUBLISHED = /publish|publié|active|in force|en vigueur/i;
const RETIRED = /retir|archiv|obsolet|supersed|withdrawn|abrog/i;
const INREVIEW = /review|revue|relecture|pending/i;
const APPROVED = /approv/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const norm = (s: unknown): string => String(s ?? "").trim();
const isStr = (s: unknown): boolean => !!norm(s);

/** Resolve PersonID → display name (XORCISM.PERSON). */
function personNames(): Map<number, string> {
  const m = new Map<number, string>();
  try {
    const pc = cols("XORCISM", "PERSON");
    const labelCol = pc.has("FullName") ? "FullName" : pc.has("PersonName") ? "PersonName" : null;
    if (!labelCol) return m;
    for (const p of getDb("XORCISM").prepare(`SELECT PersonID, ${labelCol} AS n FROM PERSON`).all() as { PersonID: number; n: string }[])
      if (p.n) m.set(Number(p.PersonID), String(p.n));
  } catch { /* PERSON absent */ }
  return m;
}

/** Full policy + document register inventory with a governance worklist. */
export function policyInventory(tenant: number | null): PolicyInventory {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='POLICY'").get()) return { ...EMPTY };
  const pc = cols("XORCISM", "POLICY");
  if (!pc.size) return { ...EMPTY };
  const owners = personNames();
  const findings: PolicyFinding[] = [];

  // ── Legal review & validation trail (XORCISM.LEGALREVIEW) ──
  let legalMap = new Map<string, any>(), legalKpi: any = { reviewed: 0, cleared: 0, pendingLegal: 0, pendingValidation: 0, rejected: 0, overdue: 0 };
  try { ensureLegalReviewTable(); const lr = legalRollup(tenant); legalMap = lr.map; legalKpi = lr.kpi; } catch { /* table absent */ }
  const legalOf = (type: string, id: number) => legalMap.get(`${type}:${id}`) || { legalStatus: null, validationStatus: null, legallyCleared: false, reviewOverdue: false };

  // ── User-acceptance of published policies (XORCISM.POLICYACKNOWLEDGEMENT) ──
  ensurePolicyAckTable();
  const ackTarget = activeTenantUserCount(tenant);
  const ackMap = loadAckMap(tenant); // PolicyID → (version → set of acknowledging UserIDs)
  // version-history counts per policy
  const verCount = new Map<number, number>();
  try {
    ensurePolicyVersionTable();
    const vtw = tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    for (const r of xo.prepare(`SELECT PolicyID, COUNT(*) n FROM POLICYVERSION ${vtw} GROUP BY PolicyID`).all() as { PolicyID: number; n: number }[]) verCount.set(Number(r.PolicyID), Number(r.n));
  } catch { /* table absent */ }

  // ── Policies ──────────────────────────────────────────────────────────────
  const ptw = tenant != null && pc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const raw = xo.prepare(`SELECT * FROM POLICY ${ptw}`).all() as Record<string, unknown>[];
  const rows: PolicyRow[] = raw.map((p) => {
    const id = Number(p.PolicyID);
    const name = norm(p.PolicyName) || `Policy #${id}`;
    const status = norm(p.Status) || norm(p.WorkflowStatus) || "Draft";
    const reviewDate = p.ReviewDate ? norm(p.ReviewDate).slice(0, 10) : null;
    const reviewInDays = daysUntil(reviewDate);
    const retired = RETIRED.test(status);
    const published = PUBLISHED.test(status);
    const ownerId = p.OwnerPersonID != null ? Number(p.OwnerPersonID) : null;
    const owner = ownerId != null ? (owners.get(ownerId) ?? `#${ownerId}`) : null;
    const version = norm(p.Version);
    const effectiveDate = p.EffectiveDate ? norm(p.EffectiveDate).slice(0, 10) : null;

    // publication + acceptance
    const requiresAck = Number(p.RequiresAcknowledgement) === 1;
    const publishedDate = p.PublishedDate ? norm(p.PublishedDate).slice(0, 10) : null;
    const curVer = version || "1.0";
    const acceptable = published && requiresAck;
    const accepted = acceptable ? (ackMap.get(id)?.get(curVer)?.size ?? 0) : 0;
    const at = acceptable ? ackTarget : 0;
    const ackRate = at > 0 ? Math.round((accepted / at) * 100) : null;

    const issues: string[] = [];
    let score = 0;
    if (!retired) {
      if (reviewInDays != null && reviewInDays < 0) { issues.push(`review overdue (${-reviewInDays}d)`); score += 30; }
      else if (reviewInDays != null && reviewInDays <= DUE_SOON_DAYS) { issues.push(`review due in ${reviewInDays}d`); score += 6; }
      else if (!reviewDate) { issues.push("no review date"); score += 8; }
      if (!published) { issues.push(`not published (${status.toLowerCase()})`); score += 15; }
      if (!owner) { issues.push("no owner"); score += 15; }
      if (!version) { issues.push("no version"); score += 8; }
      if (!effectiveDate && published) { issues.push("no effective date"); score += 6; }
      if (acceptable && ackRate != null && ackRate < 100) { issues.push(`acceptance ${ackRate}%`); score += Math.min(15, Math.round((100 - ackRate) / 10)); }
    }
    score = Math.min(100, score);

    // emit worklist findings for the worst gaps
    if (!retired) {
      if (reviewInDays != null && reviewInDays < 0) {
        findings.push({ id, name, kind: "policy", severity: "High", reason: "review-overdue", label: `${name} — review overdue by ${-reviewInDays}d` });
      } else if (!published) {
        // work-in-progress policy: track until published; harsher if also unowned/unversioned.
        const gaps = [!owner ? "no owner" : "", !version ? "no version" : ""].filter(Boolean);
        findings.push({ id, name, kind: "policy", severity: gaps.length ? "Medium" : "Low", reason: "unpublished", label: `${name} — ${status.toLowerCase()}${gaps.length ? `, ${gaps.join(", ")}` : ""}` });
      } else if (!owner) {
        findings.push({ id, name, kind: "policy", severity: "Medium", reason: "no-owner", label: `${name} — no accountable owner` });
      } else if (reviewInDays != null && reviewInDays >= 0 && reviewInDays <= DUE_SOON_DAYS) {
        findings.push({ id, name, kind: "policy", severity: "Low", reason: "due-soon", label: `${name} — review due in ${reviewInDays}d` });
      }
      // acceptance is independent of the above cascade
      if (acceptable && ackRate != null && ackRate < 100) {
        findings.push({ id, name, kind: "policy", severity: ackRate < 50 ? "Medium" : "Low", reason: "acceptance-pending", label: `${name} — ${at - accepted} user(s) have not acknowledged (${ackRate}%)` });
      }
    }

    const lg = legalOf("policy", id);
    return {
      id, name, reference: norm(p.PolicyReference) || "—",
      docType: norm(p.DocumentType) || "Policy", parentId: p.ParentPolicyID != null ? Number(p.ParentPolicyID) : null,
      category: norm(p.Category) || "—", framework: norm(p.Framework) || "—",
      language: (norm(p.Language) || "—").toLowerCase(), status, version: version || "—",
      owner, effectiveDate, reviewDate, reviewInDays, published, retired,
      publishedDate, requiresAck, accepted, ackTarget: at, ackRate, versions: verCount.get(id) ?? 0, score, issues,
      legalStatus: lg.legalStatus, validationStatus: lg.validationStatus, legallyCleared: lg.legallyCleared, legalOverdue: lg.reviewOverdue,
    };
  });

  // ── Document register ───────────────────────────────────────────────────────
  const documents: DocumentRow[] = [];
  let expiredDocs = 0, docsNoOwner = 0;
  try {
    const cc = getDb("XCOMPLIANCE");
    if (cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='DOCUMENT'").get()) {
      const dc = cols("XCOMPLIANCE", "DOCUMENT");
      const dtw = tenant != null && dc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
      for (const d of cc.prepare(`SELECT * FROM DOCUMENT ${dtw}`).all() as Record<string, unknown>[]) {
        const id = Number(d.DocumentID);
        const name = norm(d.DocumentName) || `Document #${id}`;
        const validUntil = d.ValidUntil ? norm(d.ValidUntil).slice(0, 10) : null;
        const reviewDate = d.ReviewDate ? norm(d.ReviewDate).slice(0, 10) : null;
        const vu = daysUntil(validUntil);
        const expired = vu != null && vu < 0;
        const ownerId = d.OwnerPersonID != null ? Number(d.OwnerPersonID) : null;
        const owner = ownerId != null ? (owners.get(ownerId) ?? `#${ownerId}`) : null;
        const issues: string[] = [];
        if (expired) { issues.push(`expired (${-(vu as number)}d)`); expiredDocs++; }
        if (!owner) { issues.push("no owner"); docsNoOwner++; }
        if (!isStr(d.Version)) issues.push("no version");
        const classification = norm(d.Classification);
        const tlp = norm(d.TLP);
        if (!classification && isStr(d.DocumentName)) issues.push("unclassified");
        if (expired)
          findings.push({ id, name, kind: "document", severity: "Medium", reason: "expired", label: `${name} — expired ${-(vu as number)}d ago` });
        else if (!owner && isStr(d.DocumentName))
          findings.push({ id, name, kind: "document", severity: "Low", reason: "doc-no-owner", label: `${name} — no owner` });
        else if (!classification && isStr(d.DocumentName))
          findings.push({ id, name, kind: "document", severity: "Low", reason: "doc-unclassified", label: `${name} — no sensitivity label` });
        const lg = legalOf("document", id);
        documents.push({
          id, name, type: norm(d.DocumentType) || "—", category: norm(d.Category) || "—",
          status: norm(d.Status) || "—", version: norm(d.Version) || "—", classification, tlp,
          language: (norm(d.Language) || "—").toLowerCase(), owner, reviewDate, validUntil, expired, issues,
          legalStatus: lg.legalStatus, validationStatus: lg.validationStatus, legallyCleared: lg.legallyCleared, legalOverdue: lg.reviewOverdue,
        });
      }
    }
  } catch { /* DOCUMENT absent */ }

  // ── Sort + summary ──────────────────────────────────────────────────────────
  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  documents.sort((a, b) => (a.expired === b.expired ? 0 : a.expired ? -1 : 1) || a.name.localeCompare(b.name));
  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.name.localeCompare(b.name));

  const byStatus: Record<string, number> = {}, byFramework: Record<string, number> = {};
  const byCategory: Record<string, number> = {}, byLanguage: Record<string, number> = {};
  const byType: Record<string, number> = {};
  for (const r of rows) {
    byType[r.docType] = (byType[r.docType] || 0) + 1;
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    if (r.framework !== "—") byFramework[r.framework] = (byFramework[r.framework] || 0) + 1;
    if (r.category !== "—") byCategory[r.category] = (byCategory[r.category] || 0) + 1;
    if (r.language !== "—") byLanguage[r.language] = (byLanguage[r.language] || 0) + 1;
  }
  const active = rows.filter((r) => !r.retired);
  const avgScore = active.length ? Math.round(active.reduce((s, r) => s + r.score, 0) / active.length) : 0;

  // user-acceptance roll-up across published, acknowledgement-requiring policies
  const pubAck = rows.filter((r) => r.published && r.requiresAck);
  const requiringAck = pubAck.length;
  const requiredAcks = requiringAck * ackTarget;
  const completedAcks = pubAck.reduce((s, r) => s + r.accepted, 0);
  // no target users (e.g. a tenant with no login accounts) → acknowledgement is vacuously complete
  const ackCoverage = requiredAcks ? Math.round((completedAcks / requiredAcks) * 100) : (requiringAck ? 100 : 0);
  const pendingAcks = Math.max(0, requiredAcks - completedAcks);
  const fullyAcknowledged = pubAck.filter((r) => r.ackTarget > 0 && r.accepted >= r.ackTarget).length;

  return {
    rows, documents, findings,
    summary: {
      policies: rows.length,
      published: rows.filter((r) => r.published).length,
      draft: rows.filter((r) => !r.retired && !r.published && !INREVIEW.test(r.status) && !APPROVED.test(r.status)).length,
      inReview: rows.filter((r) => INREVIEW.test(r.status)).length,
      approved: rows.filter((r) => APPROVED.test(r.status) && !r.published).length,
      retired: rows.filter((r) => r.retired).length,
      overdueReview: rows.filter((r) => !r.retired && r.reviewInDays != null && r.reviewInDays < 0).length,
      dueSoon: rows.filter((r) => !r.retired && r.reviewInDays != null && r.reviewInDays >= 0 && r.reviewInDays <= DUE_SOON_DAYS).length,
      noOwner: active.filter((r) => !r.owner).length,
      noVersion: active.filter((r) => r.version === "—").length,
      notEffective: rows.filter((r) => r.published && !r.effectiveDate).length,
      documents: documents.length,
      expiredDocs, docsNoOwner,
      frameworks: Object.keys(byFramework).length,
      languages: Object.keys(byLanguage).length,
      avgScore,
      requiringAck, ackTarget, requiredAcks, completedAcks, ackCoverage, pendingAcks, fullyAcknowledged,
      standards: byType["Standard"] || 0, procedures: byType["Procedure"] || 0, guidelines: byType["Guideline"] || 0,
      legalReviewed: legalKpi.reviewed, legalCleared: legalKpi.cleared, legalPendingLegal: legalKpi.pendingLegal,
      legalPendingValidation: legalKpi.pendingValidation, legalRejected: legalKpi.rejected, legalOverdue: legalKpi.overdue,
      byStatus, byFramework, byCategory, byLanguage, byType,
    },
  };
}

// ── Publication + user-acceptance ──────────────────────────────────────────────
const todayStr = (): string => new Date().toISOString().slice(0, 10);

/** Count of active (approved, unlocked) users in the tenant — the acknowledgement target population. */
function activeTenantUserCount(tenant: number | null): number {
  try {
    return listUsers(tenant).filter((u) => Number(u.IsApproved ?? 1) === 1 && Number(u.IsLockedOut ?? 0) === 0).length;
  } catch { return 0; }
}

/** PolicyID → (version → set of acknowledging UserIDs), tenant-scoped. */
function loadAckMap(tenant: number | null): Map<number, Map<string, Set<number>>> {
  const m = new Map<number, Map<string, Set<number>>>();
  try {
    const xo = getDb("XORCISM");
    if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='POLICYACKNOWLEDGEMENT'").get()) return m;
    const tw = tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    for (const r of xo.prepare(`SELECT PolicyID, UserID, PolicyVersion FROM POLICYACKNOWLEDGEMENT ${tw}`).all() as { PolicyID: number; UserID: number; PolicyVersion: string }[]) {
      const pid = Number(r.PolicyID), ver = norm(r.PolicyVersion) || "1.0";
      let vm = m.get(pid); if (!vm) { vm = new Map(); m.set(pid, vm); }
      let s = vm.get(ver); if (!s) { s = new Set(); vm.set(ver, s); }
      s.add(Number(r.UserID));
    }
  } catch { /* table absent */ }
  return m;
}

/** Confirm a policy is in the caller's tenant; returns its current version (default "1.0"). */
function policyTenantOk(id: number, tenant: number | null): { version: string; status: string } | null {
  const xo = getDb("XORCISM");
  const r = xo.prepare("SELECT Version, Status, TenantID FROM POLICY WHERE PolicyID = ?").get(id) as { Version: string; Status: string; TenantID: number | null } | undefined;
  if (!r) return null;
  if (tenant != null && r.TenantID != null && Number(r.TenantID) !== tenant) return null;
  return { version: norm(r.Version) || "1.0", status: norm(r.Status) };
}

/** Publish a policy: Status=Published, PublishedDate=today, EffectiveDate, Version, RequiresAcknowledgement.
 *  Snapshots the published state into POLICYVERSION (version history). */
export function publishPolicy(id: number, opts: { effectiveDate?: string; version?: string; requiresAck?: boolean; userId?: number; userName?: string }, tenant: number | null): boolean {
  const ok = policyTenantOk(id, tenant);
  if (!ok) return false;
  const xo = getDb("XORCISM");
  const pc = cols("XORCISM", "POLICY");
  const version = norm(opts.version) || ok.version || "1.0";
  const eff = norm(opts.effectiveDate) || todayStr();
  const reqAck = opts.requiresAck === false ? 0 : 1;
  const sets: string[] = ["Status = 'Published'"]; const vals: unknown[] = [];
  if (pc.has("PublishedDate")) { sets.push("PublishedDate = ?"); vals.push(todayStr()); }
  if (pc.has("EffectiveDate")) { sets.push("EffectiveDate = ?"); vals.push(eff); }
  if (pc.has("Version")) { sets.push("Version = ?"); vals.push(version); }
  if (pc.has("RequiresAcknowledgement")) { sets.push("RequiresAcknowledgement = ?"); vals.push(reqAck); }
  if (pc.has("WorkflowStatus")) { sets.push("WorkflowStatus = 'Published'"); }
  vals.push(id);
  xo.prepare(`UPDATE POLICY SET ${sets.join(", ")} WHERE PolicyID = ?`).run(...vals);
  // version history: snapshot the freshly-published state (no-op if this version was already snapshotted)
  try { snapshotPolicyVersion(id, { changeNote: `Published v${version}`, userId: opts.userId, userName: opts.userName, dedupeVersion: true }, tenant); } catch { /* history is best-effort */ }
  return true;
}

/** Retire (withdraw) a policy. */
export function retirePolicy(id: number, tenant: number | null): boolean {
  const ok = policyTenantOk(id, tenant);
  if (!ok) return false;
  getDb("XORCISM").prepare("UPDATE POLICY SET Status = 'Retired' WHERE PolicyID = ?").run(id);
  return true;
}

/** Record a user's acknowledgement of a published policy (idempotent per policy+user+version). */
export function acknowledgePolicy(id: number, by: { userId: number; email?: string; name?: string; ip?: string; method?: string }, tenant: number | null): { ok: boolean; already: boolean } | null {
  ensurePolicyAckTable();
  const ok = policyTenantOk(id, tenant);
  if (!ok || !PUBLISHED.test(ok.status)) return null; // only published policies are acknowledgeable
  const xo = getDb("XORCISM");
  const ver = ok.version;
  const existing = xo.prepare("SELECT 1 FROM POLICYACKNOWLEDGEMENT WHERE PolicyID = ? AND UserID = ? AND IFNULL(PolicyVersion,'1.0') = ?").get(id, by.userId, ver);
  if (existing) return { ok: true, already: true };
  const aid = allocId(xo, "POLICYACKNOWLEDGEMENT", "AcknowledgementID");
  xo.prepare(`INSERT INTO POLICYACKNOWLEDGEMENT (AcknowledgementID, AcknowledgementGUID, PolicyID, UserID, UserEmail, UserName, PolicyVersion, AcknowledgedDate, Method, IPAddress, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(aid, randomUUID(), id, by.userId, by.email || null, by.name || null, ver, new Date().toISOString(), by.method || "app", by.ip || null, tenant);
  return { ok: true, already: false };
}

/** Per-policy acceptance detail: who acknowledged + who is still pending (for the admin coverage view). */
export function policyAcceptanceDetail(id: number, tenant: number | null): any {
  ensurePolicyAckTable();
  const ok = policyTenantOk(id, tenant);
  if (!ok) return null;
  const xo = getDb("XORCISM");
  const p = xo.prepare("SELECT PolicyName FROM POLICY WHERE PolicyID = ?").get(id) as { PolicyName: string } | undefined;
  const acks = xo.prepare("SELECT UserID, UserName, UserEmail, AcknowledgedDate FROM POLICYACKNOWLEDGEMENT WHERE PolicyID = ? AND IFNULL(PolicyVersion,'1.0') = ?").all(id, ok.version) as { UserID: number; UserName: string; UserEmail: string; AcknowledgedDate: string }[];
  const ackedIds = new Set(acks.map((a) => Number(a.UserID)));
  const users = listUsers(tenant).filter((u) => Number(u.IsApproved ?? 1) === 1 && Number(u.IsLockedOut ?? 0) === 0);
  const pending = users.filter((u) => !ackedIds.has(Number(u.UserID))).map((u) => ({ userId: Number(u.UserID), email: String(u.Email || ""), name: String(u.DisplayName || u.Email || `#${u.UserID}`) }));
  return {
    id, name: norm(p?.PolicyName) || `Policy #${id}`, version: ok.version,
    target: users.length, accepted: acks.length,
    acknowledgements: acks.map((a) => ({ userId: Number(a.UserID), name: String(a.UserName || a.UserEmail || `#${a.UserID}`), date: String(a.AcknowledgedDate || "").slice(0, 10) })),
    pending: pending.slice(0, 300),
  };
}

/** The published, acknowledgement-requiring policies a given user has NOT yet acknowledged. */
export function myPendingPolicies(userId: number, tenant: number | null): { id: number; name: string; version: string; publishedDate: string | null }[] {
  ensurePolicyAckTable();
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='POLICY'").get()) return [];
  const pc = cols("XORCISM", "POLICY");
  if (!pc.has("RequiresAcknowledgement")) return [];
  const ptw = tenant != null && pc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const rows = xo.prepare(`SELECT PolicyID, PolicyName, Status, Version, RequiresAcknowledgement, PublishedDate FROM POLICY ${ptw}`).all() as Record<string, unknown>[];
  const acked = new Set((xo.prepare("SELECT PolicyID, PolicyVersion FROM POLICYACKNOWLEDGEMENT WHERE UserID = ?").all(userId) as { PolicyID: number; PolicyVersion: string }[]).map((a) => `${Number(a.PolicyID)}:${norm(a.PolicyVersion) || "1.0"}`));
  const out: { id: number; name: string; version: string; publishedDate: string | null }[] = [];
  for (const r of rows) {
    if (!PUBLISHED.test(norm(r.Status)) || Number(r.RequiresAcknowledgement) !== 1) continue;
    const id = Number(r.PolicyID), ver = norm(r.Version) || "1.0";
    if (acked.has(`${id}:${ver}`)) continue;
    out.push({ id, name: norm(r.PolicyName) || `Policy #${id}`, version: ver, publishedDate: r.PublishedDate ? norm(r.PublishedDate).slice(0, 10) : null });
  }
  return out;
}

/** Demo seed (tenant only): publish 2 policies (requiring ack) + acknowledge the first by all tenant users. */
export function seedPolicyAck(tenant: number): { published: number; acks: number } {
  ensurePolicyAckTable();
  const xo = getDb("XORCISM");
  const pc = cols("XORCISM", "POLICY");
  if (!pc.has("RequiresAcknowledgement") || !xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='POLICY'").get()) return { published: 0, acks: 0 };
  if (Number((xo.prepare("SELECT COUNT(*) n FROM POLICYACKNOWLEDGEMENT WHERE TenantID = ?").get(tenant) as { n: number }).n)) return { published: 0, acks: 0 };
  const ptw = pc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const pols = (xo.prepare(`SELECT PolicyID, Status FROM POLICY ${ptw} ORDER BY PolicyID LIMIT 8`).all() as { PolicyID: number; Status: string }[]).filter((p) => !RETIRED.test(norm(p.Status))).slice(0, 2);
  let published = 0, acks = 0;
  for (const p of pols) { publishPolicy(Number(p.PolicyID), { requiresAck: true }, tenant); published++; }
  if (pols[0]) {
    for (const u of listUsers(tenant).filter((u) => Number(u.IsApproved ?? 1) === 1 && Number(u.IsLockedOut ?? 0) === 0)) {
      const r = acknowledgePolicy(Number(pols[0].PolicyID), { userId: Number(u.UserID), email: String(u.Email || ""), name: String(u.DisplayName || ""), method: "seed" }, tenant);
      if (r && !r.already) acks++;
    }
  }
  return { published, acks };
}

// ── Version history (XORCISM.POLICYVERSION) ─────────────────────────────────────
/** Snapshot the policy's current state into the version history. dedupeVersion skips if the latest
 *  snapshot is already this exact version (so publishing twice at the same version doesn't duplicate). */
export function snapshotPolicyVersion(id: number, opts: { changeNote?: string; userId?: number; userName?: string; dedupeVersion?: boolean }, tenant: number | null): { versionId: number } | null {
  ensurePolicyVersionTable();
  const ok = policyTenantOk(id, tenant);
  if (!ok) return null;
  const xo = getDb("XORCISM");
  const pc = cols("XORCISM", "POLICY");
  const sel = ["PolicyName", "Status", "Version", "PolicyContent", "Scope", "EffectiveDate", "PublishedDate"].filter((c) => pc.has(c));
  const p = xo.prepare(`SELECT ${sel.map((c) => `"${c}"`).join(", ")} FROM POLICY WHERE PolicyID = ?`).get(id) as Record<string, unknown> | undefined;
  if (!p) return null;
  const version = norm(p.Version) || ok.version || "1.0";
  if (opts.dedupeVersion) {
    const last = xo.prepare("SELECT Version FROM POLICYVERSION WHERE PolicyID = ? ORDER BY PolicyVersionID DESC LIMIT 1").get(id) as { Version: string } | undefined;
    if (last && norm(last.Version) === version) return null; // already snapshotted at this version
  }
  const vid = allocId(xo, "POLICYVERSION", "PolicyVersionID");
  xo.prepare(`INSERT INTO POLICYVERSION (PolicyVersionID, PolicyVersionGUID, PolicyID, Version, Status, PolicyName, PolicyContent, Scope, EffectiveDate, PublishedDate, ChangeNote, ChangedByUserID, ChangedByName, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(vid, randomUUID(), id, version, norm(p.Status), norm(p.PolicyName), p.PolicyContent != null ? String(p.PolicyContent) : null, p.Scope != null ? String(p.Scope) : null,
      p.EffectiveDate != null ? String(p.EffectiveDate) : null, p.PublishedDate != null ? String(p.PublishedDate) : null,
      (opts.changeNote || "").slice(0, 500), opts.userId ?? null, (opts.userName || "").slice(0, 160) || null, new Date().toISOString(), tenant);
  return { versionId: vid };
}

/** Version history list for a policy (newest first, content excluded for size). */
export function policyVersions(id: number, tenant: number | null): any[] {
  ensurePolicyVersionTable();
  if (!policyTenantOk(id, tenant)) return [];
  return (getDb("XORCISM").prepare(
    "SELECT PolicyVersionID, Version, Status, EffectiveDate, PublishedDate, ChangeNote, ChangedByName, CreatedDate, LENGTH(COALESCE(PolicyContent,'')) AS contentLen FROM POLICYVERSION WHERE PolicyID = ? ORDER BY PolicyVersionID DESC"
  ).all(id) as any[]).map((v) => ({
    versionId: Number(v.PolicyVersionID), version: norm(v.Version) || "—", status: norm(v.Status) || "—",
    effectiveDate: v.EffectiveDate ? norm(v.EffectiveDate).slice(0, 10) : null, publishedDate: v.PublishedDate ? norm(v.PublishedDate).slice(0, 10) : null,
    changeNote: norm(v.ChangeNote), changedBy: norm(v.ChangedByName) || null, at: norm(v.CreatedDate).slice(0, 19).replace("T", " "), hasContent: Number(v.contentLen) > 0,
  }));
}

/** Full content of one historical version. */
export function policyVersionDetail(versionId: number, tenant: number | null): any {
  ensurePolicyVersionTable();
  const xo = getDb("XORCISM");
  const v = xo.prepare("SELECT * FROM POLICYVERSION WHERE PolicyVersionID = ?").get(versionId) as Record<string, unknown> | undefined;
  if (!v) return null;
  if (tenant != null && v.TenantID != null && Number(v.TenantID) !== tenant) return null;
  return {
    versionId: Number(v.PolicyVersionID), policyId: Number(v.PolicyID), version: norm(v.Version) || "—", status: norm(v.Status) || "—",
    name: norm(v.PolicyName), content: v.PolicyContent != null ? String(v.PolicyContent) : "", scope: v.Scope != null ? String(v.Scope) : "",
    effectiveDate: v.EffectiveDate ? norm(v.EffectiveDate).slice(0, 10) : null, publishedDate: v.PublishedDate ? norm(v.PublishedDate).slice(0, 10) : null,
    changeNote: norm(v.ChangeNote), changedBy: norm(v.ChangedByName) || null, at: norm(v.CreatedDate),
  };
}

/** One-time backfill: give every already-published policy an initial version-history entry. Idempotent. */
export function backfillPolicyVersions(): void {
  try {
    ensurePolicyVersionTable();
    const xo = getDb("XORCISM");
    if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='POLICY'").get()) return;
    if (!cols("XORCISM", "POLICY").has("RequiresAcknowledgement")) return; // publication feature present
    for (const p of xo.prepare("SELECT PolicyID, Status, TenantID FROM POLICY").all() as { PolicyID: number; Status: string; TenantID: number | null }[]) {
      if (!PUBLISHED.test(norm(p.Status))) continue;
      if (xo.prepare("SELECT 1 FROM POLICYVERSION WHERE PolicyID = ?").get(p.PolicyID)) continue;
      snapshotPolicyVersion(Number(p.PolicyID), { changeNote: "Initial version (backfill)" }, p.TenantID != null ? Number(p.TenantID) : null);
    }
  } catch { /* best-effort */ }
}

/** Restore a prior version's content onto the live policy as a new DRAFT (snapshots current state first). */
export function restorePolicyVersion(id: number, versionId: number, by: { userId?: number; userName?: string }, tenant: number | null): boolean {
  const ok = policyTenantOk(id, tenant);
  if (!ok) return false;
  const v = policyVersionDetail(versionId, tenant);
  if (!v || v.policyId !== id) return false;
  // preserve the current state before overwriting
  snapshotPolicyVersion(id, { changeNote: `Auto-snapshot before restoring v${v.version}`, userId: by.userId, userName: by.userName }, tenant);
  const xo = getDb("XORCISM");
  const pc = cols("XORCISM", "POLICY");
  const sets: string[] = ["Status = 'Draft'"]; const vals: unknown[] = [];
  if (pc.has("PolicyContent")) { sets.push("PolicyContent = ?"); vals.push(v.content); }
  if (pc.has("Scope") && v.scope) { sets.push("Scope = ?"); vals.push(v.scope); }
  if (pc.has("Version")) { sets.push("Version = ?"); vals.push(v.version); }
  if (pc.has("WorkflowStatus")) { sets.push("WorkflowStatus = 'Draft'"); }
  vals.push(id);
  xo.prepare(`UPDATE POLICY SET ${sets.join(", ")} WHERE PolicyID = ?`).run(...vals);
  return true;
}

// ── POLICY ↔ ASSET coverage (POLICYFORASSET) ──────────────────────────────────
// Which assets are governed by a policy, and — the gap that matters — which assets
// (especially critical / high-value ones) have NO governing policy at all.
export interface PolicyCoverage {
  summary: { policies: number; assets: number; links: number; coveredAssets: number; coveragePct: number; uncoveredAssets: number; uncoveredCritical: number; policiesNoAsset: number };
  perPolicy: { policyId: number; policyName: string; status: string; assetCount: number }[];
  uncovered: { assetId: number; assetName: string; criticality: string | null; businessValue: number | null }[];
  policiesNoAsset: { policyId: number; policyName: string; status: string }[];
}

const EMPTY_COVERAGE: PolicyCoverage = {
  summary: { policies: 0, assets: 0, links: 0, coveredAssets: 0, coveragePct: 0, uncoveredAssets: 0, uncoveredCritical: 0, policiesNoAsset: 0 },
  perPolicy: [], uncovered: [], policiesNoAsset: [],
};

export function policyAssetCoverage(tenant: number | null): PolicyCoverage {
  const xo = getDb("XORCISM");
  const has = (t: string): boolean => !!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  if (!has("POLICY") || !has("ASSET") || !has("POLICYFORASSET")) return { ...EMPTY_COVERAGE };
  const colset = (t: string): Set<string> => new Set((xo.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name));
  const ac = colset("ASSET"), pc = colset("POLICY"), lc = colset("POLICYFORASSET");
  const tcl = (cs: Set<string>): string => (tenant != null && cs.has("TenantID") ? " AND (TenantID = ? OR TenantID IS NULL)" : "");
  const ta = (cs: Set<string>): number[] => (tenant != null && cs.has("TenantID") ? [tenant] : []);

  const polName = pc.has("PolicyName") ? "PolicyName" : "'Policy '||PolicyID";
  const polStatus = pc.has("Status") ? "Status" : "''";
  const policies = xo.prepare(`SELECT PolicyID id, ${polName} name, ${polStatus} status FROM POLICY WHERE 1=1${tcl(pc)}`).all(...ta(pc)) as { id: number; name: string; status: string }[];

  const crit = ac.has("AssetCriticalityLevel") ? "AssetCriticalityLevel" : "NULL";
  const bv = ac.has("BusinessValue") ? "BusinessValue" : (ac.has("RiskScore") ? "RiskScore" : "NULL");
  const assets = xo.prepare(`SELECT AssetID id, AssetName name, ${crit} crit, ${bv} bv FROM ASSET WHERE 1=1${tcl(ac)}`).all(...ta(ac)) as { id: number; name: string; crit: string | null; bv: number | null }[];

  const links = xo.prepare(`SELECT PolicyID pid, AssetID aid FROM POLICYFORASSET WHERE AssetID IS NOT NULL${tcl(lc)}`).all(...ta(lc)) as { pid: number; aid: number }[];

  const perPolicyCount = new Map<number, number>();
  const coveredIds = new Set<number>();
  for (const l of links) { perPolicyCount.set(l.pid, (perPolicyCount.get(l.pid) || 0) + 1); coveredIds.add(l.aid); }

  const isCritical = (c: string | null, v: number | null): boolean => /crit|high/i.test(String(c || "")) || (v != null && Number(v) >= 100000);
  const inScopeCovered = assets.filter((a) => coveredIds.has(a.id)).length;
  const uncovered = assets.filter((a) => !coveredIds.has(a.id))
    .sort((a, b) => (Number(isCritical(b.crit, b.bv)) - Number(isCritical(a.crit, a.bv))) || ((Number(b.bv) || 0) - (Number(a.bv) || 0)))
    .slice(0, 100)
    .map((a) => ({ assetId: a.id, assetName: String(a.name ?? `#${a.id}`), criticality: a.crit ? String(a.crit) : null, businessValue: a.bv != null ? Number(a.bv) : null }));

  const perPolicy = policies.map((p) => ({ policyId: p.id, policyName: String(p.name ?? `#${p.id}`), status: String(p.status || ""), assetCount: perPolicyCount.get(p.id) || 0 }))
    .sort((a, b) => b.assetCount - a.assetCount);
  const published = (s: string): boolean => /publish|approv|active/i.test(s);
  const policiesNoAsset = perPolicy.filter((p) => p.assetCount === 0 && published(p.status)).map((p) => ({ policyId: p.policyId, policyName: p.policyName, status: p.status }));

  return {
    summary: {
      policies: policies.length, assets: assets.length, links: links.length,
      coveredAssets: inScopeCovered,
      coveragePct: assets.length ? Math.round((inScopeCovered / assets.length) * 100) : 0,
      uncoveredAssets: assets.length - inScopeCovered,
      uncoveredCritical: assets.filter((a) => !coveredIds.has(a.id) && isCritical(a.crit, a.bv)).length,
      policiesNoAsset: policiesNoAsset.length,
    },
    perPolicy: perPolicy.slice(0, 200),
    uncovered,
    policiesNoAsset,
  };
}
