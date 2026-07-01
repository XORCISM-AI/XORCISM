/**
 * legalreview.ts — legal review & validation trail for controlled documents.
 *
 * A governance overlay on the policy/document estate ([[policy-management]]): each POLICY
 * (XORCISM) or DOCUMENT (XCOMPLIANCE) can carry a series of reviews of two kinds —
 *   • legal       — legal-counsel review (does the document meet its legal/regulatory obligations?)
 *   • validation  — final validation / sign-off (management or authority approval)
 * — each with a status, the legal basis/jurisdiction examined, the version reviewed, a reviewer,
 * comments and a re-review due date. A target is "legally cleared" when its latest legal review AND
 * its latest validation are both approved. Rows live in XORCISM.LEGALREVIEW; targets are resolved
 * cross-DB. Reads feed both the per-document panel and the policy-management KPI rollup.
 */
import { randomUUID } from "crypto";
import { getDb, allocId } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const s = (v: unknown): string => (v == null ? "" : String(v));

export const TARGET_TYPES = ["policy", "document"] as const;
export const REVIEW_TYPES = ["legal", "validation"] as const;
export const STATUSES = ["requested", "in-review", "approved", "approved-with-changes", "rejected"];
const APPROVED = new Set(["approved", "approved-with-changes"]);

const TARGETS: Record<string, { db: string; table: string; idCol: string; nameCol: string }> = {
  policy: { db: "XORCISM", table: "POLICY", idCol: "PolicyID", nameCol: "PolicyName" },
  document: { db: "XCOMPLIANCE", table: "DOCUMENT", idCol: "DocumentID", nameCol: "DocumentName" },
};

const tw = (tenant: number | null): string => (tenant != null ? "(TenantID = ? OR TenantID IS NULL)" : "1=1");
const ta = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

export function targetName(type: string, id: number): string {
  const d = TARGETS[type];
  if (!d) return "";
  try {
    const db = getDb(d.db);
    if (!has(db, d.table)) return "";
    const r = db.prepare(`SELECT ${d.nameCol} n FROM ${d.table} WHERE ${d.idCol}=?`).get(id) as { n?: string } | undefined;
    return s(r?.n);
  } catch { return ""; }
}

const reviewRow = (r: any): any => ({
  id: r.ReviewID, targetType: r.TargetType, targetId: r.TargetID, targetName: r.TargetName,
  reviewType: r.ReviewType, status: r.Status, versionReviewed: r.VersionReviewed,
  legalBasis: r.LegalBasis, jurisdiction: r.Jurisdiction, reviewerName: r.ReviewerName,
  comments: r.Comments, requestedDate: r.RequestedDate, reviewedDate: r.ReviewedDate,
  validUntil: r.ValidUntil, createdBy: r.CreatedByName, createdDate: r.CreatedDate,
});

/** The latest review of each kind + a cleared/overdue rollup for one target. */
function rollupFromItems(items: any[]): any {
  const latest = (kind: string) => items.filter((i) => i.reviewType === kind)[0] || null; // items are DESC by id
  const legal = latest("legal"), validation = latest("validation");
  const overdue = items.some((i) => i.validUntil && Date.parse(i.validUntil) < Date.now());
  return {
    legalStatus: legal ? legal.status : null,
    validationStatus: validation ? validation.status : null,
    legallyCleared: !!(legal && APPROVED.has(legal.status) && validation && APPROVED.has(validation.status)),
    reviewOverdue: overdue,
  };
}

/** All reviews for a target + a summary (latest legal/validation, cleared, overdue). */
export function listReviews(type: string, id: number, tenant: number | null): any {
  const db = getDb("XORCISM");
  if (!has(db, "LEGALREVIEW")) return { items: [], summary: emptyRollup() };
  const rows = db.prepare(`SELECT * FROM LEGALREVIEW WHERE TargetType=? AND TargetID=? AND ${tw(tenant)} ORDER BY ReviewID DESC`).all(type, id, ...ta(tenant)) as any[];
  const items = rows.map(reviewRow);
  return { items, summary: { total: items.length, ...rollupFromItems(items) } };
}
const emptyRollup = () => ({ total: 0, legalStatus: null, validationStatus: null, legallyCleared: false, reviewOverdue: false });

/** Record a legal review or validation of a policy/document. */
export function addReview(type: string, id: number, tenant: number | null, b: any, user: { id?: number | null; name?: string }): { id: number } | { error: string } {
  if (!TARGETS[type]) return { error: "unknown target type" };
  const rt = s(b.reviewType);
  if (!(REVIEW_TYPES as readonly string[]).includes(rt)) return { error: "invalid review type" };
  const status = STATUSES.includes(s(b.status)) ? s(b.status) : "requested";
  const db = getDb("XORCISM");
  if (!has(db, "LEGALREVIEW")) return { error: "not available" };
  const rid = allocId(db, "LEGALREVIEW", "ReviewID");
  const now = new Date().toISOString();
  const reviewed = APPROVED.has(status) || status === "rejected";
  db.prepare(`INSERT INTO LEGALREVIEW (ReviewID, ReviewGUID, TargetType, TargetID, TargetName, ReviewType, Status, VersionReviewed, LegalBasis, Jurisdiction, ReviewerName, Comments, RequestedDate, ReviewedDate, ValidUntil, CreatedByUserID, CreatedByName, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    rid, randomUUID(), type, id, targetName(type, id).slice(0, 300), rt, status,
    s(b.versionReviewed).slice(0, 40), s(b.legalBasis).slice(0, 600), s(b.jurisdiction).slice(0, 200),
    s(b.reviewerName).slice(0, 160), s(b.comments).slice(0, 4000),
    s(b.requestedDate) || now.slice(0, 10), reviewed ? (s(b.reviewedDate) || now.slice(0, 10)) : (s(b.reviewedDate) || null),
    s(b.validUntil) || null, user.id ?? null, s(user.name).slice(0, 120), now, tenant);
  return { id: rid };
}

/** Update a review's status/outcome/comments (e.g. requested → approved). */
export function updateReview(reviewId: number, tenant: number | null, b: any, user: { id?: number | null; name?: string }): { ok: boolean } {
  const db = getDb("XORCISM");
  if (!has(db, "LEGALREVIEW")) return { ok: false };
  const cur = db.prepare(`SELECT * FROM LEGALREVIEW WHERE ReviewID=? AND ${tw(tenant)}`).get(reviewId, ...ta(tenant)) as any;
  if (!cur) return { ok: false };
  const status = STATUSES.includes(s(b.status)) ? s(b.status) : cur.Status;
  const reviewedDate = (APPROVED.has(status) || status === "rejected") ? (s(b.reviewedDate) || cur.ReviewedDate || new Date().toISOString().slice(0, 10)) : (b.reviewedDate !== undefined ? s(b.reviewedDate) || null : cur.ReviewedDate);
  const set = {
    Status: status,
    Comments: b.comments !== undefined ? s(b.comments).slice(0, 4000) : cur.Comments,
    LegalBasis: b.legalBasis !== undefined ? s(b.legalBasis).slice(0, 600) : cur.LegalBasis,
    Jurisdiction: b.jurisdiction !== undefined ? s(b.jurisdiction).slice(0, 200) : cur.Jurisdiction,
    VersionReviewed: b.versionReviewed !== undefined ? s(b.versionReviewed).slice(0, 40) : cur.VersionReviewed,
    ReviewerName: b.reviewerName !== undefined ? s(b.reviewerName).slice(0, 160) : cur.ReviewerName,
    ValidUntil: b.validUntil !== undefined ? (s(b.validUntil) || null) : cur.ValidUntil,
    ReviewedDate: reviewedDate,
  };
  db.prepare(`UPDATE LEGALREVIEW SET Status=?, Comments=?, LegalBasis=?, Jurisdiction=?, VersionReviewed=?, ReviewerName=?, ValidUntil=?, ReviewedDate=? WHERE ReviewID=?`)
    .run(set.Status, set.Comments, set.LegalBasis, set.Jurisdiction, set.VersionReviewed, set.ReviewerName, set.ValidUntil, set.ReviewedDate, reviewId);
  return { ok: true };
}

export function removeReview(reviewId: number, tenant: number | null): { ok: boolean } {
  const db = getDb("XORCISM");
  if (!has(db, "LEGALREVIEW")) return { ok: false };
  const r = db.prepare(`DELETE FROM LEGALREVIEW WHERE ReviewID=? AND ${tw(tenant)}`).run(reviewId, ...ta(tenant));
  return { ok: r.changes > 0 };
}

/**
 * Per-target legal-clearance rollup for the whole estate, keyed "type:id". One query; used by
 * policyInventory to badge each policy/document and to compute the legal-clearance KPIs.
 */
export function legalRollup(tenant: number | null): { map: Map<string, any>; kpi: any } {
  const map = new Map<string, any>();
  const db = getDb("XORCISM");
  const kpi = { reviewed: 0, cleared: 0, pendingLegal: 0, pendingValidation: 0, rejected: 0, overdue: 0 };
  if (!has(db, "LEGALREVIEW")) return { map, kpi };
  const byTarget = new Map<string, any[]>();
  for (const r of db.prepare(`SELECT ReviewID, TargetType, TargetID, ReviewType, Status, ValidUntil FROM LEGALREVIEW WHERE ${tw(tenant)} ORDER BY ReviewID DESC`).all(...ta(tenant)) as any[]) {
    const k = `${r.TargetType}:${r.TargetID}`;
    (byTarget.get(k) || byTarget.set(k, []).get(k)!).push({ reviewType: r.ReviewType, status: r.Status, validUntil: r.ValidUntil });
  }
  for (const [k, items] of byTarget) {
    const roll = rollupFromItems(items);
    map.set(k, roll);
    kpi.reviewed++;
    if (roll.legallyCleared) kpi.cleared++;
    if (roll.reviewOverdue) kpi.overdue++;
    if (roll.legalStatus === "rejected" || roll.validationStatus === "rejected") kpi.rejected++;
    if (!roll.legalStatus || !APPROVED.has(roll.legalStatus)) { if (roll.legalStatus !== "rejected") kpi.pendingLegal++; }
    if (!roll.validationStatus || !APPROVED.has(roll.validationStatus)) { if (roll.validationStatus !== "rejected") kpi.pendingValidation++; }
  }
  return { map, kpi };
}
