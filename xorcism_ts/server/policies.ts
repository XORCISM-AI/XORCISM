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
import { getDb } from "./db";

export interface PolicyRow {
  id: number;
  name: string;
  reference: string;
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
  score: number;                 // 0-100 (higher = worse)
  issues: string[];
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
    byStatus: Record<string, number>; byFramework: Record<string, number>;
    byCategory: Record<string, number>; byLanguage: Record<string, number>;
  };
}

const EMPTY: PolicyInventory = {
  rows: [], documents: [], findings: [],
  summary: {
    policies: 0, published: 0, draft: 0, inReview: 0, approved: 0, retired: 0,
    overdueReview: 0, dueSoon: 0, noOwner: 0, noVersion: 0, notEffective: 0,
    documents: 0, expiredDocs: 0, docsNoOwner: 0, frameworks: 0, languages: 0, avgScore: 0,
    byStatus: {}, byFramework: {}, byCategory: {}, byLanguage: {},
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
    }

    return {
      id, name, reference: norm(p.PolicyReference) || "—",
      category: norm(p.Category) || "—", framework: norm(p.Framework) || "—",
      language: (norm(p.Language) || "—").toLowerCase(), status, version: version || "—",
      owner, effectiveDate, reviewDate, reviewInDays, published, retired, score, issues,
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
        documents.push({
          id, name, type: norm(d.DocumentType) || "—", category: norm(d.Category) || "—",
          status: norm(d.Status) || "—", version: norm(d.Version) || "—", classification, tlp,
          language: (norm(d.Language) || "—").toLowerCase(), owner, reviewDate, validUntil, expired, issues,
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
  for (const r of rows) {
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    if (r.framework !== "—") byFramework[r.framework] = (byFramework[r.framework] || 0) + 1;
    if (r.category !== "—") byCategory[r.category] = (byCategory[r.category] || 0) + 1;
    if (r.language !== "—") byLanguage[r.language] = (byLanguage[r.language] || 0) + 1;
  }
  const active = rows.filter((r) => !r.retired);
  const avgScore = active.length ? Math.round(active.reduce((s, r) => s + r.score, 0) / active.length) : 0;

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
      byStatus, byFramework, byCategory, byLanguage,
    },
  };
}
