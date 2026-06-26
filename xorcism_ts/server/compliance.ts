/**
 * compliance.ts — Compliance / GRC inventory + governance worklist.
 *
 * The audit/findings counterpart of assets.ts / incidents.ts: one pane over the
 * compliance programme — audits (XCOMPLIANCE.AUDIT) with their findings posture, the
 * open-findings worklist (high-severity, overdue remediation, unassigned, no plan), and
 * policy lifecycle (XORCISM.POLICY past its review date). Audits get a 0-100 posture
 * score from their open findings. Read-only; CRUD stays in the schema-driven explorer.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { remediationCounts } from "./findingremediation";

export interface AuditRow {
  id: number;
  name: string;
  type: string;
  assessmentType: string;   // Design / Documentation / Operating Effectiveness / Combined / Readiness
  status: string;
  date: string | null;
  completed: boolean;
  findings: number;
  open: number;
  high: number;
  overdue: number;
  unassigned: number;
  score: number;          // 0-100 posture (higher = worse)
}
export interface ComplianceFinding {
  id: number;
  audit: string;
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  overdue: boolean;
  unassigned: boolean;
  noPlan: boolean;
  kind: "finding" | "policy";
  label: string;
  plans?: number;
  openPlans?: number;
}
export interface ComplianceInventory {
  rows: AuditRow[];
  findings: ComplianceFinding[];
  summary: {
    audits: number; inProgress: number; planned: number; completed: number; completionRate: number | null;
    findings: number; openFindings: number; highOpen: number; overdue: number; unassigned: number;
    policiesReview: number;
    designAssessments: number; documentationAssessments: number;
    bySeverity: Record<string, number>; byStatus: Record<string, number>; byType: Record<string, number>; byAssessmentType: Record<string, number>;
  };
}

const EMPTY: ComplianceInventory = {
  rows: [], findings: [],
  summary: { audits: 0, inProgress: 0, planned: 0, completed: 0, completionRate: null, findings: 0, openFindings: 0, highOpen: 0, overdue: 0, unassigned: 0, policiesReview: 0, designAssessments: 0, documentationAssessments: 0, bySeverity: {}, byStatus: {}, byType: {}, byAssessmentType: {} },
};

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_WEIGHT: Record<string, number> = { critical: 25, high: 18, medium: 8, low: 3, info: 1 };
const CLOSED = /closed|clos[eé]|resolv|remediat|done|accepted|accept[eé]|fixed|terminé|fermé/i;
const HIGH = /high|critical/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const normSev = (s: string): ComplianceFinding["severity"] => {
  const v = String(s || "").toLowerCase();
  return v.includes("crit") ? "Critical" : v.includes("high") ? "High" : v.includes("med") ? "Medium" : v.includes("info") ? "Info" : "Low";
};

/** Full compliance inventory (audits) + open-findings/policy worklist. */
export function complianceInventory(tenant: number | null): ComplianceInventory {
  const cc = getDb("XCOMPLIANCE");
  if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='AUDIT'").get()) return { ...EMPTY };
  const ac = cols("XCOMPLIANCE", "AUDIT");
  const tw = tenant != null && ac.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const audits = cc.prepare(`SELECT * FROM AUDIT ${tw}`).all() as Record<string, unknown>[];
  if (!audits.length) return { ...EMPTY };
  const auditName = new Map<number, string>();
  for (const a of audits) auditName.set(Number(a.AuditID), String(a.AuditName ?? "").trim() || `Audit #${a.AuditID}`);

  // Findings for these audits (AUDITFINDING has no TenantID — scope via AuditID).
  const fc = cols("XCOMPLIANCE", "AUDITFINDING");
  const findingsByAudit = new Map<number, { open: number; high: number; overdue: number; unassigned: number; total: number }>();
  const worklist: ComplianceFinding[] = [];
  if (fc.size) {
    const ids = [...auditName.keys()];
    const ph = ids.map(() => "?").join(",") || "NULL";
    const all = cc.prepare(`SELECT * FROM AUDITFINDING WHERE AuditID IN (${ph})`).all(...ids) as Record<string, unknown>[];
    for (const f of all) {
      const aid = Number(f.AuditID);
      const agg = findingsByAudit.get(aid) ?? { open: 0, high: 0, overdue: 0, unassigned: 0, total: 0 };
      agg.total++;
      const statusTxt = `${f.FindingStatus ?? ""} ${f.WorkflowStatus ?? ""}`;
      const open = !CLOSED.test(statusTxt);
      const sev = normSev(String(f.Severity ?? f.FindingCriticity ?? ""));
      const dueIn = daysUntil(f.DueDate ? String(f.DueDate) : null);
      const overdue = open && dueIn != null && dueIn < 0;
      const unassigned = open && (f.RemediationOwnerPersonID == null);
      const noPlan = open && !String(f.RemediationPlan ?? "").trim();
      if (open) {
        agg.open++;
        if (HIGH.test(sev)) agg.high++;
        if (overdue) agg.overdue++;
        if (unassigned) agg.unassigned++;
        const name = String(f.FindingName ?? "").trim() || `Finding #${f.AuditFindingID}`;
        const tags = [overdue ? "overdue" : "", unassigned ? "unassigned" : "", noPlan ? "no plan" : ""].filter(Boolean);
        worklist.push({
          id: Number(f.AuditFindingID), audit: auditName.get(aid) || `#${aid}`, name, severity: sev,
          overdue, unassigned, noPlan, kind: "finding",
          label: `${name}${tags.length ? ` (${tags.join(", ")})` : ""}`,
        });
      }
      findingsByAudit.set(aid, agg);
    }
  }

  // Policies past their review date (XORCISM.POLICY lifecycle), tenant-scoped if possible.
  let policiesReview = 0;
  try {
    const xo = getDb("XORCISM");
    const pc = cols("XORCISM", "POLICY");
    if (pc.has("ReviewDate")) {
      const ptw = tenant != null && pc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
      for (const p of xo.prepare(`SELECT PolicyName, ReviewDate, Status FROM POLICY ${ptw}`).all() as { PolicyName: string; ReviewDate: string; Status: string }[]) {
        const due = daysUntil(p.ReviewDate);
        if (due != null && due < 0) {
          policiesReview++;
          worklist.push({ id: 0, audit: "Policy", name: String(p.PolicyName || "policy"), severity: "Medium", overdue: true, unassigned: false, noPlan: false, kind: "policy", label: `Policy past review: ${p.PolicyName} (${-due}d)` });
        }
      }
    }
  } catch { /* POLICY absent */ }

  const rows: AuditRow[] = audits.map((a) => {
    const id = Number(a.AuditID);
    const agg = findingsByAudit.get(id) ?? { open: 0, high: 0, overdue: 0, unassigned: 0, total: 0 };
    const status = String(a.AuditStatus ?? "").trim() || "Planned";
    const completed = /complet|clos|done|terminé|fermé/i.test(status) || !!a.AuditClosureDate;
    // posture score from open findings (severity-weighted) + overdue/unassigned penalties.
    let score = agg.overdue * 10 + agg.unassigned * 3;
    // weight open findings by their severities — recompute from worklist for this audit
    for (const w of worklist) if (w.kind === "finding" && w.audit === auditName.get(id)) score += SEV_WEIGHT[w.severity.toLowerCase()] ?? 3;
    return {
      id, name: auditName.get(id)!, type: String(a.AuditType ?? "").trim() || "—", status,
      assessmentType: String(a.AssessmentType ?? "").trim() || "Operating Effectiveness",
      date: a.AuditDate ? String(a.AuditDate).slice(0, 10) : null, completed,
      findings: agg.total, open: agg.open, high: agg.high, overdue: agg.overdue, unassigned: agg.unassigned,
      score: Math.min(100, score),
    };
  });

  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  worklist.sort((a, b) => (SEV_RANK[a.severity.toLowerCase()] - SEV_RANK[b.severity.toLowerCase()]) || (a.overdue === b.overdue ? 0 : a.overdue ? -1 : 1) || a.audit.localeCompare(b.audit));

  // attach the remediation-plan counts to each finding (for the worklist "Plans" action)
  const planCounts = remediationCounts(worklist.filter((w) => w.kind === "finding").map((w) => w.id), tenant);
  for (const w of worklist) if (w.kind === "finding") { const c = planCounts.get(w.id); w.plans = c?.plans ?? 0; w.openPlans = c?.open ?? 0; }

  const bySeverity: Record<string, number> = {};
  for (const w of worklist) if (w.kind === "finding") bySeverity[w.severity] = (bySeverity[w.severity] || 0) + 1;
  const byStatus: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const byAssessmentType: Record<string, number> = {};
  for (const r of rows) { byStatus[r.status] = (byStatus[r.status] || 0) + 1; byType[r.type] = (byType[r.type] || 0) + 1; byAssessmentType[r.assessmentType] = (byAssessmentType[r.assessmentType] || 0) + 1; }
  const completed = rows.filter((r) => r.completed).length;

  return {
    rows, findings: worklist,
    summary: {
      audits: rows.length,
      inProgress: rows.filter((r) => /progress|cours/i.test(r.status)).length,
      planned: rows.filter((r) => /plan/i.test(r.status)).length,
      completed,
      completionRate: rows.length ? Math.round((completed / rows.length) * 100) : null,
      findings: [...findingsByAudit.values()].reduce((s, a) => s + a.total, 0),
      openFindings: worklist.filter((w) => w.kind === "finding").length,
      highOpen: worklist.filter((w) => w.kind === "finding" && HIGH.test(w.severity)).length,
      overdue: worklist.filter((w) => w.overdue && w.kind === "finding").length,
      unassigned: worklist.filter((w) => w.unassigned).length,
      policiesReview,
      designAssessments: byAssessmentType["Design Assessment"] || 0,
      documentationAssessments: byAssessmentType["Documentation Assessment"] || 0,
      bySeverity, byStatus, byType, byAssessmentType,
    },
  };
}

/**
 * Create an AUDIT from a guided form — the friendly path that replaces the raw explorer insert.
 * AUDIT is the shared GRC engagement record (compliance audit, internal/external, pentest,
 * vendor assessment, tabletop exercise, certification…); Type/Category drive how it's used by the
 * other modules. Column-aware INSERT + GUID + tenant. AuditID is a real INTEGER PRIMARY KEY.
 */
export function createAudit(
  p: { name: string; type?: string; category?: string; status?: string; auditor?: string;
       scope?: string; description?: string; date?: string; closureDate?: string; assessmentType?: string },
  tenant: number | null,
): { id: number } {
  const db = getDb("XCOMPLIANCE");
  const ac = cols("XCOMPLIANCE", "AUDIT");
  if (!ac.size) throw new Error("AUDIT table not available");
  const now = new Date().toISOString();
  const candidate: Record<string, unknown> = {
    AuditGUID: randomUUID(),
    AuditName: (p.name || "Untitled audit").slice(0, 300),
    AuditType: p.type ? String(p.type).slice(0, 80) : null,
    AssessmentType: p.assessmentType ? String(p.assessmentType).slice(0, 80) : "Operating Effectiveness",
    AuditCategory: p.category ? String(p.category).slice(0, 120) : null,
    AuditStatus: (p.status || "Planned").slice(0, 60),
    AuditorName: p.auditor ? String(p.auditor).slice(0, 200) : null,
    AuditScope: p.scope ? String(p.scope).slice(0, 2000) : null,
    AuditDescription: p.description ? String(p.description).slice(0, 4000) : null,
    AuditDate: p.date || now.slice(0, 10),
    AuditClosureDate: p.closureDate || null,
    CreatedDate: now,
    TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => ac.has(k));
  const sql = `INSERT INTO AUDIT (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`;
  const r = db.prepare(sql).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}
