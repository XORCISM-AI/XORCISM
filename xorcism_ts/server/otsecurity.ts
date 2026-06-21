/**
 * otsecurity.ts — OT / ICS / SCADA / IoT Security Management (IEC 62443 & NIST SP 800-82).
 *
 * The OT counterpart of compliance.ts: one pane over the OT security programme. OT assessments
 * REUSE XCOMPLIANCE.AUDIT (AuditType='OT Security', AuditCategory = the standard) + AUDITFINDING —
 * the same shape as Compliance / Crisis Management. On top it surfaces what's OT-specific:
 *   • OT assets — XORCISM.ASSET tagged ot/ics/scada/iot/plc/hmi/dcs/rtu via ASSETTAG (see cvematch),
 *   • IEC 62443 zones & conduits with Security Levels (OTZONE / OTCONDUIT, phased),
 *   • the seeded IEC 62443-3-3 / NIST SP 800-82 requirement catalogues (FRAMEWORK / REFERENCECONTROL).
 * Read-only inventory + a guided createOtAssessment; CRUD stays in the schema-driven explorer.
 */
import { getDb } from "./db";
import { createAudit } from "./compliance";

// An audit is "OT" if its type is OT/ICS… or its category names an OT standard.
const OT_TYPE = /\b(ot|ics|scada|iot|62443|800-82)\b/i;
const OT_STD = /(iec\s*62443|62443|nist\s*sp\s*800-?82|800-82)/i;
// ASSET tags that mark an OT/ICS/SCADA/IoT asset (matched case-insensitively against ASSETTAG.Tag).
const OT_ASSET_TAGS = ["ot", "ics", "scada", "iot", "plc", "hmi", "dcs", "rtu", "iiot", "modbus", "purdue"];
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_WEIGHT: Record<string, number> = { critical: 25, high: 18, medium: 8, low: 3, info: 1 };
const CLOSED = /closed|clos[eé]|resolv|remediat|done|accepted|fixed|fermé/i;
const HIGH = /high|critical/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(dbName: string, table: string): boolean {
  try { return !!getDb(dbName).prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const normSev = (s: string): "Critical" | "High" | "Medium" | "Low" | "Info" => {
  const v = String(s || "").toLowerCase();
  return v.includes("crit") ? "Critical" : v.includes("high") ? "High" : v.includes("med") ? "Medium" : v.includes("info") ? "Info" : "Low";
};

export interface OtInventory {
  assessments: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  otAssets: Record<string, unknown>[];
  zones: Record<string, unknown>[];
  summary: Record<string, unknown>;
}

const EMPTY: OtInventory = {
  assessments: [], findings: [], otAssets: [], zones: [],
  summary: { assessments: 0, openFindings: 0, highOpen: 0, overdue: 0, otAssets: 0, zones: 0, conduits: 0, slGaps: 0, catalogue: { total: 0 } },
};

export function otSecurityInventory(tenant: number | null): OtInventory {
  const cc = getDb("XCOMPLIANCE");
  if (!has("XCOMPLIANCE", "AUDIT")) return { ...EMPTY };
  const ac = cols("XCOMPLIANCE", "AUDIT");
  const tw = tenant != null && ac.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const allAudits = cc.prepare(`SELECT * FROM AUDIT ${tw}`).all() as Record<string, any>[];
  // Keep only the OT assessments (type OT/ICS… or an OT standard category).
  const audits = allAudits.filter((a) =>
    OT_TYPE.test(String(a.AuditType ?? "")) || OT_STD.test(String(a.AuditCategory ?? "")) || OT_STD.test(String(a.AuditName ?? "")));
  const auditName = new Map<number, string>();
  for (const a of audits) auditName.set(Number(a.AuditID), String(a.AuditName ?? "").trim() || `Assessment #${a.AuditID}`);

  // Findings for these OT assessments (AUDITFINDING scoped via AuditID).
  const fc = cols("XCOMPLIANCE", "AUDITFINDING");
  const findingsByAudit = new Map<number, { open: number; high: number; overdue: number; total: number }>();
  const worklist: Record<string, unknown>[] = [];
  if (fc.size && auditName.size) {
    const ids = [...auditName.keys()];
    const ph = ids.map(() => "?").join(",");
    for (const f of cc.prepare(`SELECT * FROM AUDITFINDING WHERE AuditID IN (${ph})`).all(...ids) as Record<string, any>[]) {
      const aid = Number(f.AuditID);
      const agg = findingsByAudit.get(aid) ?? { open: 0, high: 0, overdue: 0, total: 0 };
      agg.total++;
      const open = !CLOSED.test(`${f.FindingStatus ?? ""} ${f.WorkflowStatus ?? ""}`);
      const sev = normSev(String(f.Severity ?? f.FindingCriticity ?? ""));
      const dueIn = daysUntil(f.DueDate ? String(f.DueDate) : null);
      const overdue = open && dueIn != null && dueIn < 0;
      if (open) {
        agg.open++; if (HIGH.test(sev)) agg.high++; if (overdue) agg.overdue++;
        const name = String(f.FindingName ?? "").trim() || `Finding #${f.AuditFindingID}`;
        worklist.push({ id: Number(f.AuditFindingID), assessment: auditName.get(aid) || `#${aid}`, name, severity: sev, overdue });
      }
      findingsByAudit.set(aid, agg);
    }
  }

  const assessments = audits.map((a) => {
    const id = Number(a.AuditID);
    const agg = findingsByAudit.get(id) ?? { open: 0, high: 0, overdue: 0, total: 0 };
    const status = String(a.AuditStatus ?? "").trim() || "Planned";
    let score = agg.overdue * 10;
    for (const w of worklist) if (w.assessment === auditName.get(id)) score += SEV_WEIGHT[String(w.severity).toLowerCase()] ?? 3;
    return {
      id, name: auditName.get(id)!, standard: String(a.AuditCategory ?? "").trim() || String(a.AuditType ?? "").trim() || "—",
      status, date: a.AuditDate ? String(a.AuditDate).slice(0, 10) : null,
      findings: agg.total, open: agg.open, high: agg.high, overdue: agg.overdue, score: Math.min(100, score),
    };
  });
  assessments.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  worklist.sort((a, b) => (SEV_RANK[String(a.severity).toLowerCase()] - SEV_RANK[String(b.severity).toLowerCase()]));

  // OT assets — XORCISM.ASSET tagged ot/ics/scada/iot… via ASSETTAG.
  const otAssets: Record<string, unknown>[] = [];
  const byTag: Record<string, number> = {};
  let otAssetCount = 0;
  try {
    const xo = getDb("XORCISM");
    if (has("XORCISM", "ASSETTAG") && has("XORCISM", "ASSET")) {
      const tagPh = OT_ASSET_TAGS.map(() => "?").join(",");
      const atw = tenant != null && cols("XORCISM", "ASSET").has("TenantID") ? `AND (a.TenantID = ${tenant} OR a.TenantID IS NULL)` : "";
      const rows = xo.prepare(
        `SELECT a.AssetID id, a.AssetName name, a.AssetCriticalityLevel crit,
                GROUP_CONCAT(DISTINCT LOWER(t.Tag)) tags
         FROM ASSET a JOIN ASSETTAG t ON t.AssetID = a.AssetID
         WHERE LOWER(t.Tag) IN (${tagPh}) ${atw}
         GROUP BY a.AssetID ORDER BY a.AssetName`
      ).all(...OT_ASSET_TAGS) as { id: number; name: string; crit: string; tags: string }[];
      otAssetCount = rows.length;
      for (const r of rows) {
        const tags = (r.tags || "").split(",").filter((x) => OT_ASSET_TAGS.includes(x));
        for (const tg of tags) byTag[tg] = (byTag[tg] || 0) + 1;
        if (otAssets.length < 100) otAssets.push({ id: r.id, name: r.name || `#${r.id}`, criticality: r.crit || "", tags });
      }
    }
  } catch { /* ASSET/ASSETTAG absent */ }

  // IEC 62443 zones & conduits (phased).
  let zones: Record<string, unknown>[] = []; let conduits = 0; let slGaps = 0;
  if (has("XCOMPLIANCE", "OTZONE")) {
    const ztw = tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    zones = cc.prepare(`SELECT ZoneID id, Name name, PurdueLevel purdue, SecurityLevelTarget slt, SecurityLevelAchieved sla, Criticality criticality FROM OTZONE ${ztw} ORDER BY ZoneID`).all() as Record<string, any>[];
    for (const z of zones) if (z.slt != null && (z.sla == null || Number(z.sla) < Number(z.slt))) slGaps++;
  }
  if (has("XCOMPLIANCE", "OTCONDUIT")) {
    const ctw = tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    conduits = (cc.prepare(`SELECT COUNT(*) c FROM OTCONDUIT ${ctw}`).get() as { c: number }).c;
  }

  // Seeded requirement catalogues (REFERENCECONTROL by Provider).
  const catalogue: Record<string, number> = { iec62443: 0, nist80082: 0, total: 0 };
  if (has("XCOMPLIANCE", "REFERENCECONTROL")) {
    try {
      catalogue.iec62443 = (cc.prepare("SELECT COUNT(*) c FROM REFERENCECONTROL WHERE Provider LIKE 'IEC 62443%'").get() as { c: number }).c;
      catalogue.nist80082 = (cc.prepare("SELECT COUNT(*) c FROM REFERENCECONTROL WHERE Provider LIKE 'NIST SP 800-82%'").get() as { c: number }).c;
      catalogue.total = catalogue.iec62443 + catalogue.nist80082;
    } catch { /* ignore */ }
  }

  const bySeverity: Record<string, number> = {};
  for (const w of worklist) bySeverity[String(w.severity)] = (bySeverity[String(w.severity)] || 0) + 1;
  const byStandard: Record<string, number> = {};
  for (const a of assessments) byStandard[a.standard] = (byStandard[a.standard] || 0) + 1;

  return {
    assessments, findings: worklist, otAssets, zones,
    summary: {
      assessments: assessments.length,
      inProgress: assessments.filter((a) => /progress|cours|field/i.test(a.status)).length,
      completed: assessments.filter((a) => /complet|clos|done/i.test(a.status)).length,
      openFindings: worklist.length,
      highOpen: worklist.filter((w) => HIGH.test(String(w.severity))).length,
      overdue: worklist.filter((w) => w.overdue).length,
      otAssets: otAssetCount, byTag,
      zones: zones.length, conduits, slGaps,
      catalogue, bySeverity, byStandard,
    },
  };
}

/**
 * Create an OT security assessment — a guided wrapper over createAudit that stamps AuditType
 * 'OT Security' and the chosen IEC 62443 / NIST SP 800-82 standard as the category, so it surfaces
 * on the OT dashboard (and stays out of the generic Compliance one).
 */
export function createOtAssessment(
  p: { name: string; standard?: string; status?: string; auditor?: string; scope?: string; description?: string; date?: string },
  tenant: number | null,
): { id: number } {
  return createAudit({
    name: p.name, type: "OT Security", category: p.standard || "IEC 62443-3-3",
    status: p.status, auditor: p.auditor, scope: p.scope, description: p.description, date: p.date,
  }, tenant);
}
