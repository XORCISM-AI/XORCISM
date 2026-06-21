/**
 * patchmgmt.ts — Patch Management.
 *
 * The remediation counterpart of assets.ts: one pane over the patch lifecycle of every
 * asset↔vulnerability instance (XORCISM.ASSETVULNERABILITY ⋈ ASSET ⋈ XVULNERABILITY.VULNERABILITY,
 * cross-DB). Reuses the existing model — patch status on ASSETVULNERABILITY (PatchStatus /
 * PatchedDate / TargetDate, added by ensurePatchTables) and remediation plans on the legacy
 * ASSETVULNERABILITYREMEDIATION. Derives risk-based patch SLAs (KEV / CVSS), the overdue worklist,
 * patch-coverage %, mean-time-to-remediate (MTTR) and unpatched-KEV exposure. Read inventory +
 * two write actions (mark patched / create a remediation plan).
 */
import { getDb } from "./db";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
// Risk-based patch SLA (days from discovery) — KEV uses CISA's due date when present, else 14d.
const SLA_DAYS: Record<string, number> = { kev: 14, critical: 15, high: 30, medium: 90, low: 180, info: 180 };
export const PATCH_STATUSES = ["Unpatched", "In progress", "Patched", "Mitigated", "No patch available", "Accepted risk", "Not applicable"];
// \bpatched\b so "Patched" resolves but "Unpatched" does NOT (the substring trap).
const RESOLVED = /\bpatched\b|mitigat|accepted|not applicable|resolved|closed/i;
const DONE = /\bpatched\b|mitigat/i; // counts as "patched" for coverage/MTTR

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1 || String(v ?? "").toLowerCase() === "true"; }
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
function daysBetween(a: string | null, b: string | null): number | null {
  if (!a || !b) return null;
  const ta = Date.parse(String(a)), tb = Date.parse(String(b));
  return Number.isNaN(ta) || Number.isNaN(tb) ? null : Math.round((tb - ta) / 86_400_000);
}
const sevOf = (cvss: number | null, kev: boolean): "Critical" | "High" | "Medium" | "Low" | "Info" => {
  if (cvss != null) return cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : cvss > 0 ? "Low" : "Info";
  return kev ? "High" : "Info";
};
const addDays = (iso: string | null, n: number): string | null => {
  if (!iso) return null; const t = Date.parse(String(iso)); if (Number.isNaN(t)) return null;
  return new Date(t + n * 86_400_000).toISOString().slice(0, 10);
};

export interface PatchInventory { rows: Record<string, unknown>[]; worklist: Record<string, unknown>[]; summary: Record<string, unknown>; }

export function patchInventory(tenant: number | null): PatchInventory {
  const xo = getDb("XORCISM");
  const empty: PatchInventory = { rows: [], worklist: [], summary: { instances: 0, patched: 0, unpatched: 0, coverage: null, mttr: null, kevUnpatched: 0, overdue: 0, noPatch: 0, withPlan: 0, bySeverity: {}, byStatus: {} } };
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITY'").get()) return empty;
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  const fp = avc.has("FalsePositive") ? "AND (FalsePositive IS NULL OR FalsePositive = 0)" : "";
  const tw = tenant != null && avc.has("TenantID") ? `AND (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const sel = (c: string, d = "NULL"): string => (avc.has(c) ? c : `${d} AS ${c}`);
  const links = xo.prepare(
    `SELECT AssetVulnerabilityID, AssetID, VulnerabilityID, ${sel("PatchStatus")}, ${sel("PatchedDate")}, ${sel("TargetDate")},
            ${sel("RemediationOwnerPersonID")}, ${sel("Priority")}, ${sel("Status")}, CreatedDate
     FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${fp} ${tw}`
  ).all() as Record<string, any>[];
  if (!links.length) return empty;

  // Asset names.
  const assetName = new Map<number, { name: string; crit: string }>();
  for (const a of xo.prepare("SELECT AssetID, AssetName, AssetCriticalityLevel FROM ASSET").all() as { AssetID: number; AssetName: string; AssetCriticalityLevel: string }[])
    assetName.set(a.AssetID, { name: a.AssetName || `#${a.AssetID}`, crit: a.AssetCriticalityLevel || "" });

  // Cross-DB VULNERABILITY enrichment (chunked).
  const vuln = new Map<number, { cve: string; cvss: number | null; kev: boolean; epss: number | null; patchAvail: boolean; due: string | null; name: string }>();
  const vids = [...new Set(links.map((l) => Number(l.VulnerabilityID)))];
  const vc = cols("XVULNERABILITY", "VULNERABILITY");
  if (vids.length && vc.size) {
    const xv = getDb("XVULNERABILITY");
    const g = (c: string, d = "NULL"): string => (vc.has(c) ? c : `${d} AS ${c}`);
    for (let i = 0; i < vids.length; i += 400) {
      const chunk = vids.slice(i, i + 400); const ph = chunk.map(() => "?").join(",");
      for (const r of xv.prepare(
        `SELECT VulnerabilityID, ${g("VULReferentialID")}, ${g("CVSSBaseScore")}, ${g("KEV")}, ${g("EPSS")},
                ${g("VULPatchAvailable")}, ${g("DueDate")}, ${g("VULName")} FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`
      ).all(...chunk) as Record<string, any>[]) {
        vuln.set(Number(r.VulnerabilityID), {
          cve: String(r.VULReferentialID ?? "").trim() || `VULN#${r.VulnerabilityID}`,
          cvss: r.CVSSBaseScore != null && r.CVSSBaseScore !== "" ? Number(r.CVSSBaseScore) : null,
          kev: truthy(r.KEV), epss: r.EPSS != null && r.EPSS !== "" ? Number(r.EPSS) : null,
          patchAvail: truthy(r.VULPatchAvailable), due: r.DueDate ? String(r.DueDate).slice(0, 10) : null,
          name: String(r.VULName ?? "").trim(),
        });
      }
    }
  }

  // Remediation plans per asset-vuln.
  const planBy = new Map<number, { name: string; status: string; type: string; target: string | null }>();
  if (xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITYREMEDIATION'").get()) {
    const rc = cols("XORCISM", "ASSETVULNERABILITYREMEDIATION");
    const rg = (c: string): string => (rc.has(c) ? c : `NULL AS ${c}`);
    for (const r of xo.prepare(`SELECT AssetVulnerabilityID, RemediationName, ${rg("Status")}, ${rg("RemediationType")}, ${rg("TargetDate")} FROM ASSETVULNERABILITYREMEDIATION`).all() as Record<string, any>[])
      planBy.set(Number(r.AssetVulnerabilityID), { name: String(r.RemediationName ?? ""), status: String(r.Status ?? ""), type: String(r.RemediationType ?? ""), target: r.TargetDate ? String(r.TargetDate).slice(0, 10) : null });
  }

  const rows = links.map((l) => {
    const v = vuln.get(Number(l.VulnerabilityID));
    const kev = v?.kev ?? false;
    const cvss = v?.cvss ?? null;
    const severity = sevOf(cvss, kev);
    const plan = planBy.get(Number(l.AssetVulnerabilityID));
    // Default unset status to "Unpatched" (VULPatchAvailable is usually unknown/null — an analyst
    // marks "No patch available" explicitly; we don't infer it from a missing flag).
    let patchStatus = String(l.PatchStatus ?? "").trim() || "Unpatched";
    const resolved = RESOLVED.test(patchStatus);
    // effective SLA due date: CISA/KEV due, else target, else discovery + risk-based SLA.
    const slaDays = kev ? SLA_DAYS.kev : SLA_DAYS[severity.toLowerCase()] ?? 90;
    const due = v?.due || (l.TargetDate ? String(l.TargetDate).slice(0, 10) : null) || addDays(l.CreatedDate ? String(l.CreatedDate) : null, slaDays);
    const dueIn = daysUntil(due);
    const overdue = !resolved && dueIn != null && dueIn < 0;
    const a = assetName.get(Number(l.AssetID));
    let score = (kev ? 50 : 0) + (SEV_RANK[severity.toLowerCase()] != null ? (4 - SEV_RANK[severity.toLowerCase()]) * 8 : 0)
      + (v?.epss != null ? Math.round(v.epss * 20) : 0) + (overdue ? 15 : 0) + (v?.patchAvail && !resolved ? 10 : 0);
    if (resolved) score = 0;
    return {
      id: Number(l.AssetVulnerabilityID), assetId: Number(l.AssetID), asset: a?.name ?? `#${l.AssetID}`, criticality: a?.crit ?? "",
      cve: v?.cve ?? `VULN#${l.VulnerabilityID}`, vulnerabilityId: Number(l.VulnerabilityID), name: v?.name ?? "",
      severity, cvss, kev, epss: v?.epss ?? null, patchAvailable: v?.patchAvail ?? false,
      patchStatus, resolved, patchedDate: l.PatchedDate ? String(l.PatchedDate).slice(0, 10) : null,
      due, dueIn, overdue, hasPlan: !!plan, planStatus: plan?.status ?? "", planType: plan?.type ?? "",
      score: Math.min(100, score),
    };
  });

  rows.sort((a, b) => b.score - a.score || (a.dueIn ?? 1e9) - (b.dueIn ?? 1e9));
  const open = rows.filter((r) => !r.resolved);

  // KPIs.
  const patched = rows.filter((r) => DONE.test(r.patchStatus));
  const noPatch = rows.filter((r) => /no patch/i.test(r.patchStatus)).length;
  const accepted = rows.filter((r) => /accepted|not applicable/i.test(r.patchStatus)).length;
  const remediable = rows.length - noPatch - accepted;
  const mttrVals = patched.map((r) => {
    const link = links.find((l) => Number(l.AssetVulnerabilityID) === r.id);
    return daysBetween(link?.CreatedDate ? String(link.CreatedDate) : null, r.patchedDate);
  }).filter((n): n is number => n != null && n >= 0);
  const bySeverity: Record<string, number> = {}; const byStatus: Record<string, number> = {};
  for (const r of rows) { byStatus[r.patchStatus] = (byStatus[r.patchStatus] || 0) + 1; if (!r.resolved) bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1; }

  return {
    rows, worklist: open.slice(0, 200),
    summary: {
      instances: rows.length,
      patched: patched.length,
      unpatched: open.length,
      noPatch, accepted,
      coverage: remediable > 0 ? Math.round((patched.length / remediable) * 100) : null,
      mttr: mttrVals.length ? Math.round(mttrVals.reduce((s, n) => s + n, 0) / mttrVals.length) : null,
      kevUnpatched: open.filter((r) => r.kev).length,
      overdue: rows.filter((r) => r.overdue).length,
      withPlan: rows.filter((r) => r.hasPlan).length,
      bySeverity, byStatus,
    },
  };
}

/** Update the patch status of one asset↔vulnerability instance (sets PatchedDate when 'Patched'). */
export function updatePatchStatus(assetVulnId: number, status: string, tenant: number | null): { ok: boolean } {
  const xo = getDb("XORCISM");
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  if (!avc.has("PatchStatus")) throw new Error("patch columns not available");
  const st = PATCH_STATUSES.includes(status) ? status : "Unpatched";
  const patchedDate = DONE.test(st) ? new Date().toISOString().slice(0, 10) : null;
  const tw = tenant != null && avc.has("TenantID") ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const args: unknown[] = [st, patchedDate, assetVulnId];
  if (tw) args.push(tenant);
  const r = xo.prepare(`UPDATE ASSETVULNERABILITY SET PatchStatus = ?, PatchedDate = ? WHERE AssetVulnerabilityID = ? ${tw}`).run(...args);
  return { ok: r.changes > 0 };
}

/** Create a remediation plan for an asset↔vulnerability instance (legacy ASSETVULNERABILITYREMEDIATION). */
export function createRemediation(
  p: { assetVulnId: number; name: string; description?: string; type?: string; status?: string; targetDate?: string; ownerPersonId?: number | null; priority?: string },
  tenant: number | null,
): { id: number } {
  const xo = getDb("XORCISM");
  const rc = cols("XORCISM", "ASSETVULNERABILITYREMEDIATION");
  if (!rc.size) throw new Error("ASSETVULNERABILITYREMEDIATION table not available");
  const now = new Date().toISOString();
  const nextId = (xo.prepare("SELECT COALESCE(MAX(AssetVulnerabilityRemediationID),0)+1 AS n FROM ASSETVULNERABILITYREMEDIATION").get() as { n: number }).n;
  const candidate: Record<string, unknown> = {
    AssetVulnerabilityRemediationID: nextId,
    AssetVulnerabilityID: p.assetVulnId,
    RemediationName: (p.name || "Remediation plan").slice(0, 300),
    RemediationDescription: p.description ? String(p.description).slice(0, 4000) : null,
    RemediationType: p.type ? String(p.type).slice(0, 60) : "Patch",
    Status: (p.status || "Planned").slice(0, 60),
    TargetDate: p.targetDate || null,
    Priority: p.priority ? String(p.priority).slice(0, 40) : null,
    PersonID: p.ownerPersonId ?? null,
    CreatedDate: now, ValidFrom: now.slice(0, 10), TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => rc.has(k));
  xo.prepare(`INSERT INTO ASSETVULNERABILITYREMEDIATION (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`).run(...keys.map((k) => candidate[k]));
  // Reflect the plan on the asset-vuln (owner / target / priority) so the worklist updates.
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  const set: string[] = []; const args: unknown[] = [];
  if (avc.has("TargetDate") && p.targetDate) { set.push("TargetDate = ?"); args.push(p.targetDate); }
  if (avc.has("RemediationOwnerPersonID") && p.ownerPersonId != null) { set.push("RemediationOwnerPersonID = ?"); args.push(p.ownerPersonId); }
  if (avc.has("Priority") && p.priority) { set.push("Priority = ?"); args.push(p.priority); }
  if (avc.has("PatchStatus")) { set.push("PatchStatus = COALESCE(NULLIF(PatchStatus,''), 'In progress')"); }
  if (set.length) { args.push(p.assetVulnId); xo.prepare(`UPDATE ASSETVULNERABILITY SET ${set.join(", ")} WHERE AssetVulnerabilityID = ?`).run(...args); }
  return { id: nextId };
}
