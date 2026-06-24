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
import { randomUUID } from "crypto";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
// The 6-level remediation priority scale (Very Low → Critical), shared with the remediation form.
export const PRIORITY_LEVELS = ["Very Low", "Low", "Moderate", "High", "Very High", "Critical"];
/** Map a 0-100 prioritization score onto the 6-level priority scale. */
function recommendPriority(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 65) return "Very High";
  if (score >= 45) return "High";
  if (score >= 25) return "Moderate";
  if (score >= 10) return "Low";
  return "Very Low";
}
/** Map a remediation priority onto an XTICKET priority bucket (Critical/High/Medium/Low). */
function ticketPriority(p?: string): string {
  const s = String(p || "").toLowerCase();
  if (s === "critical" || s === "very high") return "Critical";
  if (s === "high") return "High";
  if (s === "low" || s === "very low") return "Low";
  return "Medium";
}
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

export interface PatchInventory { rows: Record<string, unknown>[]; worklist: Record<string, unknown>[]; packages: Record<string, unknown>[]; summary: Record<string, unknown>; }

export function patchInventory(tenant: number | null): PatchInventory {
  const xo = getDb("XORCISM");
  const empty: PatchInventory = { rows: [], worklist: [], packages: [], summary: { instances: 0, patched: 0, unpatched: 0, coverage: null, mttr: null, kevUnpatched: 0, overdue: 0, noPatch: 0, withPlan: 0, packages: 0, bySeverity: {}, byStatus: {} } };
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

  // Asset context (name + the prioritization signals: criticality, internet exposure, business value).
  const ac = cols("XORCISM", "ASSET");
  const asel = (c: string): string => (ac.has(c) ? c : `NULL AS ${c}`);
  const assetName = new Map<number, { name: string; crit: string; publicFacing: boolean; value: number }>();
  for (const a of xo.prepare(`SELECT AssetID, AssetName, ${asel("AssetCriticalityLevel")}, ${asel("PublicFacing")}, ${asel("FinancialValue")}, ${asel("BusinessValue")} FROM ASSET`).all() as Record<string, any>[]) {
    const val = Math.max(Number(a.FinancialValue) || 0, Number(a.BusinessValue) || 0);
    assetName.set(Number(a.AssetID), { name: a.AssetName || `#${a.AssetID}`, crit: String(a.AssetCriticalityLevel || ""), publicFacing: truthy(a.PublicFacing), value: val });
  }

  // Cross-DB VULNERABILITY enrichment (chunked).
  const vuln = new Map<number, { cve: string; cvss: number | null; kev: boolean; epss: number | null; patchAvail: boolean; due: string | null; name: string; exploited: boolean }>();
  const vids = [...new Set(links.map((l) => Number(l.VulnerabilityID)))];
  const vc = cols("XVULNERABILITY", "VULNERABILITY");
  if (vids.length && vc.size) {
    const xv = getDb("XVULNERABILITY");
    const g = (c: string, d = "NULL"): string => (vc.has(c) ? c : `${d} AS ${c}`);
    for (let i = 0; i < vids.length; i += 400) {
      const chunk = vids.slice(i, i + 400); const ph = chunk.map(() => "?").join(",");
      for (const r of xv.prepare(
        `SELECT VulnerabilityID, ${g("VULReferentialID")}, ${g("CVSSBaseScore")}, ${g("KEV")}, ${g("EPSS")},
                ${g("VULPatchAvailable")}, ${g("DueDate")}, ${g("VULName")},
                ${g("Exploited")}, ${g("EasilyExploitable")}, ${g("SsvcExploitation")} FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`
      ).all(...chunk) as Record<string, any>[]) {
        // exploit maturity: explicit Exploited / EasilyExploitable flags or an SSVC "active/poc" decision.
        const exploited = truthy(r.Exploited) || truthy(r.EasilyExploitable) || /active|poc|public/i.test(String(r.SsvcExploitation ?? ""));
        vuln.set(Number(r.VulnerabilityID), {
          cve: String(r.VULReferentialID ?? "").trim() || `VULN#${r.VulnerabilityID}`,
          cvss: r.CVSSBaseScore != null && r.CVSSBaseScore !== "" ? Number(r.CVSSBaseScore) : null,
          kev: truthy(r.KEV), epss: r.EPSS != null && r.EPSS !== "" ? Number(r.EPSS) : null,
          patchAvail: truthy(r.VULPatchAvailable), due: r.DueDate ? String(r.DueDate).slice(0, 10) : null,
          name: String(r.VULName ?? "").trim(), exploited,
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
    // ── Prioritization score (0-100): threat × severity × asset-context × urgency × actionability.
    //    Aligns with SSVC/EPSS/KEV + CTEM practice — patch what is exploited AND on a valuable,
    //    exposed asset first, not just the highest CVSS. Each driver is captured for explainability.
    const drivers: string[] = [];
    let score = 0;
    if (kev) { score += 40; drivers.push("KEV (actively exploited) +40"); }           // threat: known-exploited
    else if (v?.exploited) { score += 22; drivers.push("Exploit available +22"); }     // threat: exploit maturity
    if (kev && v?.exploited) { score += 6; drivers.push("Exploit maturity +6"); }
    if (v?.epss != null) { const p = Math.round(v.epss * 22); if (p) { score += p; drivers.push(`EPSS ${(v.epss * 100).toFixed(0)}% +${p}`); } } // probability
    const sevPts: Record<string, number> = { critical: 20, high: 14, medium: 7, low: 2, info: 0 };
    const sp = sevPts[severity.toLowerCase()] ?? 0; if (sp) { score += sp; drivers.push(`${severity} severity +${sp}`); }
    const critPts = /crown|critical/i.test(a?.crit ?? "") ? 18 : /high/i.test(a?.crit ?? "") ? 12 : /medium|moderate/i.test(a?.crit ?? "") ? 6 : 0;
    if (critPts) { score += critPts; drivers.push(`${a?.crit} asset +${critPts}`); }    // asset criticality / business value
    if (a?.publicFacing) { score += 12; drivers.push("Internet-facing asset +12"); }    // exposure / blast surface
    if (overdue) { score += 10; drivers.push("Past SLA due +10"); }                      // urgency
    if (v?.patchAvail && !resolved) { score += 6; drivers.push("Patch available +6"); }  // actionability
    if (resolved) { score = 0; drivers.length = 0; }
    score = Math.min(100, score);
    const recommendedPriority = resolved ? "" : recommendPriority(score);
    return {
      id: Number(l.AssetVulnerabilityID), assetId: Number(l.AssetID), asset: a?.name ?? `#${l.AssetID}`, criticality: a?.crit ?? "",
      publicFacing: a?.publicFacing ?? false,
      cve: v?.cve ?? `VULN#${l.VulnerabilityID}`, vulnerabilityId: Number(l.VulnerabilityID), name: v?.name ?? "",
      severity, cvss, kev, exploited: v?.exploited ?? false, epss: v?.epss ?? null, patchAvailable: v?.patchAvail ?? false,
      patchStatus, resolved, patchedDate: l.PatchedDate ? String(l.PatchedDate).slice(0, 10) : null,
      due, dueIn, overdue, hasPlan: !!plan, planName: plan?.name ?? "", planStatus: plan?.status ?? "", planType: plan?.type ?? "",
      score, recommendedPriority, scoreDrivers: drivers,
    };
  });

  // ── Patch packages: a named remediation/patch (RemediationName) can fix many CVEs across assets.
  // Group the rows by their plan name → distinct CVEs fixed, assets affected, and how many remain open.
  const pkgMap = new Map<string, { name: string; type: string; cves: Set<string>; assets: Set<number>; open: number; resolved: number; kev: number; maxScore: number }>();
  for (const r of rows) {
    if (!r.planName) continue;
    let p = pkgMap.get(r.planName);
    if (!p) { p = { name: r.planName, type: r.planType, cves: new Set(), assets: new Set(), open: 0, resolved: 0, kev: 0, maxScore: 0 }; pkgMap.set(r.planName, p); }
    p.cves.add(r.cve); p.assets.add(r.assetId);
    if (r.resolved) p.resolved++; else p.open++;
    if (r.kev) p.kev++;
    p.maxScore = Math.max(p.maxScore, r.score);
  }
  const packages = [...pkgMap.values()]
    .map((p) => ({ name: p.name, type: p.type, cves: p.cves.size, assets: p.assets.size, open: p.open, resolved: p.resolved, kev: p.kev, status: p.open === 0 ? "Complete" : p.resolved > 0 ? "In progress" : "Planned", score: p.maxScore }))
    .sort((a, b) => b.cves - a.cves || b.score - a.score);

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
    rows, worklist: open.slice(0, 200), packages,
    summary: {
      instances: rows.length,
      packages: packages.length,
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

/** Open an XTICKET work item for a remediation plan (asset↔vuln). Idempotent per asset-vuln instance
 * (tag remediation-av:<id>). Resolves the CVE + asset name for a meaningful subject. Best-effort. */
export function createRemediationTicket(
  p: { assetVulnId: number; name: string; priority?: string; targetDate?: string; description?: string },
  _tenant: number | null, userEmail?: string,
): { ticketId: number; created: boolean } | null {
  const xo = getDb("XORCISM");
  const av = xo.prepare("SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE AssetVulnerabilityID = ?").get(p.assetVulnId) as { AssetID: number; VulnerabilityID: number } | undefined;
  if (!av) return null;
  let asset = `#${av.AssetID}`;
  try { const a = xo.prepare("SELECT AssetName FROM ASSET WHERE AssetID = ?").get(av.AssetID) as { AssetName?: string } | undefined; if (a?.AssetName) asset = a.AssetName; } catch { /* keep id */ }
  let cve = `VULN#${av.VulnerabilityID}`;
  try { const v = getDb("XVULNERABILITY").prepare("SELECT VULReferentialID FROM VULNERABILITY WHERE VulnerabilityID = ?").get(av.VulnerabilityID) as { VULReferentialID?: string } | undefined; if (v?.VULReferentialID) cve = String(v.VULReferentialID).trim(); } catch { /* keep id */ }
  let xt; try { xt = getDb("XTICKET"); } catch { return null; }
  const tc = cols("XTICKET", "TICKET");
  if (!tc.has("TicketID")) return null;
  const tag = `remediation-av:${p.assetVulnId}`;
  if (tc.has("Tags")) {
    const ex = xt.prepare("SELECT TicketID FROM TICKET WHERE Tags LIKE ?").get(`%${tag}%`) as { TicketID: number } | undefined;
    if (ex) return { ticketId: ex.TicketID, created: false };
  }
  const id = (xt.prepare("SELECT COALESCE(MAX(TicketID),0)+1 n FROM TICKET").get() as { n: number }).n;
  const now = new Date().toISOString();
  const prio = ticketPriority(p.priority);
  const field: Record<string, unknown> = {
    TicketID: id, TicketGUID: randomUUID(), TicketNumber: `REM-${id}`,
    Subject: `Remediate ${cve} on ${asset}`.slice(0, 300),
    Description: `Remediation plan: ${p.name}${p.description ? "\n\n" + p.description : ""}\n\nAuto-opened by XORCISM on remediation-plan creation (asset-vulnerability #${p.assetVulnId}).`,
    Status: "Open", Priority: prio, Severity: prio, TicketType: "Security", CategoryID: null,
    Tags: `remediation,patch,${tag}`, DueDate: p.targetDate || null, RequesterEmail: userEmail || null,
    CreatedDate: now, UpdatedDate: now,
  };
  const keys = Object.keys(field).filter((k) => tc.has(k));
  xt.prepare(`INSERT INTO TICKET (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`).run(...keys.map((k) => field[k]));
  return { ticketId: id, created: true };
}

export interface RemediationPlan {
  AssetVulnerabilityRemediationID: number; AssetVulnerabilityID: number;
  RemediationName: string; RemediationType: string | null; Status: string | null;
  Priority: string | null; TargetDate: string | null; RemediationDescription: string | null;
  PersonID: number | null; OwnerName: string | null; CreatedDate: string | null;
}

/** All remediation plans for an asset's vulnerability instances, grouped by AssetVulnerabilityID.
 * Powers the inline plan list in the ASSET form's "Vulnerabilities for Asset" panel. */
export function listRemediationsForAsset(assetId: number, _tenant: number | null): Record<number, RemediationPlan[]> {
  const xo = getDb("XORCISM");
  const rc = cols("XORCISM", "ASSETVULNERABILITYREMEDIATION");
  if (!rc.size) return {};
  const avIds = (xo.prepare("SELECT AssetVulnerabilityID FROM ASSETVULNERABILITY WHERE AssetID = ?").all(assetId) as { AssetVulnerabilityID: number }[]).map((r) => r.AssetVulnerabilityID);
  if (!avIds.length) return {};
  const ph = avIds.map(() => "?").join(",");
  const want = ["AssetVulnerabilityRemediationID", "AssetVulnerabilityID", "RemediationName", "RemediationType", "Status", "Priority", "TargetDate", "RemediationDescription", "PersonID", "CreatedDate"].filter((c) => rc.has(c));
  const rows = xo.prepare(`SELECT ${want.map((c) => `"${c}"`).join(", ")} FROM ASSETVULNERABILITYREMEDIATION WHERE AssetVulnerabilityID IN (${ph}) ORDER BY AssetVulnerabilityRemediationID DESC`).all(...avIds) as Record<string, any>[];
  const pids = [...new Set(rows.map((r) => r.PersonID).filter((x) => x != null))] as number[];
  const names = new Map<number, string>();
  if (pids.length && cols("XORCISM", "PERSON").has("FullName")) {
    const pph = pids.map(() => "?").join(",");
    for (const p of xo.prepare(`SELECT PersonID, FullName FROM PERSON WHERE PersonID IN (${pph})`).all(...pids) as { PersonID: number; FullName: string }[]) names.set(p.PersonID, p.FullName);
  }
  const out: Record<number, RemediationPlan[]> = {};
  for (const r of rows) {
    const plan = { ...r, OwnerName: r.PersonID != null ? (names.get(r.PersonID) ?? null) : null } as RemediationPlan;
    (out[r.AssetVulnerabilityID] ||= []).push(plan);
  }
  return out;
}
