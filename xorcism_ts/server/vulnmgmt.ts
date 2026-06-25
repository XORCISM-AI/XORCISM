/**
 * vulnmgmt.ts — Vulnerability Management.
 *
 * The vulnerability-centric governance pane (the threat-side counterpart of patch-management's
 * per-instance lifecycle view, and a sibling of asset-management / identities): one row per
 * distinct vulnerability (XVULNERABILITY.VULNERABILITY) affecting the tenant's assets
 * (XORCISM.ASSETVULNERABILITY ⋈ ASSET, cross-DB), enriched with KEV / CVSS / EPSS / SSVC /
 * exploitation, asset blast-radius, remediation coverage, and a risk-ranked triage worklist.
 * Read inventory + two write actions (track a CVE against an asset, set a disposition).
 */
import { allocId, getDb } from "./db";

const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
// A link counts as "resolved" (no longer demanding triage) when its patch lifecycle is closed.
const PATCH_RESOLVED = /\bpatched\b|mitigat|accepted|not applicable|resolved|closed/i;
const DISPOSED_STATUS = 2; // AssetVulnerabilityStatusID we set when a vuln is dispositioned (accept-risk).

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(dbName: string, table: string): boolean {
  try { return !!getDb(dbName).prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1 || String(v ?? "").toLowerCase() === "true"; }
function num(v: unknown): number | null { return v != null && v !== "" && !Number.isNaN(Number(v)) ? Number(v) : null; }
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
function daysSince(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86_400_000);
}
const sevOf = (cvss: number | null, kev: boolean): "Critical" | "High" | "Medium" | "Low" | "Info" => {
  if (cvss != null) return cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : cvss > 0 ? "Low" : "Info";
  return kev ? "High" : "Info";
};
const critRank = (c: string): number => ({ critical: 4, high: 3, very: 4, medium: 2, moderate: 2, low: 1 } as Record<string, number>)[String(c).toLowerCase().split(/\s/)[0]] ?? 0;

export interface VulnInventory { rows: Record<string, unknown>[]; worklist: Record<string, unknown>[]; summary: Record<string, unknown>; }

export function vulnInventory(tenant: number | null): VulnInventory {
  const xo = getDb("XORCISM");
  const empty: VulnInventory = {
    rows: [], worklist: [],
    summary: { openVulns: 0, affectedAssets: 0, instances: 0, kev: 0, exploited: 0, ssvcAct: 0, critical: 0, high: 0,
      epssHigh: 0, overdue: 0, avgCvss: null, avgEpss: null, remediationCoverage: null, bySeverity: {}, byStatus: {}, newest: null },
  };
  if (!has("XORCISM", "ASSETVULNERABILITY")) return empty;
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  const sel = (c: string, d = "NULL"): string => (avc.has(c) ? c : `${d} AS ${c}`);
  const tw = tenant != null && avc.has("TenantID") ? `AND (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const links = xo.prepare(
    `SELECT AssetVulnerabilityID, AssetID, VulnerabilityID, ${sel("AssetVulnerabilityStatusID")}, ${sel("Status")},
            ${sel("FalsePositive")}, ${sel("PatchStatus")}, ${sel("TargetDate")}, ${sel("RemediationOwnerPersonID")},
            ${sel("Priority")}, CreatedDate
     FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${tw}`
  ).all() as Record<string, any>[];
  if (!links.length) return empty;

  // Asset names + criticality.
  const assetName = new Map<number, { name: string; crit: string }>();
  for (const a of xo.prepare("SELECT AssetID, AssetName, AssetCriticalityLevel FROM ASSET").all() as { AssetID: number; AssetName: string; AssetCriticalityLevel: string }[])
    assetName.set(a.AssetID, { name: a.AssetName || `#${a.AssetID}`, crit: a.AssetCriticalityLevel || "" });

  // Cross-DB VULNERABILITY enrichment (chunked).
  type Vmeta = { cve: string; name: string; cvss: number | null; kev: boolean; epss: number | null;
    exploited: boolean; easilyExploitable: boolean; ssvc: string; published: string | null; desc: string;
    euvd: string; euvdUrl: string };
  const vuln = new Map<number, Vmeta>();
  const vids = [...new Set(links.map((l) => Number(l.VulnerabilityID)))];
  const vc = cols("XVULNERABILITY", "VULNERABILITY");
  if (vids.length && vc.size) {
    const xv = getDb("XVULNERABILITY");
    const g = (c: string, d = "NULL"): string => (vc.has(c) ? c : `${d} AS ${c}`);
    for (let i = 0; i < vids.length; i += 400) {
      const chunk = vids.slice(i, i + 400); const ph = chunk.map(() => "?").join(",");
      for (const r of xv.prepare(
        `SELECT VulnerabilityID, ${g("VULReferentialID")}, ${g("VULName")}, ${g("CVSSBaseScore")}, ${g("KEV")}, ${g("EPSS")},
                ${g("Exploited")}, ${g("EasilyExploitable")}, ${g("SsvcDecision")}, ${g("VULPublishedDate")}, ${g("VULDescription")},
                ${g("EUVDId")}, ${g("EUVDUrl")}
         FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`
      ).all(...chunk) as Record<string, any>[]) {
        vuln.set(Number(r.VulnerabilityID), {
          cve: String(r.VULReferentialID ?? "").trim() || `VULN#${r.VulnerabilityID}`,
          name: String(r.VULName ?? "").trim(),
          cvss: num(r.CVSSBaseScore), kev: truthy(r.KEV), epss: num(r.EPSS),
          exploited: truthy(r.Exploited), easilyExploitable: truthy(r.EasilyExploitable),
          ssvc: String(r.SsvcDecision ?? "").trim(),
          published: r.VULPublishedDate ? String(r.VULPublishedDate).slice(0, 10) : null,
          desc: String(r.VULDescription ?? "").trim().slice(0, 280),
          euvd: String(r.EUVDId ?? "").trim(),
          euvdUrl: String(r.EUVDUrl ?? "").trim() || (String(r.EUVDId ?? "").trim() ? `https://euvd.enisa.europa.eu/vulnerability/${String(r.EUVDId).trim()}` : ""),
        });
      }
    }
  }

  // Group links by vulnerability.
  type Inst = { id: number; assetId: number; asset: string; crit: string; disposed: boolean; falsePositive: boolean;
    target: string | null; owner: number | null; created: string | null };
  const byVuln = new Map<number, Inst[]>();
  for (const l of links) {
    const a = assetName.get(Number(l.AssetID));
    const fp = truthy(l.FalsePositive);
    const statusClosed = num(l.AssetVulnerabilityStatusID) != null && Number(l.AssetVulnerabilityStatusID) >= DISPOSED_STATUS;
    const patchResolved = PATCH_RESOLVED.test(String(l.PatchStatus ?? ""));
    const inst: Inst = {
      id: Number(l.AssetVulnerabilityID), assetId: Number(l.AssetID), asset: a?.name ?? `#${l.AssetID}`, crit: a?.crit ?? "",
      disposed: fp || statusClosed || patchResolved, falsePositive: fp,
      target: l.TargetDate ? String(l.TargetDate).slice(0, 10) : null,
      owner: num(l.RemediationOwnerPersonID), created: l.CreatedDate ? String(l.CreatedDate) : null,
    };
    const arr = byVuln.get(Number(l.VulnerabilityID)); if (arr) arr.push(inst); else byVuln.set(Number(l.VulnerabilityID), [inst]);
  }

  const rows = [...byVuln.entries()].map(([vid, insts]) => {
    const v = vuln.get(vid);
    const kev = v?.kev ?? false;
    const cvss = v?.cvss ?? null;
    const severity = sevOf(cvss, kev);
    const open = insts.filter((i) => !i.disposed);
    const maxCrit = insts.reduce((m, i) => Math.max(m, critRank(i.crit)), 0);
    // earliest open target date that is overdue
    const overdue = open.some((i) => { const d = daysUntil(i.target); return d != null && d < 0; });
    const ages = open.map((i) => daysSince(i.created)).filter((n): n is number => n != null);
    const oldestAge = ages.length ? Math.max(...ages) : null;
    const hasOwner = open.some((i) => i.owner != null);

    // priority score (0–100)
    let score = (kev ? 45 : 0)
      + (v?.exploited ? 18 : 0)
      + (v?.ssvc === "Act" ? 25 : v?.ssvc === "Attend" ? 10 : 0)
      + (SEV_RANK[severity] != null ? (4 - SEV_RANK[severity]) * 8 : 0)
      + (v?.epss != null ? Math.round(v.epss * 25) : 0)
      + Math.min(open.length, 5) * 2
      + maxCrit * 2
      + (overdue ? 12 : 0)
      + (v?.easilyExploitable ? 6 : 0);
    if (!open.length) score = 0;
    score = Math.min(100, score);

    // top triage reason for the worklist (one per open vuln, highest-priority reason wins)
    let reason = "", reasonSev: "Critical" | "High" | "Medium" | "Low" = "Low", action = "";
    if (open.length) {
      if (kev) { reason = "Known Exploited (CISA KEV)"; reasonSev = "Critical"; action = "Patch within KEV due date"; }
      else if (v?.ssvc === "Act") { reason = "SSVC decision: Act"; reasonSev = "Critical"; action = "Remediate immediately"; }
      else if (v?.exploited) { reason = "Active exploitation observed"; reasonSev = "High"; action = "Prioritise remediation"; }
      else if (severity === "Critical") { reason = `Critical severity (CVSS ${cvss})`; reasonSev = "High"; action = "Schedule patch (15-day SLA)"; }
      else if (v?.epss != null && v.epss >= 0.5) { reason = `High exploit probability (EPSS ${Math.round(v.epss * 100)}%)`; reasonSev = "High"; action = "Prioritise remediation"; }
      else if (overdue) { reason = "Remediation overdue"; reasonSev = "High"; action = "Escalate to owner"; }
      else if (severity === "High") { reason = `High severity (CVSS ${cvss})`; reasonSev = "Medium"; action = "Schedule patch (30-day SLA)"; }
      else if (open.length >= 3) { reason = `Wide blast radius (${open.length} assets)`; reasonSev = "Medium"; action = "Assess exposure"; }
      else if (!hasOwner) { reason = "No remediation owner assigned"; reasonSev = "Low"; action = "Assign owner"; }
      else { reason = "Open vulnerability"; reasonSev = "Low"; action = "Track to closure"; }
    }

    return {
      id: vid, cve: v?.cve ?? `VULN#${vid}`, name: v?.name ?? "", description: v?.desc ?? "",
      severity, cvss, kev, epss: v?.epss ?? null, exploited: v?.exploited ?? false, easilyExploitable: v?.easilyExploitable ?? false,
      ssvc: v?.ssvc ?? "", published: v?.published ?? null, euvd: v?.euvd ?? "", euvdUrl: v?.euvdUrl ?? "",
      affectedAssets: insts.length, openInstances: open.length, resolvedInstances: insts.length - open.length,
      assets: insts.slice(0, 8).map((i) => i.asset), maxCriticality: maxCrit,
      overdue, oldestAgeDays: oldestAge, hasOwner, falsePositive: insts.every((i) => i.falsePositive),
      reason, reasonSeverity: reasonSev, action, score,
    };
  });

  rows.sort((a, b) => b.score - a.score || (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || (b.cvss ?? 0) - (a.cvss ?? 0));
  const openRows = rows.filter((r) => r.openInstances > 0);

  // KPIs.
  const totalInstances = links.length;
  const openInstances = rows.reduce((s, r) => s + (r.openInstances as number), 0);
  const resolvedInstances = totalInstances - openInstances;
  const cvssVals = openRows.map((r) => r.cvss).filter((n): n is number => n != null);
  const epssVals = openRows.map((r) => r.epss).filter((n): n is number => n != null);
  const affected = new Set<number>();
  for (const insts of byVuln.values()) for (const i of insts) if (!i.disposed) affected.add(i.assetId);
  const bySeverity: Record<string, number> = {}; const byStatus: Record<string, number> = {};
  for (const r of openRows) bySeverity[r.severity as string] = (bySeverity[r.severity as string] || 0) + 1;
  byStatus["Open"] = openInstances; byStatus["Resolved"] = resolvedInstances;
  const newest = openRows.map((r) => r.published).filter(Boolean).sort().slice(-1)[0] ?? null;

  return {
    rows: openRows,
    worklist: openRows.filter((r) => r.reason).slice(0, 200),
    summary: {
      openVulns: openRows.length, affectedAssets: affected.size, instances: openInstances,
      kev: openRows.filter((r) => r.kev).length,
      exploited: openRows.filter((r) => r.exploited).length,
      ssvcAct: openRows.filter((r) => r.ssvc === "Act").length,
      critical: openRows.filter((r) => r.severity === "Critical").length,
      high: openRows.filter((r) => r.severity === "High").length,
      epssHigh: openRows.filter((r) => r.epss != null && (r.epss as number) >= 0.5).length,
      overdue: openRows.filter((r) => r.overdue).length,
      avgCvss: cvssVals.length ? Math.round((cvssVals.reduce((s, n) => s + n, 0) / cvssVals.length) * 10) / 10 : null,
      avgEpss: epssVals.length ? Math.round((epssVals.reduce((s, n) => s + n, 0) / epssVals.length) * 1000) / 10 : null,
      remediationCoverage: totalInstances > 0 ? Math.round((resolvedInstances / totalInstances) * 100) : null,
      bySeverity, byStatus, newest,
    },
  };
}

/** In-scope assets (id + name), for the "track a CVE" picker. */
export function assetPickList(tenant: number | null): { id: number; name: string }[] {
  const xo = getDb("XORCISM");
  if (!has("XORCISM", "ASSET")) return [];
  const tw = tenant != null && cols("XORCISM", "ASSET").has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  return (xo.prepare(`SELECT AssetID, AssetName FROM ASSET ${tw} ORDER BY AssetName COLLATE NOCASE`).all() as { AssetID: number; AssetName: string }[])
    .map((a) => ({ id: a.AssetID, name: a.AssetName || `#${a.AssetID}` }));
}

/**
 * Track a vulnerability against an asset — resolve a CVE id to its VULNERABILITY row and create an
 * open ASSETVULNERABILITY link (idempotent on asset+vuln+tenant). The guided-create action of the page.
 */
export function trackVulnerability(
  p: { cve: string; assetId: number; targetDate?: string; priority?: string; ownerPersonId?: number | null },
  tenant: number | null,
): { id: number; existed: boolean; cve: string } {
  const xo = getDb("XORCISM");
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  if (!avc.size) throw new Error("ASSETVULNERABILITY table not available");
  const cve = String(p.cve ?? "").trim();
  if (!cve) throw new Error("CVE id required");
  const assetId = Number(p.assetId);
  if (!Number.isInteger(assetId) || assetId <= 0) throw new Error("asset required");
  // asset must be in scope
  const asset = xo.prepare(`SELECT AssetID FROM ASSET WHERE AssetID = ?${tenant != null && cols("XORCISM", "ASSET").has("TenantID") ? " AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null && cols("XORCISM", "ASSET").has("TenantID") ? [assetId, tenant] : [assetId]));
  if (!asset) throw new Error("asset not found / not in scope");

  // resolve CVE → VulnerabilityID
  const xv = getDb("XVULNERABILITY");
  const vrow = xv.prepare("SELECT VulnerabilityID FROM VULNERABILITY WHERE VULReferentialID = ? OR VULReferential = ? LIMIT 1")
    .get(cve, cve) as { VulnerabilityID: number } | undefined;
  if (!vrow) throw new Error(`CVE not found in vulnerability database: ${cve}`);
  const vid = vrow.VulnerabilityID;

  // idempotent
  const twArr: unknown[] = [assetId, vid];
  let tw = "";
  if (tenant != null && avc.has("TenantID")) { tw = " AND (TenantID = ? OR TenantID IS NULL)"; twArr.push(tenant); }
  const existing = xo.prepare(`SELECT AssetVulnerabilityID FROM ASSETVULNERABILITY WHERE AssetID = ? AND VulnerabilityID = ?${tw}`).get(...twArr) as { AssetVulnerabilityID: number } | undefined;
  if (existing) return { id: existing.AssetVulnerabilityID, existed: true, cve };

  const now = new Date().toISOString();
  const nextId = allocId(xo, "ASSETVULNERABILITY", "AssetVulnerabilityID");
  const candidate: Record<string, unknown> = {
    AssetVulnerabilityID: nextId, AssetID: assetId, VulnerabilityID: vid,
    CreatedDate: now, ValidFromDate: now.slice(0, 10),
    AssetVulnerabilityStatusID: 0, Status: "Open", FalsePositive: 0, PatchStatus: "Unpatched",
    TargetDate: p.targetDate || null, Priority: p.priority ? String(p.priority).slice(0, 40) : null,
    RemediationOwnerPersonID: p.ownerPersonId ?? null, TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => avc.has(k));
  xo.prepare(`INSERT INTO ASSETVULNERABILITY (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`).run(...keys.map((k) => candidate[k]));
  return { id: nextId, existed: false, cve };
}

/**
 * Set a disposition on every in-scope instance of a vulnerability: false-positive, accept-risk, or
 * reopen. Lets an analyst triage a CVE across all affected assets in one action.
 */
export function setVulnDisposition(
  p: { vulnerabilityId: number; disposition: "false-positive" | "accept-risk" | "reopen" },
  tenant: number | null,
): { ok: boolean; affected: number } {
  const xo = getDb("XORCISM");
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  const vid = Number(p.vulnerabilityId);
  if (!Number.isInteger(vid) || vid <= 0) throw new Error("vulnerabilityId required");
  const set: string[] = []; const args: unknown[] = [];
  if (p.disposition === "false-positive") {
    if (avc.has("FalsePositive")) { set.push("FalsePositive = 1"); }
    if (avc.has("Status")) { set.push("Status = ?"); args.push("False positive"); }
    if (avc.has("AssetVulnerabilityStatusID")) { set.push(`AssetVulnerabilityStatusID = ${DISPOSED_STATUS}`); }
  } else if (p.disposition === "accept-risk") {
    if (avc.has("AssetVulnerabilityStatusID")) { set.push(`AssetVulnerabilityStatusID = ${DISPOSED_STATUS}`); }
    if (avc.has("Status")) { set.push("Status = ?"); args.push("Accepted risk"); }
  } else { // reopen
    if (avc.has("FalsePositive")) { set.push("FalsePositive = 0"); }
    if (avc.has("AssetVulnerabilityStatusID")) { set.push("AssetVulnerabilityStatusID = 0"); }
    if (avc.has("Status")) { set.push("Status = ?"); args.push("Open"); }
    if (avc.has("PatchStatus")) { set.push("PatchStatus = NULLIF(PatchStatus, 'Patched')"); }
  }
  if (!set.length) throw new Error("no writable disposition columns");
  let tw = ""; args.push(vid);
  if (tenant != null && avc.has("TenantID")) { tw = " AND (TenantID = ? OR TenantID IS NULL)"; args.push(tenant); }
  const r = xo.prepare(`UPDATE ASSETVULNERABILITY SET ${set.join(", ")} WHERE VulnerabilityID = ?${tw}`).run(...args);
  return { ok: r.changes > 0, affected: r.changes };
}
