/**
 * voc.ts — Vulnerability Operations Center (VOC): vulnerability remediation run as an operations
 * function (the SOC's counterpart for vulns).
 *
 * The backlog is XORCISM.ASSETVULNERABILITY cross-enriched with XVULNERABILITY.VULNERABILITY
 * (CVE / CVSS / KEV / EPSS / CISA due date). Against a configurable remediation-SLA policy
 * (VOCSLATIER) it derives the operational KPIs — open backlog, MTTR, SLA-compliance %, aging
 * buckets, remediation velocity, KEV exposure — a risk-ranked remediation worklist, remediation
 * campaigns (VOCCAMPAIGN, with burndown) and a risk-acceptance / exception register (VOCEXCEPTION).
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const DONE = /\bpatched\b|mitigat|remediat|closed|fixed/i;
const truthy = (v: unknown): boolean => v === 1 || v === "1" || v === true || Number(v) === 1;
function cols(dbn: string, t: string): Set<string> { try { return new Set((getDb(dbn).prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); } }
const ms = (v: unknown): number | null => { if (v == null || v === "") return null; const t = Date.parse(String(v).replace(" ", "T")); return Number.isFinite(t) ? t : null; };
const days = (a: number, b: number): number => Math.round((b - a) / 86400000);
function sevOf(cvss: number | null, kev: boolean): string {
  if (kev) return cvss != null && cvss < 7 ? "High" : "Critical";
  if (cvss == null) return "Medium";
  return cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : "Low";
}
const DEFAULT_TIERS = [{ tier: "KEV", days: 14 }, { tier: "Critical", days: 15 }, { tier: "High", days: 30 }, { tier: "Medium", days: 90 }, { tier: "Low", days: 180 }];

export function slaPolicy(tenant: number | null): { tier: string; days: number; label: string }[] {
  try {
    const rows = getDb("XVULNERABILITY").prepare(`SELECT Tier, RemediationDays, Label FROM VOCSLATIER ${tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : ""} ORDER BY SortOrder`).all(...(tenant != null ? [tenant] : [])) as any[];
    if (rows.length) return rows.map((r) => ({ tier: String(r.Tier), days: Number(r.RemediationDays), label: String(r.Label ?? "") }));
  } catch { /* */ }
  return DEFAULT_TIERS.map((t) => ({ ...t, label: "" }));
}

interface Inst { id: number; assetId: number; vulnId: number; cve: string; name: string; asset: string; severity: string; kev: boolean; cvss: number | null; epss: number | null;
  patched: boolean; patchStatus: string; ageDays: number | null; dueDate: string | null; slaStatus: string; overdueDays: number; owner: string | null; createdMs: number | null; patchedMs: number | null; }

function backlog(tenant: number | null): { rows: Inst[]; sla: Map<string, number> } {
  const xo = getDb("XORCISM"), now = Date.now();
  const sla = new Map(slaPolicy(tenant).map((t) => [t.tier, t.days]));
  const avc = cols("XORCISM", "ASSETVULNERABILITY");
  if (!avc.size) return { rows: [], sla };
  const sel = (c: string) => (avc.has(c) ? c : `NULL AS ${c}`);
  const tw = tenant != null && avc.has("TenantID") ? "WHERE TenantID = ?" : "";
  const links = xo.prepare(`SELECT AssetVulnerabilityID, AssetID, VulnerabilityID, ${sel("PatchStatus")}, ${sel("PatchedDate")}, ${sel("TargetDate")}, ${sel("CreatedDate")}, ${sel("RemediationOwnerPersonID")}, ${sel("FalsePositive")} FROM ASSETVULNERABILITY ${tw}`).all(...(tw ? [tenant] : [])) as any[];
  const assetName = new Map<number, string>();
  for (const a of xo.prepare("SELECT AssetID, AssetName FROM ASSET").all() as any[]) assetName.set(Number(a.AssetID), String(a.AssetName || `#${a.AssetID}`));
  const persons = new Map<number, string>();
  try { for (const p of xo.prepare("SELECT PersonID, FullName FROM PERSON").all() as any[]) persons.set(Number(p.PersonID), String(p.FullName || `#${p.PersonID}`)); } catch { /* */ }

  // cross-DB VULNERABILITY enrichment
  const vuln = new Map<number, { cve: string; name: string; cvss: number | null; kev: boolean; epss: number | null; due: string | null }>();
  const vids = [...new Set(links.map((l) => Number(l.VulnerabilityID)).filter(Boolean))];
  const vc = cols("XVULNERABILITY", "VULNERABILITY");
  if (vids.length && vc.size) {
    const xv = getDb("XVULNERABILITY"); const g = (c: string) => (vc.has(c) ? c : `NULL AS ${c}`);
    for (let i = 0; i < vids.length; i += 400) {
      const chunk = vids.slice(i, i + 400); const ph = chunk.map(() => "?").join(",");
      for (const r of xv.prepare(`SELECT VulnerabilityID, ${g("VULReferentialID")}, ${g("VULName")}, ${g("CVSSBaseScore")}, ${g("KEV")}, ${g("EPSS")}, ${g("DueDate")} FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as any[])
        vuln.set(Number(r.VulnerabilityID), { cve: String(r.VULReferentialID ?? "").trim() || `VULN#${r.VulnerabilityID}`, name: String(r.VULName ?? "").trim(), cvss: r.CVSSBaseScore != null && r.CVSSBaseScore !== "" ? Number(r.CVSSBaseScore) : null, kev: truthy(r.KEV), epss: r.EPSS != null && r.EPSS !== "" ? Number(r.EPSS) : null, due: r.DueDate ? String(r.DueDate).slice(0, 10) : null });
    }
  }

  const rows: Inst[] = links.filter((l) => !truthy(l.FalsePositive)).map((l) => {
    const v = vuln.get(Number(l.VulnerabilityID));
    const kev = v?.kev ?? false, cvss = v?.cvss ?? null, severity = sevOf(cvss, kev);
    const patchStatus = String(l.PatchStatus ?? "").trim() || "Unpatched";
    const patched = DONE.test(patchStatus) || ms(l.PatchedDate) != null;
    const createdMs = ms(l.CreatedDate), patchedMs = ms(l.PatchedDate);
    const ageDays = createdMs != null ? days(createdMs, patched && patchedMs != null ? patchedMs : now) : null;
    // SLA due: CISA KEV due date, else explicit TargetDate, else discovery + tier days
    const tierDays = kev ? (sla.get("KEV") ?? 14) : (sla.get(severity) ?? 90);
    const dueMs = (kev && v?.due ? ms(v.due) : null) ?? ms(l.TargetDate) ?? (createdMs != null ? createdMs + tierDays * 86400000 : null);
    const dueDate = dueMs != null ? new Date(dueMs).toISOString().slice(0, 10) : null;
    let slaStatus = "—", overdueDays = 0;
    if (!patched && dueMs != null) {
      const left = days(now, dueMs);
      if (left < 0) { slaStatus = "breached"; overdueDays = -left; }
      else if (left <= Math.max(3, Math.round(tierDays * 0.2))) slaStatus = "approaching";
      else slaStatus = "within";
    } else if (patched) slaStatus = "remediated";
    return { id: Number(l.AssetVulnerabilityID), assetId: Number(l.AssetID), vulnId: Number(l.VulnerabilityID),
      cve: v?.cve ?? `VULN#${l.VulnerabilityID}`, name: v?.name ?? "", asset: assetName.get(Number(l.AssetID)) || `#${l.AssetID}`,
      severity, kev, cvss, epss: v?.epss ?? null, patched, patchStatus, ageDays, dueDate, slaStatus, overdueDays,
      owner: l.RemediationOwnerPersonID != null ? (persons.get(Number(l.RemediationOwnerPersonID)) || `#${l.RemediationOwnerPersonID}`) : null,
      createdMs, patchedMs };
  });
  return { rows, sla };
}

const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

export function vocDashboard(tenant: number | null): any {
  const { rows } = backlog(tenant);
  const now = Date.now();
  const open = rows.filter((r) => !r.patched);
  const patched = rows.filter((r) => r.patched);
  const remediable = rows.length; // FP already excluded
  const mttrVals = patched.filter((r) => r.createdMs != null && r.patchedMs != null && r.patchedMs >= r.createdMs).map((r) => days(r.createdMs!, r.patchedMs!));
  const mttr = mttrVals.length ? Math.round(mttrVals.reduce((a, b) => a + b, 0) / mttrVals.length) : null;
  const breached = open.filter((r) => r.slaStatus === "breached");
  const withinSla = open.filter((r) => r.slaStatus === "within" || r.slaStatus === "approaching");
  const velocity30 = patched.filter((r) => r.patchedMs != null && now - r.patchedMs <= 30 * 86400000).length;
  const aging = { "0-30": 0, "31-60": 0, "61-90": 0, "90+": 0 } as Record<string, number>;
  for (const r of open) { const a = r.ageDays ?? 0; aging[a <= 30 ? "0-30" : a <= 60 ? "31-60" : a <= 90 ? "61-90" : "90+"]++; }
  const avgAge = open.length ? Math.round(open.reduce((s, r) => s + (r.ageDays ?? 0), 0) / open.length) : 0;

  // risk-ranked worklist
  const worklist = open.map((r) => ({ id: r.id, cve: r.cve, asset: r.asset, severity: r.severity, kev: r.kev, epss: r.epss, cvss: r.cvss, slaStatus: r.slaStatus, overdueDays: r.overdueDays, ageDays: r.ageDays, dueDate: r.dueDate, owner: r.owner, patchStatus: r.patchStatus,
    score: (r.slaStatus === "breached" ? 100 : r.slaStatus === "approaching" ? 40 : 0) + (r.kev ? 50 : 0) + (3 - (SEV_RANK[r.severity] ?? 3)) * 15 + Math.round((r.epss ?? 0) * 30) }))
    .sort((a, b) => b.score - a.score).slice(0, 60);

  // campaigns + exceptions
  const xv = getDb("XVULNERABILITY");
  let campaigns: any[] = [], exceptions: any[] = [];
  try {
    const camps = xv.prepare(`SELECT * FROM VOCCAMPAIGN ${tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : ""} ORDER BY CampaignID DESC`).all(...(tenant != null ? [tenant] : [])) as any[];
    campaigns = camps.map((c) => {
      const scope = String(c.Scope || "all").toLowerCase();
      const inScope = rows.filter((r) => scope === "all" ? true : scope === "kev" ? r.kev : r.severity.toLowerCase() === scope);
      const total = inScope.length, done = inScope.filter((r) => r.patched).length;
      return { id: Number(c.CampaignID), name: String(c.Name ?? ""), scope, target: c.TargetDate ? String(c.TargetDate).slice(0, 10) : "", status: String(c.Status ?? "Active"), total, done, pct: total ? Math.round((done / total) * 100) : 0 };
    });
  } catch { /* */ }
  try {
    const exc = xv.prepare(`SELECT * FROM VOCEXCEPTION ${tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : ""} ORDER BY ExceptionID DESC`).all(...(tenant != null ? [tenant] : [])) as any[];
    exceptions = exc.map((e) => ({ id: Number(e.ExceptionID), title: String(e.Title ?? ""), scope: String(e.Scope ?? ""), justification: String(e.Justification ?? ""), approvedBy: String(e.ApprovedBy ?? ""), status: String(e.Status ?? "Active"), expiry: e.ExpiryDate ? String(e.ExpiryDate).slice(0, 10) : "", expired: e.ExpiryDate ? (ms(e.ExpiryDate) != null && ms(e.ExpiryDate)! < now) : false }));
  } catch { /* */ }

  return {
    worklist, slaPolicy: slaPolicy(tenant), aging, campaigns, exceptions,
    summary: {
      backlog: open.length, remediated: patched.length, total: remediable,
      coverage: remediable ? Math.round((patched.length / remediable) * 100) : null,
      mttrDays: mttr, slaCompliance: open.length ? Math.round((withinSla.length / open.length) * 100) : null,
      breached: breached.length, kevOpen: open.filter((r) => r.kev).length, criticalOpen: open.filter((r) => r.severity === "Critical").length,
      velocity30, avgAgeDays: avgAge, unassigned: open.filter((r) => !r.owner).length, activeExceptions: exceptions.filter((e) => e.status === "Active" && !e.expired).length, campaigns: campaigns.length,
    },
  };
}

// ── mutations ────────────────────────────────────────────────────────────────────
function nextId(t: string, pk: string): number { return (getDb("XVULNERABILITY").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${t}`).get() as { n: number }).n; }

export function setSlaTier(tier: string, days: number, tenant: number | null): boolean {
  const xv = getDb("XVULNERABILITY"); const d = Math.max(1, Math.round(days));
  const ex = xv.prepare("SELECT SlaID FROM VOCSLATIER WHERE Tier = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tier, tenant) as { SlaID: number } | undefined;
  if (ex) xv.prepare("UPDATE VOCSLATIER SET RemediationDays = ? WHERE SlaID = ?").run(d, ex.SlaID);
  else { const id = nextId("VOCSLATIER", "SlaID"); const so = DEFAULT_TIERS.findIndex((t) => t.tier === tier); xv.prepare("INSERT INTO VOCSLATIER (SlaID, Tier, RemediationDays, SortOrder, TenantID) VALUES (?,?,?,?,?)").run(id, tier, d, so < 0 ? 9 : so, tenant); }
  return true;
}

export function createCampaign(p: { name: string; scope?: string; targetDate?: string; description?: string }, tenant: number | null): { id: number } {
  const xv = getDb("XVULNERABILITY"); const id = nextId("VOCCAMPAIGN", "CampaignID"); const now = new Date().toISOString();
  xv.prepare("INSERT INTO VOCCAMPAIGN (CampaignID, CampaignGUID, Name, Description, Scope, TargetDate, Status, StartDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), p.name.slice(0, 300), (p.description || "").slice(0, 2000), (p.scope || "all").toLowerCase(), p.targetDate ?? null, "Active", now.slice(0, 10), tenant, now);
  return { id };
}

export function createException(p: { title: string; vulnerabilityId?: number; assetVulnerabilityId?: number; scope?: string; justification?: string; compensating?: string; approvedBy?: string; expiryDate?: string }, tenant: number | null): { id: number } {
  const xv = getDb("XVULNERABILITY"); const id = nextId("VOCEXCEPTION", "ExceptionID"); const now = new Date().toISOString();
  xv.prepare("INSERT INTO VOCEXCEPTION (ExceptionID, ExceptionGUID, VulnerabilityID, AssetVulnerabilityID, Scope, Title, Justification, CompensatingControl, ApprovedBy, Status, ExpiryDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), p.vulnerabilityId ?? null, p.assetVulnerabilityId ?? null, p.scope ?? "cve", p.title.slice(0, 300), (p.justification || "").slice(0, 2000), p.compensating ?? null, p.approvedBy ?? null, "Active", p.expiryDate ?? null, tenant, now);
  return { id };
}

/** Assign a remediation owner + target date to an asset-vulnerability instance (XORCISM). */
export function assignInstance(assetVulnId: number, p: { ownerPersonId?: number; targetDate?: string; priority?: string }, tenant: number | null): boolean {
  const xo = getDb("XORCISM"); const avc = cols("XORCISM", "ASSETVULNERABILITY");
  const tw = tenant != null && avc.has("TenantID") ? "AND TenantID = ?" : "";
  if (!xo.prepare(`SELECT 1 FROM ASSETVULNERABILITY WHERE AssetVulnerabilityID = ? ${tw}`).get(...(tw ? [assetVulnId, tenant] : [assetVulnId]))) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (p.ownerPersonId != null && avc.has("RemediationOwnerPersonID")) { sets.push("RemediationOwnerPersonID = ?"); vals.push(p.ownerPersonId); }
  if (p.targetDate != null && avc.has("TargetDate")) { sets.push("TargetDate = ?"); vals.push(p.targetDate); }
  if (p.priority != null && avc.has("Priority")) { sets.push("Priority = ?"); vals.push(p.priority); }
  if (!sets.length) return true;
  vals.push(assetVulnId);
  xo.prepare(`UPDATE ASSETVULNERABILITY SET ${sets.join(", ")} WHERE AssetVulnerabilityID = ?`).run(...vals);
  return true;
}

export function remediateInstance(assetVulnId: number, tenant: number | null): boolean {
  const xo = getDb("XORCISM"); const avc = cols("XORCISM", "ASSETVULNERABILITY");
  if (!avc.has("PatchStatus")) return false;
  const tw = tenant != null && avc.has("TenantID") ? "AND TenantID = ?" : "";
  const r = xo.prepare(`UPDATE ASSETVULNERABILITY SET PatchStatus = 'Patched'${avc.has("PatchedDate") ? ", PatchedDate = ?" : ""} WHERE AssetVulnerabilityID = ? ${tw}`)
    .run(...[...(avc.has("PatchedDate") ? [new Date().toISOString()] : []), assetVulnId, ...(tw ? [tenant] : [])]);
  return r.changes > 0;
}

// ── seed ──────────────────────────────────────────────────────────────────────
export function seedVoc(tenant: number): { slaTiers: number; campaigns: number; exceptions: number; backfilled: number } {
  const xv = getDb("XVULNERABILITY");
  let st = 0;
  if (!(xv.prepare("SELECT COUNT(*) n FROM VOCSLATIER").get() as { n: number }).n) {
    let id = 1; const ins = xv.prepare("INSERT INTO VOCSLATIER (SlaID, Tier, RemediationDays, Label, SortOrder, TenantID) VALUES (?,?,?,?,?,?)");
    DEFAULT_TIERS.forEach((t, i) => { ins.run(id++, t.tier, t.days, t.tier === "KEV" ? "Known-exploited (CISA BOD 22-01)" : `${t.tier} severity`, i, null); st++; });
  }
  let bf = 0;
  // backfill ASSETVULNERABILITY operational data so the VOC has realistic KPIs (ages, some remediated, owners)
  const xo = getDb("XORCISM"); const avc = cols("XORCISM", "ASSETVULNERABILITY");
  if (avc.has("CreatedDate")) {
    const ownerId = (xo.prepare("SELECT PersonID FROM PERSON WHERE FullName LIKE '%Tom%' LIMIT 1").get() as { PersonID: number } | undefined)?.PersonID ?? null;
    const links = xo.prepare(`SELECT AssetVulnerabilityID, CreatedDate, PatchStatus, PatchedDate, RemediationOwnerPersonID FROM ASSETVULNERABILITY ${avc.has("TenantID") ? "WHERE TenantID = ?" : ""}`).all(...(avc.has("TenantID") ? [tenant] : [])) as any[];
    links.forEach((l, i) => {
      const sets: string[] = []; const vals: unknown[] = [];
      // stagger discovery dates 5..120 days ago so aging buckets populate
      if (!l.CreatedDate || ms(l.CreatedDate) == null) { const dage = 5 + (i * 17) % 115; sets.push("CreatedDate = ?"); vals.push(new Date(Date.now() - dage * 86400000).toISOString()); }
      // remediate ~30% (every 3rd) to give MTTR + velocity + coverage
      if (i % 3 === 0 && avc.has("PatchStatus") && !DONE.test(String(l.PatchStatus ?? ""))) {
        sets.push("PatchStatus = ?"); vals.push("Patched");
        if (avc.has("PatchedDate")) { sets.push("PatchedDate = ?"); vals.push(new Date(Date.now() - ((i * 5) % 20) * 86400000).toISOString()); }
      }
      if (ownerId != null && i % 2 === 0 && avc.has("RemediationOwnerPersonID") && l.RemediationOwnerPersonID == null) { sets.push("RemediationOwnerPersonID = ?"); vals.push(ownerId); }
      if (sets.length) { vals.push(l.AssetVulnerabilityID); xo.prepare(`UPDATE ASSETVULNERABILITY SET ${sets.join(", ")} WHERE AssetVulnerabilityID = ?`).run(...vals); bf++; }
    });
  }
  let nc = 0, ne = 0;
  if (!(xv.prepare("SELECT COUNT(*) n FROM VOCCAMPAIGN WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) {
    createCampaign({ name: "KEV burndown — Q2", scope: "kev", targetDate: new Date(Date.now() + 21 * 86400000).toISOString().slice(0, 10), description: "Remediate all known-exploited (CISA KEV) vulnerabilities this sprint." }, tenant);
    createCampaign({ name: "Critical patch sprint", scope: "critical", targetDate: new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10), description: "Clear the critical-severity backlog." }, tenant); nc = 2;
  }
  if (!(xv.prepare("SELECT COUNT(*) n FROM VOCEXCEPTION WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) {
    createException({ title: "Legacy app — CVE deferred pending EOL migration", scope: "instance", justification: "Vendor app reaches end-of-life in Q4; mitigated by network segmentation + WAF. Remediation = decommission.", compensating: "Network segmentation, WAF virtual patch", approvedBy: "Sara Klein (GRC Lead)", expiryDate: new Date(Date.now() + 120 * 86400000).toISOString().slice(0, 10) }, tenant); ne = 1;
  }
  return { slaTiers: st, campaigns: nc, exceptions: ne, backfilled: bf };
}
