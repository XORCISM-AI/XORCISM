/**
 * engagements.ts — Pentest engagements modeled as AUDITs (AuditType = "Pentest").
 *
 * An engagement is an XCOMPLIANCE.AUDIT row of type "Pentest". It scopes ASSETs
 * (XORCISM.ASSETAUDIT), runs tool connectors against their targets (via the job
 * queue + a backing XENGAGEMENT for ROE — see routes/pentest.ts), and collects
 * AUDITFINDINGs (linked to the audit via a new AuditID column + to assets via
 * ASSETAUDITFINDING) and VULNERABILITYs (ASSETVULNERABILITY → XVULNERABILITY).
 *
 * All reads/writes are tenant-scoped through the parent AUDIT (which carries
 * TenantID); AUDITFINDING / ASSETAUDIT(FINDING) inherit scope from their audit.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export const PENTEST_TYPE = "Pentest";

function now(): string {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}
function today(): string {
  return new Date().toISOString().slice(0, 10);
}
function cols(db: ReturnType<typeof getDb>, table: string): Set<string> {
  return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
}

/** Idempotent: AUDITFINDING gains AuditID (link to its engagement) + Source. Run after ensureComplianceDb. */
export function ensurePentestColumns(): void {
  const db = getDb("XCOMPLIANCE");
  const c = cols(db, "AUDITFINDING");
  if (!c.has("AuditID")) db.exec('ALTER TABLE "AUDITFINDING" ADD COLUMN AuditID INTEGER');
  if (!c.has("Source")) db.exec('ALTER TABLE "AUDITFINDING" ADD COLUMN Source TEXT');
  db.exec("CREATE INDEX IF NOT EXISTS ix_auditfinding_audit ON AUDITFINDING(AuditID)");
}

export interface Engagement {
  AuditID: number; AuditName: string; AuditScope: string | null; AuditorName: string | null;
  AuditStatus: string | null; AuditDate: string | null; AuditClosureDate: string | null;
  AuditDescription: string | null; assets?: number; findings?: number; openFindings?: number;
}

/** Restricts an audit id to a tenant-scoped pentest engagement (or undefined). */
export function getEngagement(auditId: number, tenant: number | null): Engagement | undefined {
  const db = getDb("XCOMPLIANCE");
  const where = ["AuditID = ?", "AuditType = ?"];
  const args: unknown[] = [auditId, PENTEST_TYPE];
  if (tenant != null) { where.push("TenantID = ?"); args.push(tenant); }
  return db.prepare(
    `SELECT AuditID, AuditName, AuditScope, AuditorName, AuditStatus, AuditDate, AuditClosureDate, AuditDescription
     FROM AUDIT WHERE ${where.join(" AND ")}`
  ).get(...args) as Engagement | undefined;
}

export function listEngagements(tenant: number | null): Engagement[] {
  const db = getDb("XCOMPLIANCE");
  const where = ["AuditType = ?"];
  const args: unknown[] = [PENTEST_TYPE];
  if (tenant != null) { where.push("TenantID = ?"); args.push(tenant); }
  const rows = db.prepare(
    `SELECT AuditID, AuditName, AuditScope, AuditorName, AuditStatus, AuditDate, AuditClosureDate, AuditDescription
     FROM AUDIT WHERE ${where.join(" AND ")} ORDER BY AuditID DESC`
  ).all(...args) as Engagement[];
  const xo = getDb("XORCISM");
  for (const e of rows) {
    try { e.assets = (xo.prepare("SELECT COUNT(*) n FROM ASSETAUDIT WHERE AuditID = ?").get(e.AuditID) as { n: number }).n; } catch { e.assets = 0; }
    try {
      const f = db.prepare(
        "SELECT COUNT(*) n, SUM(CASE WHEN LOWER(COALESCE(FindingStatus,'open')) NOT IN ('closed','resolved','fixed','remediated') THEN 1 ELSE 0 END) o FROM AUDITFINDING WHERE AuditID = ?"
      ).get(e.AuditID) as { n: number; o: number };
      e.findings = f.n; e.openFindings = f.o ?? 0;
    } catch { e.findings = 0; e.openFindings = 0; }
  }
  return rows;
}

export function createEngagement(
  o: { name: string; scope?: string; lead?: string; status?: string; description?: string; startDate?: string },
  tenant: number | null
): number {
  const db = getDb("XCOMPLIANCE");
  const c = cols(db, "AUDIT");
  const fields = ["AuditID", "AuditGUID", "AuditName", "AuditType", "AuditScope", "AuditorName", "AuditStatus", "AuditDate", "AuditDescription"];
  const place = ["(SELECT COALESCE(MAX(AuditID),0)+1 FROM AUDIT)", "?", "?", "?", "?", "?", "?", "?", "?"];
  const vals: unknown[] = [randomUUID(), o.name.slice(0, 300), PENTEST_TYPE, (o.scope || "").slice(0, 4000) || null,
    (o.lead || "").slice(0, 200) || null, o.status || "Planned", o.startDate || today(), (o.description || "").slice(0, 4000) || null];
  if (c.has("AuditCategory")) { fields.push("AuditCategory"); place.push("?"); vals.push(PENTEST_TYPE); }
  if (c.has("TenantID")) { fields.push("TenantID"); place.push("?"); vals.push(tenant); }
  db.prepare(`INSERT INTO AUDIT (${fields.join(",")}) VALUES (${place.join(",")})`).run(...vals);
  return (db.prepare("SELECT MAX(AuditID) m FROM AUDIT WHERE AuditGUID = ?").get(vals[0]) as { m: number }).m;
}

export function updateEngagement(
  auditId: number, tenant: number | null,
  o: { name?: string; scope?: string; lead?: string; status?: string; description?: string }
): boolean {
  if (!getEngagement(auditId, tenant)) return false;
  const db = getDb("XCOMPLIANCE");
  const set: string[] = []; const args: unknown[] = [];
  if (o.name != null) { set.push("AuditName = ?"); args.push(o.name.slice(0, 300)); }
  if (o.scope != null) { set.push("AuditScope = ?"); args.push(o.scope.slice(0, 4000)); }
  if (o.lead != null) { set.push("AuditorName = ?"); args.push(o.lead.slice(0, 200)); }
  if (o.description != null) { set.push("AuditDescription = ?"); args.push(o.description.slice(0, 4000)); }
  if (o.status != null) {
    set.push("AuditStatus = ?"); args.push(o.status);
    if (/clos/i.test(o.status)) { set.push("AuditClosureDate = ?"); args.push(today()); }
  }
  if (!set.length) return true;
  args.push(auditId);
  db.prepare(`UPDATE AUDIT SET ${set.join(", ")} WHERE AuditID = ?`).run(...args);
  return true;
}

// ── Scope (assets) ───────────────────────────────────────────────────────────
export interface ScopeAsset {
  AssetID: number; AssetName: string; websiteurl: string | null;
  ipaddressIPv4: string | null; ipaddressIPv6: string | null;
  ipnetrangestartIPv4: string | null; ipnetrangeendIPv4: string | null;
  fqdn: string | null; hostname: string | null; RiskScore: number | null;
}

export function getEngagementAssets(auditId: number): ScopeAsset[] {
  const xo = getDb("XORCISM");
  return xo.prepare(
    `SELECT a.AssetID, a.AssetName, a.websiteurl, a.ipaddressIPv4, a.ipaddressIPv6,
            a.ipnetrangestartIPv4, a.ipnetrangeendIPv4, a.fqdn, a.hostname, a.RiskScore
     FROM ASSETAUDIT aa JOIN ASSET a ON a.AssetID = aa.AssetID
     WHERE aa.AuditID = ? ORDER BY a.AssetName`
  ).all(auditId) as ScopeAsset[];
}

/** Replaces the engagement's in-scope assets (tenant-checked). Returns the new count. */
export function setEngagementAssets(auditId: number, assetIds: number[], tenant: number | null): number {
  const xo = getDb("XORCISM");
  // keep only assets that exist within the tenant
  const valid = new Set<number>();
  if (assetIds.length) {
    const ph = assetIds.map(() => "?").join(",");
    const where = tenant != null ? `AND TenantID = ${tenant}` : "";
    for (const r of xo.prepare(`SELECT AssetID FROM ASSET WHERE AssetID IN (${ph}) ${where}`).all(...assetIds) as { AssetID: number }[]) valid.add(r.AssetID);
  }
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM ASSETAUDIT WHERE AuditID = ?").run(auditId);
    const ts = now();
    for (const aid of valid) {
      xo.prepare(
        `INSERT INTO ASSETAUDIT (AssetAuditID, AssetAuditGUID, AssetID, AuditID, Date, ValidFrom)
         VALUES ((SELECT COALESCE(MAX(AssetAuditID),0)+1 FROM ASSETAUDIT), ?, ?, ?, ?, ?)`
      ).run(randomUUID(), aid, auditId, ts, ts);
    }
  });
  tx();
  return valid.size;
}

/** Web / network scan targets derived from the in-scope assets (for ROE + connector launch). */
export function engagementTargets(assets: ScopeAsset[]): { asset: string; target: string; kind: "web" | "net" }[] {
  const out: { asset: string; target: string; kind: "web" | "net" }[] = [];
  for (const a of assets) {
    const name = a.AssetName || `#${a.AssetID}`;
    if (a.websiteurl) out.push({ asset: name, target: String(a.websiteurl).trim(), kind: "web" });
    for (const ip of [a.ipaddressIPv4, a.ipaddressIPv6]) if (ip && String(ip).trim()) out.push({ asset: name, target: String(ip).trim(), kind: "net" });
    if (a.ipnetrangestartIPv4 && a.ipnetrangeendIPv4) out.push({ asset: name, target: `${a.ipnetrangestartIPv4}-${a.ipnetrangeendIPv4}`, kind: "net" });
    // bare hostname/fqdn → both web and net candidates
    const host = (a.fqdn || a.hostname || "").toString().trim();
    if (host && !a.websiteurl) out.push({ asset: name, target: host, kind: "net" });
  }
  return out;
}

// ── Vulnerabilities in scope ─────────────────────────────────────────────────
export interface ScopeVuln {
  AssetVulnerabilityID: number; AssetID: number; AssetName: string; VulnerabilityID: number;
  ref: string; severity: string; cvss: number | null; kev: number; epss: number | null; status: string | null;
}

function sevFromCvss(c: number): string {
  if (!Number.isFinite(c) || c <= 0) return "";
  if (c >= 9) return "Critical"; if (c >= 7) return "High"; if (c >= 4) return "Medium"; return "Low";
}

export function vulnsForEngagement(auditId: number): ScopeVuln[] {
  const xo = getDb("XORCISM");
  const av = xo.prepare(
    `SELECT av.AssetVulnerabilityID, av.AssetID, a.AssetName, av.VulnerabilityID, av.Status
     FROM ASSETAUDIT aa JOIN ASSETVULNERABILITY av ON av.AssetID = aa.AssetID
     JOIN ASSET a ON a.AssetID = av.AssetID
     WHERE aa.AuditID = ? AND COALESCE(av.FalsePositive,0)=0 LIMIT 2000`
  ).all(auditId) as { AssetVulnerabilityID: number; AssetID: number; AssetName: string; VulnerabilityID: number; Status: string | null }[];
  const ids = [...new Set(av.map((r) => r.VulnerabilityID).filter(Boolean))];
  const meta = new Map<number, { ref: string; cvss: number | null; kev: number; epss: number | null }>();
  if (ids.length) {
    try {
      const xv = getDb("XVULNERABILITY");
      const ph = ids.map(() => "?").join(",");
      for (const v of xv.prepare(
        `SELECT VulnerabilityID id, COALESCE(NULLIF(VULReferential,''), NULLIF(VULName,''), 'Vuln #'||VulnerabilityID) ref,
                CVSSBaseScore cvss, KEV kev, EPSS epss FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`
      ).all(...ids) as { id: number; ref: string; cvss: number | null; kev: unknown; epss: number | null }[]) {
        meta.set(v.id, { ref: v.ref, cvss: v.cvss, kev: Number(v.kev) || 0, epss: v.epss });
      }
    } catch { /* XVULNERABILITY unavailable */ }
  }
  return av.map((r) => {
    const m = meta.get(r.VulnerabilityID);
    return {
      AssetVulnerabilityID: r.AssetVulnerabilityID, AssetID: r.AssetID, AssetName: r.AssetName,
      VulnerabilityID: r.VulnerabilityID, ref: m?.ref || `Vuln #${r.VulnerabilityID}`,
      severity: m && m.kev > 0 ? "KEV" : sevFromCvss(Number(m?.cvss)), cvss: m?.cvss ?? null,
      kev: m?.kev || 0, epss: m?.epss ?? null, status: r.Status,
    };
  });
}

// ── Findings ─────────────────────────────────────────────────────────────────
export interface Finding {
  AuditFindingID: number; FindingName: string; Severity: string | null; FindingStatus: string | null;
  FindingDescription: string | null; RemediationPlan: string | null; FindingDate: string | null;
  Source: string | null; assets?: { AssetID: number; AssetName: string }[];
}

export function getEngagementFindings(auditId: number): Finding[] {
  const db = getDb("XCOMPLIANCE");
  const rows = db.prepare(
    `SELECT AuditFindingID, FindingName, Severity, FindingStatus, FindingDescription, RemediationPlan, FindingDate, Source
     FROM AUDITFINDING WHERE AuditID = ? ORDER BY AuditFindingID DESC`
  ).all(auditId) as Finding[];
  const xo = getDb("XORCISM");
  for (const f of rows) {
    try {
      f.assets = xo.prepare(
        `SELECT a.AssetID, a.AssetName FROM ASSETAUDITFINDING af JOIN ASSET a ON a.AssetID = af.AssetID WHERE af.AuditFindingID = ?`
      ).all(f.AuditFindingID) as { AssetID: number; AssetName: string }[];
    } catch { f.assets = []; }
  }
  return rows;
}

export function createFinding(
  auditId: number,
  o: { name: string; severity?: string; status?: string; description?: string; remediation?: string; source?: string; assetIds?: number[] }
): number {
  const db = getDb("XCOMPLIANCE");
  const ts = now();
  db.prepare(
    `INSERT INTO AUDITFINDING (AuditFindingID, AuditFindingGUID, AuditID, FindingName, FindingDescription,
        FindingDate, FindingStatus, Severity, FindingCriticity, RemediationPlan, Source)
     VALUES ((SELECT COALESCE(MAX(AuditFindingID),0)+1 FROM AUDITFINDING), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(randomUUID(), auditId, o.name.slice(0, 300), (o.description || "").slice(0, 8000) || null, ts,
    o.status || "Open", o.severity || "Medium", o.severity || null, (o.remediation || "").slice(0, 8000) || null,
    (o.source || "manual").slice(0, 100));
  const fid = (db.prepare("SELECT MAX(AuditFindingID) m FROM AUDITFINDING WHERE AuditID = ?").get(auditId) as { m: number }).m;
  if (o.assetIds && o.assetIds.length) linkFindingAssets(fid, o.assetIds);
  return fid;
}

export function linkFindingAssets(findingId: number, assetIds: number[]): void {
  const xo = getDb("XORCISM");
  const ts = now();
  for (const aid of [...new Set(assetIds)].filter((n) => Number.isInteger(n) && n > 0)) {
    try {
      xo.prepare(
        `INSERT INTO ASSETAUDITFINDING (AssetAuditFindingID, AssetAuditFindingGUID, AssetID, AuditFindingID, Date, Status, ValidFrom)
         VALUES ((SELECT COALESCE(MAX(AssetAuditFindingID),0)+1 FROM ASSETAUDITFINDING), ?, ?, ?, ?, 'Open', ?)`
      ).run(randomUUID(), aid, findingId, ts, ts);
    } catch { /* link table absent / dup */ }
  }
}

/** Promotes an in-scope vulnerability to an AUDITFINDING (linked to its asset). */
export function findingFromVuln(auditId: number, vulnerabilityId: number, assetId: number): number {
  const v = vulnsForEngagement(auditId).find((x) => x.VulnerabilityID === vulnerabilityId && x.AssetID === assetId)
    || vulnsForEngagement(auditId).find((x) => x.VulnerabilityID === vulnerabilityId);
  const ref = v?.ref || `Vuln #${vulnerabilityId}`;
  const sev = v?.severity === "KEV" ? "Critical" : (v?.severity || "Medium");
  return createFinding(auditId, {
    name: ref, severity: sev || "Medium", status: "Open", source: "vulnerability",
    description: `Confirmed exploitable vulnerability ${ref}` + (v?.cvss ? ` (CVSS ${v.cvss})` : "") + (v && v.kev > 0 ? " — in CISA KEV" : ""),
    assetIds: assetId ? [assetId] : (v ? [v.AssetID] : []),
  });
}
