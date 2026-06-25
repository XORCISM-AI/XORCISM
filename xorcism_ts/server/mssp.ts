/**
 * mssp.ts — MSSP / multi-tenant rollup cockpit (/mssp).
 *
 * A super-admin-only cross-tenant view: one row per tenant with its headline posture (enterprise
 * risk score → posture grade), asset/vuln/KEV counts, open high/critical incidents, open compliance
 * findings and AI-governance gaps — so an MSSP (or a parent org) can compare clients at a glance and
 * spot the worst-off. Read-only; reuses the per-tenant scoring already in the platform.
 */
import { getDb } from "./db";
import { enterpriseRiskBreakdown } from "./riskscore";

const safe = <T>(fn: () => T, dflt: T): T => { try { return fn(); } catch { return dflt; } };
// Posture score = 200/(200+EnterpriseRisk) × 100 (mirrors boardreport.ts).
const postureScore = (enterpriseRisk: number): number => Math.round((200 / (200 + Math.max(0, enterpriseRisk))) * 100);
const grade = (s: number): string => (s >= 85 ? "A" : s >= 70 ? "B" : s >= 55 ? "C" : s >= 40 ? "D" : "F");

interface TenantRow {
  tenant: number; name: string; posture: number; grade: string; enterpriseRisk: number;
  assets: number; openVulns: number; kev: number; openIncidents: number; openFindings: number; aiGaps: number;
}

/** List the tenants known to the platform (XID.TENANT if present, else distinct ASSET.TenantID). */
function listTenants(): { id: number; name: string }[] {
  const out = new Map<number, string>();
  safe(() => {
    const xid = getDb("XID");
    if (xid.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='TENANT'").get()) {
      for (const r of xid.prepare("SELECT TenantID id, COALESCE(TenantName, Name, 'Tenant '||TenantID) name FROM TENANT").all() as { id: number; name: string }[]) out.set(r.id, r.name);
    }
  }, undefined);
  safe(() => {
    const xo = getDb("XORCISM");
    const c = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((x) => x.name));
    if (c.has("TenantID")) for (const r of xo.prepare("SELECT DISTINCT TenantID id FROM ASSET WHERE TenantID IS NOT NULL").all() as { id: number }[]) if (!out.has(r.id)) out.set(r.id, `Tenant ${r.id}`);
  }, undefined);
  return [...out.entries()].map(([id, name]) => ({ id, name })).sort((a, b) => a.id - b.id);
}

function tenantRow(t: { id: number; name: string }): TenantRow {
  const breakdown = safe(() => enterpriseRiskBreakdown(t.id), { total: 0 } as any);
  const posture = safe(() => postureScore(breakdown.total), 0);
  const xo = getDb("XORCISM");
  const aHasT = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((x) => x.name)).has("TenantID");
  const assets = safe(() => (xo.prepare(`SELECT COUNT(*) n FROM ASSET ${aHasT ? "WHERE TenantID=?" : ""}`).get(...(aHasT ? [t.id] : [])) as { n: number }).n, 0);
  const openVulns = safe(() => (xo.prepare(
    `SELECT COUNT(*) n FROM ASSETVULNERABILITY av ${aHasT ? "JOIN ASSET a ON a.AssetID=av.AssetID WHERE a.TenantID=? AND" : "WHERE"} COALESCE(av.FalsePositive,0)=0 AND LOWER(COALESCE(av.Status,'')) NOT IN ('fixed','patched','resolved','closed')`
  ).get(...(aHasT ? [t.id] : [])) as { n: number }).n, 0);
  const kev = safe(() => {
    const xv = getDb("XVULNERABILITY");
    const vcols = new Set((xv.prepare('PRAGMA table_info("VULNERABILITY")').all() as { name: string }[]).map((x) => x.name));
    const kevExpr = vcols.has("IsKEV") ? "IsKEV" : vcols.has("KEV") ? "KEV" : null;
    if (!kevExpr) return 0;
    const vids = xo.prepare(`SELECT DISTINCT av.VulnerabilityID id FROM ASSETVULNERABILITY av ${aHasT ? "JOIN ASSET a ON a.AssetID=av.AssetID WHERE a.TenantID=? AND" : "WHERE"} COALESCE(av.FalsePositive,0)=0`).all(...(aHasT ? [t.id] : [])) as { id: number }[];
    if (!vids.length) return 0;
    let n = 0;
    for (let i = 0; i < vids.length; i += 800) { const chunk = vids.slice(i, i + 800).map((v) => v.id); const ph = chunk.map(() => "?").join(","); n += (xv.prepare(`SELECT COUNT(*) n FROM VULNERABILITY WHERE ${kevExpr}=1 AND VulnerabilityID IN (${ph})`).get(...chunk) as { n: number }).n; }
    return n;
  }, 0);
  const openIncidents = safe(() => {
    const xi = getDb("XINCIDENT");
    const c = new Set((xi.prepare('PRAGMA table_info("INCIDENT")').all() as { name: string }[]).map((x) => x.name));
    if (!c.has("Severity")) return 0;
    const tw = c.has("TenantID") ? "AND TenantID=?" : "";
    return (xi.prepare(`SELECT COUNT(*) n FROM INCIDENT WHERE LOWER(COALESCE(Severity,'')) IN ('critical','high') AND LOWER(COALESCE(Status,'')) NOT IN ('closed','resolved','done') ${tw}`).get(...(c.has("TenantID") ? [t.id] : [])) as { n: number }).n;
  }, 0);
  const openFindings = safe(() => {
    const xc = getDb("XCOMPLIANCE");
    return (xc.prepare(
      `SELECT COUNT(*) n FROM AUDITFINDING f JOIN AUDIT a ON a.AuditID=f.AuditID WHERE LOWER(COALESCE(f.FindingStatus,''))<>'closed' AND (a.TenantID=? OR a.TenantID IS NULL)`
    ).get(t.id) as { n: number }).n;
  }, 0);
  const aiGaps = safe(() => {
    const xo2 = getDb("XORCISM");
    if (!xo2.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='AISYSTEM'").get()) return 0;
    return (xo2.prepare("SELECT COUNT(*) n FROM AISYSTEM WHERE (TenantID=? OR TenantID IS NULL) AND (Frameworks IS NULL OR Frameworks='' OR Guardrails IS NULL OR Guardrails='')").get(t.id) as { n: number }).n;
  }, 0);
  return { tenant: t.id, name: t.name, posture, grade: grade(posture), enterpriseRisk: Math.round(breakdown.total || 0), assets, openVulns, kev, openIncidents, openFindings, aiGaps };
}

export function msspRollup(): any {
  const tenants = listTenants();
  const rows = tenants.map(tenantRow).sort((a, b) => a.posture - b.posture); // worst posture first
  const summary = {
    tenants: rows.length,
    avgPosture: rows.length ? Math.round(rows.reduce((s, r) => s + r.posture, 0) / rows.length) : 0,
    atRisk: rows.filter((r) => r.posture < 55).length,
    totalKev: rows.reduce((s, r) => s + r.kev, 0),
    totalOpenIncidents: rows.reduce((s, r) => s + r.openIncidents, 0),
    totalOpenFindings: rows.reduce((s, r) => s + r.openFindings, 0),
  };
  return { summary, tenants: rows };
}
