/**
 * fusion.ts — Exploitability & relevance fusion score.
 *
 * Answers "is THIS exposure actually dangerous to ME?" by fusing every signal XORCISM
 * already holds into one 0–100 score + a transparent breakdown:
 *   EPSS (probability) · CVSS (severity) · KEV (known-exploited) · public exploit
 *   (Exploit-DB) · in-the-wild (CTI/INTELEXCHANGE) — then weighted by blast radius
 *   (how many assets, and their business value). No competitor has all these inputs
 *   under one roof, so none can compute this in one number.
 */
import { getDb } from "./db";
import { exploitsForCve } from "./exploitdb";
import { vprThreatLevel } from "./vpr";

export interface FusionScore {
  VulnerabilityID: number; ref: string; cvss: number | null; kev: number; epss: number | null;
  exploits: number; itw: boolean; assets: number; maxValue: number | null;
  publicFacing?: boolean; window?: "hours" | "days" | "weeks";
  score: number; priority: number; factors: string[];
  vpr?: number | null; vprLevel?: string; // Tenable VPR (or XORCISM estimate) — surfaced alongside the fusion score
  assetIds?: number[]; // the AssetIDs this exposure sits on (for attack-path reachability)
}

// AI-era patch window: with AI-assisted exploitation the median time-to-exploit has collapsed to hours,
// so the operative remediation window depends on demonstrated exploitability, not just severity.
function patchWindow(v: { kev: number; itw: boolean; exploits: number; epss: number | null }): "hours" | "days" | "weeks" {
  if (v.kev || v.itw || (v.exploits > 0 && (v.epss ?? 0) >= 0.5)) return "hours";
  if (v.exploits > 0 || (v.epss != null && v.epss >= 0.1)) return "days";
  return "weeks";
}

const CVE_RX = /CVE-\d{4}-\d{3,7}/i;

function colset(db: ReturnType<typeof getDb>, table: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
}

/** Compute the fused score + breakdown from the raw signals. */
function fuse(v: { VulnerabilityID: number; ref: string; cvss: number | null; kev: number; epss: number | null; exploits: number; itw: boolean; assets: number; maxValue: number | null; publicFacing?: boolean; vpr?: number | null }): FusionScore {
  const factors: string[] = [];
  let score = 0;
  if (v.epss != null && v.epss > 0) { const p = Math.round(v.epss * 40); score += p; factors.push(`EPSS ${(v.epss * 100).toFixed(1)}% (+${p})`); }
  if (v.cvss != null && v.cvss > 0) { const p = Math.round((v.cvss / 10) * 20); score += p; factors.push(`CVSS ${v.cvss} (+${p})`); }
  if (v.kev) { score += 25; factors.push("KEV — known exploited (+25)"); }
  if (v.exploits > 0) { score += 20; factors.push(`${v.exploits} public exploit${v.exploits > 1 ? "s" : ""} on Exploit-DB (+20)`); }
  if (v.itw) { score += 10; factors.push("Seen in CTI / in the wild (+10)"); }
  score = Math.min(100, score);
  const blast = Math.min(18, v.assets * 3);
  const valPts = v.maxValue && v.maxValue > 0 ? Math.min(18, Math.log10(v.maxValue + 1) * 6) : 0;
  // internet-facing / reachable assets raise real-world exploitability (reachability over abstract severity)
  const expoPts = v.publicFacing ? 12 : 0;
  const priority = Math.min(100, Math.round(score * 0.7 + blast + valPts + expoPts));
  if (v.assets) factors.push(`${v.assets} affected asset${v.assets > 1 ? "s" : ""}`);
  if (v.publicFacing) factors.push("internet-facing / reachable (+12)");
  const window = patchWindow(v);
  factors.push(window === "hours" ? "AI-era window: remediate within HOURS" : window === "days" ? "AI-era window: remediate within days" : "AI-era window: weeks");
  if (v.vpr != null) factors.push(`Tenable VPR ${v.vpr} (${vprThreatLevel(v.vpr)})`);
  return { ...v, publicFacing: !!v.publicFacing, window, score, priority, factors, vpr: v.vpr ?? null, vprLevel: v.vpr != null ? vprThreatLevel(v.vpr) : "" };
}

function cveOf(ref: string): string | null { const m = (ref || "").match(CVE_RX); return m ? m[0].toUpperCase() : null; }

/** In-the-wild CVE set from XTHREAT.INTELEXCHANGE (CTI). Best-effort. */
function itwCves(cves: string[]): Set<string> {
  const out = new Set<string>();
  if (!cves.length) return out;
  try {
    const xt = getDb("XTHREAT");
    if (!colset(xt, "INTELEXCHANGE").has("CveTags")) return out;
    const rows = xt.prepare("SELECT CveTags FROM INTELEXCHANGE WHERE CveTags IS NOT NULL AND CveTags<>''").all() as { CveTags: string }[];
    const hay = rows.map((r) => r.CveTags.toUpperCase()).join(" ");
    for (const c of cves) if (hay.includes(c)) out.add(c);
  } catch { /* XTHREAT unavailable */ }
  return out;
}

/** Fusion score for a single vulnerability (id). */
export function fusionForVuln(vid: number): FusionScore | null {
  const xo = getDb("XORCISM");
  const pub = colset(xo, "ASSET").has("PublicFacing") ? ", MAX(COALESCE(a.PublicFacing,0)) pub" : ", 0 pub";
  const agg = xo.prepare(
    `SELECT COUNT(DISTINCT av.AssetID) assets, MAX(COALESCE(a.BusinessValue, a.RiskScore, 0)) maxValue${pub}
     FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID=av.AssetID
     WHERE av.VulnerabilityID=? AND COALESCE(av.FalsePositive,0)=0`
  ).get(vid) as { assets: number; maxValue: number | null; pub: number } | undefined;
  let ref = `Vuln #${vid}`, cvss: number | null = null, kev = 0, epss: number | null = null, vpr: number | null = null;
  try {
    const xv = getDb("XVULNERABILITY");
    const hasVpr = colset(xv, "VULNERABILITY").has("Vpr");
    const m = xv.prepare(
      `SELECT COALESCE(NULLIF(VULReferential,''), NULLIF(VULName,''), 'Vuln #'||VulnerabilityID) ref, CVSSBaseScore cvss, KEV kev, EPSS epss${hasVpr ? ", Vpr vpr" : ""}
       FROM VULNERABILITY WHERE VulnerabilityID=?`
    ).get(vid) as { ref: string; cvss: number | null; kev: unknown; epss: number | null; vpr?: number | null } | undefined;
    if (m) { ref = m.ref; cvss = m.cvss; kev = Number(m.kev) || 0; epss = m.epss; vpr = m.vpr ?? null; }
  } catch { /* */ }
  const cve = cveOf(ref);
  const exploits = cve ? exploitsForCve(cve).length : 0;
  const itw = cve ? itwCves([cve]).has(cve) : false;
  return fuse({ VulnerabilityID: vid, ref, cvss, kev, epss, exploits, itw, assets: agg?.assets || 0, maxValue: agg?.maxValue ?? null, publicFacing: Number(agg?.pub) > 0, vpr });
}

/** Per-vuln exploitability (0–100, no blast radius) for a set of ids. Reused by the attack-path engine. */
export function vulnExploitability(vids: number[]): Map<number, number> {
  const out = new Map<number, number>();
  const ids = [...new Set(vids.filter((n) => Number.isInteger(n) && n > 0))];
  if (!ids.length) return out;
  const meta = new Map<number, { ref: string; cvss: number | null; kev: number; epss: number | null }>();
  try {
    const xv = getDb("XVULNERABILITY");
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
      for (const m of xv.prepare(
        `SELECT VulnerabilityID id, COALESCE(NULLIF(VULReferential,''), NULLIF(VULName,''), 'Vuln #'||VulnerabilityID) ref, CVSSBaseScore cvss, KEV kev, EPSS epss
         FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`
      ).all(...chunk) as { id: number; ref: string; cvss: number | null; kev: unknown; epss: number | null }[]) {
        meta.set(m.id, { ref: m.ref, cvss: m.cvss, kev: Number(m.kev) || 0, epss: m.epss });
      }
    }
  } catch { /* XVULNERABILITY unavailable */ }
  const cves = [...new Set(ids.map((id) => cveOf(meta.get(id)?.ref || "")).filter(Boolean) as string[])];
  const itw = itwCves(cves);
  for (const id of ids) {
    const m = meta.get(id);
    const cve = cveOf(m?.ref || "");
    let score = 0;
    if (m?.epss != null && m.epss > 0) score += m.epss * 40;
    if (m?.cvss != null && m.cvss > 0) score += (m.cvss / 10) * 20;
    if (m?.kev) score += 25;
    if (cve && exploitsForCve(cve).length) score += 20;
    if (cve && itw.has(cve)) score += 10;
    out.set(id, Math.min(100, Math.round(score)));
  }
  return out;
}

/** The prioritized exposure worklist: top vulns (on in-scope assets) by fused priority. */
export function topExposures(tenant: number | null, limit = 50): { results: FusionScore[]; scanned: number } {
  const xo = getDb("XORCISM");
  const aCols = colset(xo, "ASSET");
  const tenantClause = tenant != null && aCols.has("TenantID") ? "AND (a.TenantID = ? OR a.TenantID IS NULL)" : "";
  const args = tenant != null && aCols.has("TenantID") ? [tenant] : [];
  const pub = aCols.has("PublicFacing") ? "MAX(COALESCE(a.PublicFacing,0))" : "0";
  const agg = xo.prepare(
    `SELECT av.VulnerabilityID vid, COUNT(DISTINCT av.AssetID) assets, MAX(COALESCE(a.BusinessValue, a.RiskScore, 0)) maxValue,
            ${pub} pub, GROUP_CONCAT(DISTINCT av.AssetID) assetIds
     FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID=av.AssetID
     WHERE COALESCE(av.FalsePositive,0)=0 ${tenantClause}
     GROUP BY av.VulnerabilityID LIMIT 8000`
  ).all(...args) as { vid: number; assets: number; maxValue: number | null; pub: number; assetIds: string | null }[];
  if (!agg.length) return { results: [], scanned: 0 };

  const meta = new Map<number, { ref: string; cvss: number | null; kev: number; epss: number | null; vpr: number | null }>();
  try {
    const xv = getDb("XVULNERABILITY");
    const hasVpr = colset(xv, "VULNERABILITY").has("Vpr");
    const ids = agg.map((r) => r.vid);
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800);
      const ph = chunk.map(() => "?").join(",");
      for (const m of xv.prepare(
        `SELECT VulnerabilityID id, COALESCE(NULLIF(VULReferential,''), NULLIF(VULName,''), 'Vuln #'||VulnerabilityID) ref, CVSSBaseScore cvss, KEV kev, EPSS epss${hasVpr ? ", Vpr vpr" : ""}
         FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`
      ).all(...chunk) as { id: number; ref: string; cvss: number | null; kev: unknown; epss: number | null; vpr?: number | null }[]) {
        meta.set(m.id, { ref: m.ref, cvss: m.cvss, kev: Number(m.kev) || 0, epss: m.epss, vpr: m.vpr ?? null });
      }
    }
  } catch { /* XVULNERABILITY unavailable */ }

  const cves = [...new Set(agg.map((r) => cveOf(meta.get(r.vid)?.ref || "")).filter(Boolean) as string[])];
  const itw = itwCves(cves);

  const results = agg.map((r) => {
    const m = meta.get(r.vid);
    const ref = m?.ref || `Vuln #${r.vid}`;
    const cve = cveOf(ref);
    const fs = fuse({
      VulnerabilityID: r.vid, ref, cvss: m?.cvss ?? null, kev: m?.kev || 0, epss: m?.epss ?? null,
      exploits: cve ? exploitsForCve(cve).length : 0, itw: cve ? itw.has(cve) : false,
      assets: r.assets, maxValue: r.maxValue, publicFacing: Number(r.pub) > 0, vpr: m?.vpr ?? null,
    });
    fs.assetIds = String(r.assetIds || "").split(",").map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0).slice(0, 50);
    return fs;
  }).sort((a, b) => b.priority - a.priority || b.score - a.score || b.assets - a.assets).slice(0, Math.min(Math.max(1, limit), 500));

  return { results, scanned: agg.length };
}

export interface ImpactedAsset { id: number; name: string; criticality: string | null; businessValue: number | null; address: string | null; publicFacing: boolean; }

/** The in-scope assets impacted by a given vulnerability (for the exposure worklist "impacted assets" expand). */
export function assetsForVuln(vid: number, tenant: number | null): ImpactedAsset[] {
  const xo = getDb("XORCISM");
  if (!colset(xo, "ASSETVULNERABILITY").has("VulnerabilityID")) return [];
  const a = colset(xo, "ASSET");
  const tenantClause = tenant != null && a.has("TenantID") ? "AND (a.TenantID = ? OR a.TenantID IS NULL)" : "";
  const args: (number)[] = tenant != null && a.has("TenantID") ? [vid, tenant] : [vid];
  const crit = a.has("AssetCriticalityLevel") ? "a.AssetCriticalityLevel" : "NULL";
  const bv = a.has("BusinessValue") ? "a.BusinessValue" : (a.has("RiskScore") ? "a.RiskScore" : "NULL");
  const addr = ["fqdn", "hostname", "ipaddressIPv4", "websiteurl"].filter((c) => a.has(c)).map((c) => `a.${c}`);
  const addrExpr = addr.length ? `COALESCE(${addr.join(",")})` : "NULL";
  const pubExpr = a.has("websiteurl") || a.has("ipaddressIPv4")
    ? `(COALESCE(NULLIF(${a.has("websiteurl") ? "a.websiteurl" : "''"},''), '') <> '' OR COALESCE(${a.has("ipaddressIPv4") ? "a.ipaddressIPv4" : "''"},'') <> '')`
    : "0";
  const rows = xo.prepare(
    `SELECT DISTINCT a.AssetID id, a.AssetName name, ${crit} crit, ${bv} bv, ${addrExpr} addr, ${pubExpr} pub
     FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID = av.AssetID
     WHERE av.VulnerabilityID = ? AND COALESCE(av.FalsePositive,0)=0 ${tenantClause}
     ORDER BY COALESCE(${bv === "NULL" ? "0" : bv}, 0) DESC, a.AssetName LIMIT 200`
  ).all(...args) as { id: number; name: string | null; crit: string | null; bv: number | null; addr: string | null; pub: number }[];
  return rows.map((r) => ({
    id: Number(r.id), name: String(r.name ?? `Asset #${r.id}`),
    criticality: r.crit ? String(r.crit) : null, businessValue: r.bv != null ? Number(r.bv) : null,
    address: r.addr ? String(r.addr) : null, publicFacing: !!r.pub,
  }));
}
