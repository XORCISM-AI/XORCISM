/**
 * vpr.ts — Tenable VPR (Vulnerability Priority Rating) support for VULNERABILITY.
 *
 * VPR is Tenable's 0.0-10.0 risk-based score: unlike static CVSS, it is dominated by *threat*
 * intelligence (threat recency & intensity, exploit-code maturity, vulnerability age, product
 * coverage), so a high-CVSS bug with no real-world threat scores LOWER than CVSS, and an
 * actively-exploited one scores higher. XORCISM stores a real VPR when it is imported from a
 * Tenable / Nessus export (VprSource='Tenable'), and otherwise derives a VPR-style *estimate*
 * from its own signals (CVSS + EPSS + KEV + public-exploit + in-the-wild CTI), clearly labelled
 * 'estimated'. The threat level mirrors Tenable's bands (Critical 9-10 / High 7-8.9 / Medium
 * 4-6.9 / Low 0-3.9).
 */
import { getDb } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const colset = (db: ReturnType<typeof getDb>, t: string): Set<string> => {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
};
const num = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) ? n : null; };

/** Tenable VPR threat-level band for a 0-10 score. */
export function vprThreatLevel(score: number | null): string {
  if (score == null) return "";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export interface VprSignals { cvss?: number | null; epss?: number | null; kev?: boolean; exploits?: number; itw?: boolean; }

/**
 * Derive a VPR-style estimate from XORCISM's own signals. Mirrors Tenable's published behaviour:
 * CVSS contributes a minority of the base; threat intelligence (KEV / public exploit / EPSS /
 * in-the-wild) is the dominant amplifier - so untested high-CVSS issues land mid-band and
 * actively-exploited ones reach the top. Returns { score (0-10, 1dp), drivers[] }.
 */
export function estimateVpr(s: VprSignals): { score: number; drivers: string[] } {
  const drivers: string[] = [];
  const cvss = num(s.cvss) ?? 0;
  let v = cvss * 0.4; // CVSS impact = ~40% of the base
  if (cvss > 0) drivers.push(`CVSS impact ${cvss}`);
  if (s.kev) { v += 3.0; drivers.push("Known-exploited (CISA KEV)"); }
  if (s.itw) { v += 1.5; drivers.push("Threat sources: in-the-wild"); }
  if ((s.exploits ?? 0) > 0) { v += 1.5; drivers.push("Exploit code mature/available"); }
  const epss = num(s.epss);
  if (epss != null && epss > 0) { v += epss * 3.0; drivers.push(`Threat intensity (EPSS ${(epss * 100).toFixed(1)}%)`); }
  if (!s.kev && !s.itw && (s.exploits ?? 0) === 0 && (epss ?? 0) < 0.05) drivers.push("No active threat (low recency)");
  const score = Math.max(0, Math.min(10, Math.round(v * 10) / 10));
  return { score, drivers };
}

const tw = (tenant: number | null): string => (tenant != null ? "(TenantID = ? OR TenantID IS NULL)" : "1=1");
const ta = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

/** Persist a VPR on one vulnerability (imported Tenable value or a manual override). */
export function setVpr(vid: number, opts: { score: number; drivers?: string; source?: string }): { ok: boolean } {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "VULNERABILITY")) return { ok: false };
  const score = Math.max(0, Math.min(10, Number(opts.score)));
  const r = db.prepare("UPDATE VULNERABILITY SET Vpr=?, VprThreatLevel=?, VprDrivers=?, VprSource=?, VprUpdated=? WHERE VulnerabilityID=?")
    .run(score, vprThreatLevel(score), (opts.drivers || "").slice(0, 1000), (opts.source || "Tenable").slice(0, 30), new Date().toISOString(), vid);
  return { ok: r.changes > 0 };
}

/**
 * Fill a VPR-style estimate for vulnerabilities that do not carry an imported Tenable VPR.
 * Never overwrites a 'Tenable' value. Returns how many were (re)estimated.
 */
export function recomputeVprEstimates(tenant: number | null, force = false): { updated: number } {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "VULNERABILITY")) return { updated: 0 };
  const c = colset(db, "VULNERABILITY");
  if (!c.has("Vpr")) return { updated: 0 };
  const tcl = tenant != null && c.has("TenantID") ? ` AND ${tw(tenant)}` : "";
  const args = tenant != null && c.has("TenantID") ? ta(tenant) : [];
  const where = force ? "VprSource IS NULL OR VprSource != 'Tenable'" : "(Vpr IS NULL OR VprSource = 'estimated')";
  const rows = db.prepare(`SELECT VulnerabilityID id, CVSSBaseScore cvss, ${c.has("EPSS") ? "EPSS" : "NULL"} epss, ${c.has("KEV") ? "KEV" : "0"} kev FROM VULNERABILITY WHERE (${where})${tcl}`).all(...args) as any[];
  if (!rows.length) return { updated: 0 };
  // public-exploit signal (best-effort: a VULNERABILITYFORCPE / exploit reference table may exist; default 0)
  const now = new Date().toISOString();
  const upd = db.prepare("UPDATE VULNERABILITY SET Vpr=?, VprThreatLevel=?, VprDrivers=?, VprSource='estimated', VprUpdated=? WHERE VulnerabilityID=?");
  let n = 0;
  const tx = db.transaction(() => {
    for (const r of rows) {
      const est = estimateVpr({ cvss: num(r.cvss), epss: num(r.epss), kev: !!(r.kev && Number(r.kev) !== 0) });
      upd.run(est.score, vprThreatLevel(est.score), est.drivers.join("; ").slice(0, 1000), now, r.id);
      n++;
    }
  });
  tx();
  return { updated: n };
}

/** VPR posture: counts with VPR, by threat level, Tenable-vs-estimated split, average, and the top-by-VPR list. */
export function vprInventory(tenant: number | null): any {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "VULNERABILITY")) return { total: 0 };
  const c = colset(db, "VULNERABILITY");
  if (!c.has("Vpr")) return { total: 0, supported: false };
  const tcl = tenant != null && c.has("TenantID") ? ` AND ${tw(tenant)}` : "";
  const args = tenant != null && c.has("TenantID") ? ta(tenant) : [];
  const refCol = c.has("VULReferential") ? "COALESCE(NULLIF(VULReferential,''), NULLIF(VULName,''), 'Vuln #'||VulnerabilityID)" : "'Vuln #'||VulnerabilityID";
  const rows = db.prepare(`SELECT VulnerabilityID id, ${refCol} ref, Vpr, VprThreatLevel level, VprSource source, ${c.has("CVSSBaseScore") ? "CVSSBaseScore" : "NULL"} cvss FROM VULNERABILITY WHERE Vpr IS NOT NULL${tcl} ORDER BY Vpr DESC`).all(...args) as any[];
  const by = (k: string): Record<string, number> => rows.reduce((m: any, r: any) => { const x = r[k] || "-"; m[x] = (m[x] || 0) + 1; return m; }, {});
  const byLevel = by("level");
  return {
    supported: true,
    total: rows.length,
    critical: byLevel.Critical || 0, high: byLevel.High || 0, medium: byLevel.Medium || 0, low: byLevel.Low || 0,
    tenable: rows.filter((r) => r.source === "Tenable").length,
    estimated: rows.filter((r) => r.source === "estimated").length,
    avgVpr: rows.length ? Math.round((rows.reduce((n, r) => n + (Number(r.Vpr) || 0), 0) / rows.length) * 10) / 10 : 0,
    // where VPR materially disagrees with CVSS (Tenable's headline value): high CVSS but low VPR, or low CVSS but high VPR
    vprUpliftedFromCvss: rows.filter((r) => r.cvss != null && Number(r.Vpr) - Number(r.cvss) >= 2).length,
    vprDeprioritisedFromCvss: rows.filter((r) => r.cvss != null && Number(r.cvss) - Number(r.Vpr) >= 2).length,
    top: rows.slice(0, 25).map((r) => ({ id: r.id, ref: r.ref, vpr: r.Vpr, level: r.level, source: r.source, cvss: r.cvss })),
  };
}
