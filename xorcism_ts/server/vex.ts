/**
 * vex.ts — OpenVEX export. Emits a VEX (Vulnerability Exploitability eXchange) document
 * from the asset↔vulnerability links so downstream consumers know which CVEs actually
 * affect your products and which are false-positives/fixed. Format: OpenVEX v0.2.0.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const CVE_RX = /CVE-\d{4}-\d{3,7}/i;

export function generateVex(tenant: number | null): unknown {
  const xo = getDb("XORCISM");
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const tcl = tenant != null && aCols.has("TenantID") ? 'AND (a."TenantID"=? OR a."TenantID" IS NULL)' : "";
  const targs = tenant != null && aCols.has("TenantID") ? [tenant] : [];
  const rows = xo.prepare(
    `SELECT av.VulnerabilityID vid, a.AssetName name, av.Status status, COALESCE(av.FalsePositive,0) fp
     FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID=av.AssetID WHERE 1=1 ${tcl}`
  ).all(...targs) as { vid: number; name: string; status: string | null; fp: number }[];

  const refByVid = new Map<number, string>();
  try {
    const xv = getDb("XVULNERABILITY");
    const ids = [...new Set(rows.map((r) => r.vid))];
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
      for (const m of xv.prepare(`SELECT VulnerabilityID id, COALESCE(VULReferential,VULName) ref FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { id: number; ref: string }[]) refByVid.set(m.id, m.ref);
    }
  } catch { /* */ }

  // group by CVE → { products, statuses }
  const byCve = new Map<string, { products: Set<string>; statuses: Set<string> }>();
  for (const r of rows) {
    const cve = (String(refByVid.get(r.vid) || "").toUpperCase().match(CVE_RX) || [])[0];
    if (!cve) continue;
    const e = byCve.get(cve) ?? byCve.set(cve, { products: new Set(), statuses: new Set() }).get(cve)!;
    e.products.add(r.name);
    e.statuses.add(r.fp ? "not_affected" : /fixed|resolved|remediated|closed/i.test(r.status || "") ? "fixed" : "affected");
  }

  const ts = new Date().toISOString();
  const statements = [...byCve.entries()].map(([cve, e]) => {
    // status precedence: affected > under_investigation > fixed > not_affected
    const status = e.statuses.has("affected") ? "affected" : e.statuses.has("fixed") ? "fixed" : "not_affected";
    const st: Record<string, unknown> = {
      vulnerability: { name: cve },
      products: [...e.products].slice(0, 200).map((p) => ({ "@id": `pkg:xorcism/asset/${encodeURIComponent(p)}` })),
      status,
    };
    if (status === "affected") st.action_statement = "Remediate per the prioritized exposure worklist (see /exposure).";
    if (status === "not_affected") st.justification = "component_not_present";
    return st;
  });

  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `https://xorcism.ai/vex/${randomUUID()}`,
    author: "XORCISM",
    role: "Asset Owner",
    timestamp: ts,
    version: 1,
    statements,
  };
}

/** Parse a VEX document (OpenVEX or CycloneDX-VEX) into {cve, status} statements. */
function parseVexStatements(doc: any): { cve: string; status: string }[] {
  const out: { cve: string; status: string }[] = [];
  const norm = (s: string): string => {
    const v = (s || "").toLowerCase();
    if (/not[_\s-]?affected|not_affected|false[_\s-]?positive/.test(v)) return "not_affected";
    if (/fixed|resolved|remediated|patched/.test(v)) return "fixed";
    if (/under[_\s-]?investigation|in_triage|exploitable|affected/.test(v)) return "affected";
    return v || "affected";
  };
  // OpenVEX: { statements:[{ vulnerability:{name|"@id"|cve}, status }] }
  for (const st of (doc?.statements || []) as any[]) {
    const v = st?.vulnerability;
    const name = typeof v === "string" ? v : (v?.name || v?.["@id"] || v?.cve || "");
    const cve = (String(name).toUpperCase().match(CVE_RX) || [])[0];
    if (cve) out.push({ cve, status: norm(st?.status) });
  }
  // CycloneDX VEX: { vulnerabilities:[{ id, analysis:{state} }] }
  for (const v of (doc?.vulnerabilities || []) as any[]) {
    const cve = (String(v?.id || "").toUpperCase().match(CVE_RX) || [])[0];
    if (cve) out.push({ cve, status: norm(v?.analysis?.state || v?.analysis?.response?.[0]) });
  }
  return out;
}

/** Consume a VEX document: suppress (not_affected → false-positive) / mark fixed the matching
 *  ASSETVULNERABILITY rows so VEX-cleared CVEs drop out of the worklists. Tenant-scoped. */
export function consumeVex(doc: unknown, tenant: number | null): { statements: number; matchedCves: number; instancesUpdated: number; byCve: Record<string, number> } {
  const stmts = parseVexStatements(doc);
  const result = { statements: stmts.length, matchedCves: 0, instancesUpdated: 0, byCve: {} as Record<string, number> };
  if (!stmts.length) return result;

  // CVE → VulnerabilityIDs (XVULNERABILITY)
  const vidsByCve = new Map<string, number[]>();
  try {
    const xv = getDb("XVULNERABILITY");
    for (const { cve } of stmts) {
      if (vidsByCve.has(cve)) continue;
      const rows = xv.prepare("SELECT VulnerabilityID id FROM VULNERABILITY WHERE UPPER(COALESCE(VULReferential,VULName)) LIKE ?").all(`%${cve}%`) as { id: number }[];
      vidsByCve.set(cve, rows.map((r) => r.id));
    }
  } catch { /* */ }

  const xo = getDb("XORCISM");
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const avCols = new Set((xo.prepare('PRAGMA table_info("ASSETVULNERABILITY")').all() as { name: string }[]).map((c) => c.name));
  const tenantScope = tenant != null && aCols.has("TenantID");

  const tx = xo.transaction(() => {
    for (const { cve, status } of stmts) {
      if (status === "affected") continue; // VEX 'affected' keeps it in the worklist
      const vids = vidsByCve.get(cve) || [];
      if (!vids.length) continue;
      result.matchedCves++;
      const ph = vids.map(() => "?").join(",");
      const scope = tenantScope ? `AND AssetID IN (SELECT AssetID FROM ASSET WHERE TenantID=? OR TenantID IS NULL)` : "";
      const args: any[] = [...vids, ...(tenantScope ? [tenant] : [])];
      let info;
      if (status === "not_affected" && avCols.has("FalsePositive")) {
        const setStatus = avCols.has("Status") ? ", Status='Not affected (VEX)'" : "";
        info = xo.prepare(`UPDATE ASSETVULNERABILITY SET FalsePositive=1${setStatus} WHERE VulnerabilityID IN (${ph}) ${scope}`).run(...args);
      } else if (avCols.has("Status")) {
        info = xo.prepare(`UPDATE ASSETVULNERABILITY SET Status='Fixed (VEX)' WHERE VulnerabilityID IN (${ph}) ${scope}`).run(...args);
      }
      const n = info ? Number(info.changes) : 0;
      result.instancesUpdated += n;
      result.byCve[cve] = (result.byCve[cve] || 0) + n;
    }
  });
  tx();
  return result;
}
