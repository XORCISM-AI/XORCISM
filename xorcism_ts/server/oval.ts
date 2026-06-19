/**
 * oval.ts — ingest OVAL scan results from the XOR agent (OpenSCAP `oscap oval eval`).
 *
 * The agent evaluates an OVAL/SCAP content (its distro feed or SSG) and posts a
 * classified verdict list. This module:
 *   1. stores each verdict in XOVAL.OVALRESULTS (per asset × definition × scan),
 *   2. ventilates the operational findings through the SAME proven import path the
 *      inventory/vuln agent callbacks use (collected XJOB → runner):
 *        • vulnerability-class `true`  → ASSETVULNERABILITY (the referenced CVEs)
 *        • inventory-class `true`      → CPEFORASSET (the referenced CPEs)
 *        • compliance / patch          → kept in OVALRESULTS (+ a summary event)
 *
 * No heavy parsing here — the agent already classified results against the OVAL
 * definitions; this is the server-side persistence + fan-out.
 */
import fs from "fs";
import path from "path";
import { getDb } from "./db";
import { createCollectedJob } from "./jobs";

// ── OVAL content served to agents (offline / centralized content) ──────────────
const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
export function ovalContentDir(): string { return process.env.XORCISM_OVAL_CONTENT_DIR ?? path.join(DB_DIR, "oval-content"); }
const _normName = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, "");

/** OVAL/SCAP content files the admin dropped in the content dir, available to agents. */
export function listOvalContent(): { name: string; size: number }[] {
  try {
    const d = ovalContentDir();
    if (!fs.existsSync(d)) return [];
    return fs.readdirSync(d).filter((f) => /\.(xml|bz2|gz)$/i.test(f) && fs.statSync(path.join(d, f)).isFile())
      .map((f) => ({ name: f, size: fs.statSync(path.join(d, f)).size }));
  } catch { return []; }
}

/** Best content file for a platform token (e.g. "ubuntu-jammy"): substring → token → first. */
export function findOvalContent(platform: string): { path: string; name: string } | null {
  const files = listOvalContent();
  if (!files.length) return null;
  const p = _normName(platform || "");
  let hit = p ? files.find((f) => _normName(f.name).includes(p)) : undefined;
  if (!hit && p) { const toks = p.match(/[a-z]+|[0-9]+/g) || []; hit = files.find((f) => toks.some((t) => t.length >= 4 && _normName(f.name).includes(t))); }
  if (!hit) hit = files[0];
  return hit ? { path: path.join(ovalContentDir(), hit.name), name: hit.name } : null;
}

export interface OvalResultItem {
  definition_id?: string;   // OVAL definition id-pattern (oval:org:def:N)
  class?: string;           // vulnerability | inventory | compliance | patch | miscellaneous
  result?: string;          // true | false | error | unknown | not evaluated | not applicable
  title?: string;
  severity?: string;
  cves?: string[];
  cpes?: string[];
}
export interface OvalPayload {
  engine?: string;          // openscap | builtin
  content?: string;         // content id (e.g. ssg-ubuntu2204-ds / com.ubuntu.jammy.cve.oval)
  system?: Record<string, unknown>;
  results?: OvalResultItem[];
}

export interface OvalIngestSummary {
  asset: string; assetId: number | null; engine: string; content: string;
  stored: number; vulnerabilities: number; inventory: number;
  compliance: { pass: number; fail: number; other: number };
  byClass: Record<string, number>;
  jobs: number[];
}

const TRUE = new Set(["true", "1", "pass"]);
const FAIL = new Set(["false", "fail"]);

function colset(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

/** Resolve the ASSET the agent maps to (by AssetName) + its tenant. */
function resolveAsset(assetName: string, hintTenant: number | null): { id: number | null; tenantId: number | null } {
  try {
    const xo = getDb("XORCISM");
    const cols = colset("XORCISM", "ASSET");
    const hasT = cols.has("TenantID");
    const tw = hintTenant != null && hasT ? `AND "TenantID" = ${hintTenant}` : "";
    const r = xo.prepare(`SELECT AssetID, ${hasT ? "TenantID" : "NULL AS TenantID"} FROM ASSET WHERE AssetName = ? ${tw} ORDER BY AssetID LIMIT 1`).get(assetName) as { AssetID: number; TenantID: number | null } | undefined;
    return r ? { id: Number(r.AssetID), tenantId: r.TenantID != null ? Number(r.TenantID) : null } : { id: null, tenantId: hintTenant };
  } catch { return { id: null, tenantId: hintTenant }; }
}

export function ingestOvalResults(assetName: string, payload: OvalPayload, hintTenant: number | null): OvalIngestSummary {
  const xv = getDb("XOVAL");
  const results = (payload.results || []).slice(0, 5000);
  const resolved = resolveAsset(assetName, hintTenant);
  const assetId = resolved.id;
  const tenant = resolved.tenantId;
  const now = new Date().toISOString();
  const engine = String(payload.engine || "openscap");
  const content = String(payload.content || "");

  // verdict text → OVALRESULTSTYPE id
  const typeId = new Map<string, number>();
  try {
    for (const r of xv.prepare(`SELECT OVALResultsTypeId AS id, ResultValue AS v FROM OVALRESULTSTYPE WHERE ResultValue IS NOT NULL`).all() as { id: number; v: string }[]) typeId.set(r.v, r.id);
  } catch { /* enum unseeded */ }
  // definition id-pattern → OVALDefinitionID (best-effort link)
  const defId = (pattern: string): number | null => {
    if (!pattern) return null;
    try { const r = xv.prepare(`SELECT OVALDefinitionID AS id FROM OVALDEFINITION WHERE OVALDefinitionIDPattern = ? LIMIT 1`).get(pattern) as { id: number } | undefined; return r ? Number(r.id) : null; }
    catch { return null; }
  };

  const orc = colset("XOVAL", "OVALRESULTS");
  const hasExt = orc.has("AssetID") && orc.has("ResultValue");
  // Replace the asset's previous scan (latest-per-asset; bounded growth).
  if (hasExt) {
    try {
      if (assetId != null) xv.prepare(`DELETE FROM OVALRESULTS WHERE AssetID = ?`).run(assetId);
      else xv.prepare(`DELETE FROM OVALRESULTS WHERE AgentName = ?`).run(assetName);
    } catch { /* first run */ }
  }

  // OVALResultsID is a legacy non-autoincrement PK → assign it explicitly.
  let nextId = (() => { try { return (xv.prepare(`SELECT COALESCE(MAX(OVALResultsID),0) m FROM OVALRESULTS`).get() as { m: number }).m; } catch { return 0; } })();
  // The legacy OVALRESULTS has NOT-NULL columns (GeneratorTypeID, OVALDefaultDirectivesID,
  // OVALResultsTypeID) from the EF results-document model — supply neutral defaults (0).
  const insert = hasExt ? xv.prepare(
    `INSERT INTO OVALRESULTS (OVALResultsID, GeneratorTypeID, OVALDefaultDirectivesID, AssetID, OVALDefinitionID, OVALDefinitionIDPattern, OVALResultsTypeID, ResultValue, ClassValue, Title, Severity, ScanDate, AgentName, TenantID)
     VALUES (@id, 0, 0, @AssetID, @OVALDefinitionID, @pattern, @typeId, @result, @cls, @title, @sev, @scan, @agent, @tenant)`
  ) : null;

  const byClass: Record<string, number> = {};
  const compliance = { pass: 0, fail: 0, other: 0 };
  const vulns: { asset: string; ref: string; name: string; severity: string }[] = [];
  const cpes = new Set<string>();
  let stored = 0;

  const tx = xv.transaction((items: OvalResultItem[]) => {
    for (const it of items) {
      const cls = String(it.class || "").toLowerCase().trim() || "miscellaneous";
      const result = String(it.result || "").toLowerCase().trim() || "unknown";
      const pattern = String(it.definition_id || "");
      byClass[cls] = (byClass[cls] || 0) + 1;

      if (insert) {
        insert.run({
          id: ++nextId,
          AssetID: assetId, OVALDefinitionID: defId(pattern), pattern: pattern || null,
          typeId: typeId.get(result) ?? 0, result, cls, title: (it.title || "").slice(0, 1000) || null,
          sev: (it.severity || "").slice(0, 40) || null, scan: now, agent: assetName, tenant,
        });
        stored++;
      }

      if (cls === "vulnerability" && TRUE.has(result)) {
        for (const cve of (it.cves || [])) {
          if (/^CVE-\d{4}-\d{4,}$/i.test(cve)) vulns.push({ asset: assetName, ref: cve.toUpperCase(), name: (it.title || cve).slice(0, 200), severity: (it.severity || "unknown").toLowerCase() });
        }
      } else if (cls === "inventory" && TRUE.has(result)) {
        for (const cpe of (it.cpes || [])) if (cpe && cpe.startsWith("cpe:")) cpes.add(cpe);
      } else if (cls === "compliance") {
        if (TRUE.has(result)) compliance.pass++; else if (FAIL.has(result)) compliance.fail++; else compliance.other++;
      }
    }
  });
  tx(results);

  // Ventilate through the same collected-job path as the inventory/vuln callbacks.
  const jobs: number[] = [];
  const host = [{ hostname: assetName, key: assetName }];
  // dedupe CVEs
  const seen = new Set<string>(); const uvulns = vulns.filter((v) => (seen.has(v.ref) ? false : (seen.add(v.ref), true)));
  if (uvulns.length) jobs.push(createCollectedJob("xor-vuln", { assets: host, vulns: uvulns }, assetName));
  if (cpes.size) jobs.push(createCollectedJob("xor-inventory", { assets: host, cpes: [...cpes] }, assetName));

  return {
    asset: assetName, assetId, engine, content,
    stored, vulnerabilities: uvulns.length, inventory: cpes.size, compliance, byClass, jobs,
  };
}

// ── OVAL results view (for the /oval-scan page) ────────────────────────────────

export interface OvalAssetRow {
  asset: string; assetId: number | null; lastScan: string | null;
  vuln: number; compliancePass: number; complianceFail: number; inventory: number; total: number;
}
export interface OvalFinding { asset: string; assetId: number | null; cls: string; title: string; severity: string; result: string; }
export interface OvalResultsView {
  rows: OvalAssetRow[]; findings: OvalFinding[];
  summary: { assets: number; verdicts: number; complianceFail: number; compliancePass: number; passRate: number | null; cves: number; lastScan: string | null };
}

const OVAL_EMPTY: OvalResultsView = { rows: [], findings: [], summary: { assets: 0, verdicts: 0, complianceFail: 0, compliancePass: 0, passRate: null, cves: 0, lastScan: null } };

/** Aggregated OVAL scan results per asset + a worklist of compliance failures / detections. */
export function ovalResultsView(tenant: number | null): OvalResultsView {
  let xv;
  try { xv = getDb("XOVAL"); } catch { return { ...OVAL_EMPTY }; }
  const orc = colset("XOVAL", "OVALRESULTS");
  if (!orc.has("AssetID")) return { ...OVAL_EMPTY };
  const tw = tenant != null && orc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const all = xv.prepare(`SELECT AssetID, AgentName, ClassValue, ResultValue, Title, Severity, ScanDate FROM OVALRESULTS ${tw}`).all() as Record<string, unknown>[];
  if (!all.length) return { ...OVAL_EMPTY };

  // resolve asset names
  const names = new Map<number, string>();
  try {
    const xo = getDb("XORCISM");
    if (colset("XORCISM", "ASSET").has("AssetName")) for (const a of xo.prepare(`SELECT AssetID, AssetName FROM ASSET`).all() as { AssetID: number; AssetName: string }[]) names.set(Number(a.AssetID), a.AssetName);
  } catch { /* */ }

  const byAsset = new Map<string, OvalAssetRow>();
  const findings: OvalFinding[] = [];
  let cves = 0, lastScan: string | null = null;
  for (const r of all) {
    const aid = r.AssetID != null ? Number(r.AssetID) : null;
    const asset = (aid != null ? names.get(aid) : null) || String(r.AgentName || "") || (aid != null ? `#${aid}` : "unknown");
    const key = String(aid ?? asset);
    const row = byAsset.get(key) ?? { asset, assetId: aid, lastScan: null, vuln: 0, compliancePass: 0, complianceFail: 0, inventory: 0, total: 0 };
    const cls = String(r.ClassValue || "").toLowerCase();
    const result = String(r.ResultValue || "").toLowerCase();
    const scan = r.ScanDate ? String(r.ScanDate).slice(0, 19) : null;
    row.total++;
    if (scan && (!row.lastScan || scan > row.lastScan)) row.lastScan = scan;
    if (scan && (!lastScan || scan > lastScan)) lastScan = scan;
    if (cls === "vulnerability" && TRUE.has(result)) { row.vuln++; cves++; findings.push({ asset, assetId: aid, cls, title: String(r.Title || ""), severity: String(r.Severity || ""), result }); }
    else if (cls === "compliance") { if (TRUE.has(result)) row.compliancePass++; else if (FAIL.has(result)) { row.complianceFail++; findings.push({ asset, assetId: aid, cls, title: String(r.Title || ""), severity: String(r.Severity || ""), result }); } }
    else if (cls === "inventory" && TRUE.has(result)) row.inventory++;
    byAsset.set(key, row);
  }

  const rows = [...byAsset.values()].sort((a, b) => (b.vuln + b.complianceFail) - (a.vuln + a.complianceFail) || a.asset.localeCompare(b.asset));
  const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (a.cls === b.cls ? 0 : a.cls === "vulnerability" ? -1 : 1) || ((sevRank[a.severity.toLowerCase()] ?? 4) - (sevRank[b.severity.toLowerCase()] ?? 4)) || a.asset.localeCompare(b.asset));
  const pass = rows.reduce((s, r) => s + r.compliancePass, 0);
  const fail = rows.reduce((s, r) => s + r.complianceFail, 0);
  return {
    rows, findings,
    summary: { assets: rows.length, verdicts: all.length, complianceFail: fail, compliancePass: pass, passRate: (pass + fail) ? Math.round((pass / (pass + fail)) * 100) : null, cves, lastScan },
  };
}
