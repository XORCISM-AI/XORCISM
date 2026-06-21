/**
 * configuration.ts — Configuration Management inventory + governance worklist.
 *
 * The secure-configuration counterpart of assets.ts / identities.ts: one pane over the
 * organisation's configuration content library (XOVAL.OVALDEFINITION — the OVAL/SCAP
 * checks) and its verification coverage. The "configuration items" are the
 * compliance-class definitions (hardening / secure-configuration baselines); the broader
 * library also carries patch, vulnerability and inventory checks (shown as context). Each
 * baseline carries a health score (deprecated / non-accepted status / no CCE mapping) and
 * the worklist surfaces the gaps that matter: deprecated content still present, baselines
 * never verified by a scan (no OVALRESULTS), interim-status checks, and hardening checks
 * with no CCE reference. Read-only; CRUD/scan stays in the explorer & the OVAL agent.
 */
import { getDb } from "./db";
import { ovalResultsView } from "./oval";

export interface ConfigRow {
  id: number;
  pattern: string;
  title: string;
  version: string;
  status: string;
  deprecated: boolean;
  hasCce: boolean;
  platforms: number;
  score: number;          // 0-100 health gap (higher = worse)
  issues: string[];
}
export interface ConfigFinding {
  id: number;
  name: string;
  kind: "definition" | "library" | "coverage";
  severity: "High" | "Medium" | "Low";
  reason: string;
  label: string;
}
export interface ConfigurationInventory {
  rows: ConfigRow[];
  findings: ConfigFinding[];
  summary: {
    definitions: number; compliance: number; patch: number; vulnerability: number; inventory: number; miscellaneous: number;
    deprecated: number; accepted: number; interim: number;
    withCce: number; cceTotal: number;
    scannedAssets: number; verdicts: number; complianceFail: number; compliancePass: number; passRate: number | null; lastScan: string | null;
    byClass: Record<string, number>; byStatus: Record<string, number>;
  };
}

const EMPTY: ConfigurationInventory = {
  rows: [], findings: [],
  summary: {
    definitions: 0, compliance: 0, patch: 0, vulnerability: 0, inventory: 0, miscellaneous: 0,
    deprecated: 0, accepted: 0, interim: 0, withCce: 0, cceTotal: 0,
    scannedAssets: 0, verdicts: 0, complianceFail: 0, compliancePass: 0, passRate: null, lastScan: null,
    byClass: {}, byStatus: {},
  },
};

const SEV_RANK: Record<string, number> = { High: 0, Medium: 1, Low: 2 };
const ROW_CAP = 300;
const KNOWN_CLASS = /compliance|inventory|miscellaneous|patch|vulnerability/i;

function colset(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

/** OVALClassEnumerationID → class name (read from the enum table; robust to id drift). */
function ovalClassMap(xv: ReturnType<typeof getDb>): Map<number, string> {
  const m = new Map<number, string>();
  try {
    const rows = xv.prepare(`SELECT * FROM OVALCLASSENUMERATION`).all() as Record<string, unknown>[];
    for (const r of rows) {
      const id = Number(r.OVALClassEnumerationID ?? r.OVALClassEnumerationId);
      // pick the column holding the class word (compliance/patch/…)
      const name = Object.entries(r).find(([k, v]) => !/id$/i.test(k) && typeof v === "string" && KNOWN_CLASS.test(v))?.[1] as string | undefined;
      if (id && name) m.set(id, name.toLowerCase());
    }
  } catch { /* enum absent */ }
  if (!m.size) { m.set(1, "compliance"); m.set(2, "inventory"); m.set(3, "miscellaneous"); m.set(4, "patch"); m.set(5, "vulnerability"); }
  return m;
}

/** Full configuration-content inventory (hardening baselines) + verification worklist. */
export function configurationInventory(tenant: number | null): ConfigurationInventory {
  let xv;
  try { xv = getDb("XOVAL"); } catch { return { ...EMPTY }; }
  if (!xv.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='OVALDEFINITION'").get()) return { ...EMPTY };
  const dc = colset("XOVAL", "OVALDEFINITION");
  if (!dc.has("OVALDefinitionID")) return { ...EMPTY };

  const classMap = ovalClassMap(xv);
  const complianceId = [...classMap.entries()].find(([, v]) => v === "compliance")?.[0] ?? 1;

  // ── Library-wide counts (by class / status / deprecated) ────────────────────
  const byClass: Record<string, number> = {};
  for (const r of xv.prepare(`SELECT OVALClassEnumerationID AS c, COUNT(*) AS n FROM OVALDEFINITION GROUP BY OVALClassEnumerationID`).all() as { c: number; n: number }[]) {
    byClass[classMap.get(Number(r.c)) ?? "unclassified"] = (byClass[classMap.get(Number(r.c)) ?? "unclassified"] || 0) + r.n;
  }
  const byStatus: Record<string, number> = {};
  if (dc.has("StatusName")) for (const r of xv.prepare(`SELECT COALESCE(StatusName,'(none)') AS s, COUNT(*) AS n FROM OVALDEFINITION GROUP BY StatusName`).all() as { s: string; n: number }[]) byStatus[r.s] = r.n;
  const definitions = (xv.prepare(`SELECT COUNT(*) AS n FROM OVALDEFINITION`).get() as { n: number }).n;
  const deprecated = dc.has("deprecated") ? (xv.prepare(`SELECT COUNT(*) AS n FROM OVALDEFINITION WHERE deprecated = 1`).get() as { n: number }).n : 0;

  // CCE coverage (configuration items mapped to Common Configuration Enumeration)
  let withCce = 0, cceTotal = 0;
  const cceDefs = new Set<number>();
  try {
    if (xv.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='OVALDEFINITIONCCE'").get()) {
      cceTotal = (xv.prepare(`SELECT COUNT(*) AS n FROM OVALDEFINITIONCCE`).get() as { n: number }).n;
      for (const r of xv.prepare(`SELECT DISTINCT OVALDefinitionID AS id FROM OVALDEFINITIONCCE`).all() as { id: number }[]) cceDefs.add(Number(r.id));
      withCce = cceDefs.size;
    }
  } catch { /* no CCE table */ }

  // ── Rows = the compliance (hardening) configuration baselines ───────────────
  const compRaw = xv.prepare(
    `SELECT OVALDefinitionID AS id, OVALDefinitionIDPattern AS pat, OVALDefinitionTitle AS title,
            OVALDefinitionVersion AS ver, deprecated AS dep, StatusName AS st
     FROM OVALDEFINITION WHERE OVALClassEnumerationID = ? ORDER BY deprecated DESC, OVALDefinitionID DESC LIMIT ${ROW_CAP}`
  ).all(complianceId) as Record<string, unknown>[];

  // platform count per shown definition (one grouped query)
  const platCount = new Map<number, number>();
  if (compRaw.length && xv.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='OVALDEFINITIONPLATFORM'").get()) {
    const ids = compRaw.map((d) => Number(d.id));
    const ph = ids.map(() => "?").join(",");
    try { for (const r of xv.prepare(`SELECT OVALDefinitionID AS id, COUNT(*) AS n FROM OVALDEFINITIONPLATFORM WHERE OVALDefinitionID IN (${ph}) GROUP BY OVALDefinitionID`).all(...ids) as { id: number; n: number }[]) platCount.set(Number(r.id), r.n); }
    catch { /* */ }
  }

  const findings: ConfigFinding[] = [];
  let noCce = 0;
  const rows: ConfigRow[] = compRaw.map((d) => {
    const id = Number(d.id);
    const title = String(d.title ?? "").trim() || String(d.pat ?? `def #${id}`);
    const status = String(d.st ?? "").trim() || "—";
    const dep = Number(d.dep) === 1;
    const hasCce = cceDefs.has(id);
    const issues: string[] = [];
    let score = 0;
    if (dep) { issues.push("deprecated"); score += 40; }
    if (status && status !== "—" && !/accepted/i.test(status)) { issues.push(`status: ${status.toLowerCase()}`); score += 15; }
    if (!hasCce) { issues.push("no CCE"); score += 5; noCce++; }

    // Per-item worklist entries only for the consequential gaps (deprecated / not-accepted);
    // the (very common) "no CCE" gap is summarised once below to avoid drowning the worklist.
    if (dep) findings.push({ id, name: title, kind: "definition", severity: "High", reason: "deprecated", label: `${title} — deprecated baseline, review for retirement` });
    else if (status !== "—" && !/accepted/i.test(status)) findings.push({ id, name: title, kind: "definition", severity: "Low", reason: "status", label: `${title} — status ${status.toLowerCase()} (not accepted)` });

    return {
      id, pattern: String(d.pat ?? ""), title, version: String(d.ver ?? "") || "—",
      status, deprecated: dep, hasCce, platforms: platCount.get(id) ?? 0,
      score: Math.min(100, score), issues,
    };
  });

  // ── Verification coverage (OVAL scan results, tenant-scoped) ────────────────
  const scan = ovalResultsView(tenant);
  const compliance = byClass["compliance"] ?? rows.length;

  // ── Aggregate worklist findings ─────────────────────────────────────────────
  if (!scan.summary.verdicts) {
    findings.unshift({ id: 0, name: "Verification", kind: "coverage", severity: "Medium", reason: "no-scans", label: `No configuration scans recorded — ${compliance} hardening baselines unverified (run an OVAL scan)` });
  } else if (scan.summary.complianceFail > 0) {
    findings.unshift({ id: 0, name: "Verification", kind: "coverage", severity: "High", reason: "compliance-fail", label: `${scan.summary.complianceFail} compliance check(s) FAILING across ${scan.summary.assets} scanned asset(s)` });
  }
  if (deprecated > 0) {
    findings.push({ id: 0, name: "Library", kind: "library", severity: "Medium", reason: "deprecated-library", label: `${deprecated} deprecated definition(s) in the content library — review for retirement` });
  }
  if (noCce > 0) {
    findings.push({ id: 0, name: "CCE", kind: "library", severity: "Low", reason: "no-cce", label: `${noCce} of ${rows.length} hardening baselines have no CCE reference — map to Common Configuration Enumeration` });
  }

  rows.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);

  const accepted = Object.entries(byStatus).filter(([k]) => /accepted/i.test(k)).reduce((s, [, n]) => s + n, 0);
  const interim = Object.entries(byStatus).filter(([k]) => /interim|draft|incomplete/i.test(k)).reduce((s, [, n]) => s + n, 0);

  return {
    rows, findings,
    summary: {
      definitions,
      compliance: byClass["compliance"] ?? 0,
      patch: byClass["patch"] ?? 0,
      vulnerability: byClass["vulnerability"] ?? 0,
      inventory: byClass["inventory"] ?? 0,
      miscellaneous: byClass["miscellaneous"] ?? 0,
      deprecated, accepted, interim,
      withCce, cceTotal,
      scannedAssets: scan.summary.assets, verdicts: scan.summary.verdicts,
      complianceFail: scan.summary.complianceFail, compliancePass: scan.summary.compliancePass,
      passRate: scan.summary.passRate, lastScan: scan.summary.lastScan,
      byClass, byStatus,
    },
  };
}

// ── CIS Benchmarks (consensus secure-configuration baselines + CIS-CAT scan results) ──────────
export interface CisBenchmarkInventory {
  benchmarks: Record<string, unknown>[];
  summary: { total: number; recommendations: number; scanned: number; pass: number; fail: number; error: number; passRate: number | null; byCategory: Record<string, number> };
}

/** CIS Benchmark catalogue (XOVAL.CISBENCHMARK) + per-benchmark CIS-CAT pass/fail tally. */
export function cisBenchmarkInventory(_tenant: number | null): CisBenchmarkInventory {
  const empty: CisBenchmarkInventory = { benchmarks: [], summary: { total: 0, recommendations: 0, scanned: 0, pass: 0, fail: 0, error: 0, passRate: null, byCategory: {} } };
  let ov;
  try { ov = getDb("XOVAL"); } catch { return empty; }
  if (!ov.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CISBENCHMARK'").get()) return empty;
  const benches = ov.prepare("SELECT BenchmarkID id, Name name, Version version, Platform platform, Category category, RecommendationCount recs FROM CISBENCHMARK ORDER BY Category, Name").all() as Record<string, any>[];

  // result tally per benchmark + grand totals
  const tally = new Map<number, Record<string, number>>();
  let pass = 0; let fail = 0; let error = 0; let scanned = 0;
  if (ov.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CISBENCHMARKRESULT'").get()) {
    for (const r of ov.prepare("SELECT BenchmarkID b, LOWER(COALESCE(Result,'')) res, COUNT(*) n FROM CISBENCHMARKRESULT GROUP BY BenchmarkID, LOWER(COALESCE(Result,''))").all() as { b: number; res: string; n: number }[]) {
      const t = tally.get(Number(r.b)) ?? {}; t[r.res] = (t[r.res] || 0) + Number(r.n); tally.set(Number(r.b), t);
      if (r.res === "pass") pass += Number(r.n); else if (r.res === "fail") fail += Number(r.n); else if (r.res === "error" || r.res === "unknown") error += Number(r.n);
    }
    scanned = (ov.prepare("SELECT COUNT(DISTINCT BenchmarkID) n FROM CISBENCHMARKRESULT").get() as { n: number }).n;
  }
  const byCategory: Record<string, number> = {};
  const recommendations = benches.reduce((s, b) => s + Number(b.recs || 0), 0);
  const benchmarks = benches.map((b) => {
    byCategory[b.category || "Other"] = (byCategory[b.category || "Other"] || 0) + 1;
    const t = tally.get(Number(b.id)) ?? {};
    const p = t.pass || 0; const f = t.fail || 0; const tot = p + f + (t.error || 0) + (t.unknown || 0);
    return { ...b, pass: p, fail: f, scored: tot, passRate: tot ? Math.round((p / tot) * 100) : null };
  });
  const graded = pass + fail;
  return { benchmarks, summary: { total: benches.length, recommendations, scanned, pass, fail, error, passRate: graded ? Math.round((pass / graded) * 100) : null, byCategory } };
}
