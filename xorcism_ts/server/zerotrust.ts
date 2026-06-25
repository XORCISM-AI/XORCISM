/**
 * zerotrust.ts — Zero Trust cockpit (CISA Zero Trust Maturity Model v2.0).
 *
 * Three things:
 *   1) a maturity ASSESSMENT over the ZTMM catalogue (5 pillars + 3 cross-cutting capabilities ×
 *      functions × 4 stages: Traditional → Initial → Advanced → Optimal);
 *   2) per-pillar maturity derived from LIVE XORCISM signals (identities, assets, vulns, controls,
 *      DevSecOps, data labels, SOAR/CROC…) — so the cockpit is useful before any manual assessment;
 *   3) a fused TRUST SCORE (NIST SP 800-207 trust algorithm) over the identity & asset inventories.
 *
 * Mirrors the PQCMM / SOC-CMM maturity pattern; reuses identityInventory() & assetInventory().
 */
import { randomUUID } from "crypto";
import { readFileSync } from "fs";
import path from "path";
import { allocId, getDb } from "./db";
import { identityInventory } from "./identities";
import { assetInventory } from "./assets";

// ── geo-IP enrichment (impossible-travel on raw IPs) ─────────────────────────────
// Best-effort, local. Private/reserved IPs → "Internal"; public IPs → an operator-supplied
// IP→country table (XOR_GEOIP_CSV: "start_ip,end_ip,CC" per line). No external calls.
let GEO_RANGES: { lo: number; hi: number; cc: string }[] | null = null;
function ip4ToInt(ip: string): number | null {
  const m = (ip || "").trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  const p = m.slice(1, 5).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function isPrivate4(n: number): boolean {
  const o1 = (n >>> 24) & 255, o2 = (n >>> 16) & 255;
  return o1 === 10 || o1 === 127 || o1 === 0 || (o1 === 169 && o2 === 254) || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 192 && o2 === 168) || (o1 === 100 && o2 >= 64 && o2 <= 127) || o1 >= 224;
}
function geoPath(): string {
  if (process.env.XOR_GEOIP_CSV) return process.env.XOR_GEOIP_CSV;
  return path.join(process.env.DB_DIR || "C:/Users/jerom/XORCISM_databases", "geoip.csv");
}
function loadGeo(): { lo: number; hi: number; cc: string }[] {
  if (GEO_RANGES) return GEO_RANGES;
  GEO_RANGES = [];
  try {
    const p = geoPath();
    if (p) {
      for (const line of readFileSync(p, "utf-8").split(/\r?\n/)) {
        const parts = line.split(",").map((s) => s.trim());
        if (parts.length < 3) continue;
        const lo = ip4ToInt(parts[0]), hi = ip4ToInt(parts[1]);
        if (lo != null && hi != null && parts[2]) GEO_RANGES.push({ lo, hi, cc: parts[2] });
      }
      GEO_RANGES.sort((a, b) => a.lo - b.lo);
    }
  } catch { /* best-effort */ }
  return GEO_RANGES;
}
/** Country for an IP: "Internal" for private/reserved, the geo-CSV country for public, else "". */
export function geoCountry(ip: string): string {
  const n = ip4ToInt(ip);
  if (n == null) return "";
  if (isPrivate4(n)) return "Internal";
  for (const r of loadGeo()) if (n >= r.lo && n <= r.hi) return r.cc;
  return "";
}

export const ZT_STAGES = ["Traditional", "Initial", "Advanced", "Optimal"] as const;
export const ZT_PILLARS: { key: string; name: string; cross: boolean }[] = [
  { key: "identity", name: "Identity", cross: false },
  { key: "devices", name: "Devices", cross: false },
  { key: "networks", name: "Networks", cross: false },
  { key: "applications", name: "Applications & Workloads", cross: false },
  { key: "data", name: "Data", cross: false },
  { key: "visibility", name: "Visibility & Analytics", cross: true },
  { key: "automation", name: "Automation & Orchestration", cross: true },
  { key: "governance", name: "Governance", cross: true },
];

interface ZtFn { key: string; pillarKey: string; name: string; desc: string; stages: [string, string, string, string]; }
const S = (a: string, b: string, c: string, d: string): [string, string, string, string] => [a, b, c, d];

// CISA ZTMM v2.0 — a representative set of functions per pillar with one-line stage descriptions.
const ZTMM: ZtFn[] = [
  // ── Identity ──
  { key: "id-authn", pillarKey: "identity", name: "Authentication", desc: "How users & non-human identities prove who they are.",
    stages: S("Passwords / weak MFA", "MFA for most access", "Phishing-resistant MFA broadly", "Continuous, risk-adaptive auth across all access") },
  { key: "id-stores", pillarKey: "identity", name: "Identity stores", desc: "Consolidation & governance of identity directories (incl. NHI).",
    stages: S("Siloed local accounts", "Some consolidation", "Centralized human + non-human identity governance", "Fully integrated, automated identity lifecycle") },
  { key: "id-risk", pillarKey: "identity", name: "Identity risk assessments", desc: "Per-identity & per-session risk scoring.",
    stages: S("Manual / none", "Periodic identity risk review", "Automated identity risk scoring", "Real-time session risk feeds access decisions") },
  { key: "id-access", pillarKey: "identity", name: "Access management", desc: "Least-privilege & just-in-time access.",
    stages: S("Static broad privilege", "Role-based access", "Least-privilege with reviews", "Just-in-time, just-enough, automated") },
  // ── Devices ──
  { key: "dev-compliance", pillarKey: "devices", name: "Policy enforcement & compliance", desc: "Device posture/health checked before access.",
    stages: S("No device posture", "Some compliance checks", "Most access gated on device health", "Continuous device-trust gating every request") },
  { key: "dev-asset", pillarKey: "devices", name: "Asset & supply-chain risk", desc: "Inventory, vuln & supply-chain risk of devices.",
    stages: S("Partial inventory", "Inventory + periodic vuln scans", "Continuous inventory + risk-based vuln mgmt", "Automated, supply-chain-aware asset risk") },
  { key: "dev-threat", pillarKey: "devices", name: "Device threat protection", desc: "EDR / threat detection on endpoints.",
    stages: S("AV only / none", "EDR on some devices", "EDR fleet-wide with telemetry", "Unified, automated endpoint detection & response") },
  // ── Networks ──
  { key: "net-seg", pillarKey: "networks", name: "Network segmentation", desc: "Macro/micro-segmentation of the network.",
    stages: S("Flat network", "Macro-segmentation (zones)", "Micro-segmentation around workloads", "Dynamic, per-session isolation") },
  { key: "net-traffic", pillarKey: "networks", name: "Network traffic management", desc: "Policy-based, monitored east-west & north-south flows.",
    stages: S("Perimeter-only filtering", "Some internal filtering", "Policy-based traffic mgmt + monitoring", "Application-aware, automated traffic policy") },
  { key: "net-encrypt", pillarKey: "networks", name: "Traffic encryption", desc: "Encryption of data in transit, incl. internal.",
    stages: S("Limited TLS", "External traffic encrypted", "Most internal traffic encrypted", "All traffic encrypted, keys managed/rotated") },
  // ── Applications & Workloads ──
  { key: "app-access", pillarKey: "applications", name: "Application access", desc: "Per-request authz to applications.",
    stages: S("Network-location trust", "App auth at the perimeter", "Per-request app authorization", "Continuous, context-aware app access") },
  { key: "app-threat", pillarKey: "applications", name: "Application threat protection", desc: "Runtime protection (WAF/RASP) & testing.",
    stages: S("Minimal", "Perimeter WAF", "AppSec testing + runtime protection", "Integrated, automated threat protection") },
  { key: "app-devsecops", pillarKey: "applications", name: "Secure development & testing", desc: "Security in the SDLC (SAST/DAST/SCA, gates).",
    stages: S("Ad-hoc", "Some security testing", "Automated AppSec in CI with gates", "Continuous, shift-left, policy-as-code") },
  // ── Data ──
  { key: "data-inv", pillarKey: "data", name: "Data inventory & categorization", desc: "Know what data exists and its sensitivity.",
    stages: S("Unknown / manual", "Partial inventory & labels", "Most data inventoried & classified", "Automated discovery & classification") },
  { key: "data-access", pillarKey: "data", name: "Data access governance", desc: "Least-privilege, policy-driven data access.",
    stages: S("Broad access", "Role-based data access", "Least-privilege + DLP", "Dynamic, attribute-based data access") },
  { key: "data-encrypt", pillarKey: "data", name: "Data encryption", desc: "Encryption at rest & key management.",
    stages: S("Limited", "Sensitive data at rest encrypted", "Most data encrypted, keys managed", "All data encrypted, automated key rotation") },
  // ── Visibility & Analytics (cross-cutting) ──
  { key: "vis-telemetry", pillarKey: "visibility", name: "Telemetry & monitoring", desc: "Centralized logging & monitoring of all pillars.",
    stages: S("Siloed logs", "Some centralized logging", "Broad telemetry across pillars", "Unified, real-time visibility") },
  { key: "vis-analytics", pillarKey: "visibility", name: "Risk analytics", desc: "Analytics that turn telemetry into risk decisions.",
    stages: S("Manual review", "Basic dashboards", "Risk scoring & threat-informed analytics", "Automated, ML-assisted risk analytics") },
  // ── Automation & Orchestration (cross-cutting) ──
  { key: "auto-response", pillarKey: "automation", name: "Automated response", desc: "Playbook-driven, automated response actions.",
    stages: S("Manual", "Some runbooks", "SOAR playbooks for common cases", "Closed-loop, signal-driven automation") },
  { key: "auto-policy", pillarKey: "automation", name: "Policy orchestration", desc: "Policy decisions orchestrated across tools.",
    stages: S("Static, per-tool", "Some integration", "Centralized policy orchestration", "Dynamic, risk-adaptive policy across the stack") },
  // ── Governance (cross-cutting) ──
  { key: "gov-policy", pillarKey: "governance", name: "Policy & standards", desc: "ZT policy, ownership & enforcement.",
    stages: S("Ad-hoc", "Documented policies", "Enforced & reviewed policies", "Continuously assured, evidence-backed policy") },
  { key: "gov-controls", pillarKey: "governance", name: "Control assurance", desc: "Controls proven continuously from telemetry.",
    stages: S("Point-in-time attestation", "Periodic control testing", "Mostly continuous control validation", "Fully continuous, automated control assurance") },
];

const now = () => new Date().toISOString();
function has(db: ReturnType<typeof getDb>, table: string): boolean {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; }
}
function colsOf(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function tw(tenant: number | null): string { return tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : ""; }
const pctToStage = (pct: number): number => (pct >= 85 ? 3 : pct >= 60 ? 2 : pct >= 30 ? 1 : 0);
const stageToPct = (stage: number): number => Math.round((stage / 3) * 100);

// ── seed the catalogue ────────────────────────────────────────────────────────
export function seedZtFunctions(): void {
  try {
    const db = getDb("XCOMPLIANCE");
    if (!colsOf("ZTFUNCTION").size) return;
    const pillarName = (k: string) => ZT_PILLARS.find((p) => p.key === k)?.name ?? k;
    const cross = (k: string) => (ZT_PILLARS.find((p) => p.key === k)?.cross ? 1 : 0);
    const up = db.prepare(`INSERT INTO ZTFUNCTION (FunctionKey, Pillar, PillarKey, IsCrossCutting, Name, Description, Stage0, Stage1, Stage2, Stage3, DisplayOrder)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(FunctionKey) DO UPDATE SET Pillar=excluded.Pillar, PillarKey=excluded.PillarKey, IsCrossCutting=excluded.IsCrossCutting,
        Name=excluded.Name, Description=excluded.Description, Stage0=excluded.Stage0, Stage1=excluded.Stage1, Stage2=excluded.Stage2, Stage3=excluded.Stage3, DisplayOrder=excluded.DisplayOrder`);
    ZTMM.forEach((f, i) => up.run(f.key, pillarName(f.pillarKey), f.pillarKey, cross(f.pillarKey), f.name, f.desc, f.stages[0], f.stages[1], f.stages[2], f.stages[3], i + 1));
  } catch { /* best-effort */ }
}

// ── live pillar signals ────────────────────────────────────────────────────────
function count(dbName: string, sql: string): number {
  try { const r = getDb(dbName).prepare(sql).get() as { n: number } | undefined; return r ? Number(r.n) || 0 : 0; } catch { return 0; }
}
function tcond(dbName: string, table: string, tenant: number | null): string {
  try {
    const c = new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((x) => x.name));
    return tenant != null && c.has("TenantID") ? `(TenantID = ${tenant} OR TenantID IS NULL)` : "1=1";
  } catch { return "1=1"; }
}

export interface PillarSignal { pillarKey: string; name: string; cross: boolean; pct: number; stage: number; basis: string; }

// ── UEBA / session-risk (continuous verification — matures the Identity pillar) ──────
export interface SessionRiskEntity { name: string; risk: number; signins: number; failures: number; countries: number; reasons: string[]; lastSeen: string; }
const mfaYes = (v: unknown) => /^(y|yes|true|1|enabled|on)$/i.test(String(v ?? ""));

/** Per-identity behavioral risk from IDENTITYSIGNIN: MFA-less sign-ins, failed bursts, impossible
 * travel, multi-country, IdP-flagged risk. Read-only over the last 30 days. */
export function sessionRisk(tenant: number | null): { byName: Record<string, SessionRiskEntity>; summary: { identities: number; signins: number; highRisk: number; avgRisk: number; mfaLessRate: number }; worklist: SessionRiskEntity[] } {
  const byName: Record<string, SessionRiskEntity> = {};
  let totalSignins = 0, mfaLessSuccess = 0, successTotal = 0;
  try {
    const xo = getDb("XORCISM");
    if (!new Set((xo.prepare("PRAGMA table_info(IDENTITYSIGNIN)").all() as { name: string }[]).map((c) => c.name)).size)
      return { byName, summary: { identities: 0, signins: 0, highRisk: 0, avgRisk: 0, mfaLessRate: 0 }, worklist: [] };
    const since = new Date(Date.now() - 30 * 86400e3).toISOString();
    const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
    const rows = xo.prepare(`SELECT IdentityName, Timestamp, Country, MFAUsed, Result, RiskLevel, SourceIP FROM IDENTITYSIGNIN WHERE (Timestamp IS NULL OR Timestamp >= ?) ${w} ORDER BY IdentityName, Timestamp`)
      .all(...(tenant != null ? [since, tenant] : [since])) as Record<string, any>[];
    totalSignins = rows.length;
    const groups = new Map<string, Record<string, any>[]>();
    for (const r of rows) { const n = String(r.IdentityName || "").trim(); if (!n) continue; let g = groups.get(n); if (!g) { g = []; groups.set(n, g); } g.push(r); }
    for (const [name, evs] of groups) {
      let risk = 0; const reasons: string[] = [];
      const succ = evs.filter((e) => /succ/i.test(String(e.Result || "success")));
      const fails = evs.filter((e) => /fail/i.test(String(e.Result || "")));
      successTotal += succ.length;
      const mfaLess = succ.filter((e) => !mfaYes(e.MFAUsed));
      mfaLessSuccess += mfaLess.length;
      if (mfaLess.length) { risk += Math.min(30, 8 + mfaLess.length * 3); reasons.push(`${mfaLess.length} MFA-less sign-in(s)`); }
      if (fails.length >= 5) { risk += 25; reasons.push(`${fails.length} failed sign-ins (possible brute force)`); }
      else if (fails.length) reasons.push(`${fails.length} failed sign-in(s)`);
      // country from the IdP, else geo-IP enriched from the source IP ("Internal" for private IPs)
      const ctry = (e: Record<string, any>) => String(e.Country || "").trim() || geoCountry(String(e.SourceIP || ""));
      const countries = [...new Set(succ.map(ctry).filter((c) => c && c !== "Internal"))];
      let impossible = false;
      for (let i = 1; i < succ.length; i++) {
        const ca = ctry(succ[i - 1]), cb = ctry(succ[i]);
        const ta = Date.parse(succ[i - 1].Timestamp), tb = Date.parse(succ[i].Timestamp);
        if (ca && cb && ca !== "Internal" && cb !== "Internal" && ca !== cb && Number.isFinite(ta) && Number.isFinite(tb) && Math.abs(tb - ta) < 4 * 3600e3) { impossible = true; break; }
      }
      if (impossible) { risk += 35; reasons.push("impossible travel (country change within 4h)"); }
      else if (countries.length > 1) { risk += 10; reasons.push(`sign-ins from ${countries.length} countries`); }
      const idpRisk = evs.filter((e) => /med|high/i.test(String(e.RiskLevel || ""))).length;
      if (idpRisk) { risk += Math.min(25, idpRisk * 10); reasons.push(`${idpRisk} IdP-flagged risky sign-in(s)`); }
      const lastSeen = evs.map((e) => String(e.Timestamp || "")).filter(Boolean).sort().pop() || "";
      byName[name] = { name, risk: Math.min(100, risk), signins: evs.length, failures: fails.length, countries: countries.length, reasons, lastSeen: lastSeen.slice(0, 16) };
    }
  } catch { /* none */ }
  const list = Object.values(byName);
  return {
    byName,
    summary: { identities: list.length, signins: totalSignins, highRisk: list.filter((e) => e.risk >= 50).length, avgRisk: list.length ? Math.round(list.reduce((s, e) => s + e.risk, 0) / list.length) : 0, mfaLessRate: successTotal ? Math.round((mfaLessSuccess / successTotal) * 100) : 0 },
    worklist: list.filter((e) => e.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 25),
  };
}

// ── ZT policy register (conditional access / ZTNA policies modeled as data) ──────────
export function ztPolicies(tenant: number | null): { policies: any[]; summary: any } {
  const db = getDb("XCOMPLIANCE");
  let rows: Record<string, any>[] = [];
  try { rows = db.prepare(`SELECT * FROM ZTPOLICY ${tw(tenant)} ORDER BY PolicyID DESC`).all() as Record<string, any>[]; } catch { rows = []; }
  const policies = rows.map((p) => ({
    id: Number(p.PolicyID), name: String(p.Name || ""), source: String(p.Source || ""), state: String(p.State || ""),
    subjects: String(p.Subjects || ""), resources: String(p.Resources || ""), conditions: String(p.Conditions || ""),
    grantControls: String(p.GrantControls || ""), requireMfa: !!Number(p.RequireMfa), requireCompliantDevice: !!Number(p.RequireCompliantDevice), block: !!Number(p.Block),
  }));
  return {
    policies,
    summary: {
      total: policies.length, enabled: policies.filter((p) => /^enabled$/i.test(p.state)).length,
      reportOnly: policies.filter((p) => /report/i.test(p.state)).length,
      requireMfa: policies.filter((p) => p.requireMfa).length, block: policies.filter((p) => p.block).length,
      requireCompliantDevice: policies.filter((p) => p.requireCompliantDevice).length,
    },
  };
}

export function seedZtPolicyDemo(tenant: number): void {
  try {
    const db = getDb("XCOMPLIANCE");
    if (!colsOf("ZTPOLICY").size) return;
    if (db.prepare("SELECT 1 FROM ZTPOLICY WHERE TenantID = ? LIMIT 1").get(tenant)) return; // idempotent
    const demo: [string, string, string, string, string, number, number, number][] = [
      // name, state, subjects, resources, conditions, mfa, compliantDevice, block
      ["Require MFA for all users", "enabled", "All", "All", "clients=all", 1, 0, 0],
      ["Block legacy authentication", "enabled", "All", "All", "clients=exchangeActiveSync, other", 0, 0, 1],
      ["Require compliant device for admins", "enabled", "Global Administrator, Privileged Role Administrator", "All", "clients=all", 1, 1, 0],
      ["MFA for risky sign-ins (report-only)", "enabledForReportingButNotEnforced", "All", "All", "signInRisk=high, medium", 1, 0, 0],
    ];
    const ins = db.prepare("INSERT INTO ZTPOLICY (PolicyGUID, Name, Source, ExternalID, State, Subjects, Resources, Conditions, GrantControls, RequireMfa, RequireCompliantDevice, Block, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    demo.forEach((d, i) => {
      const gc = [d[5] ? "mfa" : "", d[6] ? "compliantDevice" : "", d[7] ? "block" : ""].filter(Boolean).join(", ");
      ins.run(randomUUID(), d[0], "Microsoft Entra Conditional Access", `ca-demo-${i}`, d[1], d[2], d[3], d[4], gc, d[5], d[6], d[7], tenant, new Date().toISOString());
    });
  } catch { /* best-effort demo */ }
}

export function pillarSignals(tenant: number | null): Record<string, PillarSignal> {
  const out: Record<string, PillarSignal> = {};
  const set = (k: string, pct: number, basis: string) => {
    const p = ZT_PILLARS.find((x) => x.key === k)!;
    out[k] = { pillarKey: k, name: p.name, cross: p.cross, pct: Math.round(Math.max(0, Math.min(100, pct))), stage: pctToStage(pct), basis };
  };

  // Identity — health from the identity inventory (trust = 100 - risk) + MFA on privileged humans
  try {
    const inv = identityInventory(tenant);
    const rows = inv.rows;
    const health = rows.length ? Math.round(rows.reduce((s, r) => s + (100 - r.score), 0) / rows.length) : 0;
    const privHumans = rows.filter((r) => r.klass === "Human" && /admin|privileg|root|super/i.test(r.privilege));
    const mfaOk = privHumans.filter((r) => /^(y|yes|true|enabled|on)$/i.test(r.mfa)).length;
    const mfaPct = privHumans.length ? Math.round((mfaOk / privHumans.length) * 100) : 100;
    const sr = sessionRisk(tenant).summary;
    if (rows.length && sr.signins > 0) {
      const contVer = Math.max(0, 100 - sr.avgRisk); // continuous-verification health
      const pct = Math.round(0.45 * health + 0.30 * mfaPct + 0.25 * contVer);
      set("identity", pct, `${rows.length} identities · avg trust ${health}% · ${mfaPct}% priv-MFA · ${sr.signins} sign-ins, avg session-risk ${sr.avgRisk}% (continuous verification)`);
    } else if (rows.length) {
      set("identity", Math.round(0.6 * health + 0.4 * mfaPct), `${rows.length} identities · avg trust ${health}% · ${mfaPct}% priv-MFA · no sign-in telemetry (add an IdP connector for continuous verification)`);
    } else { set("identity", 0, "no identities inventoried"); }
  } catch { set("identity", 0, "no identity data"); }

  // Devices — health from the asset inventory (trust = 100 - risk) + critical-vuln-free ratio
  try {
    const inv = assetInventory(tenant);
    const rows = inv.rows;
    const health = rows.length ? Math.round(rows.reduce((s, r) => s + (100 - r.score), 0) / rows.length) : 0;
    const clean = rows.filter((r) => (r.vulns?.critical ?? 0) === 0 && (r.vulns?.kev ?? 0) === 0).length;
    const cleanPct = rows.length ? Math.round((clean / rows.length) * 100) : 100;
    const pct = rows.length ? Math.round(0.6 * health + 0.4 * cleanPct) : 0;
    set("devices", pct, rows.length ? `${rows.length} assets · avg trust ${health}% · ${cleanPct}% free of KEV/critical vulns` : "no assets inventoried");
    // Networks — exposure & monitoring presence (reuse the same inventory)
    const internet = rows.filter((r) => r.exposure === "Internet").length;
    const expPct = rows.length ? Math.round((1 - internet / rows.length) * 100) : 100;
    const mon = count("XORCISM", `SELECT COUNT(*) n FROM MONITORINGCHECK WHERE ${tcond("XORCISM", "MONITORINGCHECK", tenant)}`);
    const netPct = Math.round(0.7 * expPct + 0.3 * Math.min(100, mon * 10));
    set("networks", rows.length || mon ? netPct : 0, `${internet}/${rows.length || 0} assets internet-facing · ${mon} monitoring checks`);
  } catch { set("devices", 0, "no asset data"); set("networks", 0, "no network data"); }

  // Applications & Workloads — DevSecOps coverage
  {
    const apps = count("XORCISM", `SELECT COUNT(*) n FROM DEVSECOPSAPP WHERE ${tcond("XORCISM", "DEVSECOPSAPP", tenant)}`);
    const scans = count("XORCISM", `SELECT COUNT(*) n FROM DEVSECOPSSCAN WHERE ${tcond("XORCISM", "DEVSECOPSSCAN", tenant)}`);
    const pct = apps ? Math.min(100, 30 + Math.min(50, scans * 5) + Math.min(20, apps * 4)) : (scans ? 30 : 0);
    set("applications", pct, `${apps} apps · ${scans} AppSec scans (SAST/DAST/SCA/secrets/IaC/container)`);
  }
  // Data — sensitivity-label coverage on documents
  {
    const total = count("XCOMPLIANCE", `SELECT COUNT(*) n FROM DOCUMENT WHERE ${tcond("XCOMPLIANCE", "DOCUMENT", tenant)}`);
    const labelCol = colsOf("DOCUMENT").has("SensitivityLabel") ? "SensitivityLabel" : (colsOf("DOCUMENT").has("Sensitivity") ? "Sensitivity" : null);
    const labelled = labelCol ? count("XCOMPLIANCE", `SELECT COUNT(*) n FROM DOCUMENT WHERE ${tcond("XCOMPLIANCE", "DOCUMENT", tenant)} AND ${labelCol} IS NOT NULL AND ${labelCol}<>''`) : 0;
    const pct = total ? Math.round((labelled / total) * 100) : 0;
    set("data", pct, total ? `${labelled}/${total} documents classified with a sensitivity label` : "no documents inventoried");
  }
  // Visibility & Analytics — incident + CTI telemetry present
  {
    const inc = count("XINCIDENT", `SELECT COUNT(*) n FROM INCIDENT WHERE ${tcond("XINCIDENT", "INCIDENT", tenant)}`);
    const alerts = count("XINCIDENT", `SELECT COUNT(*) n FROM ALERT WHERE ${tcond("XINCIDENT", "ALERT", tenant)}`);
    const cti = count("XTHREAT", `SELECT COUNT(*) n FROM THREATREPORT`);
    const pct = Math.min(100, (inc ? 25 : 0) + (alerts ? 25 : 0) + Math.min(30, cti) + (inc + alerts > 20 ? 20 : 0));
    set("visibility", pct, `${inc} incidents · ${alerts} alerts · ${cti} threat reports`);
  }
  const zp = ztPolicies(tenant).summary;
  // Automation & Orchestration — SOAR playbooks + CROC policies + ZT access-policy orchestration
  {
    const pb = count("XINCIDENT", `SELECT COUNT(*) n FROM SOARPLAYBOOK WHERE ${tcond("XINCIDENT", "SOARPLAYBOOK", tenant)}`);
    const loop = count("XTHREAT", `SELECT COUNT(*) n FROM LOOPPOLICY`);
    const polComp = zp.total ? Math.min(25, 10 + zp.enabled * 2) : 0;
    const pct = Math.min(100, (pb ? 30 : 0) + Math.min(25, pb * 5) + (loop ? 20 : 0) + polComp);
    set("automation", pct, `${pb} SOAR playbooks · ${loop} CROC loop policies · ${zp.total} ZT access policies (${zp.enabled} enabled)`);
  }
  // Governance — control implementation + published policies + the ZT policy register
  {
    const impl = count("XCOMPLIANCE", `SELECT COUNT(*) n FROM CONTROLIMPLEMENTATION WHERE ${tcond("XCOMPLIANCE", "CONTROLIMPLEMENTATION", tenant)}`);
    const pol = count("XORCISM", `SELECT COUNT(*) n FROM POLICY WHERE ${tcond("XORCISM", "POLICY", tenant)}`);
    const pct = Math.min(100, Math.min(45, impl) + Math.min(40, pol * 5) + (zp.total ? 15 : 0));
    set("governance", pct, `${impl} control implementations · ${pol} policies · ${zp.total} ZT access policies`);
  }
  return out;
}

// ── fused trust score (NIST 800-207 trust algorithm) ─────────────────────────────
export interface TrustEntity { type: "Identity" | "Asset"; id: number; name: string; trust: number; tier: string; reasons: string[]; }
const trustTier = (t: number): string => (t >= 80 ? "Trusted" : t >= 60 ? "Limited" : t >= 40 ? "Low" : "Untrusted");

export function trustScores(tenant: number | null): { posture: any; worklist: TrustEntity[] } {
  const ents: TrustEntity[] = [];
  let idAvg = 0, idCount = 0, devAvg = 0, devCount = 0;
  try {
    const inv = identityInventory(tenant);
    const sr = sessionRisk(tenant).byName;
    idCount = inv.rows.length;
    for (const r of inv.rows) {
      const s = sr[r.name];
      const penalty = s ? Math.round(s.risk * 0.4) : 0; // session risk lowers device-/identity-trust
      const trust = Math.max(0, Math.min(100, 100 - r.score - penalty));
      idAvg += trust;
      const reasons = [...r.flags.slice(0, 3), ...(s && s.risk >= 30 ? [`session risk ${s.risk}`] : [])].slice(0, 4);
      ents.push({ type: "Identity", id: r.id, name: r.name, trust, tier: trustTier(trust), reasons });
    }
    idAvg = idCount ? Math.round(idAvg / idCount) : 0;
  } catch { /* none */ }
  try {
    const inv = assetInventory(tenant);
    devCount = inv.rows.length;
    for (const r of inv.rows) {
      const trust = Math.max(0, Math.min(100, 100 - r.score));
      devAvg += trust;
      ents.push({ type: "Asset", id: r.id, name: r.name, trust, tier: trustTier(trust), reasons: r.flags.slice(0, 4) });
    }
    devAvg = devCount ? Math.round(devAvg / devCount) : 0;
  } catch { /* none */ }

  const all = ents.map((e) => e.trust);
  const overall = all.length ? Math.round(all.reduce((a, b) => a + b, 0) / all.length) : 0;
  const low = ents.filter((e) => e.trust < 50).length;
  const worklist = ents.filter((e) => e.trust < 80).sort((a, b) => a.trust - b.trust).slice(0, 25);
  return {
    posture: {
      overall, tier: trustTier(overall), entities: ents.length, low,
      identities: { avg: idAvg, count: idCount }, devices: { avg: devAvg, count: devCount },
    },
    worklist,
  };
}

// ── device-trust export feed (push to the enforcement plane / PEP) ───────────────
// A standard, consumable device-posture feed any ZTNA / IdP / PEP can poll (Cloudflare/Zscaler
// device-posture, Entra Conditional Access device-compliance, a custom PDP) to gate access on the
// XORCISM-computed device trust. `compliant` = trust >= threshold. Keyed by hostname so the
// enforcement plane can map it.
export function deviceTrustFeed(tenant: number | null, minTrust = 60): any {
  const devices: any[] = [];
  try {
    const inv = assetInventory(tenant);
    for (const r of inv.rows) {
      const trust = Math.max(0, Math.min(100, 100 - r.score));
      devices.push({
        assetId: r.id, name: r.name, hostname: r.address || null, os: r.os || null,
        criticality: r.criticality, exposure: r.exposure,
        trust, tier: trustTier(trust), compliant: trust >= minTrust, reasons: r.flags.slice(0, 5),
      });
    }
  } catch { /* none */ }
  devices.sort((a, b) => a.trust - b.trust);
  return {
    source: "XORCISM Zero Trust", schema: "device-trust/1", generated: new Date().toISOString(),
    threshold: minTrust, count: devices.length,
    compliant: devices.filter((d) => d.compliant).length, nonCompliant: devices.filter((d) => !d.compliant).length,
    devices,
  };
}

// ── pillar maturity (assessment if any, else live signal) ────────────────────────
function latestAssessmentId(tenant: number | null): number | null {
  try {
    const r = getDb("XCOMPLIANCE").prepare(`SELECT AssessmentID FROM ZTMATURITYASSESSMENT ${tw(tenant)} ORDER BY AssessmentID DESC LIMIT 1`).get() as { AssessmentID: number } | undefined;
    return r ? Number(r.AssessmentID) : null;
  } catch { return null; }
}

export function ztDashboard(tenant: number | null): any {
  const db = getDb("XCOMPLIANCE");
  const signals = pillarSignals(tenant);
  const aid = latestAssessmentId(tenant);
  const itemsByPillar = new Map<string, { cur: number[]; tgt: number[] }>();
  if (aid != null) {
    try {
      for (const it of db.prepare("SELECT PillarKey, CurrentStage, TargetStage FROM ZTMATURITYITEM WHERE AssessmentID = ?").all(aid) as any[]) {
        const e = itemsByPillar.get(it.PillarKey) ?? { cur: [], tgt: [] };
        if (it.CurrentStage != null) e.cur.push(Number(it.CurrentStage));
        e.tgt.push(it.TargetStage != null ? Number(it.TargetStage) : 3);
        itemsByPillar.set(it.PillarKey, e);
      }
    } catch { /* none */ }
  }
  const avg = (a: number[]) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
  const pillars = ZT_PILLARS.map((p) => {
    const sig = signals[p.key];
    const it = itemsByPillar.get(p.key);
    const assessed = it && it.cur.length ? avg(it.cur) : null;
    const current = assessed != null ? assessed : (sig ? sig.stage : 0);
    const target = it && it.tgt.length ? Math.round(avg(it.tgt)!) : 3;
    return {
      pillarKey: p.key, name: p.name, cross: p.cross,
      currentStage: Math.round(current * 10) / 10, currentLabel: ZT_STAGES[Math.round(current)] ?? "Traditional",
      targetStage: target, pct: Math.round((current / 3) * 100),
      signalStage: sig?.stage ?? 0, signalPct: sig?.pct ?? 0, signalBasis: sig?.basis ?? "",
      source: assessed != null ? "assessment" : "live signal",
    };
  });
  const overallStage = pillars.reduce((s, p) => s + p.currentStage, 0) / pillars.length;
  const trust = trustScores(tenant);
  const ueba = sessionRisk(tenant);
  const policies = ztPolicies(tenant);

  let assessments: any[] = [];
  try {
    assessments = (db.prepare(`SELECT AssessmentID id, Name name, Status status, OverallStage stage, Score score, StartedDate started, TargetDate target FROM ZTMATURITYASSESSMENT ${tw(tenant)} ORDER BY AssessmentID DESC`).all() as any[])
      .map((a) => ({ id: Number(a.id), name: String(a.name ?? ""), status: String(a.status ?? ""), overallStage: a.stage != null ? Number(a.stage) : null, score: a.score != null ? Number(a.score) : null, started: a.started ? String(a.started).slice(0, 10) : "", target: a.target ? String(a.target).slice(0, 10) : "" }));
  } catch { /* none */ }

  const gaps = pillars.filter((p) => p.currentStage < p.targetStage)
    .sort((a, b) => (a.targetStage - a.currentStage) - (b.targetStage - b.currentStage)).reverse();

  return {
    pillars,
    overall: { stage: Math.round(overallStage * 100) / 100, label: ZT_STAGES[Math.round(overallStage)] ?? "Traditional", pct: Math.round((overallStage / 3) * 100) },
    trust: trust.posture, trustWorklist: trust.worklist,
    ueba: { summary: ueba.summary, worklist: ueba.worklist },
    policies: policies.policies, policiesSummary: policies.summary,
    assessments, hasAssessment: aid != null, gaps,
  };
}

// ── assessment detail ───────────────────────────────────────────────────────────
export function getZtAssessment(id: number, tenant: number | null): any | null {
  const db = getDb("XCOMPLIANCE");
  const a = db.prepare(`SELECT * FROM ZTMATURITYASSESSMENT WHERE AssessmentID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as any;
  if (!a) return null;
  const fns = db.prepare("SELECT * FROM ZTFUNCTION ORDER BY DisplayOrder").all() as any[];
  const fnByKey = new Map(fns.map((f) => [f.FunctionKey, f]));
  const items = db.prepare("SELECT * FROM ZTMATURITYITEM WHERE AssessmentID = ? ORDER BY ItemID").all(id) as any[];
  const byPillar = new Map<string, any>();
  for (const it of items) {
    const f = fnByKey.get(it.FunctionKey);
    const pk = String(it.PillarKey ?? f?.PillarKey ?? "");
    const p = ZT_PILLARS.find((x) => x.key === pk);
    let sec = byPillar.get(pk);
    if (!sec) { sec = { pillarKey: pk, name: p?.name ?? pk, cross: !!p?.cross, functions: [] }; byPillar.set(pk, sec); }
    sec.functions.push({
      itemId: Number(it.ItemID), key: it.FunctionKey, name: f?.Name ?? it.FunctionKey, desc: f?.Description ?? "",
      stages: [f?.Stage0, f?.Stage1, f?.Stage2, f?.Stage3], currentStage: it.CurrentStage != null ? Number(it.CurrentStage) : null,
      targetStage: it.TargetStage != null ? Number(it.TargetStage) : 3, autoStage: it.AutoStage != null ? Number(it.AutoStage) : null,
      notes: String(it.Notes ?? ""),
    });
  }
  return {
    assessment: { id: Number(a.AssessmentID), name: String(a.Name ?? ""), scope: String(a.Scope ?? ""), owner: String(a.Owner ?? ""), status: String(a.Status ?? ""), overallStage: a.OverallStage != null ? Number(a.OverallStage) : null, score: a.Score != null ? Number(a.Score) : null, started: a.StartedDate ? String(a.StartedDate).slice(0, 10) : "", target: a.TargetDate ? String(a.TargetDate).slice(0, 10) : "" },
    pillars: [...byPillar.values()],
  };
}

function recomputeAssessment(id: number): void {
  const db = getDb("XCOMPLIANCE");
  const items = db.prepare("SELECT CurrentStage FROM ZTMATURITYITEM WHERE AssessmentID = ?").all(id) as { CurrentStage: number | null }[];
  const vals = items.map((i) => (i.CurrentStage != null ? Number(i.CurrentStage) : null)).filter((v): v is number => v != null);
  const overall = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
  db.prepare("UPDATE ZTMATURITYASSESSMENT SET OverallStage = ?, Score = ? WHERE AssessmentID = ?")
    .run(overall != null ? Math.round(overall * 100) / 100 : null, overall != null ? stageToPct(overall) : null, id);
}

export function createZtAssessment(p: { name?: string; scope?: string; owner?: string; targetDate?: string; targetStage?: number }, tenant: number | null, createdBy?: string): { id: number } {
  const db = getDb("XCOMPLIANCE");
  const signals = pillarSignals(tenant);
  const ac = colsOf("ZTMATURITYASSESSMENT");
  const id = allocId(db, "ZTMATURITYASSESSMENT", "AssessmentID");
  const rec: Record<string, unknown> = {
    AssessmentID: id, AssessmentGUID: randomUUID(), Name: (p.name || `Zero Trust maturity — ${new Date().getFullYear()}`).slice(0, 300),
    Scope: (p.scope || "").slice(0, 2000), Owner: (p.owner || "").slice(0, 200), Status: "in_progress",
    TargetStage: p.targetStage != null ? Math.max(0, Math.min(3, p.targetStage)) : 3, StartedDate: now().slice(0, 10),
    TargetDate: p.targetDate || null, TenantID: tenant, CreatedBy: createdBy ?? null, CreatedDate: now(),
  };
  const keys = Object.keys(rec).filter((k) => ac.has(k));
  const insA = db.prepare(`INSERT INTO ZTMATURITYASSESSMENT (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`);
  const ic = colsOf("ZTMATURITYITEM");
  let iid = allocId(db, "ZTMATURITYITEM", "ItemID");
  const insI = db.prepare(`INSERT INTO ZTMATURITYITEM (ItemID, AssessmentID, FunctionKey, Pillar, PillarKey, CurrentStage, TargetStage, AutoStage, TenantID) VALUES (?,?,?,?,?,?,?,?,?)`);
  const pillarName = (k: string) => ZT_PILLARS.find((x) => x.key === k)?.name ?? k;
  db.transaction(() => {
    insA.run(...keys.map((k) => rec[k]));
    if (ic.has("ItemID")) {
      for (const f of ZTMM) {
        const auto = signals[f.pillarKey]?.stage ?? null;
        insI.run(iid++, id, f.key, pillarName(f.pillarKey), f.pillarKey, auto, rec.TargetStage, auto, tenant);
      }
    }
  })();
  recomputeAssessment(id);
  return { id };
}

export function setZtItem(itemId: number, patch: { currentStage?: number; targetStage?: number; notes?: string }, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT ItemID, AssessmentID FROM ZTMATURITYITEM WHERE ItemID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [itemId, tenant] : [itemId])) as { ItemID: number; AssessmentID: number } | undefined;
  if (!row) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (patch.currentStage != null) { sets.push("CurrentStage = ?"); vals.push(Math.max(0, Math.min(3, Math.round(patch.currentStage)))); }
  if (patch.targetStage != null) { sets.push("TargetStage = ?"); vals.push(Math.max(0, Math.min(3, Math.round(patch.targetStage)))); }
  if (patch.notes != null) { sets.push("Notes = ?"); vals.push(String(patch.notes).slice(0, 2000)); }
  if (sets.length) { vals.push(itemId); db.prepare(`UPDATE ZTMATURITYITEM SET ${sets.join(", ")} WHERE ItemID = ?`).run(...vals); recomputeAssessment(row.AssessmentID); }
  return true;
}

export function deleteZtAssessment(id: number, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT AssessmentID FROM ZTMATURITYASSESSMENT WHERE AssessmentID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as { AssessmentID: number } | undefined;
  if (!row) return false;
  db.prepare("DELETE FROM ZTMATURITYITEM WHERE AssessmentID = ?").run(id);
  db.prepare("DELETE FROM ZTMATURITYASSESSMENT WHERE AssessmentID = ?").run(id);
  return true;
}

// ── demo sign-in telemetry (tenant 3) so UEBA / the Identity pillar has data ─────────
export function seedZtSigninDemo(tenant: number): void {
  try {
    const xo = getDb("XORCISM");
    if (!new Set((xo.prepare("PRAGMA table_info(IDENTITYSIGNIN)").all() as { name: string }[]).map((c) => c.name)).size) return;
    if (xo.prepare("SELECT 1 FROM IDENTITYSIGNIN WHERE TenantID = ? LIMIT 1").get(tenant)) return; // idempotent
    let names: string[] = [];
    try { names = (xo.prepare("SELECT IdentityName FROM IDENTITY WHERE (TenantID = ? OR TenantID IS NULL) AND IdentityName IS NOT NULL ORDER BY IdentityID LIMIT 4").all(tenant) as { IdentityName: string }[]).map((r) => r.IdentityName).filter(Boolean); } catch { /* none */ }
    const u = names[0] || "alice@demo.local", v = names[1] || "bob@demo.local", w = names[2] || "svc-deploy@demo.local", c = names[3] || "carol@demo.local";
    const t0 = Date.now();
    const iso = (hAgo: number) => new Date(t0 - hAgo * 3600e3).toISOString();
    // [name, ts, country, ip, mfa, result, failureReason, risk]
    const rows: [string, string, string, string, string, string, string | null, string][] = [
      [u, iso(2), "US", "203.0.113.5", "yes", "success", null, "none"],
      [u, iso(1), "RU", "198.51.100.9", "no", "success", null, "medium"], // impossible travel + MFA-less + IdP risk
      ...Array.from({ length: 6 }, (_, i) => [v, iso(5) , "US", "192.0.2.4", "no", "failure", "invalid password", "low"] as [string, string, string, string, string, string, string, string]),
      [v, iso(4), "US", "192.0.2.4", "yes", "success", null, "none"],
      [w, iso(8), "US", "10.0.0.9", "no", "success", null, "none"],
      [w, iso(7), "US", "10.0.0.9", "no", "success", null, "none"], // service account, MFA-less
      [c, iso(6), "US", "203.0.113.20", "yes", "success", null, "none"], // clean
    ];
    const ins = xo.prepare("INSERT INTO IDENTITYSIGNIN (SigninGUID, IdentityName, IdentityID, Timestamp, Country, SourceIP, MFAUsed, Result, FailureReason, RiskLevel, Source, ExternalID, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    const idOf = (n: string) => { try { const r = xo.prepare("SELECT IdentityID FROM IDENTITY WHERE IdentityName = ? LIMIT 1").get(n) as { IdentityID: number } | undefined; return r ? r.IdentityID : null; } catch { return null; } };
    rows.forEach((r, i) => ins.run(randomUUID(), r[0], idOf(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7], "demo-seed", `ztdemo-${i}`, tenant, new Date().toISOString()));
  } catch { /* best-effort demo */ }
}
