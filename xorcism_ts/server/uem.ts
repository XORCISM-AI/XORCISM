/**
 * uem.ts — Unified Exposure Management (the UEMP spine).
 *
 * Turns XORCISM's federated finding sources into ONE exposure program: collectors normalize each
 * source (CVEs, cloud misconfigs, quantum-vulnerable crypto, AI scan + AI-agent exposure, identity
 * SoD, audit/misconfig) into a canonical exposure, deduplicated by a stable Fingerprint and scored by
 * ONE generalized fusion model. syncExposures() upserts into XVULNERABILITY.EXPOSURE and drives the
 * lifecycle (new / reopened / auto-resolved when a source stops reporting). The result is a single
 * prioritized, ownable, SLA-tracked queue + a single Exposure Score + a coverage/confidence view.
 *
 * Validation re-weights the score (proven-exploitable ↑, proven-safe ↓) — the hook that lets AEV /
 * BAS results change priority, separating exposure *management* from a vulnerability *list*.
 */
import { getDb } from "./db";
import { topExposures } from "./fusion";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const cols = (db: ReturnType<typeof getDb>, t: string): Set<string> => {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
};
const s = (v: unknown): string => (v == null ? "" : String(v));
const tcl = (tenant: number | null, set: Set<string>): string => (tenant != null && set.has("TenantID") ? " AND (TenantID = ? OR TenantID IS NULL)" : "");
const tArg = (tenant: number | null, set: Set<string>): number[] => (tenant != null && set.has("TenantID") ? [tenant] : []);

export const EXPOSURE_TYPES = ["cve", "cloud", "crypto", "ai-scan", "ai-agent", "identity", "data", "misconfig"];
const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, "": 0 };
const SLA_HOURS: Record<string, number> = { CRITICAL: 24, HIGH: 72, MEDIUM: 168, LOW: 336 };
const normSev = (v: string): string => {
  const x = v.toUpperCase();
  if (/CRIT/.test(x)) return "CRITICAL";
  if (/HIGH|SEVERE/.test(x)) return "HIGH";
  if (/MED|MOD/.test(x)) return "MEDIUM";
  if (/LOW|MINOR/.test(x)) return "LOW";
  return "MEDIUM";
};

export interface RawExposure {
  fingerprint: string; type: string; title: string; assetRef: string; assetId?: number | null;
  severity: string; baseScore: number; exploitability: string; publicFacing?: boolean; reachability?: string;
  businessValue?: number | null; assetCount?: number; sourceModule: string; sourceRef: string; factors: string[];
}

/** Generalized fusion: a severity floor amplified by exploitability, blast radius and exposure. 0-100. */
function genScore(sev: string, opts: { exploit?: string; aivss?: number | null; quantum?: boolean; publicFacing?: boolean; businessValue?: number | null; assetCount?: number; reach?: string }): { score: number; factors: string[] } {
  const factors: string[] = [];
  let score = { CRITICAL: 70, HIGH: 50, MEDIUM: 30, LOW: 12 }[sev] ?? 25;
  factors.push(`${sev} base (${score})`);
  const e = (opts.exploit || "").toLowerCase();
  if (/kev|in-the-wild|itw/.test(e)) { score += 25; factors.push("known-exploited (+25)"); }
  else if (/exploit/.test(e)) { score += 15; factors.push("public exploit (+15)"); }
  if (opts.aivss != null && opts.aivss > 0) { const b = Math.round(opts.aivss * 2); score += b; factors.push(`AIVSS ${opts.aivss} (+${b})`); }
  if (opts.quantum) { score += 8; factors.push("harvest-now-decrypt-later (+8)"); }
  if (opts.publicFacing) { score += 12; factors.push("internet-facing (+12)"); }
  if (opts.reach === "privileged-access") { score += 14; factors.push("reaches privileged access (+14)"); }
  const bv = Number(opts.businessValue) || 0;
  if (bv >= 100000) { score += 12; factors.push("crown-jewel blast (+12)"); }
  else if (bv > 0) { score += 5; factors.push("business value (+5)"); }
  if ((opts.assetCount || 0) > 5) { score += 6; factors.push(`${opts.assetCount} assets (+6)`); }
  return { score: Math.max(1, Math.min(100, Math.round(score))), factors };
}

/** Apply the validation modifier to a base score (proven-exploitable ↑ / proven-safe ↓). */
function applyValidation(base: number, validation: string): number {
  if (validation === "validated-exploitable") return Math.min(100, Math.round(base * 1.25));
  if (validation === "validated-safe") return Math.max(1, Math.round(base * 0.4));
  return base;
}

// ── Collectors (each tolerant: absent table/source contributes nothing) ────────
function collectCve(tenant: number | null): RawExposure[] {
  let out: RawExposure[] = [];
  try {
    const top = topExposures(tenant, 200).results || [];
    out = top.map((f) => {
      const exploit = f.kev ? "KEV (known-exploited)" : f.itw ? "in-the-wild" : f.exploits > 0 ? "public exploit" : "theoretical";
      return {
        fingerprint: `cve|${f.ref}`, type: "cve", title: `${f.ref}${f.cvss != null ? ` (CVSS ${f.cvss})` : ""}`,
        assetRef: `${f.assets} asset${f.assets === 1 ? "" : "s"}`, severity: f.cvss != null ? (f.cvss >= 9 ? "CRITICAL" : f.cvss >= 7 ? "HIGH" : f.cvss >= 4 ? "MEDIUM" : "LOW") : "MEDIUM",
        baseScore: f.score, exploitability: exploit, publicFacing: !!f.publicFacing, businessValue: f.maxValue, assetCount: f.assets,
        sourceModule: "Vulnerability (fusion)", sourceRef: String(f.VulnerabilityID), factors: f.factors || [],
      };
    });
  } catch { /* fusion/VULNERABILITY absent */ }
  return out;
}

function collectCloud(tenant: number | null): RawExposure[] {
  const db = getDb("XORCISM");
  if (!has(db, "CLOUDFINDING")) return [];
  const c = cols(db, "CLOUDFINDING");
  const rows = db.prepare(`SELECT CloudFindingID id, Provider, Account, CheckID, Title, Service, Severity, Resource, Status
    FROM CLOUDFINDING WHERE (Status IS NULL OR UPPER(Status) NOT IN ('PASS','PASSED','OK','RESOLVED'))${tcl(tenant, c)}`).all(...tArg(tenant, c)) as any[];
  return rows.map((r) => {
    const sev = normSev(s(r.Severity));
    const sc = genScore(sev, {});
    return { fingerprint: `cloud|${s(r.Account)}|${s(r.CheckID)}|${s(r.Resource)}`, type: "cloud",
      title: `${s(r.Title) || s(r.CheckID)}`, assetRef: `${s(r.Provider)}:${s(r.Resource) || s(r.Service)}`, severity: sev,
      baseScore: sc.score, exploitability: "misconfiguration", sourceModule: "Cloud Security", sourceRef: String(r.id), factors: sc.factors };
  });
}

function collectCrypto(tenant: number | null): RawExposure[] {
  const db = getDb("XORCISM");
  if (!has(db, "CRYPTOASSET")) return [];
  const c = cols(db, "CRYPTOASSET");
  const rows = db.prepare(`SELECT CryptoAssetID id, Name, Algorithm, AssetType, QuantumSafe, Deprecated, AssetID
    FROM CRYPTOASSET WHERE (QuantumSafe = 0 OR Deprecated = 1)${tcl(tenant, c)}`).all(...tArg(tenant, c)) as any[];
  return rows.map((r) => {
    const dep = Number(r.Deprecated) === 1;
    const sev = dep ? "HIGH" : "MEDIUM";
    const sc = genScore(sev, { quantum: Number(r.QuantumSafe) === 0 });
    return { fingerprint: `crypto|${s(r.AssetID) || s(r.Name)}|${s(r.Algorithm)}`, type: "crypto",
      title: `${dep ? "Deprecated" : "Quantum-vulnerable"} ${s(r.Algorithm) || s(r.Name)}`, assetRef: s(r.Name) || s(r.Algorithm),
      assetId: r.AssetID || null, severity: sev, baseScore: sc.score, exploitability: dep ? "deprecated algorithm" : "harvest-now-decrypt-later",
      sourceModule: "CBOM / PQC", sourceRef: String(r.id), factors: sc.factors };
  });
}

function collectAiScan(tenant: number | null): RawExposure[] {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "AVESCANFINDING")) return [];
  const rows = db.prepare("SELECT ScanFindingID id, AveId, Title, Severity, AivssScore, File, Status FROM AVESCANFINDING WHERE Status IS NULL OR UPPER(Status) != 'RESOLVED'").all() as any[];
  return rows.map((r) => {
    const sev = normSev(s(r.Severity));
    const sc = genScore(sev, { aivss: r.AivssScore });
    return { fingerprint: `ai-scan|${s(r.File)}|${s(r.AveId)}`, type: "ai-scan", title: `${s(r.AveId)} ${s(r.Title)}`,
      assetRef: s(r.File), severity: sev, baseScore: sc.score, exploitability: "behavioral (AVE)", sourceModule: "AVE scan (bawbel-scanner)", sourceRef: String(r.id), factors: sc.factors };
  });
}

function collectAiAgent(tenant: number | null): RawExposure[] {
  const db = getDb("XAGENT");
  if (!has(db, "AVEFINDING")) return [];
  const c = cols(db, "AVEFINDING");
  const rows = db.prepare(`SELECT FindingID id, AgentName, AveId, Title, Severity, AivssScore FROM AVEFINDING WHERE Status='exposed'${tcl(tenant, c)}`).all(...tArg(tenant, c)) as any[];
  return rows.map((r) => {
    const sev = normSev(s(r.Severity));
    const sc = genScore(sev, { aivss: r.AivssScore });
    return { fingerprint: `ai-agent|${s(r.AgentName)}|${s(r.AveId)}`, type: "ai-agent", title: `${s(r.AveId)} ${s(r.Title)}`,
      assetRef: s(r.AgentName), severity: sev, baseScore: sc.score, exploitability: "ungoverned AI agent", sourceModule: "AVE agent exposure", sourceRef: String(r.id), factors: sc.factors };
  });
}

/** Does this identity hold a privileged entitlement? (lightweight identity-reachability signal). */
function privilegedIdentities(db: ReturnType<typeof getDb>): Set<number> {
  const out = new Set<number>();
  if (!has(db, "IDENTITYENTITLEMENT") || !has(db, "ENTITLEMENT")) return out;
  try {
    for (const r of db.prepare("SELECT DISTINCT ie.IdentityID id FROM IDENTITYENTITLEMENT ie JOIN ENTITLEMENT e ON e.EntitlementID=ie.EntitlementID WHERE e.Privileged=1").all() as { id: number }[]) if (r.id != null) out.add(Number(r.id));
  } catch { /* tolerate */ }
  return out;
}

function collectIdentity(tenant: number | null): RawExposure[] {
  const db = getDb("XORCISM");
  if (!has(db, "SODVIOLATION")) return [];
  const c = cols(db, "SODVIOLATION");
  const hasIdCol = c.has("IdentityID");
  const priv = hasIdCol ? privilegedIdentities(db) : new Set<number>();
  const idSel = hasIdCol ? "IdentityID," : "";
  const rows = db.prepare(`SELECT SodViolationID id, RuleName, ${idSel} IdentityName, Risk, Status FROM SODVIOLATION WHERE (Status IS NULL OR Status='open')${tcl(tenant, c)}`).all(...tArg(tenant, c)) as any[];
  return rows.map((r) => {
    const reaches = hasIdCol && priv.has(Number(r.IdentityID));
    const sev = reaches ? "CRITICAL" : normSev(s(r.Risk) || "HIGH");
    const sc = genScore(sev, { reach: reaches ? "privileged-access" : undefined });
    return { fingerprint: `identity|${s(r.IdentityName)}|${r.id}`, type: "identity", title: `SoD: ${s(r.RuleName)}`,
      assetRef: s(r.IdentityName), severity: sev, baseScore: sc.score, exploitability: "toxic entitlement combination",
      reachability: reaches ? "privileged-access" : "standard-access", sourceModule: "Access Governance (SoD)", sourceRef: String(r.id), factors: sc.factors };
  });
}

/** DSPM / data exposure: sensitive-classified documents shared at a permissive TLP (over-exposed data). */
function collectData(tenant: number | null): RawExposure[] {
  const db = getDb("XORCISM");
  if (!has(db, "DOCUMENT")) return [];
  const c = cols(db, "DOCUMENT");
  if (!c.has("Classification") || !c.has("TLP")) return [];
  const nameCol = c.has("DocumentName") ? "DocumentName" : c.has("DocumentTitle") ? "DocumentTitle" : c.has("Title") ? "Title" : "DocumentID";
  const rows = db.prepare(`SELECT DocumentID id, ${nameCol} name, Classification, TLP FROM DOCUMENT
    WHERE Classification IS NOT NULL AND TLP IS NOT NULL
      AND UPPER(Classification) IN ('CONFIDENTIAL','SECRET','TOP SECRET','RESTRICTED','PII','PHI','PCI','SENSITIVE')
      AND UPPER(TLP) IN ('CLEAR','WHITE','TLP:CLEAR','TLP:WHITE','GREEN','TLP:GREEN')${tcl(tenant, c)}`).all(...tArg(tenant, c)) as any[];
  return rows.map((r) => {
    const sev = /SECRET|PII|PHI|PCI|RESTRICTED/i.test(s(r.Classification)) ? "HIGH" : "MEDIUM";
    const sc = genScore(sev, { publicFacing: /CLEAR|WHITE/i.test(s(r.TLP)) });
    return { fingerprint: `data|${r.id}`, type: "data", title: `Over-exposed ${s(r.Classification)} document`,
      assetRef: s(r.name) || `Document #${r.id}`, severity: sev, baseScore: sc.score, exploitability: `sensitive data at ${s(r.TLP)}`,
      reachability: "data-exposure", sourceModule: "Data Security (DSPM)", sourceRef: String(r.id), factors: sc.factors };
  });
}

function collectMisconfig(tenant: number | null): RawExposure[] {
  const db = getDb("XCOMPLIANCE");
  if (!has(db, "AUDITFINDING")) return [];
  const rows = db.prepare("SELECT AuditFindingID id, FindingName, FindingStatus, FindingCriticity, FindingStakeholder FROM AUDITFINDING WHERE (FindingStatus IS NULL OR UPPER(FindingStatus) NOT IN ('CLOSED','RESOLVED','DONE'))").all() as any[];
  return rows.filter((r) => /high|crit|elev/i.test(s(r.FindingCriticity))).map((r) => {
    const sev = normSev(s(r.FindingCriticity));
    const sc = genScore(sev, {});
    return { fingerprint: `misconfig|${r.id}`, type: "misconfig", title: s(r.FindingName) || `Audit finding #${r.id}`,
      assetRef: s(r.FindingStakeholder) || "—", severity: sev, baseScore: sc.score, exploitability: "control gap", sourceModule: "Audit findings", sourceRef: String(r.id), factors: sc.factors };
  });
}

export function collectAll(tenant: number | null): RawExposure[] {
  return [collectCve, collectCloud, collectCrypto, collectAiScan, collectAiAgent, collectIdentity, collectData, collectMisconfig]
    .flatMap((fn) => { try { return fn(tenant); } catch { return []; } });
}

/** Sync the unified queue from all sources: dedup by fingerprint, drive the lifecycle. */
export function syncExposures(tenant: number | null): { scanned: number; created: number; updated: number; reopened: number; resolved: number } {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "EXPOSURE")) return { scanned: 0, created: 0, updated: 0, reopened: 0, resolved: 0 };
  const raws = collectAll(tenant);
  const now = new Date().toISOString();
  const seen = new Set<string>();
  let created = 0, updated = 0, reopened = 0, resolved = 0;
  const get = db.prepare("SELECT ExposureID, Status, Validation FROM EXPOSURE WHERE Fingerprint = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)");
  const upd = db.prepare(`UPDATE EXPOSURE SET Title=?, AssetRef=?, AssetID=?, Severity=?, BaseScore=?, Score=?, Exploitability=?,
    Reachability=?, PublicFacing=?, BusinessValue=?, AssetCount=?, SourceModule=?, SourceRef=?, Factors=?, LastSeen=?,
    Status=CASE WHEN Status='resolved' THEN 'reopened' ELSE Status END, ResolvedDate=CASE WHEN Status='resolved' THEN NULL ELSE ResolvedDate END
    WHERE ExposureID=?`);
  const ins = db.prepare(`INSERT INTO EXPOSURE (Fingerprint, Type, Title, AssetRef, AssetID, Severity, Score, BaseScore, Exploitability,
    Reachability, PublicFacing, BusinessValue, AssetCount, SourceModule, SourceRef, Validation, Status, SlaHours, DueDate, Factors, FirstSeen, LastSeen, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'unvalidated','open',?,?,?,?,?,?)`);
  const tx = db.transaction(() => {
    for (const r of raws) {
      seen.add(r.fingerprint);
      const reach = r.reachability || (r.publicFacing ? "internet-facing" : "internal");
      const existing = get.get(r.fingerprint, tenant) as { ExposureID: number; Status: string; Validation: string } | undefined;
      const score = applyValidation(r.baseScore, existing?.Validation || "unvalidated");
      if (existing) {
        upd.run(r.title.slice(0, 300), r.assetRef.slice(0, 200), r.assetId ?? null, r.severity, r.baseScore, score, r.exploitability,
          reach, r.publicFacing ? 1 : 0, r.businessValue ?? null, r.assetCount ?? null, r.sourceModule, r.sourceRef, JSON.stringify(r.factors).slice(0, 1500), now, existing.ExposureID);
        if (existing.Status === "resolved") reopened++; else updated++;
      } else {
        const sla = SLA_HOURS[r.severity] ?? 168;
        const due = new Date(Date.now() + sla * 3600 * 1000).toISOString().slice(0, 10);
        ins.run(r.fingerprint, r.type, r.title.slice(0, 300), r.assetRef.slice(0, 200), r.assetId ?? null, r.severity, score, r.baseScore, r.exploitability,
          reach, r.publicFacing ? 1 : 0, r.businessValue ?? null, r.assetCount ?? null, r.sourceModule, r.sourceRef, sla, due, JSON.stringify(r.factors).slice(0, 1500), now, now, tenant);
        created++;
      }
    }
    // auto-resolve: open exposures of the synced types whose source no longer reports them
    const syncedTypes = EXPOSURE_TYPES.map(() => "?").join(",");
    const openRows = db.prepare(`SELECT ExposureID, Fingerprint FROM EXPOSURE WHERE Status NOT IN ('resolved','risk-accepted') AND Type IN (${syncedTypes}) AND IFNULL(TenantID,-1)=IFNULL(?,-1)`).all(...EXPOSURE_TYPES, tenant) as { ExposureID: number; Fingerprint: string }[];
    const res = db.prepare("UPDATE EXPOSURE SET Status='resolved', ResolvedDate=? WHERE ExposureID=?");
    for (const o of openRows) if (!seen.has(o.Fingerprint)) { res.run(now, o.ExposureID); resolved++; }
  });
  tx();
  try { recordExposureScore(tenant); } catch { /* trend best-effort */ }
  return { scanned: raws.length, created, updated, reopened, resolved };
}

/** Persist today's Exposure Score (upsert one row per tenant per day) — the trend spine. */
export function recordExposureScore(tenant: number | null): void {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "EXPOSURESCORE")) return;
  const sum = exposureSummary(tenant);
  const day = new Date().toISOString().slice(0, 10);
  const ex = db.prepare(`SELECT ExposureScoreID FROM EXPOSURESCORE WHERE Day=? AND IFNULL(TenantID,-1)=IFNULL(?,-1)`).get(day, tenant) as { ExposureScoreID: number } | undefined;
  if (ex) db.prepare("UPDATE EXPOSURESCORE SET Score=?, Open=?, Critical=?, ValidatedExploitable=? WHERE ExposureScoreID=?").run(sum.exposureScore, sum.total, sum.critical, sum.validatedExploitable, ex.ExposureScoreID);
  else db.prepare("INSERT INTO EXPOSURESCORE (Day, Score, Open, Critical, ValidatedExploitable, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?)").run(day, sum.exposureScore, sum.total, sum.critical, sum.validatedExploitable, tenant, new Date().toISOString());
}

/** The Exposure Score over time (daily series) — for the trend sparkline + program KPI. */
export function exposureTrend(tenant: number | null, days = 90): { series: any[]; current: number; delta: number } {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "EXPOSURESCORE")) return { series: [], current: 0, delta: 0 };
  const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  const series = db.prepare(`SELECT Day, Score, Open, Critical, ValidatedExploitable FROM EXPOSURESCORE WHERE ${tw(tenant)}${days ? " AND Day >= ?" : ""} ORDER BY Day`).all(...ta(tenant), ...(days ? [since] : [])) as any[];
  const current = series.length ? series[series.length - 1].Score : 0;
  const delta = series.length > 1 ? current - series[0].Score : 0;
  return { series, current, delta };
}

const tw = (tenant: number | null): string => (tenant != null ? "IFNULL(TenantID,-1)=IFNULL(?,-1)" : "1=1");
const ta = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

/** The single prioritized exposure queue, filterable across every exposure type. */
export function exposureQueue(tenant: number | null, f?: { type?: string; severity?: string; status?: string; validation?: string; q?: string; openOnly?: boolean }): any[] {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "EXPOSURE")) return [];
  const where: string[] = [tw(tenant)], args: any[] = [...ta(tenant)];
  if (f?.type) { where.push("Type=?"); args.push(f.type); }
  if (f?.severity) { where.push("Severity=?"); args.push(f.severity.toUpperCase()); }
  if (f?.status) { where.push("Status=?"); args.push(f.status); }
  else if (f?.openOnly) where.push("Status NOT IN ('resolved','risk-accepted')");
  if (f?.validation) { where.push("Validation=?"); args.push(f.validation); }
  if (f?.q) { where.push("(Title LIKE ? OR AssetRef LIKE ?)"); args.push(`%${f.q}%`, `%${f.q}%`); }
  return db.prepare(`SELECT * FROM EXPOSURE WHERE ${where.join(" AND ")} ORDER BY (Status IN ('resolved','risk-accepted')), Score DESC, ExposureID DESC LIMIT 500`).all(...args) as any[];
}

/** KPIs + the single Exposure Score + breakdowns. */
export function exposureSummary(tenant: number | null): any {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "EXPOSURE")) return { total: 0 };
  const rows = db.prepare(`SELECT Type, Severity, Score, Status, Validation, SourceModule, DueDate, FirstSeen, ResolvedDate FROM EXPOSURE WHERE ${tw(tenant)}`).all(...ta(tenant)) as any[];
  const open = rows.filter((r) => !["resolved", "risk-accepted"].includes(r.Status));
  const by = (key: string, src = open): Record<string, number> => src.reduce((m: any, r: any) => { const k = r[key] || "—"; m[k] = (m[k] || 0) + 1; return m; }, {});
  const today = new Date().toISOString().slice(0, 10);
  const mttrDays = (() => { const done = rows.filter((r) => r.Status === "resolved" && r.FirstSeen && r.ResolvedDate); if (!done.length) return null; return Math.round(done.reduce((n, r) => n + Math.max(0, (Date.parse(r.ResolvedDate) - Date.parse(r.FirstSeen)) / 86400000), 0) / done.length * 10) / 10; })();
  // single Exposure Score: severity-weighted density of open exposures, validation-amplified, 0-100
  const weight = (r: any) => (SEV_RANK[r.Severity] || 1) * (r.Validation === "validated-exploitable" ? 1.5 : 1);
  const raw = open.reduce((n, r) => n + weight(r), 0);
  const exposureScore = open.length ? Math.min(100, Math.round((raw / open.length) * 18 + Math.min(40, open.length * 0.6))) : 0;
  return {
    total: open.length, allTime: rows.length,
    critical: open.filter((r) => r.Severity === "CRITICAL").length,
    high: open.filter((r) => r.Severity === "HIGH").length,
    validatedExploitable: open.filter((r) => r.Validation === "validated-exploitable").length,
    overdue: open.filter((r) => r.DueDate && r.DueDate < today).length,
    riskAccepted: rows.filter((r) => r.Status === "risk-accepted").length,
    resolved: rows.filter((r) => r.Status === "resolved").length,
    mttrDays, exposureScore,
    byType: by("Type"), bySeverity: by("Severity"), bySource: by("SourceModule"),
  };
}

/** Coverage / confidence: which sources are feeding the queue, freshness, and blind spots. */
export function exposureCoverage(tenant: number | null): any {
  const db = getDb("XVULNERABILITY");
  const labels: Record<string, string> = { cve: "Vulnerabilities (CVE)", cloud: "Cloud / CSPM", crypto: "Cryptography / PQC", "ai-scan": "AI component scan", "ai-agent": "AI-agent exposure", identity: "Identity / SoD", misconfig: "Audit / misconfig" };
  let rows: any[] = [];
  try { rows = db.prepare(`SELECT Type, COUNT(*) n, MAX(LastSeen) last FROM EXPOSURE WHERE ${tw(tenant)} GROUP BY Type`).all(...ta(tenant)) as any[]; } catch { /* */ }
  const byType = Object.fromEntries(rows.map((r) => [r.Type, r]));
  const sources = EXPOSURE_TYPES.map((t) => ({ type: t, label: labels[t], feeding: !!byType[t], count: byType[t]?.n || 0, lastSeen: byType[t]?.last || null }));
  // asset blind-spot estimate: assets that have NO exposure record at all
  let assets = 0, coveredAssets = 0;
  try {
    const xo = getDb("XORCISM");
    if (has(xo, "ASSET")) {
      const c = cols(xo, "ASSET");
      assets = Number((xo.prepare(`SELECT COUNT(*) n FROM ASSET WHERE 1=1${tcl(tenant, c)}`).get(...tArg(tenant, c)) as { n: number }).n) || 0;
      coveredAssets = Number((db.prepare(`SELECT COUNT(DISTINCT AssetID) n FROM EXPOSURE WHERE AssetID IS NOT NULL AND ${tw(tenant)}`).get(...ta(tenant)) as { n: number }).n) || 0;
    }
  } catch { /* */ }
  const feeding = sources.filter((x) => x.feeding).length;
  return { sources, feeding, total: EXPOSURE_TYPES.length, confidence: Math.round((feeding / EXPOSURE_TYPES.length) * 100), assets, coveredAssets, blindAssets: Math.max(0, assets - coveredAssets) };
}

// ── Lifecycle actions ──────────────────────────────────────────────────────────
export function setStatus(tenant: number | null, id: number, status: string, owner?: string): { ok: boolean } {
  const db = getDb("XVULNERABILITY");
  const valid = ["open", "triaged", "mobilizing", "resolved", "reopened", "risk-accepted"];
  if (!valid.includes(status)) return { ok: false };
  const resolved = status === "resolved" ? new Date().toISOString() : null;
  const r = db.prepare(`UPDATE EXPOSURE SET Status=?, ResolvedDate=COALESCE(?,ResolvedDate), Owner=COALESCE(?,Owner) WHERE ExposureID=? AND ${tw(tenant)}`).run(status, resolved, owner ?? null, id, ...ta(tenant));
  return { ok: r.changes > 0 };
}

export function acceptRisk(tenant: number | null, id: number, note: string): { ok: boolean } {
  const db = getDb("XVULNERABILITY");
  const r = db.prepare(`UPDATE EXPOSURE SET Status='risk-accepted', RiskAcceptNote=? WHERE ExposureID=? AND ${tw(tenant)}`).run(s(note).slice(0, 500), id, ...ta(tenant));
  return { ok: r.changes > 0 };
}

/** Set the validation state — re-weights the score (the AEV → priority hook). */
export function setValidation(tenant: number | null, id: number, validation: string): { ok: boolean; score?: number } {
  const db = getDb("XVULNERABILITY");
  const valid = ["unvalidated", "validated-exploitable", "validated-safe"];
  if (!valid.includes(validation)) return { ok: false };
  const row = db.prepare(`SELECT BaseScore FROM EXPOSURE WHERE ExposureID=? AND ${tw(tenant)}`).get(id, ...ta(tenant)) as { BaseScore: number } | undefined;
  if (!row) return { ok: false };
  const score = applyValidation(Number(row.BaseScore) || 0, validation);
  db.prepare(`UPDATE EXPOSURE SET Validation=?, Score=? WHERE ExposureID=? AND ${tw(tenant)}`).run(validation, score, id, ...ta(tenant));
  return { ok: true, score };
}

export function assignOwner(tenant: number | null, id: number, owner: string): { ok: boolean } {
  const db = getDb("XVULNERABILITY");
  const r = db.prepare(`UPDATE EXPOSURE SET Owner=? WHERE ExposureID=? AND ${tw(tenant)}`).run(s(owner).slice(0, 120), id, ...ta(tenant));
  return { ok: r.changes > 0 };
}

const PRIORITY: Record<string, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };

/** Governed mobilization: open an INTERNAL remediation ticket (XTICKET) from an exposure and link it.
 *  Stays in-platform & worker-safe — an external push (Jira/ServiceNow) uses the exported payload below. */
export function mobilizeExposure(tenant: number | null, id: number, assignee?: string): { ok: boolean; ticket?: string } {
  const xv = getDb("XVULNERABILITY");
  const e = xv.prepare(`SELECT * FROM EXPOSURE WHERE ExposureID=? AND ${tw(tenant)}`).get(id, ...ta(tenant)) as any;
  if (!e) return { ok: false };
  const xt = getDb("XTICKET");
  if (!has(xt, "TICKET")) return { ok: false };
  const tcols = cols(xt, "TICKET");
  const tid = Number((xt.prepare("SELECT COALESCE(MAX(TicketID),0)+1 n FROM TICKET").get() as { n: number }).n);
  const num = `EXP-${tid}`;
  const now = new Date().toISOString();
  const rec: Record<string, any> = {
    TicketID: tid, TicketGUID: (globalThis as any).crypto?.randomUUID?.() ?? String(tid), TicketNumber: num,
    Subject: `[Exposure ${e.Type.toUpperCase()}] ${e.Title}`.slice(0, 300),
    Description: `Unified exposure ${id} (${e.Type}). Asset: ${e.AssetRef}. Severity ${e.Severity}, score ${e.Score}. ` +
      `${e.Exploitability}; reachability ${e.Reachability}. Source: ${e.SourceModule}. SLA due ${e.DueDate || "n/a"}.`,
    Status: "Open", Priority: PRIORITY[e.Severity] || "Medium", Severity: e.Severity, TicketType: "Remediation",
    AssigneeName: assignee || e.Owner || null, Tags: `exposure,${e.Type}`, DueDate: e.DueDate || null, CreatedDate: now, UpdatedDate: now,
  };
  const keys = Object.keys(rec).filter((k) => tcols.has(k));
  xt.prepare(`INSERT INTO TICKET (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  xv.prepare(`UPDATE EXPOSURE SET Status='mobilizing', TicketRef=?, Owner=COALESCE(?,Owner) WHERE ExposureID=? AND ${tw(tenant)}`).run(num, assignee ?? null, id, ...ta(tenant));
  return { ok: true, ticket: num };
}

/** A ticketing-system-ready payload for an exposure (Jira / ServiceNow / generic) — for export, not auto-push. */
export function exposureExport(tenant: number | null, id: number): any | null {
  const db = getDb("XVULNERABILITY");
  const e = db.prepare(`SELECT * FROM EXPOSURE WHERE ExposureID=? AND ${tw(tenant)}`).get(id, ...ta(tenant)) as any;
  if (!e) return null;
  let factors: string[] = []; try { factors = JSON.parse(e.Factors || "[]"); } catch { /* */ }
  return {
    exposureId: id, fingerprint: e.Fingerprint, type: e.Type, summary: e.Title, asset: e.AssetRef,
    severity: e.Severity, score: e.Score, validation: e.Validation, exploitability: e.Exploitability,
    reachability: e.Reachability, source: e.SourceModule, dueDate: e.DueDate, owner: e.Owner, scoreFactors: factors,
    jira: { fields: { summary: `[Exposure] ${e.Title}`, priority: { name: PRIORITY[e.Severity] || "Medium" }, labels: ["exposure", e.Type], description: `${e.Exploitability}; reachability ${e.Reachability}; source ${e.SourceModule}; score ${e.Score}.` } },
    servicenow: { short_description: `[Exposure] ${e.Title}`, urgency: e.Severity === "CRITICAL" ? "1" : e.Severity === "HIGH" ? "2" : "3", category: "security", cmdb_ci: e.AssetRef, description: `${e.Exploitability}; ${e.Reachability}; ${e.SourceModule}; score ${e.Score}.` },
  };
}
