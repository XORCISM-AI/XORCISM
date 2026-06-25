/**
 * boardreport.ts — Board-ready cyber-risk report generator (/board-report).
 *
 * Informed by "A CISO's Guide to Reporting Cyber Risk to the Board" (XM Cyber, 2024):
 * report risk to the Board in BUSINESS language as Likelihood × Impact, cut through the
 * "white noise" of raw vuln/incident counts, and answer the six questions a Board actually
 * asks. We assemble those answers from XORCISM's live data (no raw counts dumped — every
 * number is framed against critical assets and posture-over-time):
 *
 *   1. What % of my critical (crown-jewel) assets are at risk at any given time?
 *   2. What are the risks?                       (top business-framed exposures)
 *   3. What do we remediate first for the biggest impact?  (choke points / least cost)
 *   4. Are our investments paying off / are protection levels increasing?  (trend)
 *   5. Do we have sufficient resources to handle the risks?  (incidents / MTTR / coverage)
 *   6. How are we improving over time?           (EnterpriseRiskScore history)
 *
 * Risk is expressed as the intersection of LIKELIHOOD and IMPACT. Everything is computed
 * per-tenant and read-only; nothing leaves the machine.
 */
import { getDb, resolveUserOrganisationId, notifyUsers } from "./db";
import { enterpriseRiskBreakdown, organisationRiskHistory } from "./riskscore";
import { topExposures } from "./fusion";
import { attackPathGraph } from "./attackpath";
import { riskHunting } from "./croc";
import { socDashboard } from "./soc";

const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const CLOSED_RX = /closed|clos[eé]|resolv|done|accepted|fixed|termin|ferm/i;

/** Maps the unbounded EnterpriseRiskScore (higher = worse) to a 0–100 board "security posture"
 *  score (higher = better, à la XM Cyber's security-score widget). Monotonic, transparent:
 *  risk 0 → 100, risk 200 → 50, risk 600 → 25. */
function postureScore(enterpriseRisk: number): number {
  return Math.round((100 * 200) / (200 + Math.max(0, enterpriseRisk)));
}
function grade(p: number): string {
  return p >= 85 ? "A" : p >= 75 ? "B" : p >= 60 ? "C" : p >= 45 ? "D" : "F";
}
function verdict(p: number): string {
  return p >= 85 ? "Strong" : p >= 70 ? "Healthy" : p >= 55 ? "Fair" : p >= 40 ? "Elevated risk" : "Critical risk";
}

/** Top open risk-register entries with their financial exposure (ALE) — the business-impact view. */
function topRisks(tenant: number | null): { rows: { title: string; level: string; ale: number | null }[]; aleTotal: number } {
  const out: { title: string; level: string; ale: number | null }[] = [];
  let aleTotal = 0;
  if (tenant == null) return { rows: out, aleTotal };
  try {
    const cc = getDb("XCOMPLIANCE");
    if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='RISKREGISTERENTRY'").get()) return { rows: out, aleTotal };
    const cols = new Set((cc.prepare(`PRAGMA table_info("RISKREGISTERENTRY")`).all() as { name: string }[]).map((c) => c.name));
    const aleCol = ["AnnualLossExpectancy", "ALE", "AnnualisedLossExpectancy", "AnnualizedLossExpectancy"].find((c) => cols.has(c)) || null;
    const lvlCol = cols.has("ResidualRiskLevel") ? "ResidualRiskLevel" : cols.has("CurrentRiskLevel") ? "CurrentRiskLevel" : null;
    const titleCol = cols.has("Title") ? "Title" : cols.has("RiskName") ? "RiskName" : cols.has("Name") ? "Name" : null;
    const sel = `SELECT ${titleCol ? `"${titleCol}"` : "''"} t, ${lvlCol ? `"${lvlCol}"` : "''"} lv${aleCol ? `, "${aleCol}" ale` : ""}, Status st, ClosedDate cd FROM RISKREGISTERENTRY WHERE TenantID = ?`;
    const all = cc.prepare(sel).all(tenant) as Record<string, unknown>[];
    for (const r of all) {
      if (CLOSED_RX.test(String(r.st ?? "")) || r.cd) continue;
      const ale = aleCol ? num(r.ale) : null;
      if (ale) aleTotal += ale;
      out.push({ title: String(r.t || "(untitled risk)"), level: String(r.lv || "Unrated"), ale: ale || null });
    }
    // rank: ALE desc, then severity keyword
    const rank = (l: string): number => /crit/i.test(l) ? 5 : /high|élev/i.test(l) ? 4 : /med|moder|moy/i.test(l) ? 3 : /low|faible/i.test(l) ? 2 : 1;
    out.sort((a, b) => (b.ale || 0) - (a.ale || 0) || rank(b.level) - rank(a.level));
  } catch { /* no risk register */ }
  return { rows: out.slice(0, 8), aleTotal };
}

/** Compliance posture: finished/total audits + open high/critical findings (resource & assurance view). */
function compliancePosture(tenant: number | null): { audits: number; auditsDone: number; openFindings: number; completionPct: number } {
  let audits = 0, auditsDone = 0, openFindings = 0;
  if (tenant == null) return { audits, auditsDone, openFindings, completionPct: 0 };
  try {
    const cc = getDb("XCOMPLIANCE");
    const a = cc.prepare("SELECT COUNT(*) total, SUM(CASE WHEN LOWER(COALESCE(AuditStatus,'')) IN ('completed','closed','finished') THEN 1 ELSE 0 END) done FROM AUDIT WHERE TenantID = ?").get(tenant) as { total: number; done: number };
    audits = num(a.total); auditsDone = num(a.done);
    const fc = new Set((cc.prepare(`PRAGMA table_info("AUDITFINDING")`).all() as { name: string }[]).map((c) => c.name));
    if (fc.size) {
      const sevCol = fc.has("Severity") ? "Severity" : fc.has("FindingCriticity") ? "FindingCriticity" : null;
      const all = cc.prepare(`SELECT f.* FROM AUDITFINDING f JOIN AUDIT a ON a.AuditID = f.AuditID WHERE a.TenantID = ?`).all(tenant) as Record<string, unknown>[];
      for (const f of all) {
        if (CLOSED_RX.test(String(f.FindingStatus ?? "") + " " + String(f.WorkflowStatus ?? ""))) continue;
        if (sevCol && /high|crit/i.test(String(f[sevCol] ?? ""))) openFindings++;
      }
    }
  } catch { /* no audits */ }
  const completionPct = audits ? Math.round((auditsDone / audits) * 100) : 0;
  return { audits, auditsDone, openFindings, completionPct };
}

export interface BoardReport {
  generatedAt: string;
  posture: { score: number; grade: string; verdict: string; enterpriseRisk: number; drivers: { key: string; label: string; value: number }[] };
  trend: { points: { date: string; posture: number; risk: number }[]; direction: "improving" | "worsening" | "flat"; deltaPct: number; startScore: number; currentScore: number; rangeDays: number };
  criticalAssets: { total: number; atRisk: number; pctAtRisk: number; pathsFound: number; entries: number };
  risks: { ref: string; priority: number; kev: boolean; exploits: number; assets: number; epssPct: number | null; whyItMatters: string }[];
  remediation: { label: string; paths: number; rationale: string }[];
  financial: { aleTotal: number; topRisks: { title: string; level: string; ale: number | null }[] };
  resources: { openIncidents: number; mttrHours: number | null; mttdMinutes: number | null; compliance: { audits: number; auditsDone: number; openFindings: number; completionPct: number } };
  questions: { q: string; a: string }[];
}

/** Build the full board report for a tenant. */
export function boardReport(tenant: number | null): BoardReport {
  const breakdown = enterpriseRiskBreakdown(tenant);
  const score = postureScore(breakdown.total);

  // — Trend (EnterpriseRiskScore history → posture-over-time) —
  let history: { date: string; score: number }[] = [];
  try {
    const org = resolveUserOrganisationId({ UserID: 0, TenantID: tenant ?? undefined } as never);
    if (org != null) {
      const since = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10);
      history = organisationRiskHistory(org, since);
    }
  } catch { /* no history */ }
  const points = history.map((h) => ({ date: h.date, posture: postureScore(h.score), risk: h.score }));
  const startScore = points.length ? points[0].posture : score;
  const currentScore = points.length ? points[points.length - 1].posture : score;
  const deltaPct = startScore ? Math.round(((currentScore - startScore) / startScore) * 100) : 0;
  const direction: "improving" | "worsening" | "flat" = deltaPct > 2 ? "improving" : deltaPct < -2 ? "worsening" : "flat";
  const rangeDays = points.length >= 2 ? Math.max(1, Math.round((Date.parse(points[points.length - 1].date) - Date.parse(points[0].date)) / 86400000)) : 0;

  // — Critical assets at risk + remediation choke points —
  const ap = attackPathGraph(tenant);
  let reachableJewels = 0;
  try { reachableJewels = num(riskHunting(tenant)?.reachableJewels); } catch { /* */ }
  const jewels = ap.stats.jewels;
  const atRisk = Math.min(jewels, reachableJewels || (ap.stats.pathsFound > 0 ? Math.max(1, Math.min(jewels, ap.chokepoints.length || 1)) : 0));
  const pctAtRisk = jewels ? Math.round((atRisk / jewels) * 100) : 0;
  const remediation = ap.chokepoints.slice(0, 3).map((c) => ({
    label: c.label, paths: c.paths,
    rationale: `Sits on ${c.paths} attack path(s) to crown jewels — hardening or segmenting it breaks the most routes for the least cost (highest ROI).`,
  }));

  // — Top business-framed risks (the "what are the risks" answer) —
  const top = topExposures(tenant, 12).results;
  const risks = top.slice(0, 6).map((t) => {
    const epssPct = t.epss != null ? Math.round(t.epss * 100) : null;
    const why = t.kev
      ? "Known exploited in the wild (CISA KEV) — adversaries are actively using this; treat as imminent."
      : t.exploits > 0
        ? "Public exploit code exists — low attacker effort to weaponize."
        : epssPct != null && epssPct >= 10
          ? `Elevated likelihood of exploitation (EPSS ${epssPct}%).`
          : "On the prioritized worklist by fused exploitability and asset value.";
    return { ref: t.ref, priority: t.priority, kev: !!t.kev, exploits: t.exploits, assets: t.assets, epssPct, whyItMatters: why };
  });
  const kevCount = top.filter((t) => t.kev).length;
  const expCount = top.filter((t) => t.exploits > 0).length;

  // — Financial impact (Likelihood × Impact, in money) —
  const fin = topRisks(tenant);

  // — Resources: incidents / MTTR / compliance —
  let socMetrics: Record<string, unknown> = {};
  try { socMetrics = (socDashboard(tenant)?.metrics || {}) as Record<string, unknown>; } catch { /* */ }
  const comp = compliancePosture(tenant);
  const resources = {
    openIncidents: num(socMetrics.openIncidents),
    mttrHours: socMetrics.mttrHours != null ? num(socMetrics.mttrHours) : null,
    mttdMinutes: socMetrics.mttdMinutes != null ? num(socMetrics.mttdMinutes) : null,
    compliance: comp,
  };

  // — The six Board questions, answered in business language from the live numbers —
  const questions = [
    {
      q: "What % of our critical assets are at risk at any given time?",
      a: jewels
        ? `${pctAtRisk}% — ${atRisk} of ${jewels} crown-jewel asset(s) sit on a viable attack path (${ap.stats.pathsFound} path(s) modeled from ${ap.stats.entries} internet-exposed foothold(s)).`
        : "No crown-jewel assets are tagged yet — tag business-critical assets to quantify this.",
    },
    {
      q: "What are the risks?",
      a: risks.length
        ? `${kevCount} known-exploited (KEV) and ${expCount} with public exploits lead the worklist; the top exposure is ${risks[0].ref} (${risks[0].whyItMatters.toLowerCase()})`
        : "No prioritized exposures on critical assets — exposure surface is currently clean.",
    },
    {
      q: "What do we remediate first to most reduce risk?",
      a: remediation.length
        ? `Harden the top choke point "${remediation[0].label}" (on ${remediation[0].paths} attack path[s]) plus the KEV/public-exploit vulnerabilities above — least cost, maximum impact.`
        : "Continue patching the prioritized exposure worklist; no single dominant choke point.",
    },
    {
      q: "Are our investments paying off — are protection levels increasing?",
      a: rangeDays
        ? `Security posture is ${direction} — ${deltaPct >= 0 ? "+" : ""}${deltaPct}% over ~${rangeDays} day(s) (posture ${startScore} → ${currentScore}/100).`
        : "Not enough history yet to trend — posture will accrue daily.",
    },
    {
      q: "Do we have sufficient resources to handle the risks?",
      a: `${resources.openIncidents} open incident(s)${resources.mttrHours != null ? `, mean time to resolve ${resources.mttrHours}h` : ""}; ${comp.openFindings} open high/critical audit finding(s) across ${comp.audits} audit(s) (${comp.completionPct}% complete).`,
    },
    {
      q: "How are we improving over time?",
      a: rangeDays
        ? `Posture grade ${grade(currentScore)} (${verdict(currentScore)}); trend ${direction} over the last ~${rangeDays} day(s).`
        : `Posture grade ${grade(score)} (${verdict(score)}); baseline established — trend will build daily.`,
    },
  ];

  return {
    generatedAt: new Date().toISOString(),
    posture: { score, grade: grade(score), verdict: verdict(score), enterpriseRisk: breakdown.total, drivers: breakdown.drivers },
    trend: { points, direction, deltaPct, startScore, currentScore, rangeDays },
    criticalAssets: { total: jewels, atRisk, pctAtRisk, pathsFound: ap.stats.pathsFound, entries: ap.stats.entries },
    risks,
    remediation,
    financial: { aleTotal: fin.aleTotal, topRisks: fin.rows },
    resources,
    questions,
  };
}

/** Scheduled board-report delivery: generate the report per tenant and notify that tenant's users
 *  with the headline posture + a link to /board-report. Best-effort; called by the scheduler when an
 *  XSCHEDULE row with connector 'board-report' fires. Returns {tenants, notified}. */
export function runScheduledBoardReports(onlyTenant?: number | null): { tenants: number; notified: number } {
  let tenants = 0, notified = 0;
  // resolve tenants (distinct ASSET.TenantID); null = global → super-admins
  const targets: (number | null)[] = [];
  if (onlyTenant !== undefined) targets.push(onlyTenant);
  else {
    try {
      const xo = getDb("XORCISM");
      const c = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((x) => x.name));
      if (c.has("TenantID")) for (const r of xo.prepare("SELECT DISTINCT TenantID id FROM ASSET WHERE TenantID IS NOT NULL").all() as { id: number }[]) targets.push(r.id);
    } catch { /* */ }
    if (!targets.length) targets.push(null);
  }
  const usersOf = (tenant: number | null): number[] => {
    try {
      const xid = getDb("XID");
      const uc = new Set((xid.prepare('PRAGMA table_info("XUSER")').all() as { name: string }[]).map((x) => x.name));
      if (!uc.has("UserID")) return [];
      if (tenant == null) {
        const adminCol = uc.has("isSuperAdmin") ? "isSuperAdmin" : uc.has("IsSuperAdmin") ? "IsSuperAdmin" : null;
        const sql = adminCol ? `SELECT UserID id FROM XUSER WHERE ${adminCol}=1` : "SELECT UserID id FROM XUSER LIMIT 5";
        return (xid.prepare(sql).all() as { id: number }[]).map((r) => r.id);
      }
      if (!uc.has("TenantID")) return [];
      return (xid.prepare("SELECT UserID id FROM XUSER WHERE TenantID=?").all(tenant) as { id: number }[]).map((r) => r.id);
    } catch { return []; }
  };
  for (const t of targets) {
    let rep: BoardReport;
    try { rep = boardReport(t); } catch { continue; }
    tenants++;
    const users = usersOf(t);
    if (!users.length) continue;
    notified += notifyUsers(users, {
      title: `Board report ready — posture ${rep.posture.score}/100 (${rep.posture.grade})`,
      message: `Enterprise risk ${rep.posture.enterpriseRisk}; trend ${rep.trend.direction}. ${rep.criticalAssets.atRisk}/${rep.criticalAssets.total} crown jewels at risk. Open the full board report.`,
      level: rep.posture.score >= 70 ? "success" : rep.posture.score >= 55 ? "info" : "warning",
      link: "/board-report", source: "Scheduled board report", tenantId: t ?? null,
    });
  }
  return { tenants, notified };
}
