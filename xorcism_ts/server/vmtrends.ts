/**
 * vmtrends.ts — Vulnerability-Management executive report: risk & SLA posture **over time** plus a
 * data-driven **myth-busting** briefing for the board.
 *
 * Enterprise vulnerability programs are judged on one thing: *can you prove risk went down?* The VOC
 * (voc.ts) gives the point-in-time picture; this module persists a daily snapshot of the headline VM
 * KPIs (XVULNERABILITY.VMSNAPSHOT) so the point-in-time picture becomes trend lines — risk-weighted
 * exposure, open backlog, KEV exposure, SLA compliance, MTTR and remediation coverage over 90+ days.
 *
 * It then turns the org's *own* live numbers into a "myths vs reality" section that debunks the
 * misconceptions that keep VM programs ineffective ("patch everything", "CVSS = priority",
 * "100% patched = secure", "a quarterly scan is enough", "the open count is our KPI",
 * "VM is IT's problem"). Surfaced at /vm-report.
 */
import { allocId, getDb } from "./db";
import { backlog, Inst } from "./voc";

const today = (): string => new Date().toISOString().slice(0, 10);
const dayStr = (msAgo: number): string => new Date(Date.now() - msAgo * 86400000).toISOString().slice(0, 10);
const pct = (a: number, b: number): number => (b ? Math.round((a / b) * 100) : 0);
const clamp = (n: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, n));
const days = (a: number, b: number): number => Math.round((b - a) / 86400000);

const isExploitable = (r: Inst): boolean => r.kev || (r.epss != null && r.epss >= 0.1);
const SEV_BASE: Record<string, number> = { Critical: 40, High: 20, Medium: 8, Low: 2 };

/** Per-instance risk weight: severity floor + active-exploitation + exploit-probability + SLA breach.
 *  Summed over the open backlog this is the program's risk-weighted exposure (the real signal). */
export function riskWeight(r: Inst): number {
  return (SEV_BASE[r.severity] ?? 8) + (r.kev ? 40 : 0) + Math.round((r.epss ?? 0) * 30) +
    (r.slaStatus === "breached" ? 20 : r.slaStatus === "approaching" ? 8 : 0);
}

export interface Posture {
  open: number; total: number; remediated: number; kevOpen: number; exploitableOpen: number;
  criticalOpen: number; highOpen: number; riskExposure: number; slaCompliance: number | null;
  overdue: number; mttrDays: number | null; coverage: number | null; unassignedOpen: number;
}

function computePosture(rows: Inst[]): Posture {
  const open = rows.filter((r) => !r.patched);
  const patched = rows.filter((r) => r.patched);
  const total = rows.length;
  const mttrVals = patched.filter((r) => r.createdMs != null && r.patchedMs != null && r.patchedMs >= r.createdMs).map((r) => days(r.createdMs!, r.patchedMs!));
  const withinSla = open.filter((r) => r.slaStatus === "within" || r.slaStatus === "approaching").length;
  return {
    open: open.length, total, remediated: patched.length,
    kevOpen: open.filter((r) => r.kev).length,
    exploitableOpen: open.filter(isExploitable).length,
    criticalOpen: open.filter((r) => r.severity === "Critical").length,
    highOpen: open.filter((r) => r.severity === "High").length,
    riskExposure: open.reduce((s, r) => s + riskWeight(r), 0),
    slaCompliance: open.length ? pct(withinSla, open.length) : 100,
    overdue: open.filter((r) => r.slaStatus === "breached").length,
    mttrDays: mttrVals.length ? Math.round(mttrVals.reduce((a, b) => a + b, 0) / mttrVals.length) : null,
    coverage: total ? pct(patched.length, total) : null,
    unassignedOpen: open.filter((r) => !r.owner).length,
  };
}

// ── snapshot persistence ───────────────────────────────────────────────────────────
function upsertSnapshot(tenant: number | null, date: string, p: Posture, source: string): void {
  const xv = getDb("XVULNERABILITY");
  const ex = xv.prepare("SELECT SnapshotID FROM VMSNAPSHOT WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) AND SnapshotDate = ?").get(tenant, date) as { SnapshotID: number } | undefined;
  if (ex) {
    xv.prepare(`UPDATE VMSNAPSHOT SET OpenCount=?, TotalCount=?, RemediatedCount=?, KevOpen=?, ExploitableOpen=?, CriticalOpen=?, HighOpen=?,
      RiskExposure=?, SlaCompliance=?, OverdueCount=?, MttrDays=?, Coverage=?, UnassignedOpen=?, Source=? WHERE SnapshotID=?`)
      .run(p.open, p.total, p.remediated, p.kevOpen, p.exploitableOpen, p.criticalOpen, p.highOpen, p.riskExposure, p.slaCompliance, p.overdue, p.mttrDays, p.coverage, p.unassignedOpen, source, ex.SnapshotID);
  } else {
    const id = allocId(xv, "VMSNAPSHOT", "SnapshotID");
    xv.prepare(`INSERT INTO VMSNAPSHOT (SnapshotID, TenantID, SnapshotDate, OpenCount, TotalCount, RemediatedCount, KevOpen, ExploitableOpen,
      CriticalOpen, HighOpen, RiskExposure, SlaCompliance, OverdueCount, MttrDays, Coverage, UnassignedOpen, Source, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id, tenant, date, p.open, p.total, p.remediated, p.kevOpen, p.exploitableOpen, p.criticalOpen, p.highOpen, p.riskExposure, p.slaCompliance, p.overdue, p.mttrDays, p.coverage, p.unassignedOpen, source, new Date().toISOString());
  }
}

/** Capture (upsert) today's VM posture snapshot for a tenant. Background/scheduler-safe; returns the posture. */
export function captureVmSnapshot(tenant: number | null, dateOverride?: string): Posture {
  const { rows } = backlog(tenant);
  const p = computePosture(rows);
  try { upsertSnapshot(tenant, dateOverride ?? today(), p, "auto"); } catch { /* best-effort */ }
  return p;
}

interface Snap { date: string; openCount: number; totalCount: number; remediatedCount: number; kevOpen: number; exploitableOpen: number; criticalOpen: number; highOpen: number; riskExposure: number; slaCompliance: number | null; overdueCount: number; mttrDays: number | null; coverage: number | null; unassignedOpen: number; }

function history(tenant: number | null, sinceDays: number): Snap[] {
  try {
    const since = dayStr(sinceDays);
    const rows = getDb("XVULNERABILITY").prepare(`SELECT * FROM VMSNAPSHOT WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) AND SnapshotDate >= ? ORDER BY SnapshotDate`).all(tenant, since) as any[];
    return rows.map((r) => ({ date: String(r.SnapshotDate), openCount: Number(r.OpenCount ?? 0), totalCount: Number(r.TotalCount ?? 0), remediatedCount: Number(r.RemediatedCount ?? 0), kevOpen: Number(r.KevOpen ?? 0), exploitableOpen: Number(r.ExploitableOpen ?? 0), criticalOpen: Number(r.CriticalOpen ?? 0), highOpen: Number(r.HighOpen ?? 0), riskExposure: Number(r.RiskExposure ?? 0), slaCompliance: r.SlaCompliance == null ? null : Number(r.SlaCompliance), overdueCount: Number(r.OverdueCount ?? 0), mttrDays: r.MttrDays == null ? null : Number(r.MttrDays), coverage: r.Coverage == null ? null : Number(r.Coverage), unassignedOpen: Number(r.UnassignedOpen ?? 0) }));
  } catch { return []; }
}

interface Delta { first: number | null; last: number | null; abs: number | null; pct: number | null; improving: boolean }
/** Trend delta first→last over the window. `lowerIsBetter` decides the improving flag. */
function delta(hist: Snap[], key: keyof Snap, lowerIsBetter: boolean): Delta {
  const pts = hist.map((h) => h[key]).filter((v) => typeof v === "number") as number[];
  if (pts.length < 2) { const v = pts.length ? pts[pts.length - 1] : null; return { first: v, last: v, abs: 0, pct: 0, improving: false }; }
  const a = pts[0], b = pts[pts.length - 1];
  const abs = b - a, p = a ? Math.round((abs / a) * 100) : null;
  return { first: a, last: b, abs, pct: p, improving: lowerIsBetter ? b <= a : b >= a };
}

// ── myth-busting (org's own live numbers debunk the misconception) ───────────────────
interface Myth { myth: string; reality: string; stat: string; metric: string; ref: string }

function buildMyths(rows: Inst[], hist: Snap[], p: Posture): Myth[] {
  const open = rows.filter((r) => !r.patched);
  const N = open.length || 1;
  const exploit = p.exploitableOpen;
  const cvssCritNoise = open.filter((r) => r.cvss != null && r.cvss >= 9 && !r.kev && (r.epss == null || r.epss < 0.05)).length;
  const kevLowCvss = open.filter((r) => r.kev && r.cvss != null && r.cvss < 7).length;
  const now = Date.now();
  const new30 = open.filter((r) => r.createdMs != null && now - r.createdMs <= 30 * 86400000).length;
  const newKev30 = open.filter((r) => r.kev && r.createdMs != null && now - r.createdMs <= 30 * 86400000).length;
  const rExp = delta(hist, "riskExposure", true);
  const rOpen = delta(hist, "openCount", true);

  return [
    {
      myth: "“We have to patch everything.”",
      reality: "Volume is not the goal — risk reduction is. You cannot patch your way to zero, and you don't need to.",
      stat: `Only ${p.kevOpen} of ${open.length} open findings (${pct(p.kevOpen, N)}%) are known-exploited (KEV) and ${exploit} (${pct(exploit, N)}%) are exploitable at all. Fire-fight those; the remaining ${100 - pct(exploit, N)}% can be scheduled, not panicked over.`,
      metric: `${p.kevOpen} / ${open.length}`,
      ref: "CISA KEV · FIRST EPSS",
    },
    {
      myth: "“CVSS severity tells us what to fix first.”",
      reality: "CVSS scores theoretical badness, not likelihood. Exploit probability (EPSS) and active use (KEV) re-rank the list.",
      stat: (cvssCritNoise || kevLowCvss)
        ? `${cvssCritNoise} of your CVSS-Critical findings have <5% exploit probability (EPSS) — over-ranked — while ${kevLowCvss} actively-exploited (KEV) findings score below CVSS 7 and would be buried. CVSS alone mis-orders both ends.`
        : `Every CVE here is enriched with EPSS (exploit probability) and KEV (active use), so a CVSS-Critical with <5% EPSS is ranked below an actively-exploited Medium — exactly the call CVSS alone cannot make. ${p.kevOpen} of your open findings are KEV-driven.`,
      metric: (cvssCritNoise || kevLowCvss) ? `${cvssCritNoise} over- · ${kevLowCvss} under-ranked` : "EPSS + KEV applied",
      ref: "FIRST EPSS · CISA SSVC",
    },
    {
      myth: "“100% patched means we're secure.”",
      reality: "Coverage by count hides the risk that matters. One open KEV outweighs a thousand closed lows.",
      stat: `You're ${p.coverage ?? 0}% remediated by count, yet ${p.kevOpen} known-exploited and ${p.criticalOpen} critical findings remain open and risk-weighted exposure is still ${p.riskExposure.toLocaleString()}. Report residual risk, not a coverage percentage.`,
      metric: `${p.coverage ?? 0}% covered · ${p.riskExposure.toLocaleString()} risk`,
      ref: "NIST SP 800-40r4",
    },
    {
      myth: "“A scan once a quarter is enough.”",
      reality: "Exposure is continuous — new known-exploited vulns land almost daily and assets drift between scans.",
      stat: new30
        ? `${new30} findings surfaced in the last 30 days (${newKev30} already known-exploited). A quarterly cadence would have left them undetected for up to 90 days.`
        : `New KEV entries are published almost every week. A point-in-time quarterly scan cannot keep pace — continuous discovery is the only way to bound exposure.`,
      metric: new30 ? `${new30} new / 30d` : "continuous",
      ref: "CISA BOD 22-01",
    },
    {
      myth: "“The open-vulnerability count is our KPI.”",
      reality: "A raw count rewards hiding findings. Risk-weighted exposure and SLA compliance are the signals that move the needle.",
      stat: rExp.first != null && rExp.last != null && hist.length >= 2
        ? `Over the period, open count went ${rOpen.first}→${rOpen.last} but risk-weighted exposure went ${(rExp.first as number).toLocaleString()}→${(rExp.last as number).toLocaleString()} (${rExp.pct! > 0 ? "+" : ""}${rExp.pct}%). Count and risk can move in opposite directions — track risk.`
        : `With the count alone (${open.length} open) you cannot tell whether risk is rising or falling. Risk-weighted exposure (${p.riskExposure.toLocaleString()}) and SLA compliance (${p.slaCompliance ?? 0}%) are what the board should see.`,
      metric: hist.length >= 2 ? `risk ${rExp.pct! > 0 ? "+" : ""}${rExp.pct}%` : `${p.riskExposure.toLocaleString()} risk`,
      ref: "Risk-based VM · CISA SSVC",
    },
    {
      myth: "“Vulnerability management is IT's problem.”",
      reality: "Unowned findings don't get fixed. VM is a governed risk function with accountable owners and enforced SLAs.",
      stat: `${p.unassignedOpen} open findings have no remediation owner and ${p.overdue} have breached their SLA. Assign accountability and enforce the SLA policy, and the backlog actually moves.`,
      metric: `${p.unassignedOpen} unowned · ${p.overdue} overdue`,
      ref: "NIST CSF 2.0 (Govern)",
    },
  ];
}

function execSummary(p: Posture, trend: Record<string, Delta>, points: number): string[] {
  const out: string[] = [];
  const r = trend.risk;
  if (points >= 2 && r.first != null && r.last != null && r.pct != null) {
    const dir = r.abs! < 0 ? "down" : r.abs! > 0 ? "up" : "flat";
    out.push(`Risk-weighted exposure is ${dir} ${Math.abs(r.pct)}% over the period (${(r.first).toLocaleString()} → ${(r.last).toLocaleString()}), with ${p.kevOpen} known-exploited findings still open.`);
  } else {
    out.push(`Risk-weighted exposure stands at ${p.riskExposure.toLocaleString()} across ${p.open} open findings, ${p.kevOpen} of them known-exploited (KEV).`);
  }
  out.push(`SLA compliance is ${p.slaCompliance ?? 0}% with ${p.overdue} findings past due${p.mttrDays != null ? `; mean time-to-remediate is ${p.mttrDays} days` : ""}. Remediation coverage is ${p.coverage ?? 0}%.`);
  out.push(`${p.unassignedOpen} open findings are unowned — assigning accountability is the fastest lever to move the backlog.`);
  return out;
}

/** The /vm-report executive briefing: current posture, trend series + deltas, and the myth-busting section. */
export function vmReport(tenant: number | null): any {
  const { rows } = backlog(tenant);
  const posture = computePosture(rows);
  try { upsertSnapshot(tenant, today(), posture, "auto"); } catch { /* */ }
  const hist = history(tenant, 120);
  const trend = {
    risk: delta(hist, "riskExposure", true),
    open: delta(hist, "openCount", true),
    sla: delta(hist, "slaCompliance", false),
    kev: delta(hist, "kevOpen", true),
    mttr: delta(hist, "mttrDays", true),
    coverage: delta(hist, "coverage", false),
  };
  return {
    posture, trend,
    series: hist,
    points: hist.length,
    myths: buildMyths(rows, hist, posture),
    summary: execSummary(posture, trend, hist.length),
    generatedAt: new Date().toISOString(),
  };
}

// ── seed (demo): backfill a realistic improving posture history ──────────────────────
/** Backfill `days` days of VMSNAPSHOT for a tenant, anchored to today's real posture and ramping from
 *  a worse past — so the executive trend lines tell the risk-reduction story. Idempotent (upsert per day).
 *  Today's row is left to captureVmSnapshot (authoritative). Demo only. */
export function seedVmHistory(tenant: number, nDays = 90): { written: number } {
  const { rows } = backlog(tenant);
  const cur = computePosture(rows);
  // baseline if the backlog is empty, so the demo still demonstrates the trend
  const base: Posture = cur.open > 0 ? cur : { open: 128, total: 190, remediated: 62, kevOpen: 16, exploitableOpen: 41, criticalOpen: 22, highOpen: 47, riskExposure: 2360, slaCompliance: 84, overdue: 11, mttrDays: 21, coverage: 33, unassignedOpen: 19 };
  const noise = (seed: number): number => 1 + (((seed * 9301 + 49297) % 233280) / 233280 - 0.5) * 0.06; // ±3%
  let written = 0;
  for (let i = nDays; i >= 1; i--) {
    // factor: oldest day ≈1.9× today's risk, yesterday ≈1.05× — a steady decline
    const f = (1.05 + (1.9 - 1.05) * ((i - 1) / (nDays - 1))) * noise(i);
    const inv = clamp((1.95 - f) / 0.9, 0, 1); // 0 (oldest) → 1 (recent): progress made
    const open = Math.max(0, Math.round((base.open || 0) * f));
    const remediated = Math.round((base.remediated || 0) * (0.4 + 0.6 * inv));
    const p: Posture = {
      open,
      total: open + remediated,
      remediated,
      kevOpen: Math.round((base.kevOpen || 0) * f),
      exploitableOpen: Math.round((base.exploitableOpen || 0) * f),
      criticalOpen: Math.round((base.criticalOpen || 0) * f),
      highOpen: Math.round((base.highOpen || 0) * f),
      riskExposure: Math.round((base.riskExposure || 0) * f),
      slaCompliance: clamp(Math.round((base.slaCompliance ?? 80) - (f - 1) * 55), 28, 100),
      overdue: Math.round((base.overdue || 0) * f),
      mttrDays: base.mttrDays != null ? Math.round(base.mttrDays * f) : null,
      coverage: clamp(Math.round((base.coverage ?? 50) - (f - 1) * 45), 5, 100),
      unassignedOpen: Math.round((base.unassignedOpen || 0) * f),
    };
    try { upsertSnapshot(tenant, dayStr(i), p, "seed"); written++; } catch { /* */ }
  }
  // anchor today on the real posture
  try { upsertSnapshot(tenant, today(), cur.open > 0 ? cur : base, cur.open > 0 ? "auto" : "seed"); } catch { /* */ }
  return { written };
}
