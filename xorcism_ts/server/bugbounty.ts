/**
 * bugbounty.ts — Bug Bounty management inventory + worklist.
 *
 * The governance counterpart (like assets.ts / identities.ts) for the Bug Bounty programme data in
 * XVULNERABILITY (BUGBOUNTYPROGRAM / SUBMISSION / RESEARCHER / REWARD / SCOPE): one pane over your
 * programmes — submissions received, open/triage backlog, severity mix, rewards paid, researchers and
 * scope — plus the worklist a triage team acts on (submissions awaiting triage, high-severity still
 * open, resolved reports not linked to a tracked VULNERABILITY, programmes with no scope defined).
 * Read-only inventory + a guided createBugBountyProgram(); full CRUD stays in the schema-driven explorer.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const DB = "XVULNERABILITY";
const CLOSED = /resolv|closed|duplicate|informativ|spam|reject|not[\s-]?applicable|out[\s-]?of[\s-]?scope|disclos/i;
const HIGH = /^(critical|high)$/i;
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 };
const SEV_WEIGHT: Record<string, number> = { critical: 40, high: 22, medium: 8, low: 3, info: 1, informational: 1 };

function cols(table: string): Set<string> {
  try { return new Set((getDb(DB).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(table: string): boolean {
  try { return !!getDb(DB).prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; }
}
const d10 = (v: unknown): string | null => (v ? String(v).slice(0, 10) : null);
const num = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) && v !== null && v !== "" ? n : null; };
function daysSince(date: string | null): number | null {
  if (!date) return null; const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86_400_000);
}
const normSev = (s: string): string => {
  const v = String(s || "").toLowerCase();
  return v.includes("crit") ? "Critical" : v.includes("high") ? "High" : v.includes("med") ? "Medium" : (v.includes("info") ? "Info" : v.includes("low") ? "Low" : "");
};

export interface BugBountyInventory {
  programs: Record<string, unknown>[];
  submissions: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  summary: Record<string, unknown>;
}

const EMPTY: BugBountyInventory = {
  programs: [], submissions: [], findings: [],
  summary: { programs: 0, active: 0, submissions: 0, open: 0, awaitingTriage: 0, highOpen: 0, paid: 0, researchers: 0, currency: "EUR", bySeverity: {}, byStatus: {}, byPlatform: {} },
};

export function bugBountyInventory(_tenant: number | null): BugBountyInventory {
  if (!has("BUGBOUNTYPROGRAM")) return { ...EMPTY };
  const db = getDb(DB);
  const programs = db.prepare("SELECT * FROM BUGBOUNTYPROGRAM").all() as Record<string, any>[];
  const progName = new Map<number, string>();
  for (const p of programs) progName.set(Number(p.ProgramID), String(p.Name ?? "").trim() || `Program #${p.ProgramID}`);

  // Researchers (handle lookup) + count.
  const researcher = new Map<number, string>();
  if (has("BUGBOUNTYRESEARCHER")) {
    for (const r of db.prepare("SELECT ResearcherID, Handle, FullName FROM BUGBOUNTYRESEARCHER").all() as { ResearcherID: number; Handle: string; FullName: string }[])
      researcher.set(Number(r.ResearcherID), String(r.Handle || r.FullName || `#${r.ResearcherID}`));
  }
  // Scope counts per program.
  const scopeCount = new Map<number, number>();
  if (has("BUGBOUNTYSCOPE")) {
    for (const r of db.prepare("SELECT ProgramID, COUNT(*) n FROM BUGBOUNTYSCOPE WHERE LOWER(COALESCE(ScopeType,'in-scope')) NOT LIKE '%out%' GROUP BY ProgramID").all() as { ProgramID: number; n: number }[])
      scopeCount.set(Number(r.ProgramID), Number(r.n));
  }
  // Rewards paid per program.
  const paidByProgram = new Map<number, number>();
  let totalPaid = 0; let currency = "EUR";
  if (has("BUGBOUNTYREWARD")) {
    for (const r of db.prepare("SELECT ProgramID, Amount, Currency, Status FROM BUGBOUNTYREWARD").all() as { ProgramID: number; Amount: unknown; Currency: string; Status: string }[]) {
      if (/paid|approv/i.test(String(r.Status ?? "")) || r.Status == null) {
        const amt = num(r.Amount) ?? 0;
        paidByProgram.set(Number(r.ProgramID), (paidByProgram.get(Number(r.ProgramID)) ?? 0) + amt);
        totalPaid += amt; if (r.Currency) currency = String(r.Currency);
      }
    }
  }

  // Submissions — per-program aggregation + the global worklist.
  const findings: Record<string, unknown>[] = [];
  const submissions: Record<string, unknown>[] = [];
  const byProg = new Map<number, { total: number; open: number; triaged: number; resolved: number; critical: number; high: number }>();
  const bySeverity: Record<string, number> = {}; const byStatus: Record<string, number> = {};
  let awaitingTriage = 0; let highOpen = 0; let openTotal = 0;
  if (has("BUGBOUNTYSUBMISSION")) {
    const rows = db.prepare("SELECT * FROM BUGBOUNTYSUBMISSION").all() as Record<string, any>[];
    for (const s of rows) {
      const pid = Number(s.ProgramID);
      const sev = normSev(String(s.Severity ?? ""));
      const status = String(s.Status ?? "").trim() || "New";
      const open = !CLOSED.test(status);
      const triaged = !!s.TriagedDate;
      const submitted = d10(s.SubmittedDate || s.CreatedDate);
      const ageTriage = !triaged ? daysSince(submitted) : null;
      const title = String(s.Title ?? "").trim() || `Submission #${s.SubmissionID}`;
      const agg = byProg.get(pid) ?? { total: 0, open: 0, triaged: 0, resolved: 0, critical: 0, high: 0 };
      agg.total++;
      if (open) agg.open++; else if (/resolv/i.test(status)) agg.resolved++;
      if (triaged) agg.triaged++;
      if (open && sev === "Critical") agg.critical++;
      if (open && sev === "High") agg.high++;
      byProg.set(pid, agg);
      bySeverity[sev || "Unrated"] = (bySeverity[sev || "Unrated"] || 0) + 1;
      byStatus[status] = (byStatus[status] || 0) + 1;
      if (open) openTotal++;
      if (open && !triaged) awaitingTriage++;
      if (open && HIGH.test(sev)) highOpen++;

      let score = (open ? (SEV_WEIGHT[sev.toLowerCase()] ?? 3) : 0) + (open && !triaged ? 10 : 0) + (ageTriage != null && ageTriage > 7 ? 8 : 0);
      submissions.push({
        id: Number(s.SubmissionID), program: progName.get(pid) || `#${pid}`, programId: pid, title,
        severity: sev, status, open, triaged, cvss: num(s.CVSSBaseScore),
        target: String(s.Target ?? "").trim(), researcher: s.ResearcherID != null ? (researcher.get(Number(s.ResearcherID)) || `#${s.ResearcherID}`) : "",
        reward: num(s.RewardAmount), currency: String(s.Currency ?? currency), vulnerabilityId: s.VulnerabilityID != null ? Number(s.VulnerabilityID) : null,
        submitted, ageTriage, score,
      });

      if (open && !triaged) findings.push({ kind: "triage", id: Number(s.SubmissionID), label: `${title} — awaiting triage${ageTriage != null && ageTriage > 7 ? ` (${ageTriage}d)` : ""}`, severity: HIGH.test(sev) ? "High" : "Medium", program: progName.get(pid) || "" });
      else if (open && HIGH.test(sev)) findings.push({ kind: "open", id: Number(s.SubmissionID), label: `${title} — ${sev}, still open`, severity: sev as string, program: progName.get(pid) || "" });
      if (/resolv|accept/i.test(status) && s.VulnerabilityID == null) findings.push({ kind: "untracked", id: Number(s.SubmissionID), label: `${title} — resolved but not linked to a tracked vulnerability`, severity: "Low", program: progName.get(pid) || "" });
    }
  }

  const byPlatform: Record<string, number> = {};
  const programRows = programs.map((p) => {
    const id = Number(p.ProgramID);
    const agg = byProg.get(id) ?? { total: 0, open: 0, triaged: 0, resolved: 0, critical: 0, high: 0 };
    const platform = String(p.Platform ?? "").trim() || "Self-hosted";
    byPlatform[platform] = (byPlatform[platform] || 0) + 1;
    const scopes = scopeCount.get(id) ?? 0;
    const status = String(p.Status ?? "").trim() || "Draft";
    if (scopes === 0) findings.push({ kind: "noscope", id, label: `${progName.get(id)} — no in-scope targets defined`, severity: "Medium", program: progName.get(id) || "" });
    if (/public|active/i.test(status) && !String(p.PolicyURL ?? "").trim()) findings.push({ kind: "nopolicy", id, label: `${progName.get(id)} — public/active program without a policy URL`, severity: "Low", program: progName.get(id) || "" });
    const score = agg.critical * 40 + agg.high * 22 + agg.open * 4 + (scopes === 0 ? 10 : 0);
    return {
      id, name: progName.get(id)!, platform, status, policyUrl: String(p.PolicyURL ?? "").trim(),
      minReward: num(p.MinReward), maxReward: num(p.MaxReward), currency: String(p.Currency ?? currency),
      startDate: d10(p.StartDate), endDate: d10(p.EndDate),
      submissions: agg.total, open: agg.open, triaged: agg.triaged, resolved: agg.resolved, critical: agg.critical, high: agg.high,
      scopes, paid: paidByProgram.get(id) ?? 0, score,
    };
  });
  programRows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  submissions.sort((a, b) => Number(b.score) - Number(a.score) || (SEV_RANK[String(a.severity).toLowerCase()] ?? 9) - (SEV_RANK[String(b.severity).toLowerCase()] ?? 9));
  const sevR: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  findings.sort((a, b) => (sevR[String(a.severity)] ?? 9) - (sevR[String(b.severity)] ?? 9));

  return {
    programs: programRows, submissions: submissions.slice(0, 300), findings: findings.slice(0, 200),
    summary: {
      programs: programRows.length,
      active: programRows.filter((p) => /public|active|private/i.test(p.status)).length,
      submissions: submissions.length, open: openTotal, awaitingTriage, highOpen,
      paid: Math.round(totalPaid), researchers: researcher.size, currency,
      bySeverity, byStatus, byPlatform,
    },
  };
}

/** Guided creation of a Bug Bounty programme (the friendly "New program" modal). Column-aware INSERT. */
export function createBugBountyProgram(
  p: { name: string; platform?: string; status?: string; policyUrl?: string; scope?: string;
       minReward?: number | null; maxReward?: number | null; currency?: string; startDate?: string; endDate?: string; description?: string },
  _tenant: number | null,
): { id: number } {
  const db = getDb(DB);
  const pc = cols("BUGBOUNTYPROGRAM");
  if (!pc.size) throw new Error("BUGBOUNTYPROGRAM table not available");
  const now = new Date().toISOString();
  const nextId = (db.prepare("SELECT COALESCE(MAX(ProgramID),0)+1 AS n FROM BUGBOUNTYPROGRAM").get() as { n: number }).n;
  const candidate: Record<string, unknown> = {
    ProgramID: nextId, ProgramGUID: randomUUID(),
    Name: (p.name || "Untitled program").slice(0, 300),
    Description: p.description ? String(p.description).slice(0, 4000) : null,
    Platform: p.platform ? String(p.platform).slice(0, 120) : "Self-hosted",
    Status: p.status ? String(p.status).slice(0, 60) : "Draft",
    PolicyURL: p.policyUrl ? String(p.policyUrl).slice(0, 500) : null,
    ScopeDescription: p.scope ? String(p.scope).slice(0, 4000) : null,
    MinReward: p.minReward ?? null, MaxReward: p.maxReward ?? null,
    Currency: p.currency ? String(p.currency).slice(0, 10) : "USD",
    StartDate: p.startDate || null, EndDate: p.endDate || null, CreatedDate: now,
  };
  const keys = Object.keys(candidate).filter((k) => pc.has(k));
  db.prepare(`INSERT INTO BUGBOUNTYPROGRAM (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`).run(...keys.map((k) => candidate[k]));
  return { id: nextId };
}
