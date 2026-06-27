/**
 * ess8.ts — ASD Essential Eight Maturity Model assessment.
 *
 * The Essential Eight (Australian Signals Directorate) is the baseline set of eight mitigation
 * strategies inside the ACSC Information Security Manual, each assessed at Maturity Level 0–3.
 * This module turns the imported ISM Essential-Eight controls (Vocabulary "ACSC ISM") into a
 * self-assessment cockpit: per-strategy current vs target maturity, the organisation's overall
 * maturity (the OFFICIAL scoring = the LOWEST level achieved across all eight strategies), a
 * gap worklist, and — for each strategy — the backing ISM controls grouped by maturity level.
 * Assessment rows live in XCOMPLIANCE.ESSENTIALEIGHT (RBAC: XCOMPLIANCE.AUDIT, like other
 * maturity cockpits). Created from the ACSC ISM import (import_ism.py).
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface Ess8Strategy { id: string; name: string; group: string; description: string; keywords: string[]; }
export interface Ess8Level { level: number; name: string; summary: string; }
export interface Ess8IsmControl { id: string; text: string; levels: string[]; chapter: string; }
export interface Ess8Row {
  id: string; name: string; group: string; description: string;
  current: number; target: number; gap: number; notes: string; owner: string;
  assessedDate: string | null; controls: number; controlsByLevel: Record<string, number>;
}
export interface Ess8Dashboard {
  levels: Ess8Level[];
  strategies: Ess8Row[];
  summary: { overall: number; overallName: string; target: number; atTarget: number; belowTarget: number; assessed: number; avg: number; ismControls: number; };
  worklist: { strategy: string; current: number; target: number; reason: string }[];
}

// The eight mitigation strategies, grouped by objective (ASD Essential Eight).
export const ESS8_STRATEGIES: Ess8Strategy[] = [
  { id: "app-control", name: "Application control", group: "Prevent execution of malicious code",
    description: "Prevent execution of unapproved/malicious programs (executables, libraries, scripts, installers, drivers).",
    keywords: ["application control"] },
  { id: "patch-applications", name: "Patch applications", group: "Prevent execution of malicious code",
    description: "Patch/update applications (browsers, office suites, PDF, security products) and remove unsupported ones; rapid patching of exploitable vulnerabilities.",
    keywords: ["patch", "vulnerabilit"] },
  { id: "office-macros", name: "Configure Microsoft Office macro settings", group: "Prevent execution of malicious code",
    description: "Block macros from the internet, allow only vetted macros, and log/monitor macro execution.",
    keywords: ["macro"] },
  { id: "user-hardening", name: "User application hardening", group: "Prevent execution of malicious code",
    description: "Harden user applications: block web ads, Java and unneeded browser/PDF/Office features; disable legacy components; log blocked activity.",
    keywords: ["web browser", "user application", "internet explorer", "advertisement", "java", ".net", "powershell", "command-line"] },
  { id: "restrict-admin", name: "Restrict administrative privileges", group: "Limit the extent of incidents",
    description: "Limit, validate and monitor privileged access; use separate privileged accounts, just-in-time admin, and privileged-access workstations.",
    keywords: ["privileged access", "privileged user", "administrative privilege", "just-in-time"] },
  { id: "patch-os", name: "Patch operating systems", group: "Limit the extent of incidents",
    description: "Patch/update operating systems and firmware; remove unsupported operating systems; rapid patching of exploitable OS vulnerabilities.",
    keywords: ["operating system"] },
  { id: "mfa", name: "Multi-factor authentication", group: "Limit the extent of incidents",
    description: "Enforce phishing-resistant MFA for users, privileged users, remote access and important data repositories.",
    keywords: ["multi-factor authentication", "multifactor"] },
  { id: "backups", name: "Regular backups", group: "Recover data & system availability",
    description: "Perform, retain, test and protect backups of important data, software and configuration aligned to business continuity requirements.",
    keywords: ["backup"] },
];

export const ESS8_LEVELS: Ess8Level[] = [
  { level: 0, name: "Maturity Level Zero", summary: "Weaknesses in the organisation's overall cyber security posture; the mitigation strategy is not implemented." },
  { level: 1, name: "Maturity Level One", summary: "Partly aligned with the intent of the mitigation strategy — defends against adversaries using commodity tradecraft." },
  { level: 2, name: "Maturity Level Two", summary: "Mostly aligned — defends against adversaries investing more time, effort and tooling (e.g. phishing-resistant MFA, monitoring)." },
  { level: 3, name: "Maturity Level Three", summary: "Fully aligned — defends against adaptive adversaries willing to invest significant capability and exploit weak links." },
];

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const clampLevel = (v: unknown): number => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.max(0, Math.min(3, n)) : 0; };
const tw = (tenant: number | null): string => (tenant == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");

export function ensureEss8Tables(): void {
  const db = getDb("XCOMPLIANCE");
  db.prepare(`CREATE TABLE IF NOT EXISTS ESSENTIALEIGHT (
    AssessmentID INTEGER PRIMARY KEY, EssGUID TEXT, TenantID INTEGER, Strategy TEXT,
    CurrentLevel INTEGER, TargetLevel INTEGER, Notes TEXT, Owner TEXT, AssessedDate DATE, CreatedDate DATE)`).run();
  db.prepare("CREATE INDEX IF NOT EXISTS ix_ess8_tenant ON ESSENTIALEIGHT(TenantID, Strategy)").run();
}

/** ISM Essential-Eight controls (from the ACSC ISM import) matching a strategy's keywords. */
function ismControlsFor(strat: Ess8Strategy): Ess8IsmControl[] {
  let db; try { db = getDb("XORCISM"); } catch { return []; }
  if (!has(db, "CONTROL") || !has(db, "VOCABULARY")) return [];
  const v = db.prepare("SELECT VocabularyID FROM VOCABULARY WHERE VocabularyName = 'ACSC ISM'").get() as { VocabularyID: number } | undefined;
  if (!v) return [];
  // Only E8-mapped controls (their description carries "Essential 8: ML...").
  const rows = db.prepare(
    "SELECT CIS, Statement, ControlDescription FROM CONTROL WHERE VocabularyID = ? AND ControlDescription LIKE '%Essential 8: ML%'"
  ).all(v.VocabularyID) as { CIS: string; Statement: string; ControlDescription: string }[];
  const out: Ess8IsmControl[] = [];
  for (const r of rows) {
    const hay = (r.Statement || "").toLowerCase();
    if (!strat.keywords.some((k) => hay.includes(k))) continue;
    const m = /Essential 8:\s*([^-]+?)(?:\s*-\s*Rev|$)/.exec(r.ControlDescription || "");
    const levels = (m ? m[1] : "").split(",").map((s) => s.trim()).filter((s) => /^ML\d$/.test(s));
    const chap = /ACSC ISM \/ ([^-]+?) -/.exec(r.ControlDescription || "");
    out.push({ id: r.CIS, text: (r.Statement || "").slice(0, 220), levels, chapter: chap ? chap[1].trim() : "" });
  }
  return out;
}

export function essentialEightDashboard(tenant: number | null): Ess8Dashboard {
  ensureEss8Tables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const saved = new Map<string, { CurrentLevel: number; TargetLevel: number; Notes: string; Owner: string; AssessedDate: string | null }>();
  for (const r of db.prepare(`SELECT Strategy, CurrentLevel, TargetLevel, Notes, Owner, AssessedDate FROM ESSENTIALEIGHT WHERE ${tw(tenant)}`).all(...args) as any[]) {
    saved.set(String(r.Strategy), r);
  }
  const strategies: Ess8Row[] = ESS8_STRATEGIES.map((s) => {
    const a = saved.get(s.id);
    const current = a ? clampLevel(a.CurrentLevel) : 0;
    const target = a && a.TargetLevel != null ? clampLevel(a.TargetLevel) : 1;
    const ctrls = ismControlsFor(s);
    const byLevel: Record<string, number> = { ML1: 0, ML2: 0, ML3: 0 };
    for (const c of ctrls) for (const l of c.levels) if (byLevel[l] != null) byLevel[l]++;
    return { id: s.id, name: s.name, group: s.group, description: s.description, current, target,
      gap: Math.max(0, target - current), notes: a?.Notes || "", owner: a?.Owner || "",
      assessedDate: a?.AssessedDate || null, controls: ctrls.length, controlsByLevel: byLevel };
  });
  const overall = Math.min(...strategies.map((s) => s.current));        // OFFICIAL E8 scoring
  const target = Math.min(...strategies.map((s) => s.target));
  const avg = Math.round((strategies.reduce((n, s) => n + s.current, 0) / strategies.length) * 10) / 10;
  const worklist = strategies.filter((s) => s.current < s.target)
    .sort((a, b) => (b.target - b.current) - (a.target - a.current))
    .map((s) => ({ strategy: s.name, current: s.current, target: s.target, reason: `ML${s.current} → target ML${s.target} (${s.gap} level${s.gap > 1 ? "s" : ""} to close)` }));
  return {
    levels: ESS8_LEVELS, strategies,
    summary: {
      overall, overallName: ESS8_LEVELS[overall].name, target,
      atTarget: strategies.filter((s) => s.current >= s.target).length,
      belowTarget: strategies.filter((s) => s.current < s.target).length,
      assessed: saved.size, avg,
      ismControls: strategies.reduce((n, s) => n + s.controls, 0),
    },
    worklist,
  };
}

/** Per-strategy ISM control detail (for the drill-in panel). */
export function essentialEightControls(strategyId: string): { strategy: string; controls: Ess8IsmControl[] } | null {
  const s = ESS8_STRATEGIES.find((x) => x.id === strategyId);
  if (!s) return null;
  return { strategy: s.name, controls: ismControlsFor(s) };
}

export function saveEss8(tenant: number | null, b: { strategy: string; current?: number; target?: number; notes?: string; owner?: string }): { ok: boolean } {
  ensureEss8Tables();
  if (!ESS8_STRATEGIES.some((s) => s.id === b.strategy)) throw new Error("unknown strategy");
  const db = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const args = tenant == null ? [b.strategy] : [b.strategy, tenant];
  const ex = db.prepare(`SELECT AssessmentID FROM ESSENTIALEIGHT WHERE Strategy = ? AND ${tw(tenant)}`).get(...args) as { AssessmentID: number } | undefined;
  const cur = clampLevel(b.current), tgt = clampLevel(b.target ?? 1);
  if (ex) {
    db.prepare("UPDATE ESSENTIALEIGHT SET CurrentLevel=?, TargetLevel=?, Notes=?, Owner=?, AssessedDate=? WHERE AssessmentID=?")
      .run(cur, tgt, (b.notes || "").slice(0, 1000), (b.owner || "").slice(0, 120), now, ex.AssessmentID);
  } else {
    const id = ((db.prepare("SELECT COALESCE(MAX(AssessmentID),0) AS m FROM ESSENTIALEIGHT").get() as { m: number }).m || 0) + 1;
    db.prepare("INSERT INTO ESSENTIALEIGHT (AssessmentID, EssGUID, TenantID, Strategy, CurrentLevel, TargetLevel, Notes, Owner, AssessedDate, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .run(id, randomUUID(), tenant, b.strategy, cur, tgt, (b.notes || "").slice(0, 1000), (b.owner || "").slice(0, 120), now, now);
  }
  return { ok: true };
}

/** Demo seed (tenant only) — a realistic mixed-maturity Essential Eight assessment, target ML3. */
export function seedEss8Demo(tenant: number): { strategies: number } {
  ensureEss8Tables();
  const db = getDb("XCOMPLIANCE");
  if (Number((db.prepare("SELECT COUNT(*) n FROM ESSENTIALEIGHT WHERE TenantID = ?").get(tenant) as { n: number }).n)) return { strategies: 0 };
  const demo: Record<string, number> = { "app-control": 1, "patch-applications": 2, "office-macros": 1, "user-hardening": 1,
    "restrict-admin": 2, "patch-os": 2, "mfa": 2, "backups": 3 };
  for (const s of ESS8_STRATEGIES) saveEss8(tenant, { strategy: s.id, current: demo[s.id] ?? 0, target: 3, owner: "CISO office" });
  return { strategies: ESS8_STRATEGIES.length };
}
