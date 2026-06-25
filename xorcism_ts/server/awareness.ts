/**
 * awareness.ts — Security Awareness Training + Phishing Simulations (KnowBe4-style).
 *
 * Course catalogue (TRAINING) + per-person enrollment/completion (TRAININGFORPERSON) + phishing
 * simulation campaigns (PHISHINGSIMULATION) with per-recipient outcomes (PHISHINGRESULT:
 * sent/opened/clicked/submitted/reported). Derives the org's training-completion rate, the
 * Phish-Prone Percentage™-style click rate, repeat clickers, and a per-user human-risk score,
 * plus a remediation worklist (overdue training, repeat clickers, never-trained).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(table: string): boolean { try { return !!getDb("XORCISM").prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; } }
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1; }
const DONE = /complet|done|passed|terminé|réussi/i;

export function awarenessInventory(tenant: number | null): { trainings: any[]; phishing: any[]; users: any[]; worklist: any[]; summary: any } {
  const db = getDb("XORCISM");
  const empty = { trainings: [], phishing: [], users: [], worklist: [],
    summary: { trainings: 0, enrolled: 0, completed: 0, completionRate: null, campaigns: 0, recipients: 0, clicked: 0, reported: 0, phishPronePct: null, repeatClickers: 0, neverTrained: 0, avgRisk: 0, highRisk: 0 } };
  if (!has("TRAINING")) return empty;

  // people
  const persons = new Map<number, string>();
  if (cols("PERSON").has("FullName")) for (const p of db.prepare("SELECT PersonID, FullName FROM PERSON").all() as { PersonID: number; FullName: string }[]) persons.set(Number(p.PersonID), p.FullName || `#${p.PersonID}`);

  // trainings + enrollment stats
  const tc = cols("TRAINING");
  const tw = tenant != null && tc.has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const trainingRows = db.prepare(`SELECT * FROM TRAINING ${tw}`).all() as Record<string, any>[];
  const enrollments = has("TRAININGFORPERSON") ? (db.prepare(`SELECT * FROM TRAININGFORPERSON ${tenant != null && cols("TRAININGFORPERSON").has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : ""}`).all() as Record<string, any>[]) : [];
  const enrByTraining = new Map<number, Record<string, any>[]>();
  for (const e of enrollments) { const a = enrByTraining.get(Number(e.TrainingID)); if (a) a.push(e); else enrByTraining.set(Number(e.TrainingID), [e]); }

  const trainings = trainingRows.map((t) => {
    const id = Number(t.TrainingID);
    const enr = enrByTraining.get(id) || [];
    const done = enr.filter((e) => DONE.test(String(e.Status ?? "")) || e.DateCompleted).length;
    return { id, name: String(t.TrainingName ?? `Training #${id}`), category: String(t.Category ?? ""), provider: String(t.Provider ?? ""),
      duration: t.DurationMinutes != null ? Number(t.DurationMinutes) : null, required: truthy(t.Required), status: String(t.Status ?? ""),
      enrolled: enr.length, completed: done, completionRate: enr.length ? Math.round((done / enr.length) * 100) : null };
  });

  // phishing campaigns + results
  const phishing: any[] = []; const results: Record<string, any>[] = [];
  if (has("PHISHINGSIMULATION")) {
    const sw = tenant != null && cols("PHISHINGSIMULATION").has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    const sims = db.prepare(`SELECT * FROM PHISHINGSIMULATION ${sw} ORDER BY PhishingSimulationID DESC`).all() as Record<string, any>[];
    const allRes = has("PHISHINGRESULT") ? (db.prepare("SELECT * FROM PHISHINGRESULT").all() as Record<string, any>[]) : [];
    const resBySim = new Map<number, Record<string, any>[]>();
    for (const r of allRes) { results.push(r); const a = resBySim.get(Number(r.PhishingSimulationID)); if (a) a.push(r); else resBySim.set(Number(r.PhishingSimulationID), [r]); }
    for (const s of sims) {
      const rs = resBySim.get(Number(s.PhishingSimulationID)) || [];
      const sent = rs.length, clicked = rs.filter((r) => truthy(r.Clicked)).length, reported = rs.filter((r) => truthy(r.ReportedPhish)).length, submitted = rs.filter((r) => truthy(r.SubmittedData)).length;
      phishing.push({ id: Number(s.PhishingSimulationID), name: String(s.Name ?? "Phishing test"), theme: String(s.Theme ?? ""), difficulty: String(s.Difficulty ?? ""),
        status: String(s.Status ?? ""), sentDate: s.SentDate ? String(s.SentDate).slice(0, 10) : null,
        sent, clicked, reported, submitted, clickRate: sent ? Math.round((clicked / sent) * 100) : 0, reportRate: sent ? Math.round((reported / sent) * 100) : 0 });
    }
  }

  // per-user human-risk score
  const userMap = new Map<number, { id: number; name: string; clicks: number; submitted: number; reported: number; campaigns: number; trainingsDone: number; trainingsAssigned: number }>();
  const u = (id: number) => { let x = userMap.get(id); if (!x) { x = { id, name: persons.get(id) || `#${id}`, clicks: 0, submitted: 0, reported: 0, campaigns: 0, trainingsDone: 0, trainingsAssigned: 0 }; userMap.set(id, x); } return x; };
  for (const r of results) { if (r.PersonID == null) continue; const x = u(Number(r.PersonID)); x.campaigns++; if (truthy(r.Clicked)) x.clicks++; if (truthy(r.SubmittedData)) x.submitted++; if (truthy(r.ReportedPhish)) x.reported++; }
  for (const e of enrollments) { if (e.PersonID == null) continue; const x = u(Number(e.PersonID)); x.trainingsAssigned++; if (DONE.test(String(e.Status ?? "")) || e.DateCompleted) x.trainingsDone++; }
  const users = [...userMap.values()].map((x) => {
    const incomplete = Math.max(0, x.trainingsAssigned - x.trainingsDone);
    let risk = x.clicks * 30 + x.submitted * 25 - x.reported * 10 + incomplete * 8 + (x.trainingsAssigned === 0 ? 10 : 0);
    risk = Math.max(0, Math.min(100, risk));
    return { ...x, incomplete, risk, phishProne: x.clicks > 0, repeatClicker: x.clicks >= 2 };
  }).sort((a, b) => b.risk - a.risk);

  const recipients = users.reduce((s, x) => s + x.campaigns, 0);
  const clickedTotal = phishing.reduce((s, p) => s + p.clicked, 0);
  const reportedTotal = phishing.reduce((s, p) => s + p.reported, 0);
  const enrolledTotal = enrollments.length, completedTotal = enrollments.filter((e) => DONE.test(String(e.Status ?? "")) || e.DateCompleted).length;

  // worklist
  const worklist: any[] = [];
  for (const x of users.filter((x) => x.repeatClicker).slice(0, 30)) worklist.push({ kind: "user", id: x.id, name: x.name, severity: "High", reason: `Repeat phishing clicker (${x.clicks}× clicked)` });
  for (const x of users.filter((x) => x.submitted > 0).slice(0, 30)) worklist.push({ kind: "user", id: x.id, name: x.name, severity: "Critical", reason: "Submitted credentials to a phishing test" });
  for (const x of users.filter((x) => x.trainingsAssigned > 0 && x.incomplete > 0).slice(0, 30)) worklist.push({ kind: "user", id: x.id, name: x.name, severity: "Medium", reason: `${x.incomplete} training(s) incomplete` });
  const enrolledPersons = new Set(enrollments.map((e) => Number(e.PersonID)));
  for (const [pid, name] of persons) if (!enrolledPersons.has(pid)) worklist.push({ kind: "user", id: pid, name, severity: "Medium", reason: "Never enrolled in awareness training" });
  const sevR: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  worklist.sort((a, b) => sevR[a.severity] - sevR[b.severity]);

  return {
    trainings, phishing, users: users.slice(0, 100), worklist: worklist.slice(0, 60),
    summary: {
      trainings: trainings.length, enrolled: enrolledTotal, completed: completedTotal,
      completionRate: enrolledTotal ? Math.round((completedTotal / enrolledTotal) * 100) : null,
      campaigns: phishing.length, recipients,
      clicked: clickedTotal, reported: reportedTotal,
      phishPronePct: recipients ? Math.round((clickedTotal / recipients) * 100) : null,
      repeatClickers: users.filter((x) => x.repeatClicker).length,
      neverTrained: [...persons.keys()].filter((p) => !enrolledPersons.has(p)).length,
      avgRisk: users.length ? Math.round(users.reduce((s, x) => s + x.risk, 0) / users.length) : 0,
      highRisk: users.filter((x) => x.risk >= 50).length,
    },
  };
}

export function createTraining(p: { name: string; category?: string; provider?: string; duration?: number; required?: boolean; description?: string }, tenant: number | null): { id: number } {
  const db = getDb("XORCISM"); const tc = cols("TRAINING"); const now = new Date().toISOString();
  const id = allocId(db, "TRAINING", "TrainingID");
  const rec: Record<string, unknown> = { TrainingID: id, TrainingGUID: randomUUID(), TrainingName: (p.name || "Training").slice(0, 200),
    TrainingDescription: (p.description || "").slice(0, 2000), Category: p.category ?? null, Provider: p.provider ?? null,
    DurationMinutes: p.duration ?? null, Required: p.required ? 1 : 0, Status: "Active", CreatedDate: now, TenantID: tenant };
  const keys = Object.keys(rec).filter((k) => tc.has(k));
  db.prepare(`INSERT INTO TRAINING (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  return { id };
}

export function createPhishingSim(p: { name: string; theme?: string; difficulty?: string; description?: string }, tenant: number | null): { id: number } {
  const db = getDb("XORCISM"); const sc = cols("PHISHINGSIMULATION"); const now = new Date().toISOString();
  const id = allocId(db, "PHISHINGSIMULATION", "PhishingSimulationID");
  const rec: Record<string, unknown> = { PhishingSimulationID: id, PhishingSimulationGUID: randomUUID(), Name: (p.name || "Phishing test").slice(0, 200),
    Theme: p.theme ?? null, Difficulty: p.difficulty ?? "Medium", Description: (p.description || "").slice(0, 2000), Status: "Draft", CreatedDate: now, TenantID: tenant };
  const keys = Object.keys(rec).filter((k) => sc.has(k));
  db.prepare(`INSERT INTO PHISHINGSIMULATION (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  return { id };
}
