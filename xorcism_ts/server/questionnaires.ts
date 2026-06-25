/**
 * questionnaires.ts — Guided QUESTIONNAIRE runner / journey.
 *
 * A program-management layer ABOVE the read-only OCIL definition model (QUESTIONNAIRE → QUESTION
 * linked via QUESTIONFORQUESTIONNAIRE, with ANSWER/ANSWERFORQUESTION holding the answer *choices*).
 * A QUESTIONNAIRERUN is a per-tenant guided pass over a questionnaire (e.g. the CSA AI-CAIQ TPRM
 * questionnaire, or an OCIL questionnaire): it materializes one QUESTIONNAIRERESPONSE per linked
 * question (grouped into sections by control-domain prefix), captures answer + comment + evidence,
 * and tracks completion + a conformance score. Mirrors the compliance-journey wizard (journeys.ts).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const ANSWERS = new Set(["", "yes", "no", "partial", "na"]);

function nowIso(): string { return new Date().toISOString(); }

function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

/** Derive a section/domain code from a question name: "A&A-01.1" → "A&A", "AIS-02" → "AIS". */
export function sectionOf(qName: unknown): string {
  const s = String(qName ?? "").trim();
  const m = s.match(/^([A-Za-z][A-Za-z0-9&]{0,7}?)-\d/);
  if (m) return m[1].toUpperCase();
  const first = s.split(/[\s:._-]/)[0];
  return first ? first.slice(0, 16).toUpperCase() : "GENERAL";
}

function tw(tenant: number | null): string { return tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : ""; }

// ── catalogue ───────────────────────────────────────────────────────────────────
export function listQuestionnaires(tenant: number | null): any[] {
  const db = getDb("XCOMPLIANCE");
  let rows: Record<string, any>[];
  try {
    rows = db.prepare(
      `SELECT qn.QuestionnaireID, qn.QuestionnaireName, qn.QuestionnaireDescription, qn.Language,
              COUNT(qfq.QuestionID) AS questions
         FROM QUESTIONNAIRE qn
         LEFT JOIN QUESTIONFORQUESTIONNAIRE qfq ON qfq.QuestionnaireID = qn.QuestionnaireID
        WHERE (qn.TenantID = ? OR qn.TenantID IS NULL)
        GROUP BY qn.QuestionnaireID
       HAVING questions > 0
        ORDER BY questions DESC, qn.QuestionnaireName COLLATE NOCASE`
    ).all(tenant) as Record<string, any>[];
  } catch { return []; }
  if (!rows.length) return [];
  // section counts in one pass
  const ids = rows.map((r) => Number(r.QuestionnaireID));
  const secByQ = new Map<number, Set<string>>();
  try {
    const ph = ids.map(() => "?").join(",");
    const pairs = db.prepare(
      `SELECT qfq.QuestionnaireID AS qid, q.QuestionName AS nm
         FROM QUESTIONFORQUESTIONNAIRE qfq JOIN QUESTION q ON q.QuestionID = qfq.QuestionID
        WHERE qfq.QuestionnaireID IN (${ph})`
    ).all(...ids) as { qid: number; nm: unknown }[];
    for (const p of pairs) {
      const set = secByQ.get(Number(p.qid)) ?? new Set<string>();
      set.add(sectionOf(p.nm)); secByQ.set(Number(p.qid), set);
    }
  } catch { /* best-effort */ }
  return rows.map((r) => ({
    id: Number(r.QuestionnaireID),
    name: String(r.QuestionnaireName ?? `Questionnaire ${r.QuestionnaireID}`),
    description: String(r.QuestionnaireDescription ?? ""),
    language: String(r.Language ?? ""),
    questions: Number(r.questions ?? 0),
    sections: secByQ.get(Number(r.QuestionnaireID))?.size ?? 0,
  }));
}

// ── progress ──────────────────────────────────────────────────────────────────
function runProgress(runId: number): { total: number; answered: number; na: number; yes: number; no: number; partial: number; pct: number; conformance: number } {
  const rows = getDb("XCOMPLIANCE").prepare("SELECT Answer FROM QUESTIONNAIRERESPONSE WHERE RunID = ?").all(runId) as { Answer: string | null }[];
  const total = rows.length;
  let answered = 0, na = 0, yes = 0, no = 0, partial = 0;
  for (const r of rows) {
    const a = String(r.Answer ?? "").toLowerCase();
    if (!a) continue;
    answered++;
    if (a === "na") na++; else if (a === "yes") yes++; else if (a === "no") no++; else if (a === "partial") partial++;
  }
  const applicable = answered - na;
  const pct = total ? Math.round((answered / total) * 100) : 0;
  const conformance = applicable ? Math.round(((yes + 0.5 * partial) / applicable) * 100) : 0;
  return { total, answered, na, yes, no, partial, pct, conformance };
}

// ── dashboard ───────────────────────────────────────────────────────────────────
export function questionnaireRunsDashboard(tenant: number | null): { questionnaires: any[]; runs: any[]; summary: any } {
  const db = getDb("XCOMPLIANCE");
  let runs: any[] = [];
  try {
    const rows = db.prepare(`SELECT * FROM QUESTIONNAIRERUN ${tw(tenant)} ORDER BY RunID DESC`).all() as Record<string, any>[];
    runs = rows.map((j) => {
      const p = runProgress(Number(j.RunID));
      return {
        id: Number(j.RunID), questionnaireId: Number(j.QuestionnaireID ?? 0),
        questionnaireName: String(j.QuestionnaireName ?? ""), name: String(j.Name ?? ""),
        subject: String(j.Subject ?? ""), respondent: String(j.Respondent ?? ""), owner: String(j.Owner ?? ""),
        status: String(j.Status ?? "in_progress"),
        startedDate: j.StartedDate ? String(j.StartedDate).slice(0, 10) : "",
        targetDate: j.TargetDate ? String(j.TargetDate).slice(0, 10) : "",
        submittedDate: j.SubmittedDate ? String(j.SubmittedDate).slice(0, 10) : "",
        ...p,
      };
    });
  } catch { runs = []; }
  const active = runs.filter((r) => r.status !== "archived");
  const summary = {
    runs: runs.length,
    submitted: runs.filter((r) => r.status === "submitted" || r.status === "reviewed").length,
    inFlight: active.filter((r) => r.pct < 100 && r.status !== "submitted").length,
    avgProgress: active.length ? Math.round(active.reduce((s, r) => s + r.pct, 0) / active.length) : 0,
    avgConformance: active.length ? Math.round(active.reduce((s, r) => s + r.conformance, 0) / active.length) : 0,
  };
  return { questionnaires: listQuestionnaires(tenant), runs, summary };
}

// ── detail (sectioned) ────────────────────────────────────────────────────────
export function getRun(id: number, tenant: number | null): { run: any; sections: any[]; progress: any } | null {
  const db = getDb("XCOMPLIANCE");
  const j = db.prepare(`SELECT * FROM QUESTIONNAIRERUN WHERE RunID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as Record<string, any> | undefined;
  if (!j) return null;
  const rows = db.prepare(
    `SELECT r.ResponseID, r.QuestionID, r.Section, r.DisplayOrder, r.Answer, r.Comment, r.Evidence,
            q.QuestionName, q.QuestionText, q.QuestionDescription
       FROM QUESTIONNAIRERESPONSE r
       LEFT JOIN QUESTION q ON q.QuestionID = r.QuestionID
      WHERE r.RunID = ?
      ORDER BY COALESCE(r.DisplayOrder, 999999), r.ResponseID`
  ).all(id) as Record<string, any>[];
  const secMap = new Map<string, any>();
  for (const s of rows) {
    const key = String(s.Section ?? sectionOf(s.QuestionName));
    let sec = secMap.get(key);
    if (!sec) { sec = { key, name: key, questions: [] }; secMap.set(key, sec); }
    sec.questions.push({
      responseId: Number(s.ResponseID), questionId: Number(s.QuestionID ?? 0),
      name: String(s.QuestionName ?? ""), text: String(s.QuestionText ?? ""),
      description: String(s.QuestionDescription ?? ""),
      answer: String(s.Answer ?? ""), comment: String(s.Comment ?? ""), evidence: String(s.Evidence ?? ""),
    });
  }
  const sections = [...secMap.values()].map((sec) => {
    const total = sec.questions.length;
    const answered = sec.questions.filter((q: any) => q.answer).length;
    return { ...sec, total, answered, pct: total ? Math.round((answered / total) * 100) : 0 };
  });
  const run = {
    id: Number(j.RunID), questionnaireId: Number(j.QuestionnaireID ?? 0), questionnaireName: String(j.QuestionnaireName ?? ""),
    name: String(j.Name ?? ""), subject: String(j.Subject ?? ""), respondent: String(j.Respondent ?? ""), owner: String(j.Owner ?? ""),
    status: String(j.Status ?? "in_progress"),
    startedDate: j.StartedDate ? String(j.StartedDate).slice(0, 10) : "",
    targetDate: j.TargetDate ? String(j.TargetDate).slice(0, 10) : "",
    submittedDate: j.SubmittedDate ? String(j.SubmittedDate).slice(0, 10) : "",
  };
  return { run, sections, progress: runProgress(id) };
}

// ── create / mutate ───────────────────────────────────────────────────────────
export function startRun(
  p: { questionnaireId: number; name?: string; subject?: string; respondent?: string; owner?: string; targetDate?: string },
  tenant: number | null, createdBy?: string
): { id: number } {
  const db = getDb("XCOMPLIANCE");
  const qn = db.prepare(`SELECT QuestionnaireID, QuestionnaireName FROM QUESTIONNAIRE WHERE QuestionnaireID = ? AND (TenantID = ? OR TenantID IS NULL)`)
    .get(p.questionnaireId, tenant) as { QuestionnaireID: number; QuestionnaireName?: string } | undefined;
  if (!qn) throw new Error("unknown questionnaire");
  const questions = db.prepare(
    `SELECT q.QuestionID, q.QuestionName
       FROM QUESTIONFORQUESTIONNAIRE qfq JOIN QUESTION q ON q.QuestionID = qfq.QuestionID
      WHERE qfq.QuestionnaireID = ?
      ORDER BY COALESCE(qfq.DisplayOrder, 999999), qfq.QuestionForQuestionnaireID`
  ).all(p.questionnaireId) as { QuestionID: number; QuestionName: unknown }[];
  if (!questions.length) throw new Error("questionnaire has no questions");

  const now = nowIso();
  const name = (p.name || `${qn.QuestionnaireName ?? "Questionnaire"} run`).slice(0, 300);
  const rc = cols("QUESTIONNAIRERUN");
  const rid = allocId(db, "QUESTIONNAIRERUN", "RunID");
  const rrec: Record<string, unknown> = {
    RunID: rid, RunGUID: randomUUID(), QuestionnaireID: p.questionnaireId, QuestionnaireName: qn.QuestionnaireName ?? "",
    Name: name, Subject: (p.subject || "").slice(0, 300), Respondent: (p.respondent || "").slice(0, 200), Owner: (p.owner || "").slice(0, 200),
    Status: "in_progress", StartedDate: now.slice(0, 10), TargetDate: p.targetDate || null, SubmittedDate: null,
    Score: null, Conformance: null, TenantID: tenant, CreatedBy: createdBy ?? null, CreatedDate: now,
  };
  const rkeys = Object.keys(rrec).filter((k) => rc.has(k));
  const insertRun = db.prepare(`INSERT INTO QUESTIONNAIRERUN (${rkeys.map((k) => `"${k}"`).join(",")}) VALUES (${rkeys.map(() => "?").join(",")})`);
  const respCols = cols("QUESTIONNAIRERESPONSE");
  let respId = allocId(db, "QUESTIONNAIRERESPONSE", "ResponseID");
  const insertResp = db.prepare(
    `INSERT INTO QUESTIONNAIRERESPONSE (ResponseID, RunID, QuestionID, Section, DisplayOrder, Answer, TenantID) VALUES (?,?,?,?,?,?,?)`
  );
  const txn = db.transaction(() => {
    insertRun.run(...rkeys.map((k) => rrec[k]));
    if (respCols.has("ResponseID")) {
      questions.forEach((q, i) => { insertResp.run(respId++, rid, q.QuestionID, sectionOf(q.QuestionName), i + 1, null, tenant); });
    }
  });
  txn();
  return { id: rid };
}

export function saveResponse(
  responseId: number, patch: { answer?: string; comment?: string; evidence?: string }, tenant: number | null
): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT ResponseID, RunID FROM QUESTIONNAIRERESPONSE WHERE ResponseID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [responseId, tenant] : [responseId])) as { ResponseID: number; RunID: number } | undefined;
  if (!row) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (patch.answer != null) {
    const a = String(patch.answer).toLowerCase();
    if (!ANSWERS.has(a)) return false;
    sets.push("Answer = ?"); vals.push(a || null);
    sets.push("AnsweredDate = ?"); vals.push(a ? nowIso() : null);
  }
  if (patch.comment != null) { sets.push("Comment = ?"); vals.push(String(patch.comment).slice(0, 4000)); }
  if (patch.evidence != null) { sets.push("Evidence = ?"); vals.push(String(patch.evidence).slice(0, 1000)); }
  if (!sets.length) return true;
  vals.push(responseId);
  db.prepare(`UPDATE QUESTIONNAIRERESPONSE SET ${sets.join(", ")} WHERE ResponseID = ?`).run(...vals);
  // nudge the run back into progress if it had been submitted and is being edited
  db.prepare("UPDATE QUESTIONNAIRERUN SET Status = 'in_progress' WHERE RunID = ? AND Status = 'submitted'").run(row.RunID);
  return true;
}

export function submitRun(id: number, tenant: number | null): { progress: any } | null {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT RunID FROM QUESTIONNAIRERUN WHERE RunID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as { RunID: number } | undefined;
  if (!row) return null;
  const p = runProgress(id);
  db.prepare("UPDATE QUESTIONNAIRERUN SET Status = 'submitted', SubmittedDate = ?, Score = ?, Conformance = ? WHERE RunID = ?")
    .run(nowIso(), p.pct, p.conformance, id);
  return { progress: p };
}

export function deleteRun(id: number, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT RunID FROM QUESTIONNAIRERUN WHERE RunID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as { RunID: number } | undefined;
  if (!row) return false;
  db.prepare("DELETE FROM QUESTIONNAIRERESPONSE WHERE RunID = ?").run(id);
  db.prepare("DELETE FROM QUESTIONNAIRERUN WHERE RunID = ?").run(id);
  return true;
}
