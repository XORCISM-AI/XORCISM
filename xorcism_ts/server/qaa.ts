/**
 * qaa.ts — Security Questionnaire Auto-Answer (Conveyor / Loopio / Vanta-style).
 *
 * Vendors constantly receive customer security questionnaires (SIG, CAIQ, bespoke spreadsheets). This
 * drafts answers from XORCISM's OWN knowledge base — a reusable answer library, published policies and
 * controls, and the live control-assurance posture — retrieving the most relevant snippets per question
 * and (when the local LLM is reachable) drafting a concise answer grounded ONLY in that context. Works
 * offline too: without Ollama it returns the best library match or a stitched, citation-backed draft.
 *
 * Everything stays local (Ollama on localhost) — no questionnaire content leaves the infrastructure.
 */
import { getDb } from "./db";
import { ollamaChat, ollamaStatus } from "./ai";
import { controlAssurance } from "./assurance";

export interface Snippet { source: string; text: string; lib?: boolean }
export interface QaaAnswer {
  question: string; answer: string; sources: string[];
  confidence: "high" | "medium" | "low"; fromLibrary: boolean; ai: boolean;
}

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const cols = (db: ReturnType<typeof getDb>, t: string): Set<string> => {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
};
const STOP = new Set(["the", "a", "an", "is", "are", "do", "does", "you", "your", "we", "our", "have", "has", "to", "of", "and", "or", "in", "on", "for", "with", "how", "what", "any", "all", "be", "can", "this", "that", "it", "as", "by", "at", "from", "use", "used", "data"]);
const toks = (s: string): string[] => String(s || "").toLowerCase().match(/[a-z0-9]{3,}/g)?.filter((w) => !STOP.has(w)) || [];

// ── answer library (persisted, reusable past answers) ───────────────────────────────
export function ensureQaaTables(): void {
  try {
    getDb("XCOMPLIANCE").exec(`CREATE TABLE IF NOT EXISTS QUESTIONNAIREANSWER (
      AnswerID INTEGER PRIMARY KEY, TenantID INTEGER, Question TEXT, Answer TEXT, Tags TEXT,
      Source TEXT, UsedCount INTEGER DEFAULT 0, UpdatedDate TEXT)`);
  } catch { /* */ }
}
function tw(tenant: number | null): { sql: string; args: number[] } {
  return tenant == null ? { sql: "TenantID IS NULL", args: [] } : { sql: "(TenantID = ? OR TenantID IS NULL)", args: [tenant] };
}
export function library(tenant: number | null): { id: number; question: string; answer: string; tags: string; usedCount: number }[] {
  try {
    ensureQaaTables();
    const w = tw(tenant);
    return (getDb("XCOMPLIANCE").prepare(`SELECT AnswerID id, Question question, Answer answer, COALESCE(Tags,'') tags, COALESCE(UsedCount,0) usedCount FROM QUESTIONNAIREANSWER WHERE ${w.sql} ORDER BY UsedCount DESC, AnswerID DESC LIMIT 500`).all(...w.args) as { id: number; question: string; answer: string; tags: string; usedCount: number }[]);
  } catch { return []; }
}
export function saveAnswer(tenant: number | null, question: string, answer: string, tags = ""): { id: number } {
  ensureQaaTables();
  const db = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const w = tw(tenant);
  const ex = db.prepare(`SELECT AnswerID id FROM QUESTIONNAIREANSWER WHERE ${w.sql} AND LOWER(Question)=LOWER(?) LIMIT 1`).get(...w.args, question) as { id: number } | undefined;
  if (ex) { db.prepare("UPDATE QUESTIONNAIREANSWER SET Answer=?, Tags=?, UpdatedDate=?, UsedCount=COALESCE(UsedCount,0)+1 WHERE AnswerID=?").run(answer, tags, now, ex.id); return { id: ex.id }; }
  const id = ((db.prepare("SELECT COALESCE(MAX(AnswerID),0)+1 id FROM QUESTIONNAIREANSWER").get() as { id: number }).id) || 1;
  db.prepare("INSERT INTO QUESTIONNAIREANSWER (AnswerID,TenantID,Question,Answer,Tags,Source,UsedCount,UpdatedDate) VALUES (?,?,?,?,?,?,1,?)").run(id, tenant, question, answer, tags, "saved", now);
  return { id };
}
export function deleteAnswer(tenant: number | null, id: number): void {
  try { const w = tw(tenant); getDb("XCOMPLIANCE").prepare(`DELETE FROM QUESTIONNAIREANSWER WHERE AnswerID=? AND ${w.sql}`).run(id, ...w.args); } catch { /* */ }
}

// ── knowledge base: library + policies + controls + live assurance posture ──────────
export function gatherKnowledge(tenant: number | null): Snippet[] {
  const out: Snippet[] = [];
  for (const a of library(tenant)) if (a.question && a.answer) out.push({ source: "Answer library", text: `Q: ${a.question}\nA: ${a.answer}`, lib: true });

  // Policies (published security documentation)
  try {
    const xc = getDb("XCOMPLIANCE");
    if (has(xc, "POLICY")) {
      const c = cols(xc, "POLICY");
      const name = c.has("Name") ? "Name" : c.has("Title") ? "Title" : c.has("PolicyName") ? "PolicyName" : null;
      const body = c.has("Summary") ? "Summary" : c.has("Description") ? "Description" : c.has("PolicyText") ? "PolicyText" : null;
      if (name) for (const r of xc.prepare(`SELECT "${name}" n${body ? `, "${body}" d` : ""} FROM POLICY LIMIT 200`).all() as { n: string; d?: string }[])
        if (r.n) out.push({ source: `Policy: ${r.n}`, text: `${r.n}. ${(r.d || "").slice(0, 600)}` });
    }
  } catch { /* */ }

  // Controls catalogue
  try {
    const xo = getDb("XORCISM");
    if (has(xo, "CONTROL")) {
      const c = cols(xo, "CONTROL");
      const name = c.has("ControlName") ? "ControlName" : c.has("Name") ? "Name" : c.has("Title") ? "Title" : null;
      const body = c.has("Description") ? "Description" : c.has("ControlText") ? "ControlText" : null;
      if (name) for (const r of xo.prepare(`SELECT "${name}" n${body ? `, "${body}" d` : ""} FROM CONTROL WHERE "${name}" IS NOT NULL LIMIT 400`).all() as { n: string; d?: string }[])
        if (r.n) out.push({ source: `Control: ${r.n}`, text: `${r.n}. ${(r.d || "").slice(0, 400)}` });
    }
  } catch { /* */ }

  // Live control-assurance posture (great questionnaire evidence)
  try {
    const a = controlAssurance(tenant);
    out.push({ source: "Security posture", text: `Continuously-monitored control posture: ${a.stats.provenPct}% of measurable controls proven. ` + a.frameworks.map((f) => `${f.label} readiness ${f.readinessPct}%`).join("; ") + "." });
    for (const c of a.controls) out.push({ source: `Control objective: ${c.name}`, text: `${c.name} — status ${c.status}. ${c.metric}. ${(c.evidence || []).join("; ")}` });
  } catch { /* */ }

  return out;
}

function retrieve(question: string, kb: Snippet[], k = 6): { snip: Snippet; score: number }[] {
  const q = new Set(toks(question));
  if (!q.size) return [];
  return kb.map((s) => {
    const st = toks(s.text);
    let score = 0; const seen = new Set<string>();
    for (const w of st) if (q.has(w) && !seen.has(w)) { seen.add(w); score++; }
    if (s.lib) score *= 1.6; // prefer curated library answers
    return { snip: s, score };
  }).filter((x) => x.score > 0).sort((a, b) => b.score - a.score).slice(0, k);
}

export async function answerQuestions(tenant: number | null, questions: string[]): Promise<{ answers: QaaAnswer[]; ai: boolean; model: string }> {
  const kb = gatherKnowledge(tenant);
  const status = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  const aiUp = !!status.reachable;
  const answers: QaaAnswer[] = [];

  for (const raw of questions) {
    const question = String(raw || "").trim();
    if (!question) continue;
    const hits = retrieve(question, kb, 6);
    const qToks = new Set(toks(question));
    const top = hits[0];
    const coverage = top ? Math.min(1, top.score / Math.max(3, qToks.size)) : 0;
    const sources = [...new Set(hits.map((h) => h.snip.source))].slice(0, 5);

    if (!hits.length) { answers.push({ question, answer: "Not documented — needs manual input.", sources: [], confidence: "low", fromLibrary: false, ai: false }); continue; }

    // exact-ish library hit → return it verbatim (highest confidence, no AI needed)
    const libHit = hits.find((h) => h.snip.lib && h.score / 1.6 >= Math.max(2, qToks.size * 0.6));
    if (libHit) {
      const ans = libHit.snip.text.replace(/^Q:.*?\nA:\s*/s, "").trim();
      answers.push({ question, answer: ans, sources, confidence: "high", fromLibrary: true, ai: false });
      continue;
    }

    if (aiUp) {
      const ctx = hits.map((h, i) => `[${i + 1}] (${h.snip.source}) ${h.snip.text}`).join("\n\n").slice(0, 6000);
      try {
        const answer = (await ollamaChat([
          { role: "system", content: "You are a security & compliance analyst drafting answers to a customer security questionnaire. Answer the question concisely (1–4 sentences) using ONLY the provided context about the organization. State facts plainly. If the context does not cover the question, reply exactly: 'Not documented — needs manual input.' Do not invent controls or certifications." },
          { role: "user", content: `Context:\n${ctx}\n\nQuestionnaire question: ${question}\n\nDrafted answer:` },
        ], 0.2, 60000)).trim();
        const documented = !/^not documented/i.test(answer);
        answers.push({ question, answer, sources, confidence: documented ? (coverage >= 0.6 ? "high" : "medium") : "low", fromLibrary: false, ai: true });
        continue;
      } catch { /* fall through to offline stitch */ }
    }

    // offline stitch: surface the most relevant evidence with citations
    const stitch = "Based on internal documentation:\n" + hits.slice(0, 3).map((h) => `• (${h.snip.source}) ${h.snip.text.replace(/^Q:.*?\nA:\s*/s, "").slice(0, 240)}`).join("\n");
    answers.push({ question, answer: stitch, sources, confidence: coverage >= 0.6 ? "medium" : "low", fromLibrary: false, ai: false });
  }
  return { answers, ai: aiUp, model: status.model || "" };
}
