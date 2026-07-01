/**
 * gapassess.ts — Automated gap assessment: how well does the governance estate (POLICYs + DOCUMENTs)
 * cover a selected Framework / Regulation?
 *
 * Pipeline (documentation-coverage, not technical evidence — that is policyval.ts's job):
 *   1. RESOLVE — a selected FRAMEWORK maps to a VOCABULARY, whose CONTROL rows are the requirements to cover.
 *   2. CORPUS — gather the organisation's written governance: every POLICY (name + prose) and DOCUMENT
 *      (name + description + category), each a retrievable chunk.
 *   3. RETRIEVE — for each control, rank corpus chunks by keyword overlap (deterministic, always available;
 *      embeddings used to re-rank when Ollama is reachable) and take the top few as candidate evidence.
 *   4. ASSESS — local AI classifies each control covered / partial / gap against its retrieved excerpts,
 *      citing the document(s) and proposing a remediation. Offline fallback: a keyword-overlap heuristic
 *      (honest: it never claims "covered" without AI, only "partial" when the docs clearly mention the topic).
 *   5. REPORT — coverage %, per-control status with rationale + evidence + recommendation, and a gap worklist,
 *      persisted as a GAPASSESSMENT run (with history for trend).
 *
 * The AI reasons over the retrieved text; the deterministic layer picks the evidence and always produces a
 * defensible, sourced result even with no AI. Reuses XORCISM.FRAMEWORK/VOCABULARY/CONTROL/POLICY/DOCUMENT.
 */
import { getDb, allocId } from "./db";
import { ollamaStatus, ollamaChat } from "./ai";

export type GapStatus = "covered" | "partial" | "gap" | "unknown";
export interface CorpusDoc { kind: "policy" | "document"; id: number; name: string; text: string; }
export interface ControlRow { id: number; ref: string; name: string; desc: string; }
export interface GapItem {
  controlId: number; ref: string; name: string; status: GapStatus;
  rationale: string; evidence: string; recommendation: string; source: "ai" | "heuristic";
}
export interface GapReport {
  assessmentId: number | null; frameworkId: number; frameworkName: string; vocabularyName: string | null;
  runAt: string | null; ai: boolean; model: string;
  totalControls: number; assessed: number; coveragePct: number;
  counts: { covered: number; partial: number; gap: number; unknown: number };
  corpus: { policies: number; documents: number };
  items: GapItem[]; gaps: GapItem[];
  history: { assessmentId: number; runAt: string; coveragePct: number }[];
}

const now = (): string => new Date().toISOString();
function cols(db: ReturnType<typeof getDb>, t: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
}
const STATUS_WEIGHT: Record<GapStatus, number> = { covered: 1, partial: 0.5, gap: 0, unknown: 0 };
const MAX_CONTROLS = 200; // hard cap per run (AI cost); default lower, see runGapAssessment

// ── tables ───────────────────────────────────────────────────────────────────────
export function ensureGapTables(): void {
  try {
    getDb("XORCISM").exec(`
      CREATE TABLE IF NOT EXISTS GAPASSESSMENT (
        AssessmentID INTEGER PRIMARY KEY, FrameworkID INTEGER, FrameworkName TEXT, VocabularyID INTEGER,
        VocabularyName TEXT, RunAt TEXT, Ai INTEGER, Model TEXT, TotalControls INTEGER, Assessed INTEGER,
        CoveragePct INTEGER, Covered INTEGER, Partial INTEGER, Gaps INTEGER, Policies INTEGER, Documents INTEGER, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS GAPASSESSMENTITEM (
        ItemID INTEGER PRIMARY KEY, AssessmentID INTEGER, ControlID INTEGER, ControlRef TEXT, ControlName TEXT,
        Status TEXT, Rationale TEXT, Evidence TEXT, Recommendation TEXT, Source TEXT, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_gapassess_fw ON GAPASSESSMENT(FrameworkID);
      CREATE INDEX IF NOT EXISTS ix_gapitem_assess ON GAPASSESSMENTITEM(AssessmentID);`);
  } catch { /* */ }
}

// ── corpus (the written governance estate) ─────────────────────────────────────────
function pickText(row: Record<string, unknown>, candidates: string[]): string {
  let text = "";
  for (const c of candidates) { const v = row[c]; if (typeof v === "string" && v.trim().length > text.length) text = v.trim(); }
  return text;
}

export function governanceCorpus(tenant: number | null): CorpusDoc[] {
  const xo = getDb("XORCISM");
  const out: CorpusDoc[] = [];
  // POLICY: name + the longest prose column present (lifecycle modules may add content columns)
  const pc = cols(xo, "POLICY");
  if (pc.has("PolicyID")) {
    const tw = tenant != null && pc.has("TenantID") ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
    const args = tenant != null && pc.has("TenantID") ? [tenant] : [];
    for (const row of xo.prepare(`SELECT * FROM POLICY ${tw}`).all(...args) as Record<string, unknown>[]) {
      const name = String(row["PolicyName"] ?? row["Name"] ?? `Policy #${row["PolicyID"]}`).trim();
      const body = pickText(row, ["PolicyText", "PolicyContent", "Content", "Body", "PolicyBody", "PolicyDescription", "Description", "Summary"]);
      const text = (name + ". " + body).trim();
      if (text.length > 2) out.push({ kind: "policy", id: Number(row["PolicyID"]), name: name || `Policy #${row["PolicyID"]}`, text: text.slice(0, 4000) });
    }
  }
  // DOCUMENT: name + description + category/author (controlled-document register)
  const dc = cols(xo, "DOCUMENT");
  if (dc.has("DocumentID")) {
    const tw = tenant != null && dc.has("TenantID") ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
    const args = tenant != null && dc.has("TenantID") ? [tenant] : [];
    for (const row of xo.prepare(`SELECT * FROM DOCUMENT ${tw}`).all(...args) as Record<string, unknown>[]) {
      const name = String(row["DocumentName"] ?? `Document #${row["DocumentID"]}`).trim();
      const body = pickText(row, ["DocumentDescription", "Description", "Summary"]);
      const cat = String(row["Category"] ?? "").trim();
      const text = [name, cat && `[${cat}]`, body].filter(Boolean).join(". ").trim();
      if (text.length > 2 && name) out.push({ kind: "document", id: Number(row["DocumentID"]), name, text: text.slice(0, 4000) });
    }
  }
  return out.slice(0, 500);
}

// ── framework → controls ───────────────────────────────────────────────────────────
export interface FrameworkTarget { frameworkId: number; frameworkName: string; vocabularyId: number | null; vocabularyName: string | null; controls: ControlRow[]; }

export function frameworkControls(frameworkId: number): FrameworkTarget {
  const xo = getDb("XORCISM");
  const fw = xo.prepare("SELECT FrameworkID, FrameworkName, VocabularyID FROM FRAMEWORK WHERE FrameworkID=?").get(frameworkId) as
    { FrameworkID: number; FrameworkName: string; VocabularyID: number | null } | undefined;
  if (!fw) throw new Error("framework not found");
  const vid = fw.VocabularyID != null ? Number(fw.VocabularyID) : null;
  let vocabularyName: string | null = null;
  const controls: ControlRow[] = [];
  if (vid != null) {
    const v = xo.prepare("SELECT VocabularyName FROM VOCABULARY WHERE VocabularyID=?").get(vid) as { VocabularyName: string } | undefined;
    vocabularyName = v ? String(v.VocabularyName) : null;
    if (cols(xo, "CONTROL").has("VocabularyID")) {
      for (const c of xo.prepare("SELECT ControlID, ControlName, ControlDescription FROM CONTROL WHERE VocabularyID=? ORDER BY ControlID").all(vid) as
        { ControlID: number; ControlName: string | null; ControlDescription: string | null }[]) {
        const name = String(c.ControlName ?? "").trim();
        const desc = String(c.ControlDescription ?? "").trim();
        if (!name && !desc) continue;
        // ControlName often begins with the code ("A.5.1 …", "A&A-01 …", "AIS-01 …"); take the leading
        // token when it looks like an identifier code (has a digit/dot/hyphen), else fall back to the id.
        const first = name.split(/\s+/)[0] ?? "";
        const ref = (first && first.length <= 20 && /[0-9.\-]/.test(first) ? first : String(c.ControlID)).trim();
        controls.push({ id: Number(c.ControlID), ref, name: name || ref, desc });
      }
    }
  }
  return { frameworkId, frameworkName: String(fw.FrameworkName ?? `Framework #${frameworkId}`), vocabularyId: vid, vocabularyName, controls };
}

/** Frameworks that can be assessed (mapped to a vocabulary with ≥1 control), for the picker. */
export function assessableFrameworks(): { id: number; name: string; vocabularyName: string | null; controls: number }[] {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='FRAMEWORK'").get()) return [];
  if (!cols(xo, "CONTROL").has("VocabularyID")) return [];
  const counts = new Map<number, number>();
  for (const r of xo.prepare("SELECT VocabularyID, COUNT(*) n FROM CONTROL WHERE VocabularyID IS NOT NULL GROUP BY VocabularyID").all() as { VocabularyID: number; n: number }[])
    counts.set(Number(r.VocabularyID), Number(r.n));
  const vocabName = new Map<number, string>();
  for (const v of xo.prepare("SELECT VocabularyID, VocabularyName FROM VOCABULARY").all() as { VocabularyID: number; VocabularyName: string }[])
    vocabName.set(Number(v.VocabularyID), String(v.VocabularyName).trim());
  return (xo.prepare("SELECT FrameworkID, FrameworkName, VocabularyID FROM FRAMEWORK WHERE VocabularyID IS NOT NULL ORDER BY FrameworkName COLLATE NOCASE").all() as
    { FrameworkID: number; FrameworkName: string; VocabularyID: number }[])
    .map((f) => ({ id: Number(f.FrameworkID), name: String(f.FrameworkName), vocabularyName: vocabName.get(Number(f.VocabularyID)) ?? null, controls: counts.get(Number(f.VocabularyID)) ?? 0 }))
    .filter((f) => f.controls > 0);
}

// ── retrieval (keyword overlap; embeddings re-rank when available) ───────────────────
const STOP = new Set("the a an and or of to in for on with is are be as by from that this shall must should will not no any all its their your our you we they it he she at into per via using use used ensure ensured provide provided maintain maintained include included information system systems security control controls policy policies document documents organisation organization organizational".split(/\s+/));
function tokens(s: string): Set<string> {
  return new Set((s.toLowerCase().match(/[a-z0-9][a-z0-9\-]{2,}/g) ?? []).filter((w) => !STOP.has(w)));
}
interface Ranked { doc: CorpusDoc; score: number; }
function overlapRank(control: ControlRow, corpus: CorpusDoc[], docTokens: Set<string>[]): Ranked[] {
  const ct = tokens(control.name + " " + control.desc);
  if (!ct.size) return [];
  const ranked: Ranked[] = corpus.map((doc, i) => {
    let hit = 0; for (const w of ct) if (docTokens[i].has(w)) hit++;
    return { doc, score: hit / ct.size };
  });
  return ranked.filter((r) => r.score > 0).sort((a, b) => b.score - a.score);
}

// ── AI classification ────────────────────────────────────────────────────────────
function snippet(doc: CorpusDoc, control: ControlRow): string {
  // Return a short window of the doc text around the best-matching control keyword, else the head.
  const ct = [...tokens(control.name + " " + control.desc)];
  const lc = doc.text.toLowerCase();
  let at = -1; for (const w of ct) { const p = lc.indexOf(w); if (p >= 0 && (at < 0 || p < at)) at = p; }
  const start = at < 0 ? 0 : Math.max(0, at - 80);
  return doc.text.slice(start, start + 320).trim();
}

async function classifyBatchAI(batch: { control: ControlRow; cand: Ranked[] }[], model: string): Promise<Map<number, GapItem> | null> {
  const payload = batch.map((b) => ({
    id: b.control.id, ref: b.control.ref, control: `${b.control.name}${b.control.desc ? " — " + b.control.desc : ""}`.slice(0, 400),
    excerpts: b.cand.slice(0, 3).map((r) => ({ doc: r.doc.name.slice(0, 120), text: snippet(r.doc, b.control) })),
  }));
  const sys = `You are a GRC analyst performing a documentation gap assessment. For EACH control, decide whether the organisation's governance documents (given as retrieved EXCERPTS) address it:
- "covered": a document clearly and specifically addresses the control's intent.
- "partial": the topic is mentioned but incompletely, vaguely, or only tangentially.
- "gap": no excerpt meaningfully addresses the control.
Cite the document name(s) you relied on in "evidence" (use ONLY the provided doc names; empty string if none). Give a one-sentence "rationale" and, for partial/gap, a concrete one-sentence "recommendation" (what to write/add). Reply with ONLY a JSON array, one object per control: {"id":number,"status":"covered"|"partial"|"gap","rationale":str,"evidence":str,"recommendation":str}.`;
  const user = JSON.stringify(payload);
  let out: string;
  try { out = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.1, 90000); }
  catch { return null; }
  const m = out.match(/\[[\s\S]*\]/); if (!m) return null;
  let arr: any[]; try { arr = JSON.parse(m[0]); } catch { return null; }
  const byId = new Map<number, GapItem>();
  const valid: GapStatus[] = ["covered", "partial", "gap"];
  const names = new Set(batch.flatMap((b) => b.cand.map((r) => r.doc.name)));
  for (const x of arr) {
    const id = Number(x?.id); const b = batch.find((z) => z.control.id === id); if (!b) continue;
    const status: GapStatus = valid.includes(x?.status) ? x.status : "unknown";
    // keep only cited doc names we actually supplied (defend against hallucinated evidence)
    const ev = String(x?.evidence ?? "").split(/[;,]/).map((s) => s.trim()).filter((s) => s && [...names].some((n) => n.toLowerCase().includes(s.toLowerCase()) || s.toLowerCase().includes(n.toLowerCase()))).slice(0, 4).join("; ");
    byId.set(id, {
      controlId: id, ref: b.control.ref, name: b.control.name, status,
      rationale: String(x?.rationale ?? "").slice(0, 500),
      evidence: ev || (status === "gap" ? "" : b.cand[0]?.doc.name ?? ""),
      recommendation: status === "covered" ? "" : String(x?.recommendation ?? "").slice(0, 500), source: "ai",
    });
  }
  return byId;
}

function classifyHeuristic(control: ControlRow, cand: Ranked[]): GapItem {
  const best = cand[0]?.score ?? 0;
  // Honest offline verdict: without AI we cannot confirm "covered", only flag mention vs gap.
  const status: GapStatus = best >= 0.34 ? "partial" : "gap";
  const evidence = status === "partial" ? cand.slice(0, 2).map((r) => r.doc.name).join("; ") : "";
  return {
    controlId: control.id, ref: control.ref, name: control.name, status,
    rationale: status === "partial"
      ? `Governance documents mention related terms (${Math.round(best * 100)}% keyword overlap) — enable local AI for a precise coverage verdict.`
      : "No governance document meaningfully mentions this control's terms.",
    evidence, recommendation: status === "gap" ? `Author or extend a policy/procedure covering: ${control.name}.` : "Confirm the mention fully implements the control; expand if partial.",
    source: "heuristic",
  };
}

// ── run ─────────────────────────────────────────────────────────────────────────
export async function runGapAssessment(frameworkId: number, tenant: number | null, limit = 60): Promise<GapReport> {
  ensureGapTables();
  const target = frameworkControls(frameworkId);
  if (target.vocabularyId == null) throw new Error("this framework is not mapped to a controls vocabulary — map it under Frameworks first");
  if (!target.controls.length) throw new Error("the mapped vocabulary has no controls");
  const corpus = governanceCorpus(tenant);
  const totalControls = target.controls.length;
  const controls = target.controls.slice(0, Math.min(Math.max(1, limit), MAX_CONTROLS));

  const status = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  const useAI = status.reachable && corpus.length > 0;
  const model = useAI ? (status.model || "") : "";

  // Pre-tokenize the corpus once; retrieval is deterministic keyword overlap (instant, always available,
  // and it leaves the whole time budget to the AI classification rather than to embedding the corpus).
  const docTokens = corpus.map((d) => tokens(d.text));
  const candidatesFor = (c: ControlRow): Ranked[] => overlapRank(c, corpus, docTokens).slice(0, 5);

  // Bound total wall-clock: local models are slow, so once the AI budget is spent, the remaining
  // controls fall back to the instant heuristic (each item records which engine judged it).
  const budgetMs = Number(process.env.GAP_AI_BUDGET_MS || 240000);
  const started = Date.now();
  const items: GapItem[] = [];
  const BATCH = 5;
  for (let i = 0; i < controls.length; i += BATCH) {
    const batch = controls.slice(i, i + BATCH).map((control) => ({ control, cand: candidatesFor(control) }));
    let aiRes: Map<number, GapItem> | null = null;
    if (useAI && Date.now() - started < budgetMs) aiRes = await classifyBatchAI(batch, model);
    for (const b of batch) items.push(aiRes?.get(b.control.id) ?? classifyHeuristic(b.control, b.cand));
  }

  const counts = { covered: 0, partial: 0, gap: 0, unknown: 0 };
  let score = 0;
  for (const it of items) { counts[it.status]++; score += STATUS_WEIGHT[it.status]; }
  const assessed = items.length;
  const coveragePct = assessed ? Math.round((score / assessed) * 100) : 0;
  const policies = corpus.filter((d) => d.kind === "policy").length;
  const documents = corpus.filter((d) => d.kind === "document").length;

  // persist run + items
  const xo = getDb("XORCISM");
  const aid = allocId(xo, "GAPASSESSMENT", "AssessmentID");
  const runAt = now();
  xo.prepare(`INSERT INTO GAPASSESSMENT (AssessmentID,FrameworkID,FrameworkName,VocabularyID,VocabularyName,RunAt,Ai,Model,TotalControls,Assessed,CoveragePct,Covered,Partial,Gaps,Policies,Documents,TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    aid, frameworkId, target.frameworkName, target.vocabularyId, target.vocabularyName, runAt, useAI ? 1 : 0, model,
    totalControls, assessed, coveragePct, counts.covered, counts.partial, counts.gap, policies, documents, tenant);
  let iid = allocId(xo, "GAPASSESSMENTITEM", "ItemID");
  const ins = xo.prepare(`INSERT INTO GAPASSESSMENTITEM (ItemID,AssessmentID,ControlID,ControlRef,ControlName,Status,Rationale,Evidence,Recommendation,Source,TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
  const tx = xo.transaction(() => {
    for (const it of items) ins.run(iid++, aid, it.controlId, it.ref.slice(0, 40), it.name.slice(0, 300), it.status, it.rationale.slice(0, 600), it.evidence.slice(0, 400), it.recommendation.slice(0, 600), it.source, tenant);
  });
  tx();

  return {
    assessmentId: aid, frameworkId, frameworkName: target.frameworkName, vocabularyName: target.vocabularyName,
    runAt, ai: useAI, model, totalControls, assessed, coveragePct, counts,
    corpus: { policies, documents }, items, gaps: items.filter((it) => it.status === "gap" || it.status === "partial"),
    history: assessmentHistory(frameworkId, tenant),
  };
}

// ── read ────────────────────────────────────────────────────────────────────────
function assessmentHistory(frameworkId: number, tenant: number | null): { assessmentId: number; runAt: string; coveragePct: number }[] {
  ensureGapTables();
  const xo = getDb("XORCISM");
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const args = tenant != null ? [frameworkId, tenant] : [frameworkId];
  return (xo.prepare(`SELECT AssessmentID, RunAt, CoveragePct FROM GAPASSESSMENT WHERE FrameworkID=? ${tw} ORDER BY AssessmentID DESC LIMIT 20`).all(...args) as
    { AssessmentID: number; RunAt: string; CoveragePct: number }[]).reverse()
    .map((r) => ({ assessmentId: Number(r.AssessmentID), runAt: String(r.RunAt), coveragePct: Number(r.CoveragePct) }));
}

export function getAssessment(assessmentId: number, tenant: number | null): GapReport | null {
  ensureGapTables();
  const xo = getDb("XORCISM");
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const hArgs = tenant != null ? [assessmentId, tenant] : [assessmentId];
  const h = xo.prepare(`SELECT * FROM GAPASSESSMENT WHERE AssessmentID=? ${tw}`).get(...hArgs) as Record<string, unknown> | undefined;
  if (!h) return null;
  const items = (xo.prepare("SELECT ControlID, ControlRef, ControlName, Status, Rationale, Evidence, Recommendation, Source FROM GAPASSESSMENTITEM WHERE AssessmentID=? ORDER BY ItemID").all(assessmentId) as Record<string, unknown>[])
    .map((r) => ({
      controlId: Number(r.ControlID), ref: String(r.ControlRef ?? ""), name: String(r.ControlName ?? ""),
      status: String(r.Status ?? "unknown") as GapStatus, rationale: String(r.Rationale ?? ""),
      evidence: String(r.Evidence ?? ""), recommendation: String(r.Recommendation ?? ""), source: (String(r.Source ?? "heuristic") as "ai" | "heuristic"),
    }));
  return {
    assessmentId: Number(h.AssessmentID), frameworkId: Number(h.FrameworkID), frameworkName: String(h.FrameworkName ?? ""),
    vocabularyName: h.VocabularyName != null ? String(h.VocabularyName) : null, runAt: String(h.RunAt ?? ""),
    ai: !!h.Ai, model: String(h.Model ?? ""), totalControls: Number(h.TotalControls ?? 0), assessed: Number(h.Assessed ?? items.length),
    coveragePct: Number(h.CoveragePct ?? 0),
    counts: { covered: Number(h.Covered ?? 0), partial: Number(h.Partial ?? 0), gap: Number(h.Gaps ?? 0), unknown: items.filter((i) => i.status === "unknown").length },
    corpus: { policies: Number(h.Policies ?? 0), documents: Number(h.Documents ?? 0) },
    items, gaps: items.filter((it) => it.status === "gap" || it.status === "partial"),
    history: assessmentHistory(Number(h.FrameworkID), tenant),
  };
}

/** Latest assessment for a framework (or an empty shell listing the target), for the page's initial load. */
export function latestForFramework(frameworkId: number, tenant: number | null): GapReport | null {
  ensureGapTables();
  const xo = getDb("XORCISM");
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const args = tenant != null ? [frameworkId, tenant] : [frameworkId];
  const row = xo.prepare(`SELECT AssessmentID FROM GAPASSESSMENT WHERE FrameworkID=? ${tw} ORDER BY AssessmentID DESC LIMIT 1`).get(...args) as { AssessmentID: number } | undefined;
  return row ? getAssessment(Number(row.AssessmentID), tenant) : null;
}

export interface GapOverview { frameworks: { id: number; name: string; vocabularyName: string | null; controls: number; lastRunAt: string | null; lastCoveragePct: number | null }[]; corpus: { policies: number; documents: number }; }
export function gapOverview(tenant: number | null): GapOverview {
  ensureGapTables();
  const xo = getDb("XORCISM");
  const last = new Map<number, { runAt: string; pct: number }>();
  try {
    for (const r of xo.prepare("SELECT FrameworkID, RunAt, CoveragePct FROM GAPASSESSMENT ORDER BY AssessmentID DESC").all() as { FrameworkID: number; RunAt: string; CoveragePct: number }[])
      if (!last.has(Number(r.FrameworkID))) last.set(Number(r.FrameworkID), { runAt: String(r.RunAt), pct: Number(r.CoveragePct) });
  } catch { /* */ }
  const corpus = governanceCorpus(tenant);
  return {
    frameworks: assessableFrameworks().map((f) => ({ ...f, lastRunAt: last.get(f.id)?.runAt ?? null, lastCoveragePct: last.get(f.id)?.pct ?? null })),
    corpus: { policies: corpus.filter((d) => d.kind === "policy").length, documents: corpus.filter((d) => d.kind === "document").length },
  };
}
