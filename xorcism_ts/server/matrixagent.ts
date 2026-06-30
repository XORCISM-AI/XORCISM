/**
 * matrixagent.ts — Matrix Knowledge-Base Agent.
 *
 * Replicates the MITRE ATLAS Knowledge Base Agent (mitre-atlas/atlas-knowledge-base-agent — a
 * Langflow RAG chatbot over the ATLAS matrix) and generalises it across ALL the adversarial /
 * defensive matrices XORCISM already imports: MITRE ATT&CK, MITRE ATLAS, A3M (Agentic AI Attack
 * Matrix), Google SAIF, MITRE D3FEND and the Mitigant cloud matrix. Ask a natural-language
 * question; the agent does keyword retrieval over the matrix tables (the "dataset/vector-store"
 * step — offline, no embeddings) then composes an answer with the local AI (Ollama), citing the
 * exact techniques (the "graph" step → cited entities + links). Degrades to a structured retrieval
 * digest when no LLM is reachable, so it always works offline.
 */
import { getDb } from "./db";
import { ollamaChat, OLLAMA_MODEL, aiProviderInfo } from "./ai";

interface MatrixDef {
  key: string; label: string; scope: "offensive" | "defensive" | "ai" | "cloud";
  db: string; table: string; idCol: string; nameCol: string; descCol: string;
  ref: (id: string) => string;
}

/** Registry of the imported matrices, with their (differing) column names + a reference-URL builder. */
export const MATRICES: MatrixDef[] = [
  { key: "attack", label: "MITRE ATT&CK", scope: "offensive", db: "XATTACK", table: "ATTACKTECHNIQUE", idCol: "('T'||TechniqueID)", nameCol: "AttackTechniqueName", descCol: "AttackTechniqueDescription", ref: (id) => `https://attack.mitre.org/techniques/${id}` },
  { key: "atlas", label: "MITRE ATLAS (AI/ML)", scope: "ai", db: "XTHREAT", table: "ATLASTECHNIQUE", idCol: "AtlasID", nameCol: "Name", descCol: "Description", ref: (id) => `https://atlas.mitre.org/techniques/${id}` },
  { key: "a3m", label: "A3M — Agentic AI Attack Matrix", scope: "ai", db: "XTHREAT", table: "A3MTECHNIQUE", idCol: "AATID", nameCol: "Name", descCol: "Description", ref: (id) => `https://github.com/precize/Agentic-AI-Attack-Matrix` },
  { key: "saif", label: "Google SAIF", scope: "ai", db: "XTHREAT", table: "SAIFRISK", idCol: "SaifID", nameCol: "Name", descCol: "Description", ref: () => `https://saif.google` },
  { key: "d3fend", label: "MITRE D3FEND", scope: "defensive", db: "XTHREAT", table: "D3FENDTECHNIQUE", idCol: "D3FENDID", nameCol: "Name", descCol: "Definition", ref: (id) => `https://d3fend.mitre.org/technique/${id}` },
  { key: "mitigant", label: "Mitigant (cloud)", scope: "cloud", db: "XTHREAT", table: "MITIGANTTECHNIQUE", idCol: "TechID", nameCol: "Title", descCol: "Description", ref: () => `https://threats.mitigant.io` },
];

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const STOP = new Set(["the", "and", "for", "with", "that", "this", "what", "which", "how", "are", "does", "can", "into", "from", "your", "you", "use", "used", "using", "about", "their", "they", "when", "where", "who", "why", "show", "list", "give", "tell", "explain", "describe", "techniques", "technique", "attack", "attacks", "against", "have", "has", "was", "were", "will", "would", "could", "should", "between", "related", "relate"]);

function keywords(q: string): string[] {
  return Array.from(new Set((q || "").toLowerCase().replace(/[^a-z0-9.\s-]/g, " ").split(/\s+/).filter((w) => w.length >= 3 && !STOP.has(w)))).slice(0, 12);
}

export interface MatrixHit { matrix: string; matrixLabel: string; scope: string; id: string; name: string; snippet: string; url: string; score: number; }

/** Keyword retrieval over the requested matrices (or all). Ranks by # distinct keyword hits (title weighted). */
export function searchMatrices(question: string, matrixKey?: string, limit = 12): MatrixHit[] {
  const kw = keywords(question);
  if (!kw.length) return [];
  const defs = MATRICES.filter((m) => !matrixKey || m.key === matrixKey);
  const hits: MatrixHit[] = [];
  for (const m of defs) {
    const db = getDb(m.db);
    if (!has(db, m.table)) continue;
    const like = kw.map(() => `(${m.nameCol} LIKE ? OR ${m.descCol} LIKE ?)`).join(" OR ");
    const args: string[] = [];
    for (const w of kw) { args.push(`%${w}%`, `%${w}%`); }
    let rows: any[] = [];
    try {
      rows = db.prepare(`SELECT ${m.idCol} id, ${m.nameCol} name, ${m.descCol} descr FROM ${m.table} WHERE ${like} LIMIT 60`).all(...args) as any[];
    } catch { continue; }
    for (const r of rows) {
      const name = String(r.name || ""), descr = String(r.descr || "");
      const hay = (name + " " + descr).toLowerCase();
      let score = 0;
      for (const w of kw) { if (name.toLowerCase().includes(w)) score += 3; else if (hay.includes(w)) score += 1; }
      if (!score) continue;
      hits.push({ matrix: m.key, matrixLabel: m.label, scope: m.scope, id: String(r.id || ""), name, snippet: descr.slice(0, 280), url: m.ref(String(r.id || "")), score });
    }
  }
  return hits.sort((a, b) => b.score - a.score).slice(0, limit);
}

/** Coverage = per-matrix row counts (0 / absent if not imported), for the picker + posture. */
export function matrixCoverage(): { matrices: any[]; total: number; provider: any } {
  const out = MATRICES.map((m) => {
    let count = 0; try { const db = getDb(m.db); if (has(db, m.table)) count = Number((db.prepare(`SELECT COUNT(*) n FROM ${m.table}`).get() as { n: number }).n) || 0; } catch { /* */ }
    return { key: m.key, label: m.label, scope: m.scope, count, imported: count > 0 };
  });
  return { matrices: out, total: out.reduce((n, m) => n + m.count, 0), provider: aiProviderInfo() };
}

/** Answer a natural-language question over the matrices (RAG: retrieve → LLM compose, with citations). */
export async function askMatrix(question: string, matrixKey?: string): Promise<{ answer: string; sources: MatrixHit[]; model: string; offline: boolean }> {
  const hits = searchMatrices(question, matrixKey, 12);
  const sources = hits.slice(0, 8);
  if (!sources.length) {
    return { answer: "No matching techniques were found in the imported matrices for that question. Try different keywords, or import the relevant matrix (ATT&CK / ATLAS / A3M / SAIF / D3FEND / Mitigant).", sources: [], model: "", offline: true };
  }
  const context = sources.map((h) => `[${h.matrixLabel} ${h.id}] ${h.name}: ${h.snippet}`).join("\n");
  const system =
    "You are a threat-intelligence analyst answering questions about adversarial & defensive technique matrices " +
    "(MITRE ATT&CK, MITRE ATLAS for AI/ML, the A3M agentic-AI attack matrix, Google SAIF, MITRE D3FEND, Mitigant). " +
    "Answer ONLY from the provided CONTEXT (retrieved matrix entries). Be concise and cite the technique ids inline " +
    "like [ATLAS AML.T0011]. If the context is insufficient, say so. Never invent technique ids that are not in the CONTEXT.";
  const user = `Question: ${question}\n\nCONTEXT (retrieved matrix techniques):\n${context}`;
  try {
    const answer = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
    if (!answer) throw new Error("empty");
    return { answer, sources, model: OLLAMA_MODEL, offline: false };
  } catch {
    // offline fallback — a structured retrieval digest (no LLM reachable)
    const digest = sources.map((h) => `• [${h.matrixLabel} ${h.id}] ${h.name}\n  ${h.snippet}`).join("\n\n");
    return { answer: `Local AI is unavailable — showing the ${sources.length} most relevant matrix techniques retrieved for your question:\n\n${digest}`, sources, model: "(retrieval only)", offline: true };
  }
}
