/**
 * ai.ts (routes) — local LLM (Ollama): "Ask the threat model" (RAG over XORCISM)
 * and OCIL answer suggestion. All the routes are authenticated (mounted under /api).
 */
import { Router, Request, Response } from "express";
import { askThreatModel, suggestOcilAnswer, ollamaStatus, enrichThreatReport, triageVulnerability, buildIntelBrief } from "../ai";

const router = Router();

function aiError(e: unknown): string {
  const m = String((e as Error)?.message || e);
  if (/ECONNREFUSED|fetch failed|ENOTFOUND|ETIMEDOUT/i.test(m)) {
    return `Local AI unreachable. Start Ollama (\`ollama serve\`) at ${process.env.OLLAMA_URL || "http://localhost:11434"} and pull a model.`;
  }
  return m;
}

// GET /api/ai/status — is the local AI reachable + available model(s)
router.get("/ai/status", async (_req: Request, res: Response) => {
  res.json(await ollamaStatus());
});

// POST /api/ai/ask { question } — "Ask the threat model" (RAG ATT&CK/KEV/asset + LLM)
router.post("/ai/ask", async (req: Request, res: Response) => {
  const q = String((req.body as { question?: unknown })?.question ?? "").trim();
  if (!q) return void res.status(400).json({ error: "question requise" });
  if (q.length > 2000) return void res.status(400).json({ error: "question trop longue" });
  try {
    res.json(await askThreatModel(q));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/suggest-answer { question, description? } — OCIL answer draft
router.post("/ai/suggest-answer", async (req: Request, res: Response) => {
  const body = req.body as { question?: unknown; description?: unknown };
  const q = String(body?.question ?? "").trim();
  const d = body?.description ? String(body.description) : undefined;
  if (!q) return void res.status(400).json({ error: "question requise" });
  try {
    res.json(await suggestOcilAnswer(q, d));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/enrich-report { reportId } — AI analyst note + CVE extraction for a THREATREPORT
router.post("/ai/enrich-report", async (req: Request, res: Response) => {
  const id = Number((req.body as { reportId?: unknown })?.reportId);
  if (!id) return void res.status(400).json({ error: "reportId requis" });
  try {
    res.json(await enrichThreatReport(id));
  } catch (e) {
    const m = aiError(e);
    res.status(/introuvable/.test(m) ? 404 : 502).json({ error: m });
  }
});

// POST /api/ai/triage-vuln { cve?, vulnerabilityId? } — vulnerability-triage agent
router.post("/ai/triage-vuln", async (req: Request, res: Response) => {
  const body = req.body as { cve?: unknown; vulnerabilityId?: unknown };
  const cve = body?.cve ? String(body.cve).trim() : undefined;
  const vulnerabilityId = body?.vulnerabilityId ? Number(body.vulnerabilityId) : undefined;
  if (!cve && !vulnerabilityId) return void res.status(400).json({ error: "cve ou vulnerabilityId requis" });
  try {
    res.json(await triageVulnerability({ cve, vulnerabilityId }));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/brief { reportIds?, focus? } — intelligence-brief builder (Markdown)
router.post("/ai/brief", async (req: Request, res: Response) => {
  const body = req.body as { reportIds?: unknown; focus?: unknown };
  const reportIds = Array.isArray(body?.reportIds) ? body.reportIds.map(Number).filter((n) => Number.isFinite(n)) : [];
  const focus = body?.focus ? String(body.focus).slice(0, 500) : undefined;
  try {
    res.json(await buildIntelBrief(reportIds, focus));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

export default router;
