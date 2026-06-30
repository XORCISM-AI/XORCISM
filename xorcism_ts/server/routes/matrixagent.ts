/**
 * matrixagent.ts (routes) — Matrix Knowledge-Base Agent (a local-AI Q&A over the imported
 * adversarial/defensive matrices — ATT&CK / ATLAS / A3M / SAIF / D3FEND / Mitigant). Read-only.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { matrixCoverage, askMatrix, searchMatrices } from "../matrixagent";

const router = Router();
const auth = (req: Request, res: Response): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, "read", "XTHREAT", "INTELEXCHANGE")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/matrix-agent — matrix coverage (per-matrix counts) + AI provider info
router.get("/matrix-agent", (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  res.json(matrixCoverage());
});

// POST /api/matrix-agent/ask { question, matrix? } — RAG answer + cited techniques
router.post("/matrix-agent/ask", async (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  const b = req.body || {};
  const question = String(b.question || "").trim();
  if (!question) return void res.status(400).json({ error: "question required" });
  const matrix = b.matrix ? String(b.matrix) : undefined;
  try { res.json(await askMatrix(question, matrix)); }
  catch (e) { res.status(500).json({ error: String((e as Error).message || e) }); }
});

// GET /api/matrix-agent/search?q=&matrix= — retrieval only (no LLM)
router.get("/matrix-agent/search", (req: Request, res: Response) => {
  if (!auth(req, res)) return;
  res.json({ hits: searchMatrices(String(req.query.q || ""), req.query.matrix ? String(req.query.matrix) : undefined) });
});

export default router;
