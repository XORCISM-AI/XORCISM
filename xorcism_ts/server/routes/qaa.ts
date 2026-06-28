/**
 * qaa.ts (routes) — Security Questionnaire Auto-Answer.
 * Drafts answers to customer security questionnaires from XORCISM's own knowledge base
 * (answer library + policies + controls + live assurance posture). RBAC on XCOMPLIANCE.COMPLIANCEASSESSMENT.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { answerQuestions, library, saveAnswer, deleteAnswer } from "../qaa";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// POST /api/questionnaire-assistant/answer  { questions: string[] }
router.post("/questionnaire-assistant/answer", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const body = req.body || {};
  let questions: string[] = Array.isArray(body.questions) ? body.questions
    : typeof body.text === "string" ? body.text.split(/\r?\n/) : [];
  questions = questions.map((q) => String(q || "").trim()).filter(Boolean).slice(0, 100);
  if (!questions.length) return void res.status(400).json({ error: "no questions" });
  try { res.json(await answerQuestions(tenantOf(req), questions)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/questionnaire-assistant/library
router.get("/questionnaire-assistant/library", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  res.json({ library: library(tenantOf(req)) });
});

// POST /api/questionnaire-assistant/save  { question, answer, tags? }
router.post("/questionnaire-assistant/save", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  const { question, answer, tags } = req.body || {};
  if (!question || !answer) return void res.status(400).json({ error: "question and answer required" });
  res.json(saveAnswer(tenantOf(req), String(question).trim(), String(answer).trim(), String(tags || "").trim()));
});

// DELETE /api/questionnaire-assistant/library/:id
router.delete("/questionnaire-assistant/library/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XCOMPLIANCE", "COMPLIANCEASSESSMENT")) return void res.status(403).json({ error: "forbidden" });
  deleteAnswer(tenantOf(req), Number(req.params.id));
  res.json({ ok: true });
});

export default router;
