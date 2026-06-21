/**
 * investment.ts (routes) — Agentic Security Investment Advisor.
 *   GET  /api/investment-advisor             — baseline posture + investment levers
 *   POST /api/investment-advisor/simulate    — deterministic what-if (fast)
 *   POST /api/investment-advisor/advise       — local-AI board-ready recommendation (offline fallback)
 */
import { Router, Request, Response } from "express";
import { clientIp } from "../auth";
import { investmentBaseline, simulateInvestment, investmentAdvice } from "../investment";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/investment-advisor", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  try { res.json(investmentBaseline(tenantOf(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/investment-advisor/simulate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = (req.body || {}) as Record<string, unknown>;
  try {
    res.json(simulateInvestment(tenantOf(req), {
      lever: String(b.lever || ""),
      coverage: b.coverage != null ? Number(b.coverage) : undefined,
      cost: b.cost != null && String(b.cost) !== "" ? Number(b.cost) : null,
    }));
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/investment-advisor/advise", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = (req.body || {}) as Record<string, unknown>;
  investmentAdvice(tenantOf(req), {
    lever: String(b.lever || ""),
    coverage: b.coverage != null ? Number(b.coverage) : undefined,
    cost: b.cost != null && String(b.cost) !== "" ? Number(b.cost) : null,
    name: b.name ? String(b.name) : undefined,
    question: b.question ? String(b.question) : undefined,
  }).then((out) => {
    xid.addAudit({ userId: req.user!.UserID ?? null, action: "investment_advice", resourceType: "investment",
      resourceKey: String(b.lever || ""), detail: `delta=${out.simulation.riskDelta} offline=${out.offline}`, ip: clientIp(req) });
    res.json(out);
  }).catch((e) => res.status(500).json({ error: String((e as Error).message || e) }));
});

export default router;
