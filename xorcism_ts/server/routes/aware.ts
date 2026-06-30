/**
 * aware.ts (routes) — AWARE (GoodCISO/aware) autonomous AI-agent governance.
 * The governance posture (tiers T0–T4 + identity + hierarchy + framework coverage), tier assignment,
 * the revocation cascade (kill-switch), reinstate, and a demo seed. Guarded like /ai-guardrails
 * (admin-only — gated via RBAC on the agent registry, XAGENT.AIAGENT).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { awareGovernance, setAgentGovernance, revokeAgentCascade, reinstateAgent, seedAwareDemo } from "../aiguard";
import * as xid from "../xid";

const router = Router();
const who = (req: Request): string => String(req.user!.DisplayName || req.user!.Email || req.user!.UserID || "user");
const auth = (req: Request, res: Response, act: "read" | "create" | "update"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XAGENT", "AIAGENT")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const audit = (req: Request, action: string, key: string, detail?: string) =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "aware-agent", resourceKey: key, detail: detail || "", ip: clientIp(req) });

// GET /api/aware — governance posture: tiers, agents, hierarchy, framework coverage
router.get("/aware", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(awareGovernance());
});

// POST /api/aware/agent/:name/tier { tier: T0..T4, parentAgent?, fingerprint? }
router.post("/aware/agent/:name/tier", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const out = setAgentGovernance(String(req.params.name), {
    tier: b.tier != null ? String(b.tier) : undefined,
    parentAgent: b.parentAgent != null ? String(b.parentAgent) : undefined,
    fingerprint: b.fingerprint != null ? String(b.fingerprint) : undefined,
    source: "aware",
  });
  if (!out.ok) return void res.status(404).json(out);
  audit(req, "aware_set_tier", String(req.params.name), `tier=${b.tier ?? ""}`);
  res.json(out);
});

// POST /api/aware/agent/:name/revoke-cascade { reason? } — revoke the agent + all descendants (kill-switch)
router.post("/aware/agent/:name/revoke-cascade", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const reason = String((req.body || {}).reason || "operator revoke");
  const out = revokeAgentCascade(String(req.params.name), reason);
  if (!out.ok) return void res.status(404).json(out);
  audit(req, "aware_revoke_cascade", String(req.params.name), `revoked ${out.revoked}: ${out.agents.join(",")}`);
  res.json(out);
});

// POST /api/aware/agent/:name/reinstate
router.post("/aware/agent/:name/reinstate", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  reinstateAgent(String(req.params.name));
  audit(req, "aware_reinstate", String(req.params.name));
  res.json({ ok: true });
});

// POST /api/aware/seed — demo agent fleet with mixed tiers (idempotent)
router.post("/aware/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  res.json({ ok: true, ...seedAwareDemo() });
});

export default router;
