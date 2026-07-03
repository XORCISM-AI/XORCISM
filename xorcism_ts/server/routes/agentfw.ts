/**
 * agentfw.ts (routes) — Agent Policy Firewall. The pre-execution gate (/evaluate), the action ledger +
 * policies + scorecard, approve/deny (with segregation-of-duties), policy CRUD, signed-receipt-chain
 * verification, and a demo seed. Guarded by RBAC on XORCISM.LOOPPOLICY (agent/automation governance).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { dashboard, evaluateAction, approveAction, denyAction, addPolicy, deletePolicy, verifyReceipts, seedDemo, owaspAgenticCoverage } from "../agentfw";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const who = (req: Request): string => String(req.user!.DisplayName || req.user!.Email || req.user!.UserID || "user");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XORCISM", "LOOPPOLICY")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};

// GET /api/agent-firewall — ledger + policies + scorecard + receipt-chain integrity
router.get("/agent-firewall", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(dashboard(tenantOf(req)));
});

// GET /api/agent-firewall/owasp-agentic — OWASP Agentic Top 10 verification (replicates AGT `agt verify`)
router.get("/agent-firewall/owasp-agentic", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(owaspAgenticCoverage(tenantOf(req)));
});

// POST /api/agent-firewall/evaluate — the firewall gate: score + decide + sign a receipt for one action
router.post("/agent-firewall/evaluate", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.actionType || !b.target) return void res.status(400).json({ error: "actionType and target required" });
  const out = evaluateAction({
    actionType: String(b.actionType), actor: b.actor != null ? String(b.actor) : who(req), target: String(b.target),
    params: b.params != null ? String(b.params) : undefined, sensitivity: b.sensitivity != null ? String(b.sensitivity) : undefined,
    idempotencyKey: b.idempotencyKey != null ? String(b.idempotencyKey) : undefined,
  }, tenantOf(req));
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "agentfw_evaluate", resourceType: "agent-action", resourceKey: String(out.actionId), detail: `${b.actionType} → ${out.status} (blast ${out.blastRadius})`, ip: clientIp(req) });
  res.json(out);
});

// POST /api/agent-firewall/action/:id/approve — approve a pending action (segregation-of-duties enforced)
router.post("/agent-firewall/action/:id/approve", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = approveAction(Number(req.params.id), who(req), tenantOf(req));
  if (!out.ok) return void res.status(400).json(out);
  xid.addAudit({ userId: req.user!.UserID ?? null, action: "agentfw_approve", resourceType: "agent-action", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json(out);
});
router.post("/agent-firewall/action/:id/deny", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = denyAction(Number(req.params.id), who(req), tenantOf(req));
  if (!out.ok) return void res.status(400).json(out);
  res.json(out);
});

// policy CRUD
router.post("/agent-firewall/policy", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.name) return void res.status(400).json({ error: "name required" });
  const tenant = req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1);
  res.json({ ok: true, ...addPolicy(b, tenant) });
});
router.delete("/agent-firewall/policy/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  if (!deletePolicy(Number(req.params.id), tenantOf(req))) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

// GET /api/agent-firewall/verify — verify the signed-receipt hash chain
router.get("/agent-firewall/verify", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(verifyReceipts(tenantOf(req)));
});

// POST /api/agent-firewall/seed — seed default policies + sample actions (idempotent)
router.post("/agent-firewall/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const tenant = req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1);
  res.json({ ok: true, ...seedDemo(tenant) });
});

export default router;
