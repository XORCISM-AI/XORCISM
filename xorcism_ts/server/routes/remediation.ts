/**
 * remediation.ts (routes) — Autonomous Exposure Remediation (AER): the CTEM Mobilization closed loop.
 * Dashboard + worklist, mobilize-from-exposures (auto-plan), per-plan PLAN→GATE→EXECUTE→VERIFY→CLOSE
 * lifecycle, AI runbook, and signed-receipt-chain verification. Guarded by RBAC on
 * XVULNERABILITY.VULNERABILITY (read for views; create/update for the lifecycle actions).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  remediationDashboard, planDetail, planRemediation, autoPlanFromExposures, executePlan, approvePlan,
  verifyPlan, runVerificationSweep, setPlanStatus, assignPlan, verifyReceipts, seedDemo,
} from "../remediation";
import { remediationRunbook } from "../ai";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const writeTenant = (req: Request): number => (req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1));
const who = (req: Request): string => String(req.user!.DisplayName || req.user!.Email || req.user!.UserID || "user");
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XVULNERABILITY", "VULNERABILITY")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const audit = (req: Request, action: string, key: string, detail?: string) =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "remediation-plan", resourceKey: key, detail: detail || "", ip: clientIp(req) });

// GET /api/remediation — cockpit: KPIs, mobilization pipeline, worklist, policy, receipt integrity
router.get("/remediation", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(remediationDashboard(tenantOf(req)));
});

// GET /api/remediation/plan/:id — plan detail + lifecycle timeline
router.get("/remediation/plan/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const p = planDetail(Number(req.params.id), tenantOf(req));
  if (!p) return void res.status(404).json({ error: "not found" });
  res.json(p);
});

// GET /api/remediation/plan/:id/runbook — AI remediation runbook (local model + offline fallback)
router.get("/remediation/plan/:id/runbook", async (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const p = planDetail(Number(req.params.id), tenantOf(req));
  if (!p) return void res.status(404).json({ error: "not found" });
  const out = await remediationRunbook({
    ref: p.exposureRef, action: p.actionType, severity: p.severity, priority: p.priority, assets: p.assetCount,
    publicFacing: p.publicFacing, window: p.window, reason: p.plan?.reason, steps: p.plan?.steps,
  });
  res.json(out);
});

// POST /api/remediation/auto-plan — mobilize: turn the top prioritized exposures into plans (idempotent)
router.post("/remediation/auto-plan", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const out = autoPlanFromExposures(writeTenant(req), b.limit != null ? Number(b.limit) : 15, b.autonomy != null ? String(b.autonomy) : undefined);
  audit(req, "aer_auto_plan", "*", `created ${out.created}, skipped ${out.skipped} of ${out.total}`);
  res.json({ ok: true, ...out });
});

// POST /api/remediation/plan — plan one exposure (by VulnerabilityID)
router.post("/remediation/plan", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (b.vid == null) return void res.status(400).json({ error: "vid (VulnerabilityID) required" });
  try {
    const out = planRemediation(writeTenant(req), {
      vid: Number(b.vid), autonomy: b.autonomy != null ? String(b.autonomy) : undefined,
      actionType: b.actionType != null ? String(b.actionType) : undefined,
      ownerPersonId: b.ownerPersonId != null ? Number(b.ownerPersonId) : undefined,
    });
    if (out.created) audit(req, "aer_plan", String(out.plan.id), `${out.plan.actionType} ${out.plan.exposureRef}`);
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/remediation/plan/:id/execute — GATE + EXECUTE (autonomy ladder + Agent Policy Firewall)
router.post("/remediation/plan/:id/execute", async (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = await executePlan(Number(req.params.id), who(req), tenantOf(req));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "aer_execute", String(req.params.id), `decision ${out.decision} → ${out.status}`);
  res.json(out);
});

// POST /api/remediation/plan/:id/approve — approve a gated plan (SoD enforced) and execute
router.post("/remediation/plan/:id/approve", async (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = await approvePlan(Number(req.params.id), who(req), tenantOf(req));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "aer_approve", String(req.params.id));
  res.json(out);
});

// POST /api/remediation/plan/:id/verify — closed-loop verification (re-check live exposure state)
router.post("/remediation/plan/:id/verify", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = verifyPlan(Number(req.params.id), tenantOf(req), who(req));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "aer_verify", String(req.params.id), `${out.result} (open ${out.openAssets})`);
  res.json(out);
});

// POST /api/remediation/verify-sweep — verify all plans awaiting verification
router.post("/remediation/verify-sweep", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = runVerificationSweep(tenantOf(req));
  audit(req, "aer_verify_sweep", "*", `checked ${out.checked}, verified ${out.verified}, reopened ${out.reopened}`);
  res.json({ ok: true, ...out });
});

// POST /api/remediation/plan/:id/status — manual lifecycle (risk-accept / close / reopen / queue)
router.post("/remediation/plan/:id/status", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.status) return void res.status(400).json({ error: "status required" });
  const out = setPlanStatus(Number(req.params.id), String(b.status), tenantOf(req), who(req), b.note != null ? String(b.note) : undefined);
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "aer_status", String(req.params.id), String(b.status));
  res.json(out);
});

// POST /api/remediation/plan/:id/assign — route to an owner
router.post("/remediation/plan/:id/assign", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const out = assignPlan(Number(req.params.id), b.personId != null ? Number(b.personId) : null, tenantOf(req), who(req));
  if (!out.ok) return void res.status(400).json(out);
  res.json(out);
});

// GET /api/remediation/verify — verify the signed-receipt hash chain
router.get("/remediation/verify", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(verifyReceipts(tenantOf(req)));
});

// POST /api/remediation/seed — demo plans across the lifecycle (idempotent)
router.post("/remediation/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  res.json({ ok: true, ...seedDemo(writeTenant(req)) });
});

export default router;
