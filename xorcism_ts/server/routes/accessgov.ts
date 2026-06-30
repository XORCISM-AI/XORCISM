/**
 * accessgov.ts (routes) — Access Governance (Saviynt-style): the entitlement catalogue, the Segregation-of-
 * Duties violations worklist (mitigate/accept), access requests (request → approve/deny with SoD pre-check),
 * JIT expiry sweep, SoD-rule authoring, and peer-outlier intelligence. Guarded by RBAC on XORCISM.IDENTITY
 * (read for views; create/update for the lifecycle actions).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  accessGovDashboard, detectSod, requestAccess, decideRequest, jitSweep, setViolationStatus, addSodRule, sodPreCheck,
} from "../accessgov";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const writeTenant = (req: Request): number => (req.user!.isSuperAdmin ? 1 : (req.user!.tenantId ?? 1));
const who = (req: Request): string => String(req.user!.DisplayName || req.user!.Email || req.user!.UserID || "user");
const auth = (req: Request, res: Response, act: "read" | "create" | "update"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XORCISM", "IDENTITY")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const audit = (req: Request, action: string, key: string, detail?: string) =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "access-governance", resourceKey: key, detail: detail || "", ip: clientIp(req) });

// GET /api/access-governance — cockpit: SoD violations, requests, JIT, entitlements, outliers
router.get("/access-governance", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json(accessGovDashboard(tenantOf(req)));
});

// POST /api/access-governance/detect — recompute SoD violations across the estate
router.post("/access-governance/detect", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = detectSod(tenantOf(req));
  audit(req, "ag_sod_detect", "*", `${out.violations} open (+${out.created}/-${out.resolved})`);
  res.json({ ok: true, ...out });
});

// POST /api/access-governance/sod-precheck { identityId, entitlementId } — preventive simulation
router.post("/access-governance/sod-precheck", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  res.json(sodPreCheck(tenantOf(req), Number(b.identityId), Number(b.entitlementId)));
});

// POST /api/access-governance/request { identityId, entitlementId, justification?, jitHours? }
router.post("/access-governance/request", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (b.identityId == null || b.entitlementId == null) return void res.status(400).json({ error: "identityId and entitlementId required" });
  const out = requestAccess(writeTenant(req), { identityId: Number(b.identityId), entitlementId: Number(b.entitlementId), justification: b.justification != null ? String(b.justification) : undefined, jitHours: b.jitHours != null ? Number(b.jitHours) : 0 }, who(req));
  audit(req, "ag_access_request", String(out.id), out.sodConflict ? `SoD conflict: ${out.sodDetail}` : "clean");
  res.json({ ok: true, ...out });
});

// POST /api/access-governance/request/:id/decide { decision: approve|deny, overrideSod? }
router.post("/access-governance/request/:id/decide", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const decision = String(b.decision) === "deny" ? "deny" : "approve";
  const out = decideRequest(tenantOf(req), Number(req.params.id), decision, who(req), b.overrideSod === true);
  if (!out.ok) return void res.status(out.needsOverride ? 409 : 400).json(out);
  audit(req, "ag_request_decide", String(req.params.id), `${decision} → ${out.status}${b.overrideSod ? " (SoD override)" : ""}`);
  res.json(out);
});

// POST /api/access-governance/violation/:id/status { status: mitigated|accepted|resolved|open, note? }
router.post("/access-governance/violation/:id/status", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  const out = setViolationStatus(tenantOf(req), Number(req.params.id), String(b.status || ""), b.note != null ? String(b.note) : "", who(req));
  if (!out.ok) return void res.status(400).json(out);
  audit(req, "ag_violation_status", String(req.params.id), String(b.status));
  res.json(out);
});

// POST /api/access-governance/jit-sweep — expire elapsed JIT grants
router.post("/access-governance/jit-sweep", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = jitSweep(tenantOf(req));
  audit(req, "ag_jit_sweep", "*", `revoked ${out.revoked}, expired ${out.expired}`);
  res.json({ ok: true, ...out });
});

// POST /api/access-governance/sod-rule { name, functionA, functionB, risk?, mitigation?, description? }
router.post("/access-governance/sod-rule", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.name || !b.functionA || !b.functionB) return void res.status(400).json({ error: "name, functionA, functionB required" });
  const out = addSodRule(writeTenant(req), { name: String(b.name), description: b.description != null ? String(b.description) : undefined, functionA: String(b.functionA), functionB: String(b.functionB), risk: b.risk != null ? String(b.risk) : undefined, mitigation: b.mitigation != null ? String(b.mitigation) : undefined });
  detectSod(writeTenant(req));
  audit(req, "ag_sod_rule_add", String(out.id), String(b.name));
  res.json({ ok: true, ...out });
});

export default router;
