/**
 * secplans.ts (routes) — System Plans per NIST SP 800-18r2 (Security / Privacy / C-SCRM / Consolidated).
 * Create a plan per system, work the 21 plan elements across the 7-step RMF journey, map controls,
 * and export the plan as OSCAL SSP or Markdown. RBAC on XCOMPLIANCE.COMPLIANCEASSESSMENT (GRC domain).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import {
  RMF_STEPS, NIST_ELEMENTS, PLAN_TYPES, IMPACT_LEVELS, OPERATIONAL_STATUS,
  createPlan, listPlans, getPlan, updatePlan, updateElement, deletePlan,
  planMarkdown, planOscal, draftElement,
} from "../secplans";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, action: "read" | "create" | "update" | "delete"): boolean =>
  !!req.user && userCan(req.user, action, "XCOMPLIANCE", "COMPLIANCEASSESSMENT");

// Reference data for the picker / builder (plan types, RMF steps, element template).
router.get("/system-plans/meta", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json({ planTypes: PLAN_TYPES, rmfSteps: RMF_STEPS, elements: NIST_ELEMENTS, impactLevels: IMPACT_LEVELS, operationalStatus: OPERATIONAL_STATUS });
});

// List all plans for the tenant (with completeness).
router.get("/system-plans", (req: Request, res: Response) => {
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  res.json({ plans: listPlans(tenantOf(req)) });
});

// Create a plan — seeds the 21 SP 800-18r2 elements across the RMF steps.
router.post("/system-plans", (req: Request, res: Response) => {
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return void res.status(400).json({ error: "name required" });
  try {
    const { planId } = createPlan(tenantOf(req), { ...b, name: String(b.name).trim(), createdBy: req.user!.DisplayName || req.user!.Email || "user" });
    res.json({ ok: true, planId });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// One plan with its elements + the RMF-step journey.
router.get("/system-plans/:id", (req: Request, res: Response) => {
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const d = getPlan(tenantOf(req), Number(req.params.id));
  if (!d) return void res.status(404).json({ error: "not found" });
  res.json(d);
});

// Patch plan header fields (identifier, categorization, roles, operational status, RMF step, decision…).
router.patch("/system-plans/:id", (req: Request, res: Response) => {
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  updatePlan(tenantOf(req), Number(req.params.id), req.body || {});
  res.json({ ok: true });
});

// Patch one element (content / status / artifact / control refs).
router.patch("/system-plans/:id/element/:eid", (req: Request, res: Response) => {
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  updateElement(tenantOf(req), Number(req.params.id), Number(req.params.eid), req.body || {});
  res.json({ ok: true });
});

// AI draft for one element (local Ollama, offline heuristic fallback).
router.post("/system-plans/:id/element/:eid/draft", async (req: Request, res: Response) => {
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(await draftElement(tenantOf(req), Number(req.params.id), Number(req.params.eid))); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

router.delete("/system-plans/:id", (req: Request, res: Response) => {
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  deletePlan(tenantOf(req), Number(req.params.id));
  res.json({ ok: true });
});

// Export — OSCAL 1.1.2 System-Security-Plan (JSON) or Markdown artifact.
router.get("/system-plans/:id/oscal", (req: Request, res: Response) => {
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const o = planOscal(tenantOf(req), Number(req.params.id));
  if (!o) return void res.status(404).json({ error: "not found" });
  res.setHeader("Content-Disposition", `attachment; filename="system-plan-${req.params.id}.oscal.json"`);
  res.json(o);
});
router.get("/system-plans/:id/markdown", (req: Request, res: Response) => {
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const md = planMarkdown(tenantOf(req), Number(req.params.id));
  if (md == null) return void res.status(404).json({ error: "not found" });
  res.setHeader("Content-Type", "text/markdown; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="system-plan-${req.params.id}.md"`);
  res.send(md);
});

export default router;
