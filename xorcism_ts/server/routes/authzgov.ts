/**
 * authzgov.ts (routes) — API Authorization Governance: inventory of API gateways (PEP) + policy decision
 * points (OPA / Cedar / AuthZEN PDP) + policies, a posture assessment, and a vendor-neutral decision
 * evaluator (PEP test harness). RBAC: XCOMPLIANCE.AUDIT (mirrors zero-trust governance).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import {
  ensureAuthzTables, listInventory, assessAuthzPosture, registerGateway, registerPdp, registerPolicy,
  deleteRow, recordDecisionTest, buildRequest, normalizeDecision, runAuthzTestSuite, recordSuiteRun, suiteTrend, suiteTrendsByPdp,
  type DecisionRequest, type Decision,
} from "../authzgov";

// Build a decision-evaluator: call the PDP live (opt-in, http(s)-only, 5s timeout) or return "error".
function makeEvaluator(endpoint: string, live: boolean): (engine: string, req: DecisionRequest) => Promise<{ decision: Decision; raw?: unknown }> {
  return async (engine, dr) => {
    if (!live || !endpoint || !/^https?:\/\//i.test(endpoint)) return { decision: "error" };
    try {
      const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 5000);
      const resp = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(buildRequest(engine, dr)), signal: ctrl.signal });
      clearTimeout(to);
      const raw = await resp.json().catch(() => ({}));
      return { decision: normalizeDecision(engine, raw), raw };
    } catch { return { decision: "error" }; }
  };
}

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");

// GET /api/authz-governance — inventory + posture
router.get("/authz-governance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { ensureAuthzTables(); res.json({ inventory: listInventory(ten(req)), posture: assessAuthzPosture(ten(req)), suiteTrend: suiteTrend(ten(req), 30), suiteTrendsByPdp: suiteTrendsByPdp(ten(req), 20) }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/authz-governance/pdp | /gateway | /policy — register inventory
for (const kind of ["pdp", "gateway", "policy"] as const) {
  router.post(`/authz-governance/${kind}`, (req: Request, res: Response) => {
    if (!req.user) return void res.status(401).json({ error: "auth" });
    if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
    try {
      const body = (req.body || {}) as Record<string, unknown>;
      const r = kind === "pdp" ? registerPdp(ten(req), body) : kind === "gateway" ? registerGateway(ten(req), body) : registerPolicy(ten(req), body);
      xid.addAudit({ userId: req.user.UserID, action: `authz_${kind}_add`, resourceType: "table", resourceKey: `XORCISM.AUTHZ${kind.toUpperCase()}#${r.id}`, ip: clientIp(req) });
      res.json(r);
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
}

// DELETE /api/authz-governance/:kind/:id
router.delete("/authz-governance/:kind/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  const map: Record<string, "AUTHZGATEWAY" | "AUTHZPDP" | "AUTHZPOLICY"> = { gateway: "AUTHZGATEWAY", pdp: "AUTHZPDP", policy: "AUTHZPOLICY" };
  const table = map[String(req.params.kind)];
  if (!table) return void res.status(400).json({ error: "unknown kind" });
  try { res.json(deleteRow(table, Number(req.params.id))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/authz-governance/evaluate — build the engine request (PEP test harness), optionally call the
// PDP live (opt-in), normalise the decision and record the test. Returns the exact payload that would be sent.
router.post("/authz-governance/evaluate", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const engine = String(b.engine || "authzen").toLowerCase();
  const dr: DecisionRequest = { subject: String(b.subject || ""), action: String(b.action || ""), resource: String(b.resource || ""), context: (b.context as Record<string, unknown>) || {} };
  if (!dr.subject || !dr.action || !dr.resource) return void res.status(400).json({ error: "subject, action, resource required" });
  const request = buildRequest(engine, dr);
  const expected = b.expected ? String(b.expected) : undefined;
  let decision: Decision = "error"; let raw: unknown = null; let note = "not evaluated (dry-run) — payload built only";

  const endpoint = b.endpoint ? String(b.endpoint) : "";
  if (b.live === true && endpoint) {
    if (!/^https?:\/\//i.test(endpoint)) { note = "endpoint must be http(s)"; }
    else {
      try {
        const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 5000);
        const resp = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request), signal: ctrl.signal });
        clearTimeout(to);
        raw = await resp.json().catch(() => ({}));
        decision = normalizeDecision(engine, raw); note = `live PDP responded ${resp.status}`;
      } catch (e) { note = `PDP unreachable: ${(e as Error).message}`; }
    }
  }
  try {
    const rec = recordDecisionTest(ten(req), { pdpId: b.pdpId != null && b.pdpId !== "" ? Number(b.pdpId) : undefined, engine, req: dr, decision, expected, raw });
    res.json({ request, engine, decision, expected: expected || null, pass: rec.pass, note, id: rec.id });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/authz-governance/test-suite — run the OWASP BOLA/BFLA authorization test battery against a PDP
router.post("/authz-governance/test-suite", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const engine = String(b.engine || "authzen").toLowerCase();
  const endpoint = b.endpoint ? String(b.endpoint) : "";
  const live = b.live === true;
  try {
    const pdpId = b.pdpId != null && b.pdpId !== "" ? Number(b.pdpId) : undefined;
    const report = await runAuthzTestSuite(ten(req), { engine, pdpId, evaluate: makeEvaluator(endpoint, live) });
    const run = recordSuiteRun(ten(req), { engine, endpoint: endpoint || undefined, pdpId, total: report.total, passed: report.passed, failed: report.failed, errors: report.errors, findings: report.findings.length }, "manual");
    xid.addAudit({ userId: req.user.UserID, action: "authz_test_suite", resourceType: "table", resourceKey: `AUTHZDECISIONTEST (${report.failed} fail / ${report.findings.length} finding)`, ip: clientIp(req) });
    res.json({ ...report, regressed: run.regressed, trend: suiteTrend(ten(req), 30) });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
