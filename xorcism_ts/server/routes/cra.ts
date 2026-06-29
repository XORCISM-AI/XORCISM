/**
 * cra.ts (routes) — EU Cyber Resilience Act conformity cockpit. Products with digital elements, releases,
 * the Annex I requirement matrix and the release-readiness gate. RBAC: XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { ensureCraTables, craDashboard, productConformity, registerProduct, registerRelease, assessRequirement, deleteProduct, craReport, craReportMarkdown, CRA_REQUIREMENTS } from "../cra";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete"): boolean => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");

router.get("/cra", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try {
    ensureCraTables();
    if (String(req.query.format) === "md") {
      const rep = await craReport(ten(req));
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="cra-conformity-report.md"`);
      return void res.send(craReportMarkdown(rep));
    }
    if (String(req.query.report) === "1") return void res.json(await craReport(ten(req)));
    res.json({ dashboard: craDashboard(ten(req)), requirementCatalogue: CRA_REQUIREMENTS });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/cra/product/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { const c = productConformity(ten(req), Number(req.params.id)); if (!c) return void res.status(404).json({ error: "not found" }); res.json(c); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/cra/product", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  if (!(req.body || {}).name) return void res.status(400).json({ error: "name required" });
  try {
    const r = registerProduct(ten(req), req.body as Record<string, unknown>);
    xid.addAudit({ userId: req.user.UserID, action: "cra_product_add", resourceType: "table", resourceKey: `XCOMPLIANCE.CRAPRODUCT#${r.id}`, ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.post("/cra/release", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  if (!(req.body || {}).productId) return void res.status(400).json({ error: "productId required" });
  try { res.json(registerRelease(ten(req), req.body as Record<string, unknown>)); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.post("/cra/requirement/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  try { res.json(assessRequirement(ten(req), Number(req.params.id), String(b.status || "gap"), b.evidence ? String(b.evidence) : undefined)); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

router.delete("/cra/product/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(deleteProduct(Number(req.params.id))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
