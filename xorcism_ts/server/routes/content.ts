/**
 * content.ts (routes) — Content hub exports: OpenVEX document + a portable Sigma
 * rule bundle. (Attack-playbook export/import live in pentest.ts.) Authenticated.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { getDb } from "../db";
import { generateVex, consumeVex } from "../vex";

const router = Router();
function tenantOf(req: Request): number | null { return req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null); }

// GET /api/vex/export — OpenVEX document for the asset↔vulnerability links
router.get("/vex/export", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  res.setHeader("Content-Disposition", 'attachment; filename="xorcism-openvex.json"');
  res.json(generateVex(tenantOf(req)));
});

// POST /api/vex/consume — apply a VEX document (OpenVEX or CycloneDX-VEX): not_affected → suppress
// (false-positive), fixed → mark fixed on the matching asset↔vuln rows, so VEX-cleared CVEs leave
// the worklists. Body = the VEX document JSON. Requires update on the asset↔vuln link.
router.post("/vex/consume", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSETVULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const doc = req.body;
  if (!doc || typeof doc !== "object") return void res.status(400).json({ error: "post a VEX document (OpenVEX or CycloneDX-VEX) as JSON" });
  try {
    const r = consumeVex(doc, tenantOf(req));
    if (!r.statements) return void res.status(400).json({ error: "no VEX statements found — expected OpenVEX 'statements[]' or CycloneDX 'vulnerabilities[]'" });
    res.json({ ok: true, ...r });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/content/sigma-export — portable Sigma rule bundle (the detection library)
router.get("/content/sigma-export", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "SIGMARULE")) return void res.status(403).json({ error: "forbidden" });
  let rules: unknown[] = [];
  try {
    rules = getDb("XTHREAT").prepare(
      "SELECT SigmaRuleName name, SigmaRuleDescription description, AttackTags attackTags, Level level, LogSource logsource, SigmaYaml yaml FROM SIGMARULE WHERE SigmaYaml IS NOT NULL AND SigmaYaml<>'' LIMIT 5000"
    ).all();
  } catch { rules = []; }
  res.setHeader("Content-Disposition", 'attachment; filename="xorcism-sigma-rules.json"');
  res.json({ schema: "xorcism.sigma-bundle/v1", count: rules.length, rules });
});

export default router;
