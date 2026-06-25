/** crocdigest.ts (routes) — daily CROC digest ("standup"): GET /api/croc/digest.
 *  Read-only cross-cutting summary of what changed + prioritised actions. Any authenticated user. */
import { Router, Request, Response } from "express";
import { generateDigest } from "../crocdigest";

const router = Router();

router.get("/croc/digest", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(generateDigest(tenant)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
