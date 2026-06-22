/** attacktree.ts (routes) — attack trees for threat modeling. RBAC on XORCISM.THREATMODEL. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { listAttackTrees, getAttackTree, createAttackTree, addAttackTreeNode, updateAttackTreeNode, deleteAttackTreeNode } from "../attacktree";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/attack-tree", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(listAttackTrees(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/attack-tree/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  try { const t = getAttackTree(Number(req.params.id), ten(req)); if (!t) return void res.status(404).json({ error: "not found" }); res.json(t); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/attack-tree", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim()) return void res.status(400).json({ error: "name required" });
  try {
    const out = createAttackTree({ name: String(b.name), goal: b.goal ? String(b.goal) : undefined, description: b.description ? String(b.description) : undefined,
      threatModelId: b.threatModelId != null && String(b.threatModelId) !== "" ? Number(b.threatModelId) : null }, ten(req));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "attacktree_create", resourceType: "ATTACKTREE", resourceKey: String(out.id), detail: String(b.name), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/attack-tree/node", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  try {
    const out = addAttackTreeNode({ treeId: Number(b.treeId), parentId: Number(b.parentId), label: String(b.label ?? ""),
      gate: b.gate ? String(b.gate) : undefined, description: b.description ? String(b.description) : undefined,
      likelihood: b.likelihood ? String(b.likelihood) : undefined, mitigated: !!b.mitigated }, ten(req));
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/attack-tree/node/update", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!Number.isInteger(Number(b.nodeId))) return void res.status(400).json({ error: "nodeId required" });
  try {
    const out = updateAttackTreeNode({ nodeId: Number(b.nodeId), label: b.label != null ? String(b.label) : undefined,
      gate: b.gate != null ? String(b.gate) : undefined, likelihood: b.likelihood != null ? String(b.likelihood) : undefined,
      mitigated: b.mitigated != null ? !!b.mitigated : undefined, mitigationNote: b.mitigationNote != null ? String(b.mitigationNote) : undefined }, ten(req));
    res.json(out);
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/attack-tree/node/delete", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "THREATMODEL")) return void res.status(403).json({ error: "forbidden" });
  const nodeId = Number((req.body || {}).nodeId);
  if (!Number.isInteger(nodeId)) return void res.status(400).json({ error: "nodeId required" });
  try { res.json(deleteAttackTreeNode(nodeId, ten(req))); } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
