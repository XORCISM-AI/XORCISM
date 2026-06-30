/**
 * threatactor.ts (routes) — threat-actor profiling + the Diamond Model of Intrusion Analysis.
 * List/profile/upsert actors, set the four Diamond vertices + meta axes, manage curated
 * infrastructure IOCs, and a demo seed. RBAC-gated on XTHREAT.THREATACTOR; all writes audited.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { listActors, actorProfile, upsertActor, setDiamond, addInfra, removeInfra, deleteActor, seedDemo, STIX_VOCAB } from "../threatactor";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const auth = (req: Request, res: Response, act: "read" | "create" | "update" | "delete"): boolean => {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, act, "XTHREAT", "THREATACTOR")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
};
const audit = (req: Request, action: string, key: string, detail?: string) =>
  xid.addAudit({ userId: req.user!.UserID ?? null, action, resourceType: "threat-actor", resourceKey: key, detail: detail || "", ip: clientIp(req) });

// GET /api/threat-actors — list + summary + the STIX vocabularies for the builder dropdowns
router.get("/threat-actors", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  res.json({ ...listActors(tenantOf(req)), vocab: STIX_VOCAB });
});

// GET /api/threat-actors/:id — full profile + assembled Diamond Model
router.get("/threat-actors/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "read")) return;
  const p = actorProfile(tenantOf(req), Number(req.params.id));
  if (!p) return void res.status(404).json({ error: "not found" });
  res.json(p);
});

// POST /api/threat-actors — create or update a profile { id?, name, ... }
router.post("/threat-actors", (req: Request, res: Response) => {
  const create = !((req.body || {}).id > 0);
  if (!auth(req, res, create ? "create" : "update")) return;
  const b = req.body || {};
  if (!String(b.name || "").trim()) return void res.status(400).json({ error: "name required" });
  const out = upsertActor(tenantOf(req), b);
  audit(req, create ? "actor_create" : "actor_update", String(out.id), String(b.name).slice(0, 120));
  res.json(out);
});

// POST /api/threat-actors/:id/diamond — set the 4 vertices + 2 meta axes
router.post("/threat-actors/:id/diamond", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const out = setDiamond(tenantOf(req), Number(req.params.id), req.body || {});
  if (!out.ok) return void res.status(404).json(out);
  audit(req, "actor_diamond", String(req.params.id));
  res.json(out);
});

// POST /api/threat-actors/:id/infra — add a curated infrastructure IOC
router.post("/threat-actors/:id/infra", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  const b = req.body || {};
  if (!String(b.value || "").trim()) return void res.status(400).json({ error: "value required" });
  const out = addInfra(tenantOf(req), Number(req.params.id), b);
  audit(req, "actor_infra_add", String(req.params.id), `${b.type || ""}:${String(b.value).slice(0, 80)}`);
  res.json(out);
});

// DELETE /api/threat-actors/infra/:infraId
router.delete("/threat-actors/infra/:infraId", (req: Request, res: Response) => {
  if (!auth(req, res, "update")) return;
  res.json(removeInfra(tenantOf(req), Number(req.params.infraId)));
});

// DELETE /api/threat-actors/:id — soft-delete (Active=0)
router.delete("/threat-actors/:id", (req: Request, res: Response) => {
  if (!auth(req, res, "delete")) return;
  const out = deleteActor(tenantOf(req), Number(req.params.id));
  audit(req, "actor_delete", String(req.params.id));
  res.json(out);
});

// POST /api/threat-actors/seed — fully-profiled demo actor (idempotent)
router.post("/threat-actors/seed", (req: Request, res: Response) => {
  if (!auth(req, res, "create")) return;
  const t = req.user!.tenantId ?? 3;
  res.json({ ok: true, ...seedDemo(t) });
});

export default router;
