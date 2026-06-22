/**
 * connectors.ts (routes) — Connector registry + job launching + tracking.
 * Reads the connectors/<id>/connector.json manifests; creates jobs in
 * XJOB (consumed by the Python runner). Launching a tool-runner connector
 * is restricted to administrators (active tools are sensitive).
 */

import { Router, Request, Response } from "express";
import fs from "fs";
import path from "path";
import {
  createJob, getJob, listJobs,
  listEngagements, getEngagement, createEngagement, setEngagementActive,
  listWorkers, createWorker, deleteWorker,
  createSchedule, listSchedules, setScheduleEnabled, deleteSchedule,
} from "../jobs";
import { targetInScope } from "../scope";
import { validateCron } from "../cron";
import { clientIp } from "../auth";
import * as xid from "../xid";

const router = Router();

// dist/server/routes → ../../../.. = repository root → connectors/
const CONNECTORS_DIR = path.resolve(__dirname, "../../../../connectors");

interface Param {
  name: string;
  type: "string" | "int" | "bool" | "enum" | "target" | "url" | "file";
  required?: boolean;
  default?: unknown;
  values?: unknown[];
  min?: number;
  max?: number;
  pattern?: string;
  help?: string;
}
interface Manifest {
  id: string;
  name: string;
  type: string;
  category?: string;
  description?: string;
  binary?: string;
  intrusive?: boolean;
  permission?: string;
  parameters?: Param[];
}

// The catalogue is large (1200+ connectors ≈ 0.9 MB). Scanning + parsing every
// connector.json on each request costs ~300 ms (worse on OneDrive/network volumes),
// so we cache the parsed manifests in memory and only re-scan when the connectors
// directory changes (mtime) or the cache ages past the TTL (catches edits inside an
// existing manifest, which don't bump the parent-dir mtime).
const MANIFEST_TTL_MS = 60_000;
let _manifestCache: { manifests: Manifest[]; mtimeMs: number; at: number } | null = null;
function connectorsDirMtime(): number { try { return fs.statSync(CONNECTORS_DIR).mtimeMs; } catch { return 0; } }

function scanManifests(): Manifest[] {
  const out: Manifest[] = [];
  let dirs: string[] = [];
  try {
    dirs = fs.readdirSync(CONNECTORS_DIR, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);
  } catch {
    return out;
  }
  for (const d of dirs) {
    const p = path.join(CONNECTORS_DIR, d, "connector.json");
    try {
      out.push(JSON.parse(fs.readFileSync(p, "utf-8")) as Manifest);
    } catch {
      /* missing or invalid manifest ignored (drops the existsSync syscall) */
    }
  }
  return out;
}

function loadManifests(): Manifest[] {
  const mt = connectorsDirMtime();
  if (_manifestCache && _manifestCache.mtimeMs === mt && Date.now() - _manifestCache.at < MANIFEST_TTL_MS)
    return _manifestCache.manifests;
  const manifests = scanManifests();
  _manifestCache = { manifests, mtimeMs: mt, at: Date.now() };
  return manifests;
}

/** Warm the manifest cache at boot so the first /connectors load is already fast. */
export function warmManifestCache(): void { try { loadManifests(); } catch { /* non-fatal */ } }

function findManifest(id: string): Manifest | undefined {
  if (!/^[a-z0-9_-]+$/.test(id)) return undefined;
  // Serve from the warm cache when possible (manifest.id === directory name by convention),
  // so selecting/running a connector costs no disk read.
  const hit = _manifestCache?.manifests.find((m) => m.id === id);
  if (hit) return hit;
  const p = path.join(CONNECTORS_DIR, id, "connector.json");
  if (!fs.existsSync(p)) return undefined;
  try {
    return JSON.parse(fs.readFileSync(p, "utf-8")) as Manifest;
  } catch {
    return undefined;
  }
}

const HOST_RE = /^[A-Za-z0-9_.\-:/]{1,255}$/;

// Validates the received parameters against the manifest (defense in depth;
// the Python runner re-validates). Returns {values} or throws an error (message).
function validate(manifest: Manifest, raw: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const p of manifest.parameters ?? []) {
    let v = raw[p.name];
    if (v === undefined || v === "") v = p.default;
    if (v === undefined || v === "") {
      if (p.required) throw new Error(`Paramètre requis manquant : ${p.name}`);
      continue;
    }
    switch (p.type) {
      case "enum":
        if (!(p.values ?? []).includes(v)) throw new Error(`${p.name} hors liste autorisée`);
        break;
      case "int": {
        const n = Number(v);
        if (!Number.isFinite(n)) throw new Error(`${p.name} doit être un entier`);
        if (p.min != null && n < p.min) throw new Error(`${p.name} < min`);
        if (p.max != null && n > p.max) throw new Error(`${p.name} > max`);
        v = n;
        break;
      }
      case "bool":
        v = !!v;
        break;
      case "target":
        if (typeof v !== "string" || !HOST_RE.test(v)) throw new Error(`Cible invalide : ${String(v)}`);
        break;
      case "url": {
        let u: URL;
        try { u = new URL(String(v)); } catch { throw new Error(`${p.name} : URL invalide`); }
        if (!/^https?:$/.test(u.protocol)) throw new Error(`${p.name} : URL http(s) requise`);
        v = String(v);
        break;
      }
      case "string":
        v = String(v);
        if (p.pattern && !new RegExp(p.pattern).test(v as string)) throw new Error(`${p.name} format invalide`);
        if ((v as string).length > 1024) throw new Error(`${p.name} trop long`);
        break;
      default:
        v = String(v);
    }
    out[p.name] = v;
  }
  return out;
}

// GET /api/connectors — slim list for the picker. Parameters (the bulk of the payload)
// are omitted and fetched on demand per connector via GET /api/connectors/:id when one
// is selected — halves the payload (~900 KB → ~490 KB) and the client JSON parse.
router.get("/connectors", (_req: Request, res: Response) => {
  res.json(loadManifests().map((m) => ({
    id: m.id, name: m.name, type: m.type, category: m.category,
    description: m.description, intrusive: !!m.intrusive,
    hasParams: Array.isArray(m.parameters) && m.parameters.length > 0,
  })));
});

// GET /api/connectors/:id — full manifest (with parameters) for the selected connector
router.get("/connectors/:id", (req: Request, res: Response) => {
  const m = findManifest(String(req.params.id));
  if (!m) return void res.status(404).json({ error: "Connecteur inconnu" });
  res.json({
    id: m.id, name: m.name, type: m.type, category: m.category,
    description: m.description, intrusive: !!m.intrusive, parameters: m.parameters ?? [],
  });
});

// ── Engagements (scope/ROE) ──────────────────────────────────────────────────

// GET /api/engagements — active ones (for the selector); admin sees all
router.get("/engagements", (req: Request, res: Response) => {
  res.json(listEngagements(!req.user?.isAdmin));
});

// POST /api/engagements { name, scope:[...], roe } — admin
router.post("/engagements", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  const { name, scope, roe } = req.body as { name?: string; scope?: unknown; roe?: string };
  if (!name || !name.trim()) return void res.status(400).json({ error: "name requis" });
  const list = Array.isArray(scope)
    ? (scope as unknown[]).map((s) => String(s).trim()).filter(Boolean)
    : String(scope || "").split(/[\s,;\n]+/).map((s) => s.trim()).filter(Boolean);
  if (!list.length) return void res.status(400).json({ error: "périmètre (scope) vide" });
  const id = createEngagement(name.trim(), list, String(roe || ""), req.user.UserID);
  xid.addAudit({ userId: req.user.UserID, action: "engagement_created", resourceKey: name.trim(),
    detail: `scope=${list.join(",")}`, ip: clientIp(req) });
  res.json({ id });
});

// POST /api/engagements/:id/active — admin
router.post("/engagements/:id/active", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  setEngagementActive(Number(req.params.id), !!(req.body as { active?: boolean }).active);
  res.json({ ok: true });
});

interface RunBody { connector: string; params: Record<string, unknown>; engagement?: number; worker?: string }
interface Resolved { connector: string; values: Record<string, unknown>; target: string | null; engagementId: number | null; workerName: string | null }

// Validates the parameters + enforces the engagement scope (shared between immediate
// launch and scheduling). Returns the result, or null after emitting the error response.
function resolveConnectorRun(req: Request, res: Response, body: RunBody): Resolved | null {
  const { connector, params, engagement, worker } = body;
  const manifest = findManifest(connector);
  if (!manifest) { res.status(404).json({ error: "Connecteur inconnu" }); return null; }
  let values: Record<string, unknown>;
  try { values = validate(manifest, params || {}); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); return null; }

  const targetParam = (manifest.parameters ?? []).find((p) => p.type === "target" || p.type === "url");
  const target = targetParam ? String(values[targetParam.name] ?? "") : null;
  let scopeHost = target;
  if (targetParam?.type === "url" && target) { try { scopeHost = new URL(target).hostname; } catch { scopeHost = target; } }

  let engagementId: number | null = null;
  if (targetParam && target) {
    if (!engagement) { res.status(400).json({ error: "Engagement requis (périmètre/ROE)" }); return null; }
    const eng = getEngagement(Number(engagement));
    if (!eng || !eng.active) { res.status(400).json({ error: "Engagement introuvable ou inactif" }); return null; }
    let scope: string[] = [];
    try { scope = JSON.parse(eng.scope || "[]"); } catch { scope = []; }
    if (!targetInScope(scopeHost || "", scope)) {
      xid.addAudit({ userId: req.user!.UserID, action: "connector_out_of_scope", resourceType: "connector",
        resourceKey: connector, detail: `target=${target} engagement=${eng.EngagementID}`, ip: clientIp(req) });
      res.status(403).json({ error: `Cible « ${target} » hors du périmètre de l'engagement` });
      return null;
    }
    engagementId = eng.EngagementID;
  }
  const workerName = worker && worker !== "local" ? String(worker) : null;
  return { connector, values, target, engagementId, workerName };
}

// POST /api/connectors/run — creates a job (admin only; scope enforced for targets)
router.post("/connectors/run", (req: Request, res: Response) => {
  if (!req.user?.isAdmin)
    return void res.status(403).json({ error: "Réservé aux administrateurs" });
  const r = resolveConnectorRun(req, res, req.body as RunBody);
  if (!r) return;
  const jobId = createJob(r.connector, r.values, r.target, req.user.UserID, r.engagementId, r.workerName);
  xid.addAudit({
    userId: req.user.UserID, action: "connector_run", resourceType: "connector", resourceKey: r.connector,
    detail: `job=${jobId} target=${r.target ?? ""} engagement=${r.engagementId ?? ""} worker=${r.workerName ?? "local"}`,
    ip: clientIp(req),
  });
  res.json({ jobId });
});

// ── Scheduled tasks (cron recurrence) ────────────────────────────────────────────

// POST /api/schedules — creates a schedule (admin): { connector, params, engagement, worker, cron }
router.post("/schedules", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  const cron = String((req.body as { cron?: string }).cron || "").trim();
  if (!validateCron(cron))
    return void res.status(400).json({ error: "Expression cron invalide (5 champs : min heure jour mois jour-semaine)" });
  const r = resolveConnectorRun(req, res, req.body as RunBody);
  if (!r) return;
  const id = createSchedule({
    connector: r.connector, params: r.values, target: r.target,
    engagementId: r.engagementId, worker: r.workerName, cron, userId: req.user.UserID,
  });
  xid.addAudit({ userId: req.user.UserID, action: "schedule_created", resourceType: "connector",
    resourceKey: r.connector, detail: `schedule=${id} cron="${cron}" target=${r.target ?? ""}`, ip: clientIp(req) });
  res.json({ scheduleId: id });
});

// GET /api/schedules — admin: all; otherwise the user's own
router.get("/schedules", (req: Request, res: Response) => {
  res.json(listSchedules(req.user?.isAdmin ? undefined : req.user?.UserID));
});

// POST /api/schedules/:id/enabled { enabled } — admin
router.post("/schedules/:id/enabled", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  setScheduleEnabled(Number(req.params.id), !!(req.body as { enabled?: boolean }).enabled);
  res.json({ ok: true });
});

// POST /api/schedules/:id/delete — admin
router.post("/schedules/:id/delete", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  deleteSchedule(Number(req.params.id));
  res.json({ ok: true });
});

// ── Workers (remote agents) — administration ────────────────────────────────────

// GET /api/workers — list (for the selector and admin)
router.get("/workers", (_req: Request, res: Response) => {
  res.json(listWorkers());
});

// POST /api/workers { name, capabilities:[...] } — admin; returns the token ONCE
router.post("/workers", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  const { name, capabilities } = req.body as { name?: string; capabilities?: unknown };
  if (!name || !/^[A-Za-z0-9_.\-]{1,64}$/.test(name))
    return void res.status(400).json({ error: "Nom de worker invalide (A-Z a-z 0-9 _ . -)" });
  const caps = Array.isArray(capabilities) ? capabilities.map((c) => String(c)).filter(Boolean) : [];
  try {
    const { id, token } = createWorker(name, caps, req.user.UserID);
    xid.addAudit({ userId: req.user.UserID, action: "worker_created", resourceKey: name, ip: clientIp(req) });
    res.json({ id, name, token });
  } catch {
    res.status(409).json({ error: "Ce nom de worker existe déjà" });
  }
});

// POST /api/workers/:id/delete — admin
router.post("/workers/:id/delete", (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  deleteWorker(Number(req.params.id));
  res.json({ ok: true });
});

// GET /api/jobs — recent jobs (admin: all; otherwise the user's own)
router.get("/jobs", (req: Request, res: Response) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  res.json(listJobs(limit, req.user?.isAdmin ? undefined : req.user?.UserID));
});

// GET /api/jobs/:id — detail + log (owner or admin)
router.get("/jobs/:id", (req: Request, res: Response) => {
  const job = getJob(Number(req.params.id));
  if (!job) return void res.status(404).json({ error: "Job introuvable" });
  if (!req.user?.isAdmin && job.user_id !== req.user?.UserID)
    return void res.status(403).json({ error: "Accès refusé" });
  res.json(job);
});

export default router;
