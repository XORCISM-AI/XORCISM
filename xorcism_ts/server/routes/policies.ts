/**
 * policies.ts (routes) — Policy & document management inventory + governance worklist,
 * plus policy publication and per-user acceptance tracking.
 * Read guarded by read on XORCISM.POLICY; publish/retire by update; acknowledge by any authenticated user.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { policyInventory, publishPolicy, retirePolicy, acknowledgePolicy, policyAcceptanceDetail, myPendingPolicies,
  snapshotPolicyVersion, policyVersions, policyVersionDetail, restorePolicyVersion, policyAssetCoverage } from "../policies";
import { listReviews, addReview, updateReview, removeReview, TARGET_TYPES } from "../legalreview";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const canRead = (req: Request) => userCan(req.user, "read", "XORCISM", "POLICY");
const canWrite = (req: Request) => userCan(req.user, "update", "XORCISM", "POLICY");

// GET /api/policy-management — policies + document register + governance worklist + acceptance KPIs,
// plus `me`: the published policies the current user still needs to acknowledge.
router.get("/policy-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const tenant = ten(req);
  const inv = policyInventory(tenant);
  let mine: unknown[] = [];
  try { mine = myPendingPolicies(req.user.UserID, tenant); } catch { /* */ }
  res.json({ ...inv, me: { userId: req.user.UserID, name: req.user.DisplayName || req.user.Email, pending: mine } });
});

// GET /api/policy-management/coverage — POLICY↔ASSET coverage: per-policy asset counts,
// uncovered assets (critical first) and published policies governing nothing.
router.get("/policy-management/coverage", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  res.json(policyAssetCoverage(ten(req)));
});

// POST /api/policy-management/policy/:id/publish { effectiveDate?, version?, requiresAck? }
router.post("/policy-management/policy/:id/publish", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = publishPolicy(id, { effectiveDate: b.effectiveDate ? String(b.effectiveDate) : undefined, version: b.version ? String(b.version) : undefined, requiresAck: b.requiresAck !== false, userId: req.user.UserID, userName: req.user.DisplayName || req.user.Email }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "policy_publish", resourceType: "POLICY", resourceKey: String(id), detail: b.version ? `v${b.version}` : "", ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/policy-management/policy/:id/retire
router.post("/policy-management/policy/:id/retire", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const ok = retirePolicy(id, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "policy_retire", resourceType: "POLICY", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/policy-management/policy/:id/acknowledge — the current user accepts the policy.
router.post("/policy-management/policy/:id/acknowledge", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const out = acknowledgePolicy(id, { userId: req.user.UserID, email: req.user.Email, name: req.user.DisplayName || req.user.Email, ip: clientIp(req), method: "app" }, ten(req));
  if (!out) return void res.status(404).json({ error: "policy not found or not published" });
  if (!out.already) xid.addAudit({ userId: req.user.UserID ?? null, action: "policy_acknowledge", resourceType: "POLICY", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true, already: out.already });
});

// GET /api/policy-management/policy/:id/acceptance — coverage detail (who acknowledged, who is pending)
router.get("/policy-management/policy/:id/acceptance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const out = policyAcceptanceDetail(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

// ── Version history ──────────────────────────────────────────────────────────
// GET /api/policy-management/policy/:id/versions — the version history list
router.get("/policy-management/policy/:id/versions", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  res.json({ versions: policyVersions(Number(req.params.id), ten(req)) });
});

// GET /api/policy-management/version/:vid — one historical version's full content
router.get("/policy-management/version/:vid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const out = policyVersionDetail(Number(req.params.vid), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

// POST /api/policy-management/policy/:id/snapshot { changeNote? } — manually snapshot the current version
router.post("/policy-management/policy/:id/snapshot", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const note = String((req.body || {}).changeNote ?? "").slice(0, 500);
  const out = snapshotPolicyVersion(id, { changeNote: note || "Manual snapshot", userId: req.user.UserID, userName: req.user.DisplayName || req.user.Email }, ten(req));
  if (!out) return void res.status(404).json({ error: "not found or version already snapshotted" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "policy_snapshot", resourceType: "POLICY", resourceKey: String(id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// POST /api/policy-management/policy/:id/restore { versionId } — restore a prior version as a new draft
router.post("/policy-management/policy/:id/restore", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  const versionId = Number((req.body || {}).versionId);
  if (!Number.isFinite(versionId)) return void res.status(400).json({ error: "versionId required" });
  const ok = restorePolicyVersion(id, versionId, { userId: req.user.UserID, userName: req.user.DisplayName || req.user.Email }, ten(req));
  if (!ok) return void res.status(404).json({ error: "policy or version not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "policy_restore_version", resourceType: "POLICY", resourceKey: String(id), detail: `version ${versionId}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// ── Legal review & validation trail (POLICY + DOCUMENT) ───────────────────────
const who = (req: Request) => ({ id: req.user!.UserID ?? null, name: String(req.user!.DisplayName || req.user!.Email || "") });
const validTarget = (t: string) => (TARGET_TYPES as readonly string[]).includes(t);

// GET /api/policy-management/legal-reviews?type=policy&id=123 — a target's legal/validation trail
router.get("/policy-management/legal-reviews", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canRead(req)) return void res.status(403).json({ error: "forbidden" });
  const type = String(req.query.type || ""), id = Number(req.query.id);
  if (!validTarget(type) || !Number.isInteger(id)) return void res.status(400).json({ error: "valid type + id required" });
  res.json(listReviews(type, id, ten(req)));
});

// POST /api/policy-management/legal-reviews { type, id, reviewType, status, legalBasis?, jurisdiction?, versionReviewed?, reviewerName?, comments?, validUntil? }
router.post("/policy-management/legal-reviews", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const b = req.body || {};
  const out = addReview(String(b.type || ""), Number(b.id), ten(req), b, who(req));
  if ("error" in out) return void res.status(400).json(out);
  xid.addAudit({ userId: req.user.UserID ?? null, action: "legal_review_add", resourceType: b.type === "document" ? "DOCUMENT" : "POLICY", resourceKey: String(b.id), detail: `${b.reviewType}:${b.status || "requested"}`, ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

// POST /api/policy-management/legal-reviews/:rid { status?, comments?, ... } — update a review's outcome
router.post("/policy-management/legal-reviews/:rid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const out = updateReview(Number(req.params.rid), ten(req), req.body || {}, who(req));
  if (!out.ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "legal_review_update", resourceType: "LEGALREVIEW", resourceKey: String(req.params.rid), detail: String((req.body || {}).status || ""), ip: clientIp(req) });
  res.json(out);
});

// DELETE /api/policy-management/legal-reviews/:rid
router.delete("/policy-management/legal-reviews/:rid", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!canWrite(req)) return void res.status(403).json({ error: "forbidden" });
  const out = removeReview(Number(req.params.rid), ten(req));
  if (!out.ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "legal_review_remove", resourceType: "LEGALREVIEW", resourceKey: String(req.params.rid), ip: clientIp(req) });
  res.json(out);
});

export default router;
