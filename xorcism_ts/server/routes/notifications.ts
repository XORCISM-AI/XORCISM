/**
 * notifications.ts (routes) — user notifications (header bell +
 * browser notifications). Stored in XORCISM.NOTIFICATION. Mounted AFTER
 * the auth gate.
 *
 *   GET  /api/notifications            → { items, unread } of the current user
 *   POST /api/notifications/:id/read   → mark a notification as read
 *   POST /api/notifications/read-all   → mark all as read
 *   POST /api/notifications            → create (self; broadcast/other user = admin)
 */
import { Router, Request, Response } from "express";
import {
  listNotifications, unreadNotificationCount, markNotificationRead,
  markAllNotificationsRead, createNotification, notifyUsers,
} from "../db";
import * as xid from "../xid";
import { clientIp, userCan } from "../auth";
import { listRulesForUser, upsertRule, resetRule, dispatchEvent, ruleAllows, isEvent } from "../notifrules";

const router = Router();

const LEVELS = new Set(["info", "success", "warning", "error"]);

/** UserIDs in the tenant that have at least read access to a database (admins included). */
function usersWithDbReadAccess(dbName: string, tenantId: number | null): number[] {
  const out: number[] = [];
  for (const u of xid.listUsers(tenantId)) {
    if (u.IsLockedOut) continue;
    const uid = Number(u.UserID);
    if (!Number.isInteger(uid) || uid <= 0) continue;
    if (xid.isAdmin(uid)) { out.push(uid); continue; }
    const perms = xid.getEffectivePermissions(uid);
    if (perms.get(`database:${dbName}`)?.CanRead) { out.push(uid); continue; }
    for (const [k, p] of perms) {
      if (k.startsWith(`table:${dbName}.`) && p.CanRead) { out.push(uid); break; }
    }
  }
  return out;
}

// GET /api/notifications — list + unread counter of the current user
router.get("/notifications", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const limit = Math.min(Number(req.query.limit) || 30, 100);
  res.json({
    items: listNotifications(req.user.UserID, limit),
    unread: unreadNotificationCount(req.user.UserID),
  });
});

// POST /api/notifications/:id/read
router.post("/notifications/:id/read", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "id invalide" });
  const ok = markNotificationRead(req.user.UserID, id);
  res.json({ ok, unread: unreadNotificationCount(req.user.UserID) });
});

// POST /api/notifications/read-all
router.post("/notifications/read-all", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const changed = markAllNotificationsRead(req.user.UserID);
  res.json({ ok: true, changed, unread: 0 });
});

// POST /api/notifications — creates a notification.
//   target: "me" (default) | "all" | <UserID>. "all"/other user ⇒ admin required.
router.post("/notifications", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = req.body as { title?: string; message?: string; level?: string; link?: string; target?: unknown };
  const title = String(b.title || "").trim();
  if (!title) return void res.status(400).json({ error: "titre requis" });
  const level = LEVELS.has(String(b.level)) ? String(b.level) : "info";
  const message = b.message != null ? String(b.message).slice(0, 4000) : null;
  const link = b.link != null ? String(b.link).slice(0, 1000) : null;

  const target = b.target ?? "me";
  const base = { title: title.slice(0, 300), message, level, link, source: "user", tenantId: req.user.tenantId };

  // self
  if (target === "me" || target === undefined) {
    const id = createNotification({ ...base, userId: req.user.UserID });
    return void res.json({ ok: true, created: 1, id });
  }
  // broadcast / other user ⇒ admin
  if (!req.user.isAdmin) return void res.status(403).json({ error: "réservé aux administrateurs" });

  if (target === "all") {
    // super-admin: all; tenant admin: their tenant only
    const users = xid.listUsers(req.user.isSuperAdmin ? null : req.user.tenantId);
    const ids = users.map((u) => Number(u.UserID)).filter((n) => Number.isInteger(n) && n > 0);
    const created = notifyUsers(ids, base);
    xid.addAudit({ userId: req.user.UserID, action: "notify_broadcast", resourceType: "notification",
      detail: `${created} destinataires`, ip: clientIp(req) });
    return void res.json({ ok: true, created });
  }

  const uid = Number(target);
  if (!Number.isInteger(uid) || uid <= 0) return void res.status(400).json({ error: "cible invalide" });
  const id = createNotification({ ...base, userId: uid });
  xid.addAudit({ userId: req.user.UserID, action: "notify_user", resourceType: "notification",
    resourceKey: String(uid), ip: clientIp(req) });
  res.json({ ok: true, created: 1, id });
});

// ── Notification rules: which events auto-create a notification for the current user ──────────────
// GET /api/notification-rules → catalogue merged with the user's settings.
router.get("/notification-rules", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json(listRulesForUser(req.user.UserID));
});

// PUT /api/notification-rules/:eventKey { enabled?, minLevel? } → upsert the user's rule.
router.put("/notification-rules/:eventKey", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const eventKey = String(req.params.eventKey);
  if (!isEvent(eventKey)) return void res.status(404).json({ error: "unknown event" });
  const b = (req.body || {}) as { enabled?: unknown; minLevel?: unknown };
  const minLevel = b.minLevel != null && LEVELS.has(String(b.minLevel)) ? String(b.minLevel) : undefined;
  const ok = upsertRule(req.user.UserID, eventKey, { enabled: b.enabled != null ? !!b.enabled : undefined, minLevel }, req.user.tenantId ?? null);
  if (!ok) return void res.status(400).json({ error: "bad rule" });
  res.json({ ok: true, ...listRulesForUser(req.user.UserID) });
});

// DELETE /api/notification-rules/:eventKey → reset to the catalogue default.
router.delete("/notification-rules/:eventKey", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  resetRule(req.user.UserID, String(req.params.eventKey));
  res.json({ ok: true, ...listRulesForUser(req.user.UserID) });
});

// POST /api/notification-rules/test { eventKey } → fire a sample notification (forced) so the user
// can see the effect, and report whether their current rule would have allowed it.
router.post("/notification-rules/test", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const eventKey = String((req.body || {}).eventKey || "");
  if (!isEvent(eventKey)) return void res.status(404).json({ error: "unknown event" });
  const wouldNotify = ruleAllows(req.user.UserID, eventKey, "info");
  dispatchEvent(eventKey, {
    userId: req.user.UserID, tenant: req.user.tenantId ?? null, force: true,
    title: "Test notification", message: `Sample notification for the "${eventKey}" event.`, link: "/",
  });
  res.json({ ok: true, wouldNotify });
});

// POST /api/alert/notify { alertId, alertName } — broadcast a "new alert" notification
// to all users in the CURRENT tenant who have at least read access to XINCIDENT.
// Triggered from the ALERT creation form (the creator needs read on XINCIDENT.ALERT).
router.post("/alert/notify", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XINCIDENT", "ALERT"))
    return void res.status(403).json({ error: "Accès refusé" });
  const b = req.body as { alertId?: unknown; alertName?: unknown };
  const alertId = Number(b.alertId);
  const alertName = String(b.alertName ?? "").trim().slice(0, 200);
  const tenant = req.user.tenantId ?? null;

  const recipients = usersWithDbReadAccess("XINCIDENT", tenant);
  // Honor each recipient's "incident.created" notification rule (Settings → Notifications).
  const { created } = dispatchEvent("incident.created", {
    userIds: recipients, tenant,
    title: alertName ? `New alert: ${alertName}` : "New incident alert",
    message: alertName ? `A new alert "${alertName}" was created.` : "A new alert was created.",
    level: "warning",
    link: Number.isInteger(alertId) && alertId > 0
      ? `/?db=XINCIDENT&table=ALERT&filterCol=AlertID&filterVal=${alertId}`
      : "/?db=XINCIDENT&table=ALERT",
  });
  xid.addAudit({ userId: req.user.UserID, action: "alert_notify", resourceType: "table",
    resourceKey: "XINCIDENT.ALERT", detail: `alertId=${alertId} recipients=${created}`, ip: clientIp(req) });
  res.json({ ok: true, count: created });
});

export default router;
