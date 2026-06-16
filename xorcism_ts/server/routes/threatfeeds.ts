/**
 * threatfeeds.ts (routes) — curated CTI RSS feeds (XTHREAT.THREATFEED).
 * Mounted under /api after the auth gate. The server fetches/parses the feeds
 * (see server/feeds.ts); URLs come only from THREATFEED → no SSRF. Items cached.
 *
 *   GET  /api/threatfeeds            → the curated feed list
 *   GET  /api/threatfeeds/items?id=N → recent items of one feed
 *   GET  /api/threatfeeds/latest     → merged latest items across enabled feeds
 *   POST /api/threatfeeds/poll       → (admin) run the feed→THREATREPORT poll now
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import {
  listThreatFeeds, getThreatFeed, fetchFeedItems, cachedItems, pollFeedsToThreatReports, FeedItem,
} from "../feeds";

const router = Router();
const DB = "XTHREAT", TBL = "THREATFEED";

// GET /api/threatfeeds — curated feed list
router.get("/threatfeeds", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  res.json(listThreatFeeds());
});

// GET /api/threatfeeds/items?id=N&limit=15 — one feed's recent items
router.get("/threatfeeds/items", async (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const id = Number(req.query.id);
  const limit = Math.min(Math.max(Number(req.query.limit) || 15, 1), 40);
  if (!Number.isInteger(id) || id <= 0) return void res.status(400).json({ error: "id requis" });
  const feed = getThreatFeed(id);
  if (!feed) return void res.status(404).json({ error: "flux introuvable" });
  try {
    const items = await fetchFeedItems(feed);
    res.json({ feed: { id: feed.id, name: feed.name, site: feed.site }, items: items.slice(0, limit) });
  } catch (e) {
    const c = cachedItems(id);
    if (c) return void res.json({ feed: { id: feed.id, name: feed.name, site: feed.site }, items: c.slice(0, limit), stale: true });
    res.status(502).json({ error: `Flux injoignable : ${String((e as Error)?.message || e)}` });
  }
});

// GET /api/threatfeeds/latest?limit=40 — merged latest items across enabled feeds
router.get("/threatfeeds/latest", async (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const limit = Math.min(Math.max(Number(req.query.limit) || 40, 1), 80);
  const feeds = listThreatFeeds().filter((f) => f.enabled);
  const settled = await Promise.allSettled(feeds.map((f) => fetchFeedItems(f).then((items) => ({ f, items }))));
  const merged: (FeedItem & { source: string })[] = [];
  let ok = 0;
  for (const s of settled) {
    if (s.status !== "fulfilled") continue;
    ok++;
    for (const it of s.value.items.slice(0, 6)) merged.push({ ...it, source: s.value.f.name });
  }
  merged.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  res.json({ feeds: feeds.length, fetched: ok, items: merged.slice(0, limit) });
});

// POST /api/threatfeeds/poll — run the feed → THREATREPORT poll on demand (admin)
router.post("/threatfeeds/poll", async (req: Request, res: Response) => {
  if (!req.user?.isAdmin) return void res.status(403).json({ error: "Réservé aux administrateurs" });
  try {
    const r = await pollFeedsToThreatReports();
    xid.addAudit({ userId: req.user.UserID, action: "threatfeed_poll", resourceType: "table",
      resourceKey: "XTHREAT.THREATREPORT", detail: JSON.stringify(r), ip: clientIp(req) });
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(500).json({ error: String((e as Error)?.message || e) });
  }
});

export default router;
