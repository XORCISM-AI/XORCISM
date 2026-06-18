/**
 * feeds.ts — shared CTI RSS/Atom fetch + parse for the THREATFEED feeds, plus the
 * recurring poller that turns new feed items into XTHREAT.THREATREPORT entries.
 *
 * The parser is dependency-free (regex). Feed URLs always come from THREATFEED
 * (never the client) → no SSRF. Parsed items are cached in memory (10 min).
 */
import { randomUUID } from "crypto";
import { getDb, extractCves, getActiveWatchlist, watchTermMatches, createNotification, getActivePirs, pirMatches } from "./db";
import * as xid from "./xid";

export interface FeedRow {
  id: number; name: string; url: string; site: string;
  description: string; category: string; vendor: string; enabled: number;
}
export interface FeedItem { title: string; link: string; date: string; summary: string }

const UA = "Mozilla/5.0 (XORCISM threat-feeds reader)";
const TTL = 10 * 60 * 1000;
const cache = new Map<number, { items: FeedItem[]; ts: number }>();

const FEED_COLS =
  "SELECT ThreatFeedID id, ThreatFeedName name, FeedURL url, COALESCE(SiteURL,'') site, " +
  "COALESCE(ThreatFeedDescription,'') description, COALESCE(Category,'') category, COALESCE(Vendor,'') vendor, " +
  "COALESCE(Enabled,1) enabled FROM THREATFEED";

function nowTs(): string { return new Date().toISOString().slice(0, 19).replace("T", " "); }

export function listThreatFeeds(): FeedRow[] {
  return getDb("XTHREAT").prepare(FEED_COLS + " ORDER BY Enabled DESC, ThreatFeedName COLLATE NOCASE").all() as FeedRow[];
}
export function getThreatFeed(id: number): FeedRow | undefined {
  return getDb("XTHREAT").prepare(FEED_COLS + " WHERE ThreatFeedID=?").get(id) as FeedRow | undefined;
}
function enabledThreatFeeds(): FeedRow[] {
  return getDb("XTHREAT").prepare(FEED_COLS + " WHERE COALESCE(Enabled,1)=1 ORDER BY ThreatFeedName").all() as FeedRow[];
}

// ── Minimal, defensive RSS/Atom parser ───────────────────────────────────────
function unescape(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ""; } })
    .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(Number(d)); } catch { return ""; } })
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}
function stripTags(s: string): string { return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(); }
function tagText(block: string, name: string): string {
  const m = block.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, "i"));
  return m ? m[1] : "";
}
function toIso(s: string): string {
  const v = unescape(s).trim();
  if (!v) return "";
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toISOString();
}
export function parseFeed(xml: string, limit: number): FeedItem[] {
  const out: FeedItem[] = [];
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
  for (const b of blocks) {
    if (out.length >= limit) break;
    const title = unescape(tagText(b, "title")).trim();
    let link = unescape(tagText(b, "link")).trim();
    if (!link || link.startsWith("<")) {
      const m = b.match(/<link\b[^>]*href=["']([^"']+)["']/i);
      if (m) link = m[1];
    }
    const rawDate = tagText(b, "pubDate") || tagText(b, "published") || tagText(b, "updated")
      || tagText(b, "dc:date") || tagText(b, "date");
    const desc = stripTags(unescape(
      tagText(b, "description") || tagText(b, "summary") || tagText(b, "content:encoded") || tagText(b, "content")));
    if (!title && !link) continue;
    out.push({ title: title || "(untitled)", link, date: toIso(rawDate), summary: desc.slice(0, 280) });
  }
  return out;
}

export async function fetchFeedItems(feed: FeedRow): Promise<FeedItem[]> {
  const c = cache.get(feed.id);
  if (c && Date.now() - c.ts < TTL) return c.items;
  const r = await fetch(feed.url, {
    headers: { "User-Agent": UA, Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*" },
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const items = parseFeed(await r.text(), 40);
  cache.set(feed.id, { items, ts: Date.now() });
  return items;
}
export function cachedItems(id: number): FeedItem[] | undefined { return cache.get(id)?.items; }

// ── Feed → THREATREPORT poller ───────────────────────────────────────────────
export interface PollResult { feeds: number; fetched: number; checked: number; created: number; alerts?: number }

/**
 * Fetches the enabled feeds and creates a THREATREPORT for each new item (idempotent
 * by ThreatReportReference = the article URL). Bounded to recent items so the first
 * run doesn't backfill the whole archive.
 */
export async function pollFeedsToThreatReports(opts?: { maxAgeDays?: number; perFeed?: number }): Promise<PollResult> {
  const maxAgeDays = opts?.maxAgeDays ?? Number(process.env.XORCISM_FEED_MAX_AGE_DAYS || 7);
  const perFeed = opts?.perFeed ?? 12;
  const cutoff = Date.now() - maxAgeDays * 86400 * 1000;

  const feeds = enabledThreatFeeds();
  const settled = await Promise.allSettled(feeds.map((f) => fetchFeedItems(f).then((items) => ({ f, items }))));

  const xt = getDb("XTHREAT");
  const exists = xt.prepare("SELECT 1 FROM THREATREPORT WHERE ThreatReportReference = ? LIMIT 1");
  const trCols = new Set((xt.prepare(`PRAGMA table_info("THREATREPORT")`).all() as { name: string }[]).map((c) => c.name));
  const hasCve = trCols.has("CveTags");
  const ins = xt.prepare(
    hasCve
      ? `INSERT INTO THREATREPORT (ThreatReportID, ThreatReportGUID, ThreatReportName, ThreatReportDescription,
           CreatedDate, ThreatReportSource, ThreatReportReference, CveTags) VALUES (?,?,?,?,?,?,?,?)`
      : `INSERT INTO THREATREPORT (ThreatReportID, ThreatReportGUID, ThreatReportName, ThreatReportDescription,
           CreatedDate, ThreatReportSource, ThreatReportReference) VALUES (?,?,?,?,?,?,?)`
  );
  // Reports created this sweep — used for watchlist alerting after the transaction.
  const createdReports: { id: number; title: string; text: string; ref: string; cves: string[] }[] = [];

  const candidates: { ref: string; item: FeedItem; feed: FeedRow }[] = [];
  let fetched = 0, checked = 0;
  for (const s of settled) {
    if (s.status !== "fulfilled") continue;
    fetched++;
    const { f, items } = s.value;
    let n = 0;
    for (const it of items) {
      if (n >= perFeed) break;
      const ref = (it.link || `${f.name}::${it.title}`).slice(0, 500);
      if (!ref) continue;
      const t = it.date ? Date.parse(it.date) : NaN;
      if (!isNaN(t) && t < cutoff) continue; // too old
      n++; checked++;
      candidates.push({ ref, item: it, feed: f });
    }
  }

  let created = 0;
  let maxId = (xt.prepare("SELECT COALESCE(MAX(ThreatReportID),0) AS m FROM THREATREPORT").get() as { m: number }).m;
  const tx = xt.transaction(() => {
    for (const c of candidates) {
      if (exists.get(c.ref)) continue;
      maxId++;
      const t = c.item.date ? Date.parse(c.item.date) : NaN;
      const created_at = isNaN(t) ? nowTs() : new Date(t).toISOString().slice(0, 19).replace("T", " ");
      const title = (c.item.title || "(untitled)").slice(0, 250);
      const desc = `${c.item.summary || ""}\n\nSource: ${c.feed.name}${c.item.link ? ` — ${c.item.link}` : ""}`.trim().slice(0, 8000);
      const cves = extractCves(`${title}\n${desc}`);
      if (hasCve) ins.run(maxId, randomUUID(), title, desc, created_at, c.feed.name.slice(0, 200), c.ref, cves.join(",") || null);
      else ins.run(maxId, randomUUID(), title, desc, created_at, c.feed.name.slice(0, 200), c.ref);
      createdReports.push({ id: maxId, title, text: `${title}\n${desc}`, ref: c.ref, cves });
      created++;
    }
  });
  tx();

  // Watchlist alerting: notify each term's owner when a new report matches (best-effort).
  let alerts = 0;
  try {
    const watch = getActiveWatchlist();
    if (watch.length && createdReports.length) {
      for (const rep of createdReports) {
        for (const term of watch) {
          if (!term.UserID) continue;
          if (watchTermMatches(term, rep.text, rep.cves)) {
            createNotification({
              userId: term.UserID,
              title: `Watchlist hit: ${term.Term}`.slice(0, 200),
              message: rep.title,
              level: "warning",
              link: rep.ref,
              source: "watchlist",
              tenantId: term.TenantID ?? null,
            });
            alerts++;
          }
        }
      }
    }
  } catch (e) {
    console.warn(`[feeds] watchlist alerting error: ${(e as Error)?.message || e}`);
  }

  // PIR alerting: notify the requirement owner when new reporting matches a PIR keyword.
  alerts += notifyPirMatches(createdReports);
  return { feeds: feeds.length, fetched, checked, created, alerts };
}

/** Resolve a PIR owner (PERSON) to a platform user, matching on email. */
function resolvePirOwner(personId: number | null): number | null {
  if (!personId) return null;
  try {
    const xo = getDb("XORCISM");
    const cols = new Set((xo.prepare(`PRAGMA table_info("PERSON")`).all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("email")) return null;
    const row = xo.prepare(`SELECT email FROM PERSON WHERE PersonID = ?`).get(personId) as { email?: string } | undefined;
    const email = (row?.email || "").trim();
    if (!email) return null;
    const u = xid.findUserByEmail(email);
    return u ? u.UserID : null;
  } catch { return null; }
}

/** Notify each PIR's owner when a newly-collected report matches one of its keywords. */
export function notifyPirMatches(reports: { text: string; title: string; ref: string | null }[]): number {
  let alerts = 0;
  try {
    const pirs = getActivePirs();
    if (!pirs.length || !reports.length) return 0;
    const ownerCache = new Map<number, number | null>(); // PersonID → UserID (resolved once per poll)
    for (const rep of reports) {
      for (const pir of pirs) {
        if (!pirMatches(pir.Keywords, rep.text)) continue;
        const pid = pir.PersonID ?? 0;
        let uid = ownerCache.get(pid);
        if (uid === undefined) { uid = resolvePirOwner(pir.PersonID); ownerCache.set(pid, uid); }
        if (!uid) continue; // owner isn't a platform user → no one to notify in-app
        createNotification({
          userId: uid,
          title: `PIR hit: ${pir.PIRName}`.slice(0, 200),
          message: rep.title,
          level: "warning",
          link: rep.ref,
          source: "pir",
          tenantId: pir.TenantID ?? null,
        });
        alerts++;
      }
    }
  } catch (e) {
    console.warn(`[feeds] PIR alerting error: ${(e as Error)?.message || e}`);
  }
  return alerts;
}

let pollTimer: NodeJS.Timeout | null = null;

/** Starts the recurring feed → THREATREPORT poller (env XORCISM_FEED_POLL_MIN, default 30; <=0 disables). */
export function startThreatFeedPoller(): void {
  if (pollTimer) return;
  const min = Number(process.env.XORCISM_FEED_POLL_MIN ?? 30);
  if (!Number.isFinite(min) || min <= 0) {
    console.log("[feeds] THREATREPORT poller disabled (XORCISM_FEED_POLL_MIN <= 0)");
    return;
  }
  const tick = (): void => {
    pollFeedsToThreatReports()
      .then((r) => console.log(`[feeds] poll: ${r.created} new THREATREPORT (${r.fetched}/${r.feeds} feeds, ${r.checked} items checked)`))
      .catch((e) => console.warn(`[feeds] poll error: ${(e as Error)?.message || e}`));
  };
  const first = setTimeout(tick, 60_000); // first sweep ~1 min after boot
  if (typeof first.unref === "function") first.unref();
  pollTimer = setInterval(tick, min * 60 * 1000);
  if (typeof pollTimer.unref === "function") pollTimer.unref();
  console.log(`[feeds] THREATREPORT poller started (every ${min} min)`);
}
