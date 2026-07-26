/**
 * threatbrief.ts — "Morning Threat Intelligence" briefing (/threat-brief).
 *
 * A single-screen morning briefing (inspired by threatwake.com) that consolidates the panels a
 * security team scans over coffee, entirely from XORCISM data + a handful of free public feeds:
 *
 *   • Top Vulnerabilities — newest CISA KEV entries (live catalog, enriched with our local EPSS /
 *     CVSS / exploit signal) + recent high-severity CVEs ranked by EPSS (from XVULNERABILITY).
 *   • Ransomware — recent victims (ransomware.live), "N in last 24h · top group".
 *   • Botnet C2 — active command-and-control (abuse.ch Feodo Tracker): malware families +
 *     top source countries + the freshest C2 nodes.
 *   • Security News + Cloud Security — headlines from the THREATFEED RSS/Atom feeds (reusing
 *     feeds.ts), split into cloud-vendor advisories vs general security news.
 *
 * All external URLs are server-side constants (never client input) → no SSRF. Every panel is
 * fetched with Promise.allSettled + an in-memory TTL cache, so a slow/unreachable feed degrades
 * to an empty panel instead of breaking the briefing. The vulnerability panels are pure local
 * SQL and always render.
 */
import { getDb } from "./db";
import { listThreatFeeds, fetchFeedItems, FeedItem } from "./feeds";

const UA = "Mozilla/5.0 (XORCISM morning-threat-intel)";

// ── generic cached async fetch ──────────────────────────────────────────────────
interface CacheEntry { ts: number; val: unknown }
const CACHE = new Map<string, CacheEntry>();
async function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const c = CACHE.get(key);
  if (c && Date.now() - c.ts < ttlMs) return c.val as T;
  const val = await fn();
  CACHE.set(key, { ts: Date.now(), val });
  return val;
}
async function getJson(url: string, timeoutMs = 15000): Promise<any> {
  const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export const severityBand = (cvss: number | null | undefined): string =>
  cvss == null ? "" : cvss >= 9 ? "CRITICAL" : cvss >= 7 ? "HIGH" : cvss >= 4 ? "MEDIUM" : "LOW";
const pct = (epss: number | null | undefined): number | null =>
  epss == null ? null : Math.round(epss * 10000) / 100; // fraction → % (2 decimals, keeps tiny EPSS visible)

// ── Top Vulnerabilities ─────────────────────────────────────────────────────────
export interface KevItem {
  cve: string; vendor: string; product: string; name: string; added: string; due: string;
  ransomware: boolean; epss: number | null; cvss: number | null; exploited: boolean;
}
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/** Newest CISA KEV entries (live catalogue) enriched with our local EPSS/CVSS/exploit signal. */
export async function kevBrief(limit = 12): Promise<{ updated: string; total: number; items: KevItem[] }> {
  const cat = await cached("kev", 30 * 60 * 1000, () => getJson(KEV_URL, 20000).catch(() => null));
  const vulns: any[] = (cat?.vulnerabilities as any[]) || [];
  if (!vulns.length) return { updated: cat?.dateReleased || "", total: 0, items: [] };
  const newest = [...vulns].sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || ""))).slice(0, limit);

  // enrich from local XVULNERABILITY (EPSS / CVSS / Exploited) in one IN() query
  const local = new Map<string, { epss: number | null; cvss: number | null; exploited: number }>();
  try {
    const ids = newest.map((v) => String(v.cveID)).filter(Boolean);
    if (ids.length) {
      const ph = ids.map(() => "?").join(",");
      const rows = getDb("XVULNERABILITY").prepare(
        `SELECT VULName cve, EPSS epss, CVSSBaseScore cvss, COALESCE(Exploited,0) exploited
         FROM VULNERABILITY WHERE VULName IN (${ph})`).all(...ids) as any[];
      for (const r of rows) local.set(String(r.cve), { epss: r.epss ?? null, cvss: r.cvss ?? null, exploited: Number(r.exploited) || 0 });
    }
  } catch { /* local enrichment is best-effort */ }

  const items: KevItem[] = newest.map((v) => {
    const l = local.get(String(v.cveID));
    const rw = String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known";
    return {
      cve: String(v.cveID || ""), vendor: String(v.vendorProject || ""), product: String(v.product || ""),
      name: String(v.vulnerabilityName || ""), added: String(v.dateAdded || ""), due: String(v.dueDate || ""),
      ransomware: rw, epss: pct(l?.epss), cvss: l?.cvss ?? null, exploited: !!(l?.exploited),
    };
  });
  return { updated: cat?.dateReleased || "", total: vulns.length, items };
}

export interface EpssItem { cve: string; severity: string; epss: number | null; cvss: number | null; published: string; kev: boolean; exploited: boolean }
/** Recent high-severity CVEs ranked by EPSS, from local XVULNERABILITY. */
export function epssBrief(limit = 15, days = 90): { items: EpssItem[] } {
  try {
    // EPSS/CVSS have mixed storage affinity (some rows TEXT, some REAL) → CAST for correct numeric ranking.
    const rows = getDb("XVULNERABILITY").prepare(
      `SELECT VULName cve, CAST(EPSS AS REAL) epss, CAST(CVSSBaseScore AS REAL) cvss, VULPublishedDate pub,
              COALESCE(KEV,0) kev, COALESCE(Exploited,0) exploited
       FROM VULNERABILITY
       WHERE EPSS IS NOT NULL AND CAST(EPSS AS REAL) > 0 AND CAST(CVSSBaseScore AS REAL) >= 7
         AND VULName LIKE 'CVE-%'
         AND VULPublishedDate >= date('now', ?)
       ORDER BY CAST(EPSS AS REAL) DESC LIMIT ?`).all(`-${days} day`, limit) as any[];
    return {
      items: rows.map((r) => ({
        cve: String(r.cve), severity: severityBand(r.cvss), epss: pct(r.epss),
        cvss: r.cvss != null ? Number(r.cvss) : null,
        published: String(r.pub || "").slice(0, 10), kev: !!Number(r.kev), exploited: !!Number(r.exploited),
      })),
    };
  } catch { return { items: [] }; }
}

// ── Ransomware · recent victims (ransomware.live) ────────────────────────────────
export interface RansomVictim { victim: string; group: string; date: string; country: string; activity: string; domain: string }
const RANSOM_URL = "https://api.ransomware.live/v2/recentvictims";

export async function ransomwareBrief(limit = 16): Promise<{ count24h: number; topGroup: string; total: number; items: RansomVictim[] }> {
  const data = await cached("ransom", 30 * 60 * 1000, () => getJson(RANSOM_URL, 15000).catch(() => null));
  const arr: any[] = Array.isArray(data) ? data : (data?.data as any[]) || [];
  if (!arr.length) return { count24h: 0, topGroup: "", total: 0, items: [] };
  const norm = arr.map((v) => ({
    victim: String(v.victim || v.post_title || "").trim(),
    group: String(v.group || v.group_name || "").trim(),
    date: String(v.discovered || v.attackdate || v.published || "").trim(),
    country: String(v.country || "").trim(),
    activity: String(v.activity || "").trim(),
    domain: String(v.domain || "").trim(),
  })).filter((v) => v.victim);
  norm.sort((a, b) => b.date.localeCompare(a.date));
  const dayAgo = Date.now() - 86400 * 1000;
  const count24h = norm.filter((v) => { const t = Date.parse(v.date); return !isNaN(t) && t >= dayAgo; }).length;
  const tally = new Map<string, number>();
  for (const v of norm) if (v.group) tally.set(v.group, (tally.get(v.group) || 0) + 1);
  const topGroup = [...tally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "";
  return { count24h, topGroup, total: norm.length, items: norm.slice(0, limit) };
}

// ── Botnet C2 (abuse.ch Feodo Tracker) ───────────────────────────────────────────
export interface C2Node { ip: string; port: number; malware: string; country: string; lastOnline: string; asn: string }
const FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";

export async function botnetBrief(limit = 14): Promise<{
  total: number; families: { name: string; count: number }[]; countries: { cc: string; count: number }[]; items: C2Node[];
}> {
  const data = await cached("feodo", 30 * 60 * 1000, () => getJson(FEODO_URL, 15000).catch(() => null));
  const arr: any[] = Array.isArray(data) ? data : [];
  if (!arr.length) return { total: 0, families: [], countries: [], items: [] };
  const fam = new Map<string, number>(), cc = new Map<string, number>();
  for (const c of arr) {
    const m = String(c.malware || "unknown"); fam.set(m, (fam.get(m) || 0) + 1);
    const k = String(c.country || "??"); cc.set(k, (cc.get(k) || 0) + 1);
  }
  const top = (m: Map<string, number>, mapKey: string) =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, count]) => ({ [mapKey]: k, count } as any));
  const items: C2Node[] = [...arr]
    .sort((a, b) => String(b.last_online || "").localeCompare(String(a.last_online || "")))
    .slice(0, limit)
    .map((c) => ({
      ip: String(c.ip_address || ""), port: Number(c.port) || 0, malware: String(c.malware || ""),
      country: String(c.country || ""), lastOnline: String(c.last_online || ""), asn: String(c.as_name || ""),
    }));
  return { total: arr.length, families: top(fam, "name"), countries: top(cc, "cc"), items };
}

// ── Security News + Cloud Security (THREATFEED) ──────────────────────────────────
export interface NewsItem { title: string; link: string; date: string; source: string; category: string }
const CLOUD_HINT = /\b(aws|amazon|azure|microsoft|google|gcp|cloud|oracle cloud|kubernetes|saas)\b/i;
const isCloud = (f: { name: string; category: string; vendor: string }): boolean =>
  CLOUD_HINT.test(f.category) || CLOUD_HINT.test(f.vendor) || CLOUD_HINT.test(f.name);

export async function newsBrief(perBucket = 14): Promise<{ news: NewsItem[]; cloud: NewsItem[] }> {
  const feeds = listThreatFeeds().filter((f) => f.enabled);
  const settled = await Promise.allSettled(feeds.map((f) => fetchFeedItems(f).then((items) => ({ f, items }))));
  const news: NewsItem[] = [], cloud: NewsItem[] = [];
  for (const s of settled) {
    if (s.status !== "fulfilled") continue;
    const { f, items } = s.value;
    const bucket = isCloud(f) ? cloud : news;
    for (const it of items as FeedItem[]) {
      bucket.push({ title: it.title, link: it.link, date: it.date, source: f.name, category: f.category || "" });
    }
  }
  const byDate = (a: NewsItem, b: NewsItem) => String(b.date).localeCompare(String(a.date));
  news.sort(byDate); cloud.sort(byDate);
  return { news: news.slice(0, perBucket), cloud: cloud.slice(0, perBucket) };
}

// ── assemble the briefing ────────────────────────────────────────────────────────
export interface ThreatBrief {
  generatedAt: string;
  kev: Awaited<ReturnType<typeof kevBrief>>;
  epss: ReturnType<typeof epssBrief>;
  ransomware: Awaited<ReturnType<typeof ransomwareBrief>>;
  botnet: Awaited<ReturnType<typeof botnetBrief>>;
  news: NewsItem[]; cloud: NewsItem[];
  kpis: { kevNew: number; epssHigh: number; ransom24h: number; c2Active: number };
}

export async function threatBrief(): Promise<ThreatBrief> {
  const epss = epssBrief();
  const [kev, ransomware, botnet, newsCloud] = await Promise.all([
    kevBrief().catch(() => ({ updated: "", total: 0, items: [] as KevItem[] })),
    ransomwareBrief().catch(() => ({ count24h: 0, topGroup: "", total: 0, items: [] as RansomVictim[] })),
    botnetBrief().catch(() => ({ total: 0, families: [], countries: [], items: [] as C2Node[] })),
    newsBrief().catch(() => ({ news: [] as NewsItem[], cloud: [] as NewsItem[] })),
  ]);
  return {
    generatedAt: new Date().toISOString(),
    kev, epss, ransomware, botnet, news: newsCloud.news, cloud: newsCloud.cloud,
    kpis: { kevNew: kev.items.length, epssHigh: epss.items.length, ransom24h: ransomware.count24h, c2Active: botnet.total },
  };
}
