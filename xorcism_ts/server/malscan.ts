/**
 * malscan.ts — Multi-engine malware / IOC scan service (backend: XMALWARE).
 *
 * Given a hash (MD5/SHA-1/SHA-256), URL, domain, IP or a DOCUMENT blob, query several reputation
 * engines and aggregate a normalized verdict (clean / suspicious / malicious / unknown):
 *   - VirusTotal v3        (live, key: VT_API_KEY | VIRUSTOTAL_API_KEY)
 *   - Kaspersky OpenTIP    (live, key: OPENTIP_API_KEY | KASPERSKY_OPENTIP_API_KEY)
 *   - ANY.RUN TI Lookup    (live, key: ANYRUN_API_KEY)
 *   - Sucuri SiteCheck     (live, keyless — website malware / blocklist scan; url/domain only)
 *   - Mozilla HTTP Observatory (live, keyless — HTTP security-header grade A+..F; url/domain only)
 *   - Quttera ThreatSign   (pivot link to the live website scan; optional QUTTERA_API_URL/QUTTERA_API_KEY slot)
 *   - Avira                (pivot link — no public hash API; optional AVIRA_API_URL/AVIRA_API_KEY)
 *   - FortiGuard Labs      (pivot link to the threat encyclopedia / web-filter lookup)
 *   - Jotti's malware scan (pivot link — file-upload multi-scanner, no hash API)
 *
 * Engine API keys are read from the environment ONLY (never the UI), mirroring the connector model.
 * A live engine with no key, and the pivot engines, return verdict "unknown"/"unconfigured" plus a
 * deep link so an analyst can pivot to the vendor UI; the aggregate verdict derives from live
 * engines only. Results are stored in XMALWARE.MALWARESCAN (+ MALWARESCANENGINE) and can be linked
 * to a CTI observable (XTHREAT.OBSERVABLE) and to a document (XORCISM.DOCUMENT).
 */
import { createHash, randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { syncObservableById } from "./stixstore";
import { readBlob } from "./blobstore";

export type TargetType = "hash" | "url" | "domain" | "ip" | "file" | "email";
export type Verdict = "clean" | "suspicious" | "malicious" | "unknown" | "unconfigured" | "error";

export interface EngineResult {
  engine: string;
  verdict: Verdict;
  detection?: string;
  score?: number;          // 0-100 malicious confidence (engine-specific)
  positives?: number;      // engines/vendors flagging (VT-style)
  total?: number;
  category?: string;
  link?: string;           // pivot URL to the vendor UI
  live: boolean;           // true = a real API verdict, false = pivot link / unconfigured
  raw?: unknown;
}

export interface ScanResult {
  id?: number;
  guid: string;
  target: string;
  targetType: TargetType;
  md5?: string; sha1?: string; sha256?: string;
  documentId?: number | null;
  observableId?: number | null;
  verdict: Verdict;
  score: number;
  positives: number;       // live engines flagging
  total: number;           // live engines queried
  enginesQueried: number;
  enginesLive: number;
  summary: string;
  engines: EngineResult[];
}

const HEX = /^[a-f0-9]+$/i;
const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/;

function env(...names: string[]): string | undefined {
  for (const n of names) { const v = process.env[n]; if (v && v.trim()) return v.trim(); }
  return undefined;
}

/** Detect the target type when not explicitly given. */
export function detectType(raw: string): TargetType {
  const t = raw.trim();
  if (HEX.test(t) && (t.length === 32 || t.length === 40 || t.length === 64)) return "hash";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(t)) return "email"; // Have I Been Pwned breach check
  if (/^https?:\/\//i.test(t) || t.includes("/")) return "url";
  if (IPV4.test(t)) return "ip";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) return "domain";
  return "url";
}

function hashKind(h: string): "md5" | "sha1" | "sha256" | undefined {
  if (!HEX.test(h)) return undefined;
  return h.length === 32 ? "md5" : h.length === 40 ? "sha1" : h.length === 64 ? "sha256" : undefined;
}

// ── live engine adapters ───────────────────────────────────────────────────────
async function vtScan(target: string, type: TargetType, key: string): Promise<EngineResult> {
  const base = "https://www.virustotal.com/api/v3";
  let url = "", gui = "";
  if (type === "hash") { url = `${base}/files/${target}`; gui = `https://www.virustotal.com/gui/file/${target}`; }
  else if (type === "url") { const id = Buffer.from(target).toString("base64url"); url = `${base}/urls/${id}`; gui = `https://www.virustotal.com/gui/url/${id}`; }
  else if (type === "domain") { url = `${base}/domains/${target}`; gui = `https://www.virustotal.com/gui/domain/${target}`; }
  else if (type === "ip") { url = `${base}/ip_addresses/${target}`; gui = `https://www.virustotal.com/gui/ip-address/${target}`; }
  const out: EngineResult = { engine: "VirusTotal", verdict: "unknown", live: true, link: gui };
  try {
    const r = await fetch(url, { headers: { "x-apikey": key, accept: "application/json" }, signal: AbortSignal.timeout(12000) });
    if (r.status === 404) { out.verdict = "unknown"; out.detection = "not found"; return out; }
    if (!r.ok) { out.verdict = "error"; out.detection = `HTTP ${r.status}`; return out; }
    const j: any = await r.json();
    const a = j?.data?.attributes ?? {};
    const st = a.last_analysis_stats ?? {};
    const mal = Number(st.malicious || 0), sus = Number(st.suspicious || 0);
    const total = mal + sus + Number(st.harmless || 0) + Number(st.undetected || 0) + Number(st.timeout || 0);
    out.positives = mal + sus; out.total = total;
    out.detection = a?.popular_threat_classification?.suggested_threat_label || undefined;
    out.verdict = mal > 0 ? "malicious" : sus > 0 ? "suspicious" : total > 0 ? "clean" : "unknown";
    out.score = total ? Math.round(((mal + sus) / total) * 100) : (mal ? 90 : 0);
    out.raw = st;
  } catch (e) { out.verdict = "error"; out.detection = String((e as Error).message || e).slice(0, 120); }
  return out;
}

async function opentipScan(target: string, type: TargetType, key: string): Promise<EngineResult> {
  const path = type === "hash" ? "hash" : type === "url" ? "url" : type === "domain" ? "domain" : type === "ip" ? "ip" : "hash";
  const url = `https://opentip.kaspersky.com/api/v1/search/${path}?request=${encodeURIComponent(target)}`;
  const out: EngineResult = { engine: "Kaspersky OpenTIP", verdict: "unknown", live: true, link: `https://opentip.kaspersky.com/${encodeURIComponent(target)}` };
  try {
    const r = await fetch(url, { headers: { "x-api-key": key, accept: "application/json" }, signal: AbortSignal.timeout(12000) });
    if (r.status === 404) { out.verdict = "clean"; out.detection = "no detections"; return out; }
    if (!r.ok) { out.verdict = "error"; out.detection = `HTTP ${r.status}`; return out; }
    const j: any = await r.json();
    const zone = String(j?.Zone || "").toLowerCase();
    out.verdict = zone === "red" ? "malicious" : zone === "yellow" ? "suspicious" : zone === "green" ? "clean" : "unknown";
    out.score = zone === "red" ? 90 : zone === "yellow" ? 55 : zone === "green" ? 0 : 0;
    const det = (j?.FileGeneralInfo?.Categories || j?.DetectionsInfo || []) as any[];
    out.detection = Array.isArray(j?.DetectionsInfo) && j.DetectionsInfo.length ? String(j.DetectionsInfo[0]?.DetectionName || "").slice(0, 80) : undefined;
    out.raw = { Zone: j?.Zone };
  } catch (e) { out.verdict = "error"; out.detection = String((e as Error).message || e).slice(0, 120); }
  return out;
}

async function anyrunScan(target: string, type: TargetType, key: string): Promise<EngineResult> {
  // ANY.RUN TI Lookup (https://intelligence.any.run). Query DSL by hash/domain/url/ip.
  const field = type === "hash" ? (hashKind(target) || "sha256") : type === "domain" ? "domainName" : type === "ip" ? "destinationIP" : "url";
  const q = `${field}:"${target}"`;
  const url = `https://intelligence.any.run/analysis/lookup?query=${encodeURIComponent(q)}&lookupDepth=30`;
  const out: EngineResult = { engine: "ANY.RUN", verdict: "unknown", live: true, link: type === "hash" ? `https://any.run/report/${target}` : "https://intelligence.any.run/" };
  try {
    const r = await fetch(url, { headers: { Authorization: `API-Key ${key}`, accept: "application/json" }, signal: AbortSignal.timeout(12000) });
    if (r.status === 404) { out.verdict = "unknown"; out.detection = "not found"; return out; }
    if (!r.ok) { out.verdict = "error"; out.detection = `HTTP ${r.status}`; return out; }
    const j: any = await r.json();
    const summ = j?.summary ?? j ?? {};
    const tl = String(summ?.threatLevel ?? summ?.verdict ?? "").toLowerCase();
    if (tl.includes("malicious")) out.verdict = "malicious";
    else if (tl.includes("suspicious")) out.verdict = "suspicious";
    else if (tl.includes("no threat") || tl.includes("clean") || tl === "0") out.verdict = "clean";
    else out.verdict = "unknown";
    out.score = out.verdict === "malicious" ? 85 : out.verdict === "suspicious" ? 50 : 0;
    out.detection = (summ?.tags && summ.tags.length) ? String(summ.tags.slice(0, 3).join(", ")).slice(0, 80) : undefined;
    out.raw = { threatLevel: summ?.threatLevel };
  } catch (e) { out.verdict = "error"; out.detection = String((e as Error).message || e).slice(0, 120); }
  return out;
}

/**
 * Have I Been Pwned — email breach check (v3 breachedaccount). Needs HIBP_API_KEY (email/breach search
 * is key-gated). A breached email returns "suspicious" (exposed, not malware) listing the breach names;
 * 404 = clean; no key = a pivot link so the analyst can check on hibp.com.
 */
async function hibpScan(email: string, key?: string): Promise<EngineResult> {
  const gui = `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`;
  if (!key) return { engine: "Have I Been Pwned", verdict: "unconfigured", live: false, link: gui, detection: "set HIBP_API_KEY for live breach checks" };
  try {
    const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: { "hibp-api-key": key, "user-agent": "XORCISM-CTI" }, signal: AbortSignal.timeout(15000),
    });
    if (r.status === 404) return { engine: "Have I Been Pwned", verdict: "clean", live: true, link: gui, detection: "no breaches found" };
    if (!r.ok) return { engine: "Have I Been Pwned", verdict: "error", live: false, link: gui, detection: `HTTP ${r.status}${r.status === 401 ? " (invalid API key)" : r.status === 429 ? " (rate-limited)" : ""}` };
    const breaches = (await r.json().catch(() => [])) as { Name: string; PwnCount?: number; DataClasses?: string[] }[];
    const names = (breaches || []).map((b) => b.Name).filter(Boolean);
    return {
      engine: "Have I Been Pwned",
      verdict: names.length ? "suspicious" : "clean", // exposed in a breach ≠ malware → suspicious, not malicious
      live: true, link: gui, positives: names.length,
      score: names.length ? Math.min(100, 35 + names.length * 6) : 0,
      detection: names.length ? `exposed in ${names.length} breach(es): ${names.slice(0, 10).join(", ")}` : "no breaches found",
    };
  } catch (e) { return { engine: "Have I Been Pwned", verdict: "error", live: false, link: gui, detection: (e as Error).message }; }
}

// ── pivot (link-only) engines ──────────────────────────────────────────────────
function pivot(engine: string, link: string): EngineResult {
  return { engine, verdict: "unknown", live: false, link, detection: "manual lookup" };
}
function aviraResult(target: string, type: TargetType): EngineResult {
  const apiUrl = env("AVIRA_API_URL"); const key = env("AVIRA_API_KEY");
  const link = "https://www.avira.com/en/threats";
  if (!apiUrl || !key) return { ...pivot("Avira", link), verdict: "unconfigured" };
  return pivot("Avira", link); // generic adapter slot (left as pivot unless a parser is configured)
}
function fortiResult(target: string, type: TargetType): EngineResult {
  const link = type === "url" || type === "domain"
    ? `https://www.fortiguard.com/webfilter?q=${encodeURIComponent(target)}`
    : `https://www.fortiguard.com/search?q=${encodeURIComponent(target)}&engine=8`;
  return pivot("FortiGuard", link);
}
function jottiResult(): EngineResult {
  return pivot("Jotti", "https://virusscan.jotti.org/");
}

// ── website scanners (url/domain) ────────────────────────────────────────────────
/** Bare host from a url/domain target — Observatory & Sucuri want a hostname, not a full URL. */
function hostOf(target: string, type: TargetType): string {
  if (type === "url") {
    try { return new URL(/^https?:\/\//i.test(target) ? target : "https://" + target).hostname; }
    catch { /* fall through */ }
  }
  return target.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "").trim();
}

/**
 * Sucuri SiteCheck — free remote website scanner (malware, blocklist/blacklist, defacement, anomalies).
 * Keyless public JSON endpoint (rate-limited). Browser-visible content only (no server-side backdoors).
 */
async function sucuriScan(target: string, type: TargetType): Promise<EngineResult> {
  const host = hostOf(target, type);
  const gui = `https://sitecheck.sucuri.net/results/${encodeURIComponent(host)}`;
  const out: EngineResult = { engine: "Sucuri SiteCheck", verdict: "unknown", live: true, link: gui, category: "Website malware/blocklist" };
  try {
    const r = await fetch(`https://sitecheck.sucuri.net/api/v3/?scan=${encodeURIComponent(host)}`, {
      headers: { accept: "application/json", "user-agent": "Mozilla/5.0 (compatible; XORCISM/1.0)" }, signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) { out.verdict = "error"; out.detection = `HTTP ${r.status}`; return out; }
    const j: any = await r.json().catch(() => ({}));
    const countArr = (v: unknown): number => Array.isArray(v) ? v.length : (v && typeof v === "object" ? Object.values(v as object).reduce((s: number, x) => s + (Array.isArray(x) ? x.length : 0), 0) : 0);
    // blocklist/blacklist hits across the listed authorities
    const blHits = countArr(j?.blacklists) || countArr(j?.blacklist) || (Array.isArray(j?.ratings?.blacklist) ? j.ratings.blacklist.length : 0);
    // malware / security warnings (browser-visible)
    const malWarn = countArr(j?.warnings?.security) || countArr(j?.malware?.warnings) || countArr(j?.malware);
    const infected = j?.malware?.infected === true || j?.ratings?.total?.toLowerCase?.() === "warning" && malWarn > 0;
    if (infected || malWarn > 0) {
      out.verdict = infected ? "malicious" : "suspicious";
      out.positives = malWarn + blHits; out.score = infected ? 85 : 55;
      out.detection = [malWarn ? `${malWarn} security/malware warning(s)` : "", blHits ? `${blHits} blocklist hit(s)` : ""].filter(Boolean).join(" · ") || "issues found";
    } else if (blHits > 0) {
      out.verdict = "suspicious"; out.positives = blHits; out.score = 50; out.detection = `${blHits} blocklist hit(s)`;
    } else {
      out.verdict = "clean"; out.detection = "no malware or blocklist hits";
    }
    out.raw = { blacklists: blHits, warnings: malWarn };
  } catch (e) { out.verdict = "error"; out.detection = String((e as Error).message || e).slice(0, 120); }
  return out;
}

/**
 * Mozilla HTTP Observatory (MDN) — grades a site's HTTP security headers / config (A+ … F).
 * This is configuration hygiene, NOT a malware verdict: only a failing grade (F) nudges the
 * aggregate to "suspicious" (capped low); the grade is always surfaced. Keyless v2 API.
 */
async function observatoryScan(target: string, type: TargetType): Promise<EngineResult> {
  const host = hostOf(target, type);
  const gui = `https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(host)}`;
  const out: EngineResult = { engine: "Mozilla Observatory", verdict: "unknown", live: true, link: gui, category: "HTTP security headers" };
  try {
    const r = await fetch(`https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(host)}`, {
      method: "POST", headers: { accept: "application/json" }, signal: AbortSignal.timeout(25000),
    });
    if (!r.ok) { out.verdict = "error"; out.detection = `HTTP ${r.status}`; return out; }
    const j: any = await r.json().catch(() => ({}));
    if (j?.error) { out.verdict = "error"; out.detection = String(j.error).slice(0, 100); return out; }
    const grade = j?.grade ? String(j.grade) : null;
    const score = typeof j?.score === "number" ? j.score : null;
    const failed = typeof j?.tests_failed === "number" ? j.tests_failed
      : (typeof j?.tests_quantity === "number" && typeof j?.tests_passed === "number" ? j.tests_quantity - j.tests_passed : null);
    if (!grade) { out.verdict = "unknown"; out.detection = "no grade returned"; return out; }
    const letter = grade[0].toUpperCase();
    out.verdict = letter === "F" ? "suspicious" : "clean"; // headers hygiene → never "malicious"
    out.score = letter === "F" ? 35 : (letter === "D" ? 18 : 0); // posture-risk, intentionally capped
    out.detection = `grade ${grade}${score != null ? ` (${score}/100)` : ""}${failed != null ? ` · ${failed} test(s) failed` : ""}`;
    out.raw = { grade, score: j?.score };
  } catch (e) { out.verdict = "error"; out.detection = String((e as Error).message || e).slice(0, 120); }
  return out;
}

/**
 * Quttera ThreatSign — website malware detection + blocklist intelligence across 40+ authorities.
 * The live API is account-specific (ThreatSign), so this is a pivot to the public live scan by
 * default; a generic live slot activates when QUTTERA_API_URL + QUTTERA_API_KEY are set (env-only).
 */
function qutteraResult(target: string, type: TargetType): EngineResult {
  const host = hostOf(target, type);
  const link = `https://quttera.com/sitescan/${encodeURIComponent(host)}`;
  const apiUrl = env("QUTTERA_API_URL"); const key = env("QUTTERA_API_KEY");
  if (!apiUrl || !key) {
    return { engine: "Quttera ThreatSign", verdict: "unconfigured", live: false, link,
      detection: "set QUTTERA_API_URL + QUTTERA_API_KEY for live website malware scans", category: "Website malware/blocklist" };
  }
  // configurable adapter slot (ThreatSign endpoints/response are account-specific) — left as a pivot.
  return { engine: "Quttera ThreatSign", verdict: "unknown", live: false, link, category: "Website malware/blocklist" };
}

const VERDICT_RANK: Record<string, number> = { malicious: 4, suspicious: 3, clean: 1, unknown: 0, unconfigured: 0, error: 0 };

/** Query all engines for a target and aggregate. Does not persist. */
export async function runScan(target: string, typeHint?: TargetType): Promise<ScanResult> {
  const t = String(target || "").trim();
  const type: TargetType = typeHint || detectType(t);
  const guid = randomUUID();
  const md5 = type === "hash" && hashKind(t) === "md5" ? t.toLowerCase() : undefined;
  const sha1 = type === "hash" && hashKind(t) === "sha1" ? t.toLowerCase() : undefined;
  const sha256 = type === "hash" && hashKind(t) === "sha256" ? t.toLowerCase() : undefined;

  const supportsHashOnly = type === "hash";
  const jobs: Promise<EngineResult>[] = [];

  // Email targets go to Have I Been Pwned (breach exposure); the malware engines don't take emails.
  if (type === "email") {
    jobs.push(hibpScan(t, env("HIBP_API_KEY", "HAVEIBEENPWNED_API_KEY")));
    const engines = await Promise.all(jobs);
    const live = engines.filter((e) => e.live && e.verdict !== "error");
    let verdict: Verdict = "unknown";
    for (const e of live) if (VERDICT_RANK[e.verdict] > VERDICT_RANK[verdict]) verdict = e.verdict;
    const score = Math.max(0, ...engines.filter((e) => e.live).map((e) => Number(e.score || 0)));
    const breaches = engines.find((e) => e.engine === "Have I Been Pwned");
    const positives = breaches?.positives || 0;
    const summary = breaches?.live
      ? (positives ? `EXPOSED — ${positives} breach(es) for ${t}` : `CLEAN — no known breaches for ${t}`)
      : "Have I Been Pwned not configured — set HIBP_API_KEY for live email breach checks (pivot link available).";
    return { guid, target: t, targetType: type, verdict, score, positives, total: live.length, enginesQueried: engines.length, enginesLive: live.length, summary, engines };
  }

  const vtKey = env("VT_API_KEY", "VIRUSTOTAL_API_KEY");
  jobs.push(vtKey ? vtScan(t, type, vtKey) : Promise.resolve<EngineResult>({ engine: "VirusTotal", verdict: "unconfigured", live: false, link: type === "hash" ? `https://www.virustotal.com/gui/file/${t}` : "https://www.virustotal.com/gui/home/search" }));

  const opentipKey = env("OPENTIP_API_KEY", "KASPERSKY_OPENTIP_API_KEY");
  jobs.push(opentipKey ? opentipScan(t, type, opentipKey) : Promise.resolve<EngineResult>({ engine: "Kaspersky OpenTIP", verdict: "unconfigured", live: false, link: `https://opentip.kaspersky.com/${encodeURIComponent(t)}` }));

  const anyrunKey = env("ANYRUN_API_KEY");
  jobs.push(anyrunKey ? anyrunScan(t, type, anyrunKey) : Promise.resolve<EngineResult>({ engine: "ANY.RUN", verdict: "unconfigured", live: false, link: type === "hash" ? `https://any.run/report/${t}` : "https://intelligence.any.run/" }));

  // Website scanners — only meaningful for a url/domain (they fetch the live site).
  if (type === "url" || type === "domain") {
    jobs.push(sucuriScan(t, type));
    jobs.push(observatoryScan(t, type));
    jobs.push(Promise.resolve(qutteraResult(t, type)));
  }

  jobs.push(Promise.resolve(aviraResult(t, type)));
  jobs.push(Promise.resolve(fortiResult(t, type)));
  jobs.push(Promise.resolve(supportsHashOnly || type === "file" ? jottiResult() : { ...jottiResult(), detection: "file upload only" }));

  const engines = await Promise.all(jobs);

  const live = engines.filter((e) => e.live && e.verdict !== "error");
  const flagged = live.filter((e) => e.verdict === "malicious" || e.verdict === "suspicious");
  let verdict: Verdict = "unknown";
  for (const e of live) if (VERDICT_RANK[e.verdict] > VERDICT_RANK[verdict]) verdict = e.verdict;
  const score = Math.max(0, ...engines.filter((e) => e.live).map((e) => Number(e.score || 0)));
  const positives = flagged.length, total = live.length;

  const enginesLive = engines.filter((e) => e.live).length;
  const summary = total
    ? `${verdict.toUpperCase()} — ${positives}/${total} live engine(s) flagged this ${type}` + (score ? ` (confidence ${score}%)` : "")
    : `No live engine configured — set VT_API_KEY / OPENTIP_API_KEY / ANYRUN_API_KEY for live verdicts. ${engines.length} pivot link(s) available.`;

  return { guid, target: t, targetType: type, md5, sha1, sha256, verdict, score, positives, total, enginesQueried: engines.length, enginesLive, summary, engines };
}

// ── persistence ────────────────────────────────────────────────────────────────
function resolveObservableId(target: string): number | null {
  try {
    const row = getDb("XTHREAT").prepare("SELECT ObservableID FROM OBSERVABLE WHERE Value = ? LIMIT 1").get(target) as { ObservableID: number } | undefined;
    return row ? Number(row.ObservableID) : null;
  } catch { return null; }
}

/** Persist a scan + per-engine rows. Optionally links a DOCUMENT / OBSERVABLE and can create the observable. */
export function storeScan(res: ScanResult, opts: { tenant: number | null; createdBy?: string; documentId?: number | null; source?: string; trackObservable?: boolean }): number {
  const db = getDb("XMALWARE");
  const now = new Date().toISOString();
  let observableId = res.observableId ?? resolveObservableId(res.target);
  if (!observableId && opts.trackObservable) observableId = createObservable(res, opts.tenant);

  const scanId = allocId(db, "MALWARESCAN", "ScanID");
  db.prepare(`INSERT INTO MALWARESCAN (ScanID, ScanGUID, Target, TargetType, Md5, Sha1, Sha256, DocumentID, ObservableID,
      Verdict, Score, Positives, Total, EnginesQueried, EnginesLive, Summary, Source, TenantID, CreatedBy, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(scanId, res.guid, res.target, res.targetType, res.md5 ?? null, res.sha1 ?? null, res.sha256 ?? null,
      opts.documentId ?? null, observableId ?? null, res.verdict, res.score, res.positives, res.total,
      res.enginesQueried, res.enginesLive, res.summary, opts.source ?? "Manual", opts.tenant, opts.createdBy ?? null, now);

  const ins = db.prepare(`INSERT INTO MALWARESCANENGINE (EngineResultID, ScanID, Engine, Verdict, Detection, Score, Positives, Total, Category, Link, Live, Raw, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  let eid = allocId(db, "MALWARESCANENGINE", "EngineResultID");
  for (const e of res.engines) {
    ins.run(eid++, scanId, e.engine, e.verdict, e.detection ?? null, e.score ?? null, e.positives ?? null, e.total ?? null,
      e.category ?? null, e.link ?? null, e.live ? 1 : 0, e.raw != null ? JSON.stringify(e.raw).slice(0, 1000) : null, now);
  }
  return scanId;
}

/** Create a CTI observable (XTHREAT.OBSERVABLE) from a scan target so malicious IOCs are tracked. */
function createObservable(res: ScanResult, tenant: number | null): number | null {
  try {
    const db = getDb("XTHREAT");
    const obsType = res.targetType === "hash" ? "file" : res.targetType === "url" ? "url" : res.targetType === "domain" ? "domain-name" : res.targetType === "ip" ? "ipv4-addr" : "file";
    const id = allocId(db, "OBSERVABLE", "ObservableID");
    const now = new Date().toISOString();
    const score = res.verdict === "malicious" ? Math.max(70, res.score) : res.verdict === "suspicious" ? 50 : res.score;
    db.prepare(`INSERT INTO OBSERVABLE (ObservableID, ObservableGUID, ObservableType, Value, Description, Labels, Score, CreatedByRef, CreatedDate)
        VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(id, randomUUID(), obsType, res.target, `Multi-engine scan: ${res.summary}`.slice(0, 500),
        res.verdict === "malicious" ? "malicious-activity" : null, score, "malware-scan", now);
    try { syncObservableById(id); } catch { /* STIX store best-effort */ } // retain + index the IOC losslessly
    return id;
  } catch { return null; }
}

// ── document scan ────────────────────────────────────────────────────────────────
export function documentHashes(documentId: number): { md5?: string; sha1?: string; sha256?: string; name?: string; hasBlob: boolean } {
  const db = getDb("XORCISM");
  const row = db.prepare('SELECT DocumentName, "BLOB" AS blob, BlobSha256 FROM DOCUMENT WHERE DocumentID = ?').get(documentId) as { DocumentName?: string; blob?: Buffer | string; BlobSha256?: string } | undefined;
  if (!row) throw new Error("document not found");
  // bytes may live in the content-addressed store (offloaded) or still in the row's BLOB column
  let buf = row.BlobSha256 ? readBlob(row.BlobSha256) : null;
  if (!buf) {
    const blob = row.blob;
    if (blob == null || (typeof blob === "string" && blob === "")) return { name: row.DocumentName, hasBlob: false };
    buf = Buffer.isBuffer(blob) ? blob : Buffer.from(String(blob));
  }
  return {
    md5: createHash("md5").update(buf).digest("hex"),
    sha1: createHash("sha1").update(buf).digest("hex"),
    sha256: createHash("sha256").update(buf).digest("hex"),
    name: row.DocumentName, hasBlob: true,
  };
}

export async function scanDocument(documentId: number, opts: { tenant: number | null; createdBy?: string }): Promise<{ scanId: number; result: ScanResult }> {
  const h = documentHashes(documentId);
  if (!h.hasBlob || !h.sha256) throw new Error("document has no stored content (BLOB) to hash — upload the file first");
  const res = await runScan(h.sha256, "hash");
  res.md5 = h.md5; res.sha1 = h.sha1; res.sha256 = h.sha256; res.documentId = documentId;
  const scanId = storeScan(res, { tenant: opts.tenant, createdBy: opts.createdBy, documentId, source: "Document" });
  return { scanId, result: res };
}

// ── inventory / read ───────────────────────────────────────────────────────────
function tw(tenant: number | null, col = "TenantID"): string { return tenant != null ? `WHERE (${col} = ${tenant} OR ${col} IS NULL)` : ""; }

export function scanInventory(tenant: number | null): { summary: any; scans: any[]; worklist: any[]; documents: any[] } {
  const db = getDb("XMALWARE");
  const scans = db.prepare(`SELECT * FROM MALWARESCAN ${tw(tenant)} ORDER BY ScanID DESC LIMIT 200`).all() as Record<string, any>[];
  const rows = scans.map((s) => ({
    id: Number(s.ScanID), target: String(s.Target ?? ""), targetType: String(s.TargetType ?? ""),
    verdict: String(s.Verdict ?? "unknown"), score: Number(s.Score ?? 0), positives: Number(s.Positives ?? 0), total: Number(s.Total ?? 0),
    documentId: s.DocumentID != null ? Number(s.DocumentID) : null, observableId: s.ObservableID != null ? Number(s.ObservableID) : null,
    sha256: s.Sha256 || s.Md5 || s.Sha1 || null, source: String(s.Source ?? ""), date: s.CreatedDate ? String(s.CreatedDate).slice(0, 16).replace("T", " ") : "",
  }));
  const byVerdict = (v: string) => rows.filter((r) => r.verdict === v).length;
  const worklist = rows.filter((r) => r.verdict === "malicious" || r.verdict === "suspicious")
    .sort((a, b) => (b.verdict === "malicious" ? 1 : 0) - (a.verdict === "malicious" ? 1 : 0) || b.score - a.score).slice(0, 50);

  // documents (XORCISM.DOCUMENT) with their latest scan verdict
  let documents: any[] = [];
  try {
    const docs = getDb("XORCISM").prepare('SELECT DocumentID, DocumentName, Category, Classification, TLP, (CASE WHEN "BLOB" IS NULL OR "BLOB"=\'\' THEN 0 ELSE 1 END) AS hasBlob FROM DOCUMENT ORDER BY DocumentID DESC LIMIT 100').all() as Record<string, any>[];
    const lastByDoc = new Map<number, Record<string, any>>();
    for (const s of scans) if (s.DocumentID != null && !lastByDoc.has(Number(s.DocumentID))) lastByDoc.set(Number(s.DocumentID), s);
    documents = docs.map((d) => {
      const ls = lastByDoc.get(Number(d.DocumentID));
      return { id: Number(d.DocumentID), name: String(d.DocumentName ?? `Document #${d.DocumentID}`), category: String(d.Category ?? ""), classification: String(d.Classification ?? ""), tlp: String(d.TLP ?? ""), hasBlob: !!d.hasBlob, verdict: ls ? String(ls.Verdict) : null, scanId: ls ? Number(ls.ScanID) : null, scanDate: ls?.CreatedDate ? String(ls.CreatedDate).slice(0, 16).replace("T", " ") : null };
    });
  } catch { documents = []; }

  return {
    summary: {
      total: rows.length, malicious: byVerdict("malicious"), suspicious: byVerdict("suspicious"), clean: byVerdict("clean"), unknown: byVerdict("unknown"),
      documents: documents.length, documentsScanned: documents.filter((d) => d.verdict).length, documentsMalicious: documents.filter((d) => d.verdict === "malicious").length,
      enginesConfigured: configuredEngines(),
    },
    scans: rows, worklist, documents,
  };
}

export function getScan(id: number, tenant: number | null): { scan: any; engines: any[] } | null {
  const db = getDb("XMALWARE");
  const s = db.prepare(`SELECT * FROM MALWARESCAN WHERE ScanID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`).get(...(tenant != null ? [id, tenant] : [id])) as Record<string, any> | undefined;
  if (!s) return null;
  const engines = db.prepare("SELECT * FROM MALWARESCANENGINE WHERE ScanID = ? ORDER BY EngineResultID").all(id) as Record<string, any>[];
  return { scan: s, engines: engines.map((e) => ({ engine: e.Engine, verdict: e.Verdict, detection: e.Detection, score: e.Score, positives: e.Positives, total: e.Total, link: e.Link, live: !!e.Live })) };
}

/** Which engines have a live API key configured (for the UI banner). */
export function configuredEngines(): string[] {
  const out: string[] = [];
  if (env("VT_API_KEY", "VIRUSTOTAL_API_KEY")) out.push("VirusTotal");
  if (env("OPENTIP_API_KEY", "KASPERSKY_OPENTIP_API_KEY")) out.push("Kaspersky OpenTIP");
  if (env("ANYRUN_API_KEY")) out.push("ANY.RUN");
  // keyless website scanners (live for url/domain targets)
  out.push("Sucuri SiteCheck", "Mozilla Observatory");
  if (env("QUTTERA_API_URL") && env("QUTTERA_API_KEY")) out.push("Quttera ThreatSign");
  if (env("AVIRA_API_URL") && env("AVIRA_API_KEY")) out.push("Avira");
  return out;
}
