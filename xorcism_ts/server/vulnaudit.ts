/**
 * vulnaudit.ts — Vulnerability Assessment ("Vulners-style" inventory → enriched vuln report).
 *
 * The missing Vulners capability: "turn software inventories or host data into vulnerability reports"
 * (their Assessment / SBOM Analyzer / Library Audit). Paste a software inventory — OS package lists
 * (dpkg/rpm/apk), language packages (pip/npm/PURL), CPE URIs, or free `product version` lines — and
 * each component is matched against XORCISM's own enriched vulnerability store
 * (XVULNERABILITY.VULNERABILITYFORCPE, whose CPEID column holds the CPE 2.3 URI string directly) and
 * scored with CVSS, EPSS, KEV, SSVC and exploit availability (Exploit-DB) into a ranked, decision-ready
 * report (Act / Prioritise / Track). 100% offline over local data; the vulners connector augments
 * coverage / version-range precision when a Vulners API key is configured.
 */
import { getDb } from "./db";
import { exploitsForCve } from "./exploitdb";

const xv = (): ReturnType<typeof getDb> => getDb("XVULNERABILITY");
function has(db: ReturnType<typeof getDb>, t: string): boolean {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
}
function cols(db: ReturnType<typeof getDb>, t: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
}
const truthy = (v: unknown): boolean => v === 1 || v === "1" || v === true || /^(y|yes|true)$/i.test(String(v ?? ""));
const numOr = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) && v !== null && v !== "" ? n : null; };
const norm = (s: string): string => s.trim().toLowerCase().replace(/[\s]+/g, "_").replace(/[^a-z0-9._+-]/g, "");

export interface ParsedComponent { raw: string; vendor?: string; product: string; version?: string; ecosystem?: string }

/** Parse a free-form software inventory into components (best-effort, many formats). */
export function parseInventory(text: string): ParsedComponent[] {
  const out: ParsedComponent[] = [];
  const seen = new Set<string>();
  for (let line of String(text || "").split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#") || /^(Listing|Desired|Status|\|\/|=+|name\s+version)/i.test(line)) continue;
    let c: ParsedComponent | null = null;
    let m: RegExpMatchArray | null;
    if ((m = line.match(/cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]*)/i))) c = { raw: line, vendor: m[1], product: m[2], version: m[3] && m[3] !== "*" && m[3] !== "-" ? m[3] : undefined };
    else if ((m = line.match(/cpe:\/[aoh]:([^:]+):([^:]+):?([^:]*)/i))) c = { raw: line, vendor: m[1], product: m[2], version: m[3] || undefined };
    else if ((m = line.match(/^pkg:([a-z]+)\/(?:[^/@]+\/)?([^@/]+)@?([^?#]*)/i))) c = { raw: line, product: m[2], version: (m[3] || "").trim() || undefined, ecosystem: m[1] };
    else if ((m = line.match(/^ii\s+(\S+)\s+(\S+)/))) c = { raw: line, product: m[1].replace(/:.*/, ""), version: m[2] };            // dpkg -l
    else if ((m = line.match(/^([A-Za-z0-9][A-Za-z0-9._+-]*?)[-_]([0-9][^-\s]*)-[^-\s]+\.(?:x86_64|noarch|i[36]86|aarch64)/))) c = { raw: line, product: m[1], version: m[2] }; // rpm -qa
    else if ((m = line.match(/^([A-Za-z0-9._+-]+)\s*[=<>!~]=\s*([0-9][^\s;]*)/))) c = { raw: line, product: m[1], version: m[2] };  // pip name==version
    else if ((m = line.match(/^([@a-z0-9._/-]+)@([0-9][^\s]*)/i))) c = { raw: line, product: m[1].replace(/^@[^/]+\//, ""), version: m[2] }; // npm name@version
    else if ((m = line.match(/^(.+?)[\s,]+v?([0-9][0-9A-Za-z._-]*)\s*$/))) { const w = m[1].trim().split(/\s+/); c = w.length >= 2 ? { raw: line, vendor: w[0], product: w.slice(1).join("_"), version: m[2] } : { raw: line, product: w[0], version: m[2] }; } // "[vendor] product 1.2.3"
    else if (/^[A-Za-z0-9][A-Za-z0-9 ._+-]{1,60}$/.test(line)) { const w = line.trim().split(/\s+/); c = (w.length >= 2 && w.length <= 4) ? { raw: line, vendor: w[0], product: w.slice(1).join("_") } : { raw: line, product: line }; } // "[vendor] product"
    if (!c || !c.product) continue;
    c.product = norm(c.product); if (c.vendor) c.vendor = norm(c.vendor);
    if (!c.product || c.product.length < 2) continue;
    const key = `${c.vendor || ""}|${c.product}|${c.version || ""}`;
    if (seen.has(key)) continue; seen.add(key);
    out.push(c);
    if (out.length >= 400) break;
  }
  return out;
}

function cpePatterns(c: ParsedComponent): string[] {
  const p = c.product;
  const pats: string[] = [];
  if (c.vendor) pats.push(`cpe:2.3:_:${c.vendor}:${p}:%`);
  pats.push(`cpe:2.3:_:%:${p}:%`);          // vendor wildcard (one segment via %)
  pats.push(`cpe:2.3:_:${p}:${p}:%`);       // vendor==product (common)
  return [...new Set(pats)];
}

export interface AuditFinding { cve: string; cvss: number | null; epss: number | null; kev: boolean; ssvc: string | null; exploit: number; score: number; decision: "Act" | "Prioritise" | "Track"; title: string }
export interface AuditComponent { input: string; product: string; version?: string; ecosystem?: string; matched: boolean; cves: AuditFinding[]; topScore: number }
export interface AuditResult {
  components: AuditComponent[];
  summary: { components: number; matched: number; vulnerable: number; totalCves: number; kev: number; exploitable: number; act: number; prioritise: number; track: number; maxScore: number };
  note: string;
}

function scoreCve(kev: boolean, epss: number | null, cvss: number | null, ssvc: string | null, exploit: number): { score: number; decision: AuditFinding["decision"] } {
  let s = 0;
  if (kev) s += 40;
  if (epss != null) s += Math.min(30, epss * 30);
  if (cvss != null) s += Math.min(25, cvss * 2.5);
  if (exploit > 0) s += 15;
  s = Math.min(100, Math.round(s));
  const sd = String(ssvc || "").toLowerCase();
  const decision: AuditFinding["decision"] =
    (kev || /\bact\b/.test(sd) || (epss != null && epss >= 0.5 && cvss != null && cvss >= 7)) ? "Act"
      : (s >= 45 || /attend/.test(sd) || (cvss != null && cvss >= 9)) ? "Prioritise" : "Track";
  return { score: s, decision };
}

/** Assess a pasted software inventory → enriched, ranked vulnerability report. Read-only over XVULNERABILITY. */
export function assessInventory(text: string, opts: { perComponent?: number } = {}): AuditResult {
  const v = xv();
  const vc = cols(v, "VULNERABILITY");
  const perComp = Math.min(opts.perComponent || 100, 300);
  const empty: AuditResult = { components: [], summary: { components: 0, matched: 0, vulnerable: 0, totalCves: 0, kev: 0, exploitable: 0, act: 0, prioritise: 0, track: 0, maxScore: 0 }, note: "" };
  if (!vc.size || !has(v, "VULNERABILITYFORCPE")) return { ...empty, note: "Local vulnerability store unavailable." };
  const comps = parseInventory(text);
  if (!comps.length) return { ...empty, note: "No components parsed from the inventory." };

  const idCol = vc.has("VULName") ? "VULName" : "VULShortName";
  const g = (c: string): string => (vc.has(c) ? c : `NULL AS ${c}`);
  const findVids = (pats: string[]): number[] => {
    const where = pats.map(() => "CPEID LIKE ?").join(" OR ");
    return (v.prepare(`SELECT DISTINCT VulnerabilityID v FROM VULNERABILITYFORCPE WHERE ${where} LIMIT ${perComp}`).all(...pats) as { v: number }[]).map((r) => Number(r.v));
  };

  // gather all vids across components, then batch-load VULNERABILITY metadata once
  const compVids = comps.map((c) => ({ c, vids: findVids(cpePatterns(c)) }));
  const allVids = [...new Set(compVids.flatMap((x) => x.vids))];
  const meta = new Map<number, { cve: string; cvss: number | null; epss: number | null; kev: boolean; ssvc: string | null; title: string }>();
  for (let i = 0; i < allVids.length; i += 400) {
    const chunk = allVids.slice(i, i + 400); const ph = chunk.map(() => "?").join(",");
    for (const r of v.prepare(`SELECT VulnerabilityID, ${idCol} cve, ${g("CVSSBaseScore")}, ${g("EPSS")}, ${g("KEV")}, ${g("SsvcDecision")}, ${g("VULDescription")} FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as Record<string, unknown>[]) {
      meta.set(Number(r.VulnerabilityID), {
        cve: String(r.cve || `VID#${r.VulnerabilityID}`), cvss: numOr(r.CVSSBaseScore), epss: numOr(r.EPSS),
        kev: truthy(r.KEV), ssvc: r.SsvcDecision ? String(r.SsvcDecision) : null, title: String(r.VULDescription || "").slice(0, 160),
      });
    }
  }

  const components: AuditComponent[] = compVids.map(({ c, vids }) => {
    const cves: AuditFinding[] = [];
    for (const vid of vids) {
      const m = meta.get(vid); if (!m) continue;
      const exploit = /^CVE-/i.test(m.cve) ? exploitsForCve(m.cve).length : 0;
      const sc = scoreCve(m.kev, m.epss, m.cvss, m.ssvc, exploit);
      cves.push({ cve: m.cve, cvss: m.cvss, epss: m.epss, kev: m.kev, ssvc: m.ssvc, exploit, score: sc.score, decision: sc.decision, title: m.title });
    }
    cves.sort((a, b) => b.score - a.score || (b.cvss ?? 0) - (a.cvss ?? 0));
    return { input: c.raw.slice(0, 200), product: c.product, version: c.version, ecosystem: c.ecosystem, matched: cves.length > 0, cves: cves.slice(0, perComp), topScore: cves[0]?.score ?? 0 };
  });
  components.sort((a, b) => b.topScore - a.topScore || b.cves.length - a.cves.length);

  const all = components.flatMap((c) => c.cves);
  const summary = {
    components: components.length, matched: components.filter((c) => c.matched).length, vulnerable: components.filter((c) => c.cves.length).length,
    totalCves: all.length, kev: all.filter((f) => f.kev).length, exploitable: all.filter((f) => f.exploit > 0).length,
    act: all.filter((f) => f.decision === "Act").length, prioritise: all.filter((f) => f.decision === "Prioritise").length,
    track: all.filter((f) => f.decision === "Track").length, maxScore: all.reduce((m, f) => Math.max(m, f.score), 0),
  };
  return { components, summary, note: "Matched at product level against the local enriched store; version-range applicability is not evaluated offline — confirm per CVE (or configure the Vulners connector for precise version matching)." };
}
