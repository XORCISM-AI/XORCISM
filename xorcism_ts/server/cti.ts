/**
 * cti.ts — "CTI that acts": cross-references live threat intelligence (CISA KEV +
 * ingested THREATREPORTs) against your asset inventory and surfaces only what affects
 * YOU — then one-click opens a ticket. Threat intel that does something, not a feed.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export interface IntelMatch {
  cve: string; kev: boolean; epss: number | null; severity: string;
  assets: { id: number; name: string }[]; reports: { id: number; name: string }[];
  reasons: string[];
}

const CVE_RX = /CVE-\d{4}-\d{3,7}/gi;
function now(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }

/** Threat intel (KEV + recent reports) cross-referenced with asset-linked vulnerabilities. */
export function intelImpact(tenant: number | null): { matches: IntelMatch[]; stats: { kev: number; reported: number; assets: number } } {
  const xo = getDb("XORCISM");
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const tcl = tenant != null && aCols.has("TenantID") ? 'AND (a."TenantID"=? OR a."TenantID" IS NULL)' : "";
  const targs = tenant != null && aCols.has("TenantID") ? [tenant] : [];
  const av = xo.prepare(
    `SELECT av.VulnerabilityID vid, a.AssetID aid, a.AssetName name
     FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID=av.AssetID
     WHERE COALESCE(av.FalsePositive,0)=0 ${tcl}`
  ).all(...targs) as { vid: number; aid: number; name: string }[];
  if (!av.length) return { matches: [], stats: { kev: 0, reported: 0, assets: 0 } };

  // vuln meta (ref/CVE, KEV, EPSS)
  const meta = new Map<number, { cve: string | null; kev: number; epss: number | null }>();
  try {
    const xv = getDb("XVULNERABILITY");
    const ids = [...new Set(av.map((r) => r.vid))];
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
      for (const m of xv.prepare(`SELECT VulnerabilityID id, COALESCE(VULReferential,VULName) ref, KEV kev, EPSS epss FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { id: number; ref: string; kev: unknown; epss: number | null }[]) {
        const cve = (String(m.ref || "").toUpperCase().match(CVE_RX) || [])[0] || null;
        meta.set(m.id, { cve, kev: Number(m.kev) || 0, epss: m.epss });
      }
    }
  } catch { /* */ }

  // group by CVE → assets + flags
  const byCve = new Map<string, { kev: boolean; epss: number | null; assets: Map<number, string> }>();
  for (const r of av) {
    const m = meta.get(r.vid); if (!m?.cve) continue;
    const e = byCve.get(m.cve) ?? byCve.set(m.cve, { kev: false, epss: null, assets: new Map() }).get(m.cve)!;
    if (m.kev) e.kev = true;
    if (m.epss != null && (e.epss == null || m.epss > e.epss)) e.epss = m.epss;
    e.assets.set(r.aid, r.name);
  }

  // reports referencing each CVE (CTI)
  const reportsByCve = new Map<string, { id: number; name: string }[]>();
  try {
    const xt = getDb("XTHREAT");
    const cves = [...byCve.keys()];
    for (const rep of xt.prepare("SELECT ThreatReportID id, ThreatReportName name, CveTags FROM THREATREPORT WHERE CveTags IS NOT NULL AND CveTags<>'' ORDER BY ThreatReportID DESC LIMIT 1000").all() as { id: number; name: string; CveTags: string }[]) {
      const tags = rep.CveTags.toUpperCase();
      for (const cve of cves) if (tags.includes(cve)) (reportsByCve.get(cve) ?? reportsByCve.set(cve, []).get(cve)!).push({ id: rep.id, name: rep.name });
    }
  } catch { /* */ }

  const matches: IntelMatch[] = [];
  for (const [cve, e] of byCve) {
    const reports = reportsByCve.get(cve) || [];
    if (!e.kev && !reports.length) continue; // only intel that *acts*
    const reasons: string[] = [];
    if (e.kev) reasons.push("CISA KEV — actively exploited in the wild");
    if (reports.length) reasons.push(`Named in ${reports.length} threat report${reports.length > 1 ? "s" : ""}`);
    if (e.epss != null && e.epss >= 0.5) reasons.push(`EPSS ${(e.epss * 100).toFixed(0)}% exploitation probability`);
    matches.push({
      cve, kev: e.kev, epss: e.epss, severity: e.kev ? "Critical" : "High",
      assets: [...e.assets.entries()].map(([id, name]) => ({ id, name })),
      reports: reports.slice(0, 5), reasons,
    });
  }
  matches.sort((a, b) => Number(b.kev) - Number(a.kev) || b.assets.length - a.assets.length || (b.epss ?? 0) - (a.epss ?? 0));
  return { matches, stats: { kev: matches.filter((m) => m.kev).length, reported: matches.filter((m) => m.reports.length).length, assets: new Set(matches.flatMap((m) => m.assets.map((a) => a.id))).size } };
}

/** Open a ticket for an intel match (XTICKET). Idempotent by CVE tag. */
export function ticketForCve(tenant: number | null, cve: string, userEmail?: string): { ticketId: number; created: boolean } {
  const xt = getDb("XTICKET");
  const m = intelImpact(tenant).matches.find((x) => x.cve === cve.toUpperCase());
  const tag = `cti:${cve.toUpperCase()}`;
  const existing = xt.prepare("SELECT TicketID FROM TICKET WHERE Tags LIKE ?").get(`%${tag}%`) as { TicketID: number } | undefined;
  if (existing) return { ticketId: existing.TicketID, created: false };
  const assetNames = (m?.assets || []).map((a) => a.name).join(", ");
  const subject = `CTI: ${cve.toUpperCase()} affects ${m?.assets.length || 0} asset(s)`;
  const desc = `${(m?.reasons || []).join("; ")}.\nAffected assets: ${assetNames || "—"}.\nAuto-opened by XORCISM CTI watch.`;
  const ticketId = allocId(xt, "TICKET", "TicketID");
  xt.prepare(
    `INSERT INTO TICKET (TicketID, TicketGUID, TicketNumber, Subject, Description, Status, Priority, Severity, TicketType, Tags, CreatedDate, UpdatedDate, RequesterEmail)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(ticketId, randomUUID(), `CTI-${ticketId}`, subject, desc, "Open", m?.kev ? "High" : "Medium", m?.kev ? "Critical" : "High", "Security", `cti,${m?.kev ? "kev," : ""}${tag}`, now(), now(), userEmail || null);
  return { ticketId, created: true };
}
