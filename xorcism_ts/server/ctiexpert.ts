/**
 * ctiexpert.ts — CTI-Expert: AI-orchestrated OSINT / threat-intelligence investigation.
 *
 * Port of the cti-expert skill (github.com/7onez/cti-expert — a Claude-Code OSINT-analyst skill,
 * 67+ commands / 36+ techniques, 4 phases Acquire→Enrich→Assess→Deliver, A–F source-reliability
 * grading, 0–100 exposure scoring, STIX 2.1 IOC export) to XORCISM **using the local AI** (Ollama,
 * see ai.ts ctiInvestigate). The collectors cti-expert wraps (sherlock/maigret/holehe/theHarvester/
 * subfinder…) are already XORCISM connectors; this module adds the analyst + methodology layer:
 * a target → an investigation plan (techniques mapped to those connectors) → an AI-graded INTSUM
 * (findings, reliability, severity, exposure score, recommendations) → persisted STIX observables
 * (XTHREAT.OBSERVABLE) + an INTELEXCHANGE intel entry. Surfaced at /cti-expert.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { ctiInvestigate, type CtiInvestigationResult } from "./ai";

const now = (): string => new Date().toISOString();
const today = (): string => new Date().toISOString().slice(0, 10);

export type TargetKind = "domain" | "email" | "username" | "ip" | "person" | "org" | "phone" | "crypto";
const KINDS: TargetKind[] = ["domain", "email", "username", "ip", "person", "org", "phone", "crypto"];

/** cti-expert technique catalogue (representative of its 36 techniques), each mapped to the
 * XORCISM connector that performs the collection and the CTI phase it belongs to. */
export interface Technique { id: string; name: string; phase: "Acquire" | "Enrich" | "Assess" | "Deliver"; kinds: TargetKind[]; connector?: string }
export const TECHNIQUES: Technique[] = [
  // ── Acquire ──
  { id: "subdomain", name: "Subdomain enumeration (cert transparency)", phase: "Acquire", kinds: ["domain", "org"], connector: "subfinder" },
  { id: "dns", name: "DNS forensics & records", phase: "Acquire", kinds: ["domain", "ip"], connector: "dnsx" },
  { id: "whois", name: "WHOIS / reverse-WHOIS", phase: "Acquire", kinds: ["domain", "ip"], connector: "whois" },
  { id: "fingerprint", name: "CMS/CDN/analytics fingerprinting", phase: "Acquire", kinds: ["domain"], connector: "whatweb" },
  { id: "infra", name: "Host & service exposure", phase: "Acquire", kinds: ["domain", "ip"], connector: "shodan" },
  { id: "username", name: "Username enumeration (3000+ sites)", phase: "Acquire", kinds: ["username", "person"], connector: "sherlock" },
  { id: "maigret", name: "Account profiling", phase: "Acquire", kinds: ["username", "person"], connector: "maigret" },
  { id: "email-acct", name: "Email account discovery", phase: "Acquire", kinds: ["email"], connector: "holehe" },
  { id: "harvester", name: "Email/host harvesting", phase: "Acquire", kinds: ["domain", "org", "email"], connector: "theharvester" },
  { id: "breach", name: "Breach & paste-site search", phase: "Acquire", kinds: ["email", "username", "domain"], connector: "h8mail" },
  { id: "github", name: "GitHub developer footprint", phase: "Acquire", kinds: ["username", "org", "person"], connector: "github-osint" },
  { id: "phone", name: "Phone carrier & reputation", phase: "Acquire", kinds: ["phone"], connector: "phoneinfoga" },
  { id: "crypto", name: "Blockchain / wallet tracing", phase: "Acquire", kinds: ["crypto"] },
  { id: "people", name: "Person lookup (50+ data points)", phase: "Acquire", kinds: ["person", "email"] },
  { id: "image", name: "Reverse-image & geolocation", phase: "Acquire", kinds: ["person"] },
  { id: "x-osint", name: "X-OSINT all-in-one (phone/email/subdomain)", phase: "Acquire", kinds: ["phone", "email", "domain", "username"], connector: "x-osint" },
  { id: "vin", name: "VIN / vehicle-identification OSINT", phase: "Acquire", kinds: ["person", "org"], connector: "x-osint" },
  { id: "email-from-name", name: "Email discovery from a name", phase: "Acquire", kinds: ["person", "org"], connector: "x-osint" },
  { id: "drp", name: "Digital Risk Protection sweep (NADAR-CTI, 8 OSINT sources)", phase: "Acquire", kinds: ["domain", "org"], connector: "nadar-cti" },
  // ── Enrich ──
  { id: "crossref", name: "Cross-reference & pivot", phase: "Enrich", kinds: KINDS },
  { id: "link", name: "Link subjects / entity resolution", phase: "Enrich", kinds: KINDS },
  { id: "graph", name: "Relationship graph", phase: "Enrich", kinds: KINDS, connector: "osint-graph" },
  { id: "threat-check", name: "IOC reputation (CTI/threat-feed)", phase: "Enrich", kinds: ["domain", "ip", "email"], connector: "misp" },
  { id: "huntio", name: "C2 & malicious-infrastructure enrichment (Hunt.io)", phase: "Enrich", kinds: ["ip", "domain"], connector: "hunt-io" },
  { id: "leak-monitor", name: "Credential-leak, breach & ransomware-mention monitoring", phase: "Enrich", kinds: ["domain", "org", "email"], connector: "nadar-cti" },
  // ── Assess ──
  { id: "exposure", name: "Exposure risk scoring (0–100)", phase: "Assess", kinds: KINDS },
  { id: "threat-model", name: "Threat modeling", phase: "Assess", kinds: KINDS },
  { id: "validate", name: "Finding validation (A–F reliability)", phase: "Assess", kinds: KINDS },
  { id: "coverage", name: "Coverage gap check", phase: "Assess", kinds: KINDS },
  // ── Deliver ──
  { id: "intsum", name: "Technical INTSUM report", phase: "Deliver", kinds: KINDS },
  { id: "brief", name: "Executive summary", phase: "Deliver", kinds: KINDS },
  { id: "stix", name: "STIX 2.1 IOC export", phase: "Deliver", kinds: KINDS },
  { id: "workspace", name: "Case / workspace save", phase: "Deliver", kinds: KINDS },
];

/** Heuristic target-type detection. */
export function detectKind(target: string): TargetKind {
  const t = (target || "").trim();
  if (/^https?:\/\//i.test(t)) return "domain";
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(t)) return "email";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t) || /:[0-9a-f]*:/i.test(t)) return "ip";
  if (/^\+?\d[\d\s().-]{6,}$/.test(t)) return "phone";
  if (/^(0x[a-f0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,})$/i.test(t)) return "crypto";
  if (/^[a-z0-9-]+(\.[a-z]{2,})+$/i.test(t)) return "domain";
  if (/\s/.test(t)) return "person";
  return "username";
}

export function planFor(kind: TargetKind): Technique[] {
  return TECHNIQUES.filter((tq) => tq.kinds.includes(kind));
}

export function ensureCtiExpertTables(): void {
  const db = getDb("XTHREAT");
  db.exec(`
    CREATE TABLE IF NOT EXISTS CTIINVESTIGATION (
      InvestigationID INTEGER PRIMARY KEY,
      InvestigationGUID TEXT, Target TEXT, TargetKind TEXT, Status TEXT DEFAULT 'complete',
      ExposureScore INTEGER, Severity TEXT, Summary TEXT, Brief TEXT,
      PlanJSON TEXT, FindingsJSON TEXT, ObservablesJSON TEXT, Recommendations TEXT,
      AttackTags TEXT, Model TEXT, Offline INTEGER DEFAULT 0,
      IntelID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_ctiinv_target ON CTIINVESTIGATION(Target);
    CREATE INDEX IF NOT EXISTS ix_ctiinv_tenant ON CTIINVESTIGATION(TenantID);
  `);
}

/** What XORCISM already knows about the target (fed to the AI as enrichment context). */
function buildTargetContext(target: string): string {
  const out: string[] = [];
  try {
    const xt = getDb("XTHREAT");
    const obs = xt.prepare(
      "SELECT ObservableType, Value, Score FROM OBSERVABLE WHERE Value LIKE ? LIMIT 8"
    ).all(`%${target}%`) as { ObservableType: string; Value: string; Score: number }[];
    if (obs.length) out.push("Known observables:\n" + obs.map((o) => `- ${o.ObservableType}: ${o.Value}${o.Score != null ? ` (score ${o.Score})` : ""}`).join("\n"));
    const intel = xt.prepare(
      "SELECT IntelName, IntelSource FROM INTELEXCHANGE WHERE IntelName LIKE ? OR IntelDescription LIKE ? LIMIT 5"
    ).all(`%${target}%`, `%${target}%`) as { IntelName: string; IntelSource: string }[];
    if (intel.length) out.push("Related CTI:\n" + intel.map((i) => `- ${i.IntelName} (${i.IntelSource || "?"})`).join("\n"));
  } catch { /* best-effort */ }
  try {
    const asset = getDb("XORCISM").prepare(
      "SELECT AssetName FROM ASSET WHERE AssetName LIKE ? LIMIT 5"
    ).all(`%${target}%`) as { AssetName: string }[];
    if (asset.length) out.push("Matching assets in inventory:\n" + asset.map((a) => `- ${a.AssetName}`).join("\n"));
  } catch { /* best-effort */ }
  return out.join("\n\n");
}

const STIX_TYPE: Record<string, string> = {
  domain: "domain-name", email: "email-addr", ip: "ipv4-addr", username: "user-account",
  url: "url", "domain-name": "domain-name", "email-addr": "email-addr", hash: "file", phone: "user-account",
};

/** Persist the investigation: STIX observables → OBSERVABLE, an INTSUM → INTELEXCHANGE, the case → CTIINVESTIGATION. */
function persist(target: string, kind: TargetKind, plan: Technique[], r: CtiInvestigationResult, tenant: number | null): { id: number; intelId: number; observables: number } {
  const xt = getDb("XTHREAT");
  // 1) observables (idempotent by Value+Type)
  let obsCount = 0;
  const obsIns = xt.prepare(
    `INSERT INTO OBSERVABLE (ObservableID, ObservableGUID, StixID, ObservableType, Value, Description, Labels, Score, CreatedByRef, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  );
  for (const o of r.observables) {
    const type = STIX_TYPE[o.type] || o.type || "x-osint";
    const existing = xt.prepare("SELECT ObservableID FROM OBSERVABLE WHERE Value=? AND ObservableType=? LIMIT 1").get(o.value, type) as { ObservableID: number } | undefined;
    if (existing) continue;
    const id = (allocId(xt, "OBSERVABLE", "ObservableID"));
    obsIns.run(id, randomUUID(), `${type}--${randomUUID()}`, type, o.value, `CTI-Expert: ${kind} ${target}`, "cti-expert,osint", r.exposureScore, "cti-expert", now());
    obsCount++;
  }
  // 2) INTSUM → INTELEXCHANGE (idempotent by IntelReference)
  const ref = `cti-expert:${kind}:${target}`;
  let intelId = (xt.prepare("SELECT IntelID FROM INTELEXCHANGE WHERE IntelReference=? LIMIT 1").get(ref) as { IntelID: number } | undefined)?.IntelID ?? 0;
  const intelName = `OSINT INTSUM — ${target} (${r.severity}, ${r.exposureScore}/100)`;
  if (intelId) {
    xt.prepare("UPDATE INTELEXCHANGE SET IntelName=?, IntelDescription=?, AttackTags=?, IntelDate=? WHERE IntelID=?")
      .run(intelName, r.brief, r.attackTags.join(", "), today(), intelId);
  } else {
    intelId = (allocId(xt, "INTELEXCHANGE", "IntelID"));
    xt.prepare(
      `INSERT INTO INTELEXCHANGE (IntelID, IntelGUID, IntelName, IntelDescription, CreatedDate, IntelReference, IntelSource, IntelAuthor, IntelDate, AttackTags, IntelTags, Views)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,0)`
    ).run(intelId, randomUUID(), intelName, r.brief, now(), ref, "CTI-Expert", r.model, today(), r.attackTags.join(", "), "osint,cti-expert,intsum");
  }
  // 3) the case → CTIINVESTIGATION (idempotent by target+kind+tenant)
  const dupe = xt.prepare("SELECT InvestigationID FROM CTIINVESTIGATION WHERE Target=? AND TargetKind=? AND IFNULL(TenantID,0)=IFNULL(?,0) LIMIT 1").get(target, kind, tenant) as { InvestigationID: number } | undefined;
  const fields = [
    target, kind, r.exposureScore, r.severity, r.summary, r.brief,
    JSON.stringify(plan.map((p) => ({ id: p.id, name: p.name, phase: p.phase, connector: p.connector }))),
    JSON.stringify(r.findings), JSON.stringify(r.observables), JSON.stringify(r.recommendations),
    r.attackTags.join(", "), r.model, r.offline ? 1 : 0, intelId,
  ];
  let id: number;
  if (dupe) {
    id = dupe.InvestigationID;
    xt.prepare(
      `UPDATE CTIINVESTIGATION SET Target=?, TargetKind=?, ExposureScore=?, Severity=?, Summary=?, Brief=?,
        PlanJSON=?, FindingsJSON=?, ObservablesJSON=?, Recommendations=?, AttackTags=?, Model=?, Offline=?, IntelID=?, CreatedDate=? WHERE InvestigationID=?`
    ).run(...fields, now(), id);
  } else {
    id = (allocId(xt, "CTIINVESTIGATION", "InvestigationID"));
    xt.prepare(
      `INSERT INTO CTIINVESTIGATION (InvestigationID, InvestigationGUID, Target, TargetKind, ExposureScore, Severity, Summary, Brief,
        PlanJSON, FindingsJSON, ObservablesJSON, Recommendations, AttackTags, Model, Offline, IntelID, CreatedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(id, randomUUID(), ...fields, now(), tenant);
  }
  return { id, intelId, observables: obsCount };
}

/** Run an investigation against a target (auto-detects kind if not given), persist, and return it. */
export async function runInvestigation(target: string, kind: TargetKind | undefined, tenant: number | null): Promise<any> {
  const t = (target || "").trim();
  if (!t) throw new Error("target required");
  const k = (kind && KINDS.includes(kind)) ? kind : detectKind(t);
  const plan = planFor(k);
  const context = buildTargetContext(t);
  const result = await ctiInvestigate(t, k, plan, context);
  ensureCtiExpertTables();
  const saved = persist(t, k, plan, result, tenant);
  return { ...saved, target: t, kind: k, plan, ...result };
}

function row(r: any): any {
  return {
    id: r.InvestigationID, target: r.Target, kind: r.TargetKind, exposureScore: r.ExposureScore,
    severity: r.Severity, summary: r.Summary, brief: r.Brief, model: r.Model, offline: !!r.Offline,
    intelId: r.IntelID, createdDate: r.CreatedDate,
    plan: safeJson(r.PlanJSON, []), findings: safeJson(r.FindingsJSON, []),
    observables: safeJson(r.ObservablesJSON, []),
    recommendations: safeJson(r.Recommendations, []),
    attackTags: (r.AttackTags || "").split(",").map((s: string) => s.trim()).filter(Boolean),
  };
}
function safeJson<T>(s: string, dflt: T): T { try { return JSON.parse(s || ""); } catch { return dflt; } }

export function listInvestigations(tenant: number | null, limit = 100): any[] {
  ensureCtiExpertTables();
  const db = getDb("XTHREAT");
  const rows = db.prepare(
    `SELECT * FROM CTIINVESTIGATION WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY CreatedDate DESC LIMIT ?`
  ).all(tenant, limit) as any[];
  return rows.map(row);
}

export function getInvestigation(id: number, tenant: number | null): any | null {
  ensureCtiExpertTables();
  const r = getDb("XTHREAT").prepare(
    "SELECT * FROM CTIINVESTIGATION WHERE InvestigationID=? AND (TenantID = ? OR TenantID IS NULL)"
  ).get(id, tenant) as any;
  return r ? row(r) : null;
}

export function ctiExpertDashboard(tenant: number | null): any {
  const list = listInvestigations(tenant, 500);
  const bySeverity: Record<string, number> = { CRITICAL: 0, HIGH: 0, NOTABLE: 0, MINOR: 0 };
  const byKind: Record<string, number> = {};
  let scoreSum = 0, obs = 0;
  for (const i of list) {
    bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1;
    byKind[i.kind] = (byKind[i.kind] || 0) + 1;
    scoreSum += i.exposureScore || 0; obs += (i.observables || []).length;
  }
  const phases = ["Acquire", "Enrich", "Assess", "Deliver"].map((p) => ({ phase: p, techniques: TECHNIQUES.filter((t) => t.phase === p).length }));
  return {
    summary: {
      investigations: list.length, avgExposure: list.length ? Math.round(scoreSum / list.length) : 0,
      observables: obs, critical: bySeverity.CRITICAL, high: bySeverity.HIGH,
      techniques: TECHNIQUES.length, kinds: KINDS.length,
    },
    bySeverity, byKind, phases, kinds: KINDS,
    techniqueCatalogue: TECHNIQUES,
    recent: list.slice(0, 25),
  };
}
