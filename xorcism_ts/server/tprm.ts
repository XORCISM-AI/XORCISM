/**
 * tprm.ts — Third-Party Risk Management (Panorays / Vendict style).
 *
 * A vendor (TPRMVENDOR) carries:
 *   - inherent risk   = f(DataSensitivity, BusinessCriticality)  -> Tier
 *   - external posture = outside-in probe of the vendor's domain (DNS + TLS + security headers,
 *                        SSRF-guarded) -> PostureScore/Grade + TPRMFINDING rows (Source='external')
 *   - questionnaire conformance = from a linked QUESTIONNAIRERUN (the AI-CAIQ / OCIL run)
 *   - residual risk   = inherent reduced by the control strength (posture + conformance) -> ResidualTier
 *   - review cadence  = NextReviewDate from the tier-based cadence
 * AI support (Vendict) lives in aiassist.ts (vendor brief, questionnaire review, auto-draft answers).
 */
import { randomUUID } from "crypto";
import { lookup } from "dns/promises";
import net from "net";
import tls from "tls";
import https from "https";
import { allocId, getDb } from "./db";

const TIERS = ["Low", "Medium", "High", "Critical"] as const;
const SEV_WEIGHT: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const DATA_W: Record<string, number> = { none: 0, internal: 25, confidential: 50, pii: 75, phi: 85, regulated: 100, restricted: 100 };
const CRIT_W: Record<string, number> = { low: 25, medium: 50, high: 75, critical: 100 };
const CADENCE: Record<string, number> = { Critical: 90, High: 180, Medium: 365, Low: 730 };

const now = () => new Date().toISOString();
function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function tw(tenant: number | null): string { return tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : ""; }
const wkey = (s: string) => String(s || "").toLowerCase().replace(/[^a-z]/g, "");

// ── scoring ──────────────────────────────────────────────────────────────────
export function inherentRisk(data?: string, crit?: string): number {
  const d = DATA_W[wkey(data || "")] ?? 25;
  const c = CRIT_W[wkey(crit || "")] ?? 50;
  return Math.round(0.5 * d + 0.5 * c);
}
export function tierOf(score: number): typeof TIERS[number] {
  return score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";
}
export function gradeOf(posture: number): string {
  return posture >= 90 ? "A" : posture >= 80 ? "B" : posture >= 70 ? "C" : posture >= 55 ? "D" : "F";
}
/** Residual = inherent reduced by control strength (avg of posture & conformance, when available). */
export function residualRisk(inherent: number, posture: number | null, conformance: number | null): number {
  const parts = [posture, conformance].filter((x): x is number => x != null && Number.isFinite(x));
  if (!parts.length) return inherent;
  const strength = parts.reduce((a, b) => a + b, 0) / parts.length; // 0..100 (higher = better)
  return Math.round(inherent * (1 - (strength / 100) * 0.7)); // controls mitigate up to 70%
}

// ── SSRF-guarded external host validation ───────────────────────────────────────
function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
    if (p[0] >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    if (x === "::1" || x === "::") return true;
    if (x.startsWith("fc") || x.startsWith("fd") || x.startsWith("fe80")) return true;
    if (x.startsWith("::ffff:")) return isPrivateIp(x.slice(7));
    return false;
  }
  return true;
}
export function normalizeDomain(domain: string): string {
  return String(domain || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
}
async function safeHost(domain: string): Promise<{ host: string; ip: string } | { error: string }> {
  const host = normalizeDomain(domain);
  if (!host || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host) || host.length > 253) return { error: "invalid domain" };
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan")) return { error: "blocked host" };
  try {
    const addrs = await lookup(host, { all: true });
    if (!addrs.length) return { error: "DNS: no address" };
    for (const a of addrs) if (isPrivateIp(a.address)) return { error: "resolves to a private/reserved IP (blocked)" };
    return { host, ip: addrs[0].address };
  } catch { return { error: "DNS resolution failed" }; }
}

interface ProbeIssue { category: string; title: string; detail: string; severity: string }
/** Safe outside-in probe: TLS certificate + security headers. Never throws. */
async function probeDomain(host: string): Promise<{ issues: ProbeIssue[]; ok: boolean }> {
  const issues: ProbeIssue[] = [];
  // 1) TLS certificate
  const tlsRes = await new Promise<{ ok: boolean }>((resolve) => {
    let done = false;
    const sock = tls.connect({ host, port: 443, servername: host, timeout: 7000, rejectUnauthorized: false }, () => {
      if (done) return; done = true;
      try {
        const cert = sock.getPeerCertificate();
        const authorized = (sock as any).authorized;
        if (!authorized) issues.push({ category: "TLS", title: "Untrusted TLS certificate", detail: String((sock as any).authorizationError || "certificate not trusted"), severity: "high" });
        if (cert && cert.valid_to) {
          const days = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
          if (days < 0) issues.push({ category: "TLS", title: "TLS certificate expired", detail: `expired ${-days} day(s) ago (${cert.valid_to})`, severity: "high" });
          else if (days <= 30) issues.push({ category: "TLS", title: "TLS certificate expiring soon", detail: `expires in ${days} day(s) (${cert.valid_to})`, severity: "medium" });
          else issues.push({ category: "TLS", title: "TLS certificate valid", detail: `valid until ${cert.valid_to}${cert.issuer && cert.issuer.O ? ` (issuer: ${cert.issuer.O})` : ""}`, severity: "info" });
        }
      } catch { /* ignore */ }
      sock.end(); resolve({ ok: true });
    });
    sock.on("error", () => { if (done) return; done = true; issues.push({ category: "TLS", title: "TLS handshake failed", detail: "could not establish a TLS connection on port 443", severity: "high" }); resolve({ ok: false }); });
    sock.on("timeout", () => { if (done) return; done = true; sock.destroy(); issues.push({ category: "TLS", title: "TLS connection timed out", detail: "no response on port 443 within 7s", severity: "medium" }); resolve({ ok: false }); });
  });
  // 2) Security headers (GET /, no redirect follow)
  await new Promise<void>((resolve) => {
    const req = https.get({ host, port: 443, path: "/", servername: host, timeout: 7000, rejectUnauthorized: false, headers: { "User-Agent": "XORCISM-TPRM/1.0" } }, (res) => {
      const h = res.headers;
      const want: [string, string, string, string][] = [
        ["strict-transport-security", "Missing HSTS header", "no Strict-Transport-Security — connections can be downgraded", "medium"],
        ["content-security-policy", "Missing Content-Security-Policy", "no CSP — increased XSS/exfiltration exposure", "low"],
        ["x-frame-options", "Missing X-Frame-Options", "no clickjacking protection (X-Frame-Options/CSP frame-ancestors)", "low"],
        ["x-content-type-options", "Missing X-Content-Type-Options", "no nosniff — MIME-type confusion risk", "low"],
      ];
      for (const [hdr, title, detail, sev] of want) if (!h[hdr]) issues.push({ category: "Headers", title, detail, severity: sev });
      if (h["server"]) issues.push({ category: "Disclosure", title: "Server software disclosed", detail: `Server: ${h["server"]}`, severity: "info" });
      res.resume(); resolve();
    });
    req.on("error", () => resolve());
    req.on("timeout", () => { req.destroy(); resolve(); });
  });
  return { issues, ok: tlsRes.ok };
}

// ── findings ──────────────────────────────────────────────────────────────────
function insertFinding(vendorId: number, f: ProbeIssue & { source?: string }, tenant: number | null): void {
  const db = getDb("XCOMPLIANCE"); const fc = cols("TPRMFINDING");
  const id = allocId(db, "TPRMFINDING", "FindingID");
  const rec: Record<string, unknown> = {
    FindingID: id, FindingGUID: randomUUID(), VendorID: vendorId, Source: f.source || "external",
    Category: f.category, Title: f.title, Detail: f.detail, Severity: (f.severity || "info").toLowerCase(),
    Status: "open", CreatedDate: now(), TenantID: tenant,
  };
  const keys = Object.keys(rec).filter((k) => fc.has(k));
  db.prepare(`INSERT INTO TPRMFINDING (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
}
function vendorFindings(vendorId: number): Record<string, any>[] {
  return getDb("XCOMPLIANCE").prepare("SELECT * FROM TPRMFINDING WHERE VendorID = ? ORDER BY FindingID DESC").all(vendorId) as Record<string, any>[];
}
function postureFromFindings(vendorId: number): number {
  const open = vendorFindings(vendorId).filter((f) => String(f.Status) === "open" && (f.Source === "external" || f.Source === "breach"));
  let score = 100;
  for (const f of open) score -= (SEV_WEIGHT[String(f.Severity || "info").toLowerCase()] ?? 0);
  return Math.max(0, Math.min(100, score));
}

export function addFinding(vendorId: number, p: { source?: string; category?: string; title: string; detail?: string; severity?: string; evidence?: string }, tenant: number | null): boolean {
  if (!getVendorRow(vendorId, tenant)) return false;
  insertFinding(vendorId, { source: p.source || "manual", category: p.category || "General", title: p.title, detail: p.detail || "", severity: p.severity || "medium" }, tenant);
  recompute(vendorId, tenant);
  return true;
}
export function updateFinding(findingId: number, patch: { status?: string; severity?: string }, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT FindingID, VendorID FROM TPRMFINDING WHERE FindingID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [findingId, tenant] : [findingId])) as { FindingID: number; VendorID: number } | undefined;
  if (!row) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (patch.status && ["open", "accepted", "remediated", "false-positive"].includes(patch.status)) { sets.push("Status = ?"); vals.push(patch.status); }
  if (patch.severity && SEV_WEIGHT[patch.severity.toLowerCase()] != null) { sets.push("Severity = ?"); vals.push(patch.severity.toLowerCase()); }
  if (sets.length) { vals.push(findingId); db.prepare(`UPDATE TPRMFINDING SET ${sets.join(", ")} WHERE FindingID = ?`).run(...vals); recompute(row.VendorID, tenant); }
  return true;
}

// ── vendor read/recompute ──────────────────────────────────────────────────────
function getVendorRow(id: number, tenant: number | null): Record<string, any> | undefined {
  return getDb("XCOMPLIANCE").prepare(`SELECT * FROM TPRMVENDOR WHERE VendorID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`)
    .get(...(tenant != null ? [id, tenant] : [id])) as Record<string, any> | undefined;
}
/** Pull conformance from the linked questionnaire run (if any). */
function runConformance(runId: number | null | undefined): number | null {
  if (!runId) return null;
  try {
    const r = getDb("XCOMPLIANCE").prepare("SELECT Conformance, Score FROM QUESTIONNAIRERUN WHERE RunID = ?").get(runId) as { Conformance: number | null; Score: number | null } | undefined;
    if (!r) return null;
    return r.Conformance != null ? Number(r.Conformance) : null;
  } catch { return null; }
}

/** Recompute inherent/tier/posture/conformance/residual/cadence and persist. */
export function recompute(id: number, tenant: number | null): void {
  const db = getDb("XCOMPLIANCE");
  const v = getVendorRow(id, tenant);
  if (!v) return;
  const inherent = inherentRisk(v.DataSensitivity, v.BusinessCriticality);
  const tier = tierOf(inherent);
  const posture = vendorFindings(id).some((f) => f.Source === "external") ? postureFromFindings(id) : (v.PostureScore != null ? Number(v.PostureScore) : null);
  const conf = runConformance(v.QuestionnaireRunID) ?? (v.QuestionnaireConformance != null ? Number(v.QuestionnaireConformance) : null);
  const residual = residualRisk(inherent, posture, conf);
  const cadence = Number(v.ReviewCadenceDays) || CADENCE[tier] || 365;
  const last = v.LastAssessedDate || now().slice(0, 10);
  const next = new Date(new Date(last).getTime() + cadence * 86400000).toISOString().slice(0, 10);
  db.prepare(`UPDATE TPRMVENDOR SET InherentRisk=?, Tier=?, PostureScore=?, PostureGrade=?, QuestionnaireConformance=?, ResidualRisk=?, ResidualTier=?, ReviewCadenceDays=?, NextReviewDate=? WHERE VendorID=?`)
    .run(inherent, tier, posture, posture != null ? gradeOf(posture) : null, conf, residual, tierOf(residual), cadence, next, id);
}

function shapeVendor(v: Record<string, any>): Record<string, any> {
  const today = now().slice(0, 10);
  return {
    id: Number(v.VendorID), name: String(v.Name ?? ""), domain: String(v.Domain ?? ""), category: String(v.Category ?? ""),
    services: String(v.ServicesProvided ?? ""), owner: String(v.Owner ?? ""), contactEmail: String(v.ContactEmail ?? ""),
    status: String(v.Status ?? "onboarding"), tier: String(v.Tier ?? ""),
    dataSensitivity: String(v.DataSensitivity ?? ""), businessCriticality: String(v.BusinessCriticality ?? ""),
    usesAI: !!Number(v.UsesAI), aiUse: String(v.AIUseDescription ?? ""),
    inherentRisk: v.InherentRisk != null ? Number(v.InherentRisk) : null,
    postureScore: v.PostureScore != null ? Number(v.PostureScore) : null, postureGrade: String(v.PostureGrade ?? ""),
    questionnaireRunId: v.QuestionnaireRunID != null ? Number(v.QuestionnaireRunID) : null,
    conformance: v.QuestionnaireConformance != null ? Number(v.QuestionnaireConformance) : null,
    residualRisk: v.ResidualRisk != null ? Number(v.ResidualRisk) : null, residualTier: String(v.ResidualTier ?? ""),
    lastAssessed: v.LastAssessedDate ? String(v.LastAssessedDate).slice(0, 10) : "",
    nextReview: v.NextReviewDate ? String(v.NextReviewDate).slice(0, 10) : "",
    reviewCadenceDays: v.ReviewCadenceDays != null ? Number(v.ReviewCadenceDays) : null,
    overdue: !!(v.NextReviewDate && String(v.NextReviewDate).slice(0, 10) < today),
  };
}

export function getVendor(id: number, tenant: number | null): { vendor: any; findings: any[]; run: any } | null {
  const v = getVendorRow(id, tenant);
  if (!v) return null;
  const findings = vendorFindings(id).map((f) => ({
    id: Number(f.FindingID), source: String(f.Source ?? ""), category: String(f.Category ?? ""),
    title: String(f.Title ?? ""), detail: String(f.Detail ?? ""), severity: String(f.Severity ?? "info"),
    status: String(f.Status ?? "open"), createdDate: f.CreatedDate ? String(f.CreatedDate).slice(0, 10) : "",
  }));
  let run: any = null;
  if (v.QuestionnaireRunID) {
    try { run = getDb("XCOMPLIANCE").prepare("SELECT RunID id, QuestionnaireName name, Status status, Conformance conformance, Score completion FROM QUESTIONNAIRERUN WHERE RunID = ?").get(v.QuestionnaireRunID); } catch { /* gone */ }
  }
  return { vendor: shapeVendor(v), findings, run };
}

// ── dashboard ──────────────────────────────────────────────────────────────────
export function tprmDashboard(tenant: number | null): { vendors: any[]; questionnaireRuns: any[]; summary: any } {
  const db = getDb("XCOMPLIANCE");
  let vendors: any[] = [];
  try {
    const rows = db.prepare(`SELECT * FROM TPRMVENDOR ${tw(tenant)} ORDER BY COALESCE(ResidualRisk,InherentRisk,0) DESC, VendorID DESC`).all() as Record<string, any>[];
    const openByVendor = new Map<number, number>();
    try { for (const r of db.prepare("SELECT VendorID, COUNT(*) c FROM TPRMFINDING WHERE Status='open' GROUP BY VendorID").all() as { VendorID: number; c: number }[]) openByVendor.set(Number(r.VendorID), Number(r.c)); } catch { /* none */ }
    vendors = rows.map((v) => ({ ...shapeVendor(v), openFindings: openByVendor.get(Number(v.VendorID)) || 0 }));
  } catch { vendors = []; }
  // questionnaire runs available to link (from the runner)
  let runs: any[] = [];
  try {
    runs = (db.prepare(`SELECT RunID id, Name name, QuestionnaireName questionnaire, Subject subject, Conformance conformance, Status status FROM QUESTIONNAIRERUN ${tw(tenant)} ORDER BY RunID DESC LIMIT 200`).all() as Record<string, any>[])
      .map((r) => ({ id: Number(r.id), name: String(r.name ?? ""), questionnaire: String(r.questionnaire ?? ""), subject: String(r.subject ?? ""), conformance: r.conformance != null ? Number(r.conformance) : null, status: String(r.status ?? "") }));
  } catch { runs = []; }
  const active = vendors.filter((v) => v.status !== "terminated" && v.status !== "offboarding");
  const summary = {
    vendors: vendors.length,
    critical: vendors.filter((v) => v.residualTier === "Critical" || v.tier === "Critical").length,
    usingAI: vendors.filter((v) => v.usesAI).length,
    overdue: vendors.filter((v) => v.overdue).length,
    openFindings: vendors.reduce((s, v) => s + (v.openFindings || 0), 0),
    avgResidual: active.length ? Math.round(active.reduce((s, v) => s + (v.residualRisk ?? v.inherentRisk ?? 0), 0) / active.length) : 0,
    avgPosture: (() => { const p = vendors.map((v) => v.postureScore).filter((x) => x != null); return p.length ? Math.round(p.reduce((a, b) => a + b, 0) / p.length) : null; })(),
    assessed: vendors.filter((v) => v.postureScore != null || v.conformance != null).length,
  };
  return { vendors, questionnaireRuns: runs, summary };
}

// ── create / mutate ──────────────────────────────────────────────────────────
export function createVendor(p: Record<string, any>, tenant: number | null, createdBy?: string): { id: number } {
  const db = getDb("XCOMPLIANCE"); const vc = cols("TPRMVENDOR");
  const id = allocId(db, "TPRMVENDOR", "VendorID");
  const inherent = inherentRisk(p.dataSensitivity, p.businessCriticality);
  const tier = tierOf(inherent);
  const rec: Record<string, unknown> = {
    VendorID: id, VendorGUID: randomUUID(), Name: String(p.name || "Vendor").slice(0, 200),
    Domain: normalizeDomain(p.domain || ""), Description: String(p.description || "").slice(0, 2000),
    Category: String(p.category || "").slice(0, 120), ServicesProvided: String(p.services || "").slice(0, 1000),
    ContactName: String(p.contactName || "").slice(0, 200), ContactEmail: String(p.contactEmail || "").slice(0, 200),
    Owner: String(p.owner || "").slice(0, 200), Tier: tier,
    DataSensitivity: String(p.dataSensitivity || "Confidential"), BusinessCriticality: String(p.businessCriticality || "Medium"),
    Status: String(p.status || "onboarding"), UsesAI: p.usesAI ? 1 : 0, AIUseDescription: String(p.aiUse || "").slice(0, 2000),
    InherentRisk: inherent, ResidualRisk: inherent, ResidualTier: tier, ReviewCadenceDays: CADENCE[tier] || 365,
    LastAssessedDate: now().slice(0, 10), TenantID: tenant, CreatedBy: createdBy ?? null, CreatedDate: now(),
  };
  const keys = Object.keys(rec).filter((k) => vc.has(k));
  db.prepare(`INSERT INTO TPRMVENDOR (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  recompute(id, tenant);
  return { id };
}

export function updateVendor(id: number, p: Record<string, any>, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const v = getVendorRow(id, tenant); if (!v) return false;
  const map: [string, string][] = [
    ["name", "Name"], ["domain", "Domain"], ["description", "Description"], ["category", "Category"], ["services", "ServicesProvided"],
    ["contactName", "ContactName"], ["contactEmail", "ContactEmail"], ["owner", "Owner"], ["status", "Status"],
    ["dataSensitivity", "DataSensitivity"], ["businessCriticality", "BusinessCriticality"], ["aiUse", "AIUseDescription"],
  ];
  const sets: string[] = []; const vals: unknown[] = [];
  for (const [k, col] of map) if (p[k] !== undefined) { sets.push(`${col} = ?`); vals.push(col === "Domain" ? normalizeDomain(String(p[k])) : String(p[k]).slice(0, 2000)); }
  if (p.usesAI !== undefined) { sets.push("UsesAI = ?"); vals.push(p.usesAI ? 1 : 0); }
  if (p.reviewCadenceDays !== undefined && Number.isFinite(Number(p.reviewCadenceDays))) { sets.push("ReviewCadenceDays = ?"); vals.push(Number(p.reviewCadenceDays)); }
  if (sets.length) { vals.push(id); db.prepare(`UPDATE TPRMVENDOR SET ${sets.join(", ")} WHERE VendorID = ?`).run(...vals); }
  recompute(id, tenant);
  return true;
}

export function deleteVendor(id: number, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  if (!getVendorRow(id, tenant)) return false;
  db.prepare("DELETE FROM TPRMFINDING WHERE VendorID = ?").run(id);
  db.prepare("DELETE FROM TPRMVENDOR WHERE VendorID = ?").run(id);
  return true;
}

/** Link a questionnaire run as this vendor's security questionnaire. */
export function linkRun(id: number, runId: number | null, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  if (!getVendorRow(id, tenant)) return false;
  db.prepare("UPDATE TPRMVENDOR SET QuestionnaireRunID = ? WHERE VendorID = ?").run(runId, id);
  recompute(id, tenant);
  return true;
}

/** Run the outside-in posture assessment: clears prior external findings, probes, rescore. */
export async function assessPosture(id: number, tenant: number | null): Promise<{ ok: boolean; error?: string; posture?: number; grade?: string; findings?: number }> {
  const db = getDb("XCOMPLIANCE");
  const v = getVendorRow(id, tenant);
  if (!v) return { ok: false, error: "not found" };
  if (!v.Domain) return { ok: false, error: "vendor has no domain to assess" };
  const safe = await safeHost(String(v.Domain));
  // clear prior external findings (re-assessment)
  db.prepare("DELETE FROM TPRMFINDING WHERE VendorID = ? AND Source = 'external'").run(id);
  if ("error" in safe) {
    insertFinding(id, { category: "Reachability", title: "External assessment could not run", detail: safe.error, severity: "medium", source: "external" }, tenant);
    db.prepare("UPDATE TPRMVENDOR SET LastAssessedDate = ? WHERE VendorID = ?").run(now().slice(0, 10), id);
    recompute(id, tenant);
    return { ok: false, error: safe.error };
  }
  const { issues } = await probeDomain(safe.host);
  for (const iss of issues) insertFinding(id, { ...iss, source: "external" }, tenant);
  db.prepare("UPDATE TPRMVENDOR SET LastAssessedDate = ? WHERE VendorID = ?").run(now().slice(0, 10), id);
  recompute(id, tenant);
  const after = getVendorRow(id, tenant)!;
  return { ok: true, posture: Number(after.PostureScore), grade: String(after.PostureGrade), findings: issues.filter((i) => i.severity !== "info").length };
}

// ── demo seed (tenant 3) ───────────────────────────────────────────────────────
export function seedTprmDemo(tenant: number): void {
  try {
    const db = getDb("XCOMPLIANCE");
    if (!cols("TPRMVENDOR").size) return;
    const has = db.prepare("SELECT 1 FROM TPRMVENDOR WHERE TenantID = ? LIMIT 1").get(tenant);
    if (has) return; // idempotent
    const demo: Record<string, any>[] = [
      { name: "Aurora LLM Cloud", domain: "aurora-llm.example", category: "AI / Model provider", services: "Hosted LLM inference API for the support copilot", owner: "TPRM Lead", dataSensitivity: "PII", businessCriticality: "High", usesAI: 1, aiUse: "Processes customer support transcripts through a hosted LLM; retains prompts for 30 days.", status: "active", posture: 72, conf: 64, findings: [["external", "Headers", "Missing HSTS header", "no Strict-Transport-Security", "medium"], ["questionnaire", "Data", "No data-deletion SLA for prompts", "vendor could not commit to a prompt-deletion timeframe", "high"]] },
      { name: "Northwind Payments", domain: "northwind-pay.example", category: "Payments", services: "Card processing gateway", owner: "GRC Lead", dataSensitivity: "Regulated", businessCriticality: "Critical", usesAI: 0, status: "active", posture: 88, conf: 81, findings: [["external", "TLS", "TLS certificate valid", "valid until 2027-01-04 (issuer: DigiCert)", "info"]] },
      { name: "Helios Analytics", domain: "helios-analytics.example", category: "Analytics", services: "Product usage analytics", owner: "Data Lead", dataSensitivity: "Confidential", businessCriticality: "Medium", usesAI: 1, aiUse: "Uses ML to score user engagement; no PII sent.", status: "review", posture: 61, conf: null, findings: [["external", "Headers", "Missing Content-Security-Policy", "no CSP", "low"], ["external", "Disclosure", "Server software disclosed", "Server: nginx/1.18.0", "info"]] },
      { name: "Quill Docs SaaS", domain: "quill-docs.example", category: "Productivity", services: "Document collaboration", owner: "IT Lead", dataSensitivity: "Internal", businessCriticality: "Low", usesAI: 0, status: "onboarding", posture: null, conf: null, findings: [] },
    ];
    for (const d of demo) {
      const { id } = createVendor(d, tenant, "demo-seed");
      const vc = cols("TPRMVENDOR");
      const sets: string[] = []; const vals: unknown[] = [];
      if (d.posture != null && vc.has("PostureScore")) { sets.push("PostureScore = ?", "PostureGrade = ?"); vals.push(d.posture, gradeOf(d.posture)); }
      if (d.conf != null && vc.has("QuestionnaireConformance")) { sets.push("QuestionnaireConformance = ?"); vals.push(d.conf); }
      if (d.status && vc.has("Status")) { sets.push("Status = ?"); vals.push(d.status); }
      if (sets.length) { vals.push(id); db.prepare(`UPDATE TPRMVENDOR SET ${sets.join(", ")} WHERE VendorID = ?`).run(...vals); }
      for (const [src, cat, title, detail, sev] of d.findings as string[][]) insertFinding(id, { source: src, category: cat, title, detail, severity: sev }, tenant);
      recompute(id, tenant);
    }
  } catch { /* best-effort demo */ }
}
