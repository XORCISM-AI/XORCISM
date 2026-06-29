/**
 * authzgov.ts — API Authorization Governance.
 *
 * XORCISM is not an API gateway; this module lets it *inventory, assess and govern* the API gateways and
 * external authorization policy engines that protect an estate's APIs — the PEP / PDP / PAP topology of
 * NIST SP 800-207 Zero Trust, and the modern policy engines that implement it: OPA (Rego), Cedar
 * (Amazon Verified Permissions), and any AuthZEN-conformant PDP (OpenID Foundation Authorization API 1.0).
 *
 *   PEP  Policy Enforcement Point — the API gateway intercepting the request (Kong/Apigee/APIM/Envoy/…)
 *   PDP  Policy Decision Point   — the engine returning permit/deny (OPA / Cedar / AuthZEN PDP)
 *   PAP  Policy Administration   — where policies are authored (policy-as-code repo)
 *
 * Two capabilities:
 *   1) a posture ASSESSMENT scoring the authZ architecture against OWASP API Security Top 10 (the authZ
 *      classes — BOLA/BFLA/BOPLA/Broken-AuthN/Misconfig), NIST CSF 2.0 PR.AA and NIST 800-207 ZT;
 *   2) a vendor-neutral DECISION evaluator — pure request/response adapters for OPA, Cedar and AuthZEN so
 *      XORCISM can act as a PEP test harness / PDP conformance checker (deterministic; network call guarded).
 */
import { createHash, randomUUID } from "crypto";
import { getDb, createEvidence } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const tw = (tenant: number | null): string => (tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "");
const tp = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

export function ensureAuthzTables(): void {
  const db = getDb("XORCISM");
  db.exec(`
    CREATE TABLE IF NOT EXISTS AUTHZGATEWAY(
      GatewayID INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT, GatewayType TEXT,
      AuthnMethods TEXT, AuthzModel TEXT, PdpID INTEGER, BaseUrl TEXT, Environment TEXT,
      DenyByDefault INTEGER, DecisionLogging INTEGER, AssetID INTEGER, Notes TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AUTHZPDP(
      PdpID INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT, Engine TEXT, Endpoint TEXT,
      AuthzenCompliant INTEGER, Status TEXT, Notes TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AUTHZPOLICY(
      PolicyID INTEGER PRIMARY KEY AUTOINCREMENT, PdpID INTEGER, Name TEXT, Engine TEXT, Language TEXT,
      Source TEXT, ContentHash TEXT, Version TEXT, DefaultDeny INTEGER, Versioned INTEGER, Tested INTEGER,
      Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AUTHZDECISIONTEST(
      TestID INTEGER PRIMARY KEY AUTOINCREMENT, PdpID INTEGER, Engine TEXT, Subject TEXT, Action TEXT,
      Resource TEXT, Context TEXT, Decision TEXT, Expected TEXT, Pass INTEGER, RawResponse TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AUTHZSUITERUN(
      RunID INTEGER PRIMARY KEY AUTOINCREMENT, At TEXT, Engine TEXT, Endpoint TEXT, PdpID INTEGER,
      Total INTEGER, Passed INTEGER, Failed INTEGER, Errors INTEGER, Findings INTEGER, Source TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_authzgw_tn ON AUTHZGATEWAY(TenantID);
    CREATE INDEX IF NOT EXISTS ix_authzpdp_tn ON AUTHZPDP(TenantID);
    CREATE INDEX IF NOT EXISTS ix_authzsuite_tn ON AUTHZSUITERUN(TenantID, At);`);
  // legacy-table guards: columns added after the table first shipped
  try {
    const gw = new Set((db.prepare("PRAGMA table_info(AUTHZGATEWAY)").all() as { name: string }[]).map((c) => c.name));
    if (!gw.has("AssetID")) db.exec("ALTER TABLE AUTHZGATEWAY ADD COLUMN AssetID INTEGER");
    const pdp = new Set((db.prepare("PRAGMA table_info(AUTHZPDP)").all() as { name: string }[]).map((c) => c.name));
    if (!pdp.has("RegressionEnabled")) db.exec("ALTER TABLE AUTHZPDP ADD COLUMN RegressionEnabled INTEGER");
  } catch { /* */ }
}

// Find-or-create the gateway as an ASSET so it appears in the inventory / attack surface. Idempotent by name.
function ensureAsset(tenant: number | null, name: string, baseUrl?: string | null): number | null {
  const db = getDb("XORCISM");
  if (!has(db, "ASSET") || !name) return null;
  const cols = new Set((db.prepare("PRAGMA table_info(ASSET)").all() as { name: string }[]).map((c) => c.name));
  if (!cols.has("AssetID") || !cols.has("AssetName")) return null;
  const found = db.prepare(`SELECT AssetID FROM ASSET WHERE AssetName=? ${tenant != null && cols.has("TenantID") ? "AND (TenantID=? OR TenantID IS NULL)" : ""} LIMIT 1`)
    .get(...(tenant != null && cols.has("TenantID") ? [name, tenant] : [name])) as { AssetID: number } | undefined;
  if (found) return Number(found.AssetID);
  const rec: Record<string, unknown> = {
    AssetID: (Number((db.prepare("SELECT COALESCE(MAX(AssetID),0) m FROM ASSET").get() as { m: number }).m) || 0) + 1,
    AssetName: name, CreatedDate: new Date().toISOString(),
  };
  if (cols.has("AssetGUID")) rec.AssetGUID = randomUUID();
  if (cols.has("AssetDescription")) rec.AssetDescription = "API gateway (PEP) registered via API Authorization Governance.";
  if (cols.has("AssetCriticalityLevel")) rec.AssetCriticalityLevel = "High";
  if (cols.has("PublicFacing")) rec.PublicFacing = 1;
  if (cols.has("websiteurl") && baseUrl) rec.websiteurl = baseUrl;
  if (cols.has("TenantID")) rec.TenantID = tenant;
  const keys = Object.keys(rec).filter((k) => cols.has(k));
  try { db.prepare(`INSERT INTO ASSET (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k])); return Number(rec.AssetID); }
  catch { return null; }
}

// ── Decision model (PARC: Principal / Action / Resource / Context) ───────────────────
export interface DecisionRequest { subject: string; action: string; resource: string; context?: Record<string, unknown>; }
export type Decision = "allow" | "deny" | "error";
const SPLIT = (s: string): { type: string; id: string } => {
  const i = String(s ?? "").indexOf(":"); // "user:alice" → {type:user,id:alice}; "alice" → {type:"",id:alice}
  return i > 0 ? { type: s.slice(0, i), id: s.slice(i + 1) } : { type: "", id: String(s ?? "") };
};

/** AuthZEN Authorization API 1.0 evaluation body (OpenID Foundation). POST {pdp}/access/v1/evaluation. */
export function toAuthzenRequest(r: DecisionRequest): Record<string, unknown> {
  const s = SPLIT(r.subject), res = SPLIT(r.resource);
  return {
    subject: { type: s.type || "user", id: s.id },
    action: { name: r.action },
    resource: { type: res.type || "resource", id: res.id },
    context: r.context || {},
  };
}
/** OPA data API input. POST {pdp}/v1/data/<package>/allow with { input }. */
export function toOpaInput(r: DecisionRequest): Record<string, unknown> {
  return { input: { subject: r.subject, action: r.action, resource: r.resource, context: r.context || {} } };
}
/** Cedar / Amazon Verified Permissions authorization request shape. */
export function toCedarRequest(r: DecisionRequest): Record<string, unknown> {
  const s = SPLIT(r.subject), res = SPLIT(r.resource);
  return {
    principal: { entityType: s.type || "User", entityId: s.id },
    action: { actionType: "Action", actionId: r.action },
    resource: { entityType: res.type || "Resource", entityId: res.id },
    context: r.context || {},
  };
}
export function buildRequest(engine: string, r: DecisionRequest): Record<string, unknown> {
  return engine === "opa" ? toOpaInput(r) : engine === "cedar" || engine === "avp" ? toCedarRequest(r) : toAuthzenRequest(r);
}

/** Normalise a PDP response to allow/deny/error across engines (the interop core). */
export function normalizeDecision(engine: string, raw: unknown): Decision {
  if (raw == null || typeof raw !== "object") return "error";
  const o = raw as Record<string, unknown>;
  if (engine === "opa") {
    const r = o.result;
    if (r === true) return "allow";
    if (r === false) return "deny";
    if (r && typeof r === "object") { const a = (r as Record<string, unknown>).allow; if (a === true) return "allow"; if (a === false) return "deny"; }
    return "error";
  }
  if (engine === "cedar" || engine === "avp") {
    const d = String(o.decision ?? "").toUpperCase();
    if (d.startsWith("ALLOW")) return "allow";
    if (d.startsWith("DENY")) return "deny";
    return "error";
  }
  // authzen (and default): { decision: true|false }
  if (o.decision === true) return "allow";
  if (o.decision === false) return "deny";
  return "error";
}

// ── Inventory CRUD ───────────────────────────────────────────────────────────────────
const b = (v: unknown): number | null => (v == null || v === "" ? null : (v === true || v === 1 || v === "1" || v === "true" || v === "yes" ? 1 : 0));
const s = (v: unknown, n = 400): string | null => (v == null || String(v).trim() === "" ? null : String(v).slice(0, n));

export function registerPdp(tenant: number | null, p: Record<string, unknown>, source = "manual"): { id: number } {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const info = db.prepare(`INSERT INTO AUTHZPDP (Name, Engine, Endpoint, AuthzenCompliant, Status, RegressionEnabled, Notes, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(s(p.name), s(p.engine, 30) || "other", s(p.endpoint), b(p.authzenCompliant), s(p.status, 30) || "unknown", b(p.regressionEnabled), s(p.notes, 2000), source, tenant, new Date().toISOString());
  return { id: Number(info.lastInsertRowid) };
}

// ── Scheduled regression suite (persist each battery run for a pass-rate trend) ────────
export interface SuiteRunRollup { at: string; total: number; passed: number; failed: number; errors: number; findings: number; }
/** Persist a battery run; returns whether it regressed (more failures than the last run for this PDP). */
export function recordSuiteRun(tenant: number | null, r: { engine: string; endpoint?: string; pdpId?: number; total: number; passed: number; failed: number; errors: number; findings: number }, source = "manual"): { id: number; regressed: boolean; prevFailed: number | null } {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const scope = r.pdpId != null ? "PdpID=?" : tenant != null ? "TenantID=?" : "TenantID IS NULL";
  const prev = db.prepare(`SELECT Failed FROM AUTHZSUITERUN WHERE ${scope} ORDER BY RunID DESC LIMIT 1`)
    .get(...(r.pdpId != null ? [r.pdpId] : tenant != null ? [tenant] : [])) as { Failed: number } | undefined;
  const prevFailed = prev ? Number(prev.Failed) : null;
  const info = db.prepare(`INSERT INTO AUTHZSUITERUN (At, Engine, Endpoint, PdpID, Total, Passed, Failed, Errors, Findings, Source, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(new Date().toISOString().replace("T", " ").slice(0, 19), r.engine, r.endpoint || null, r.pdpId ?? null, r.total, r.passed, r.failed, r.errors, r.findings, source, tenant);
  return { id: Number(info.lastInsertRowid), regressed: prevFailed != null && r.failed > prevFailed, prevFailed };
}

export function suiteTrend(tenant: number | null, n = 30): SuiteRunRollup[] {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const rows = db.prepare(`SELECT At, Total, Passed, Failed, Errors, Findings FROM AUTHZSUITERUN ${tw(tenant)} ORDER BY At DESC, RunID DESC LIMIT ?`)
    .all(...(tenant != null ? [tenant, n] : [n])) as Record<string, unknown>[];
  return rows.reverse().map((r) => ({ at: String(r.At || "").slice(0, 10), total: Number(r.Total) || 0, passed: Number(r.Passed) || 0, failed: Number(r.Failed) || 0, errors: Number(r.Errors) || 0, findings: Number(r.Findings) || 0 }));
}

/** Per-PDP pass-rate trend: { pdpId: rollup[] } for the runs attributed to each PDP. */
export function suiteTrendsByPdp(tenant: number | null, n = 20): Record<number, SuiteRunRollup[]> {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const rows = db.prepare(`SELECT PdpID, At, Total, Passed, Failed, Errors, Findings FROM AUTHZSUITERUN
    WHERE PdpID IS NOT NULL ${tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : ""} ORDER BY At ASC, RunID ASC`)
    .all(...(tenant != null ? [tenant] : [])) as Record<string, unknown>[];
  const out: Record<number, SuiteRunRollup[]> = {};
  for (const r of rows) {
    const id = Number(r.PdpID); (out[id] = out[id] || []).push({ at: String(r.At || "").slice(0, 10), total: Number(r.Total) || 0, passed: Number(r.Passed) || 0, failed: Number(r.Failed) || 0, errors: Number(r.Errors) || 0, findings: Number(r.Findings) || 0 });
  }
  for (const id of Object.keys(out)) out[Number(id)] = out[Number(id)].slice(-n);
  return out;
}

/** PDPs opted into scheduled regression with an http(s) decision endpoint (across tenants for the scheduler). */
export function listRegressionPdps(): { pdpId: number; name: string; engine: string; endpoint: string; tenant: number | null }[] {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  return (db.prepare("SELECT PdpID, Name, Engine, Endpoint, TenantID FROM AUTHZPDP WHERE RegressionEnabled=1 AND Endpoint IS NOT NULL").all() as Record<string, unknown>[])
    .filter((p) => /^https?:\/\//i.test(String(p.Endpoint || "")))
    .map((p) => ({ pdpId: Number(p.PdpID), name: String(p.Name || ""), engine: String(p.Engine || "authzen"), endpoint: String(p.Endpoint), tenant: p.TenantID == null ? null : Number(p.TenantID) }));
}
export function registerGateway(tenant: number | null, p: Record<string, unknown>, source = "manual"): { id: number; assetId: number | null } {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const name = s(p.name) || "";
  const assetId = name ? ensureAsset(tenant, name, s(p.baseUrl)) : null; // gateway shows up in the asset inventory
  const info = db.prepare(`INSERT INTO AUTHZGATEWAY (Name, GatewayType, AuthnMethods, AuthzModel, PdpID, BaseUrl, Environment, DenyByDefault, DecisionLogging, AssetID, Notes, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(name, s(p.gatewayType, 30) || "other", s(Array.isArray(p.authnMethods) ? (p.authnMethods as string[]).join(",") : p.authnMethods, 200), s(p.authzModel, 40) || "none",
      p.pdpId != null && p.pdpId !== "" ? Number(p.pdpId) : null, s(p.baseUrl), s(p.environment, 40), b(p.denyByDefault), b(p.decisionLogging), assetId, s(p.notes, 2000), source, tenant, new Date().toISOString());
  return { id: Number(info.lastInsertRowid), assetId };
}
export function registerPolicy(tenant: number | null, p: Record<string, unknown>, source = "manual"): { id: number } {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const content = p.content != null ? String(p.content) : "";
  const hash = content ? createHash("sha256").update(content).digest("hex").slice(0, 16) : (s(p.contentHash, 64) || null);
  const info = db.prepare(`INSERT INTO AUTHZPOLICY (PdpID, Name, Engine, Language, Source, ContentHash, Version, DefaultDeny, Versioned, Tested, Notes, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(p.pdpId != null && p.pdpId !== "" ? Number(p.pdpId) : null, s(p.name), s(p.engine, 30) || "other", s(p.language, 20), s(p.policySource || p.source, 400), hash, s(p.version, 40), b(p.defaultDeny), b(p.versioned), b(p.tested), s(p.notes, 2000), tenant, new Date().toISOString());
  // record the policy-as-code as a discrete audit evidence artifact (idempotent by name)
  try {
    const flags = [b(p.defaultDeny) ? "default-deny" : "", b(p.versioned) ? "versioned" : "", b(p.tested) ? "tested" : ""].filter(Boolean).join(", ");
    createEvidence(`Authorization policy: ${s(p.name) || "policy"} (${s(p.engine, 30) || "other"})${flags ? ` — ${flags}` : ""}`);
  } catch { /* evidence is best-effort */ }
  return { id: Number(info.lastInsertRowid) };
}
export function deleteRow(table: "AUTHZGATEWAY" | "AUTHZPDP" | "AUTHZPOLICY", id: number): { ok: boolean } {
  ensureAuthzTables();
  const col = table === "AUTHZGATEWAY" ? "GatewayID" : table === "AUTHZPDP" ? "PdpID" : "PolicyID";
  getDb("XORCISM").prepare(`DELETE FROM ${table} WHERE ${col}=?`).run(id);
  return { ok: true };
}

export interface AuthzInventory { gateways: Record<string, unknown>[]; pdps: Record<string, unknown>[]; policies: Record<string, unknown>[]; tests: Record<string, unknown>[]; }
export function listInventory(tenant: number | null): AuthzInventory {
  ensureAuthzTables();
  const db = getDb("XORCISM");
  const q = (t: string, order: string): Record<string, unknown>[] => db.prepare(`SELECT * FROM ${t} ${tw(tenant)} ORDER BY ${order}`).all(...tp(tenant)) as Record<string, unknown>[];
  return { gateways: q("AUTHZGATEWAY", "Name"), pdps: q("AUTHZPDP", "Name"), policies: q("AUTHZPOLICY", "Name"), tests: db.prepare(`SELECT * FROM AUTHZDECISIONTEST ${tw(tenant)} ORDER BY TestID DESC LIMIT 50`).all(...tp(tenant)) as Record<string, unknown>[] };
}

// ── Decision test (records an evaluation; network call is guarded & optional) ──────────
export function recordDecisionTest(tenant: number | null, t: { pdpId?: number; engine: string; req: DecisionRequest; decision: Decision; expected?: string; raw?: unknown }): { id: number; pass: number | null } {
  ensureAuthzTables();
  const pass = t.expected ? (t.decision === t.expected ? 1 : 0) : null;
  const info = getDb("XORCISM").prepare(`INSERT INTO AUTHZDECISIONTEST (PdpID, Engine, Subject, Action, Resource, Context, Decision, Expected, Pass, RawResponse, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(t.pdpId ?? null, t.engine, t.req.subject, t.req.action, t.req.resource, JSON.stringify(t.req.context || {}), t.decision, t.expected || "", pass, t.raw != null ? JSON.stringify(t.raw).slice(0, 4000) : null, tenant, new Date().toISOString());
  return { id: Number(info.lastInsertRowid), pass };
}

// ── Posture assessment ───────────────────────────────────────────────────────────────
export interface AuthzControl { id: string; name: string; status: "proven" | "partial" | "gap" | "na"; weight: number; evidence: string; recommendation: string; frameworks: { fw: string; ref: string }[]; }
export interface AuthzPosture {
  score: number; controls: AuthzControl[];
  frameworks: { fw: string; label: string; readinessPct: number }[];
  counts: { gateways: number; pdps: number; policies: number; ungoverned: number };
  evaluatedAt: string;
}

const FW_LABELS: Record<string, string> = { owaspapi: "OWASP API Top 10", nistcsf: "NIST CSF 2.0", zt: "NIST 800-207 ZT" };
const truthy = (v: unknown): boolean => v === 1 || v === "1" || v === true;
const strong = new Set(["oidc", "jwt", "mtls"]);

export function assessAuthzPosture(tenant: number | null): AuthzPosture {
  ensureAuthzTables();
  const inv = listInventory(tenant);
  const gws = inv.gateways, pdps = inv.pdps, pols = inv.policies;
  const C: AuthzControl[] = [];
  const add = (c: AuthzControl) => C.push(c);
  // helper: classify proven/partial/gap from a per-item predicate set
  const ratio = (arr: unknown[], pred: (x: Record<string, unknown>) => boolean): number => arr.length ? arr.filter((x) => pred(x as Record<string, unknown>)).length / arr.length : 0;
  const tier = (r: number, count: number): "proven" | "partial" | "gap" | "na" => !count ? "na" : r >= 0.999 ? "proven" : r > 0 ? "partial" : "gap";

  // 1) Strong edge authentication (OWASP API2, NIST CSF PR.AA-02/03)
  const authnOk = (g: Record<string, unknown>): boolean => { const m = String(g.AuthnMethods || "").toLowerCase().split(/[,\s]+/).filter(Boolean); return m.length > 0 && m.every((x) => strong.has(x)); };
  const rAuthn = ratio(gws, authnOk);
  add({ id: "edge-authn", name: "Strong edge authentication", status: tier(rAuthn, gws.length), weight: 1,
    evidence: gws.length ? `${Math.round(rAuthn * 100)}% of gateways use only strong auth (OIDC/JWT/mTLS)` : "no gateways inventoried",
    recommendation: "Replace static API keys / basic auth at the edge with OIDC/JWT or mTLS.",
    frameworks: [{ fw: "owaspapi", ref: "API2:2023" }, { fw: "nistcsf", ref: "PR.AA-02" }] });

  // 2) Externalized, centralized authorization — a PDP (NIST 800-207 PE/PA/PEP, OWASP API5)
  const ext = (g: Record<string, unknown>): boolean => g.PdpID != null || String(g.AuthzModel || "").toLowerCase() === "external-pdp";
  const rExt = ratio(gws, ext);
  add({ id: "external-pdp", name: "Externalized authorization (PDP)", status: tier(rExt, gws.length), weight: 1.2,
    evidence: gws.length ? `${Math.round(rExt * 100)}% of gateways delegate to a policy decision point` : (pdps.length ? `${pdps.length} PDP(s) registered` : "no PDP / external authorization"),
    recommendation: "Delegate fine-grained authorization to a central PDP (OPA / Cedar / AuthZEN) instead of scattering it in each service.",
    frameworks: [{ fw: "zt", ref: "PE/PA/PEP" }, { fw: "owaspapi", ref: "API5:2023" }] });

  // 3) Deny-by-default (OWASP API1/API5, NIST CSF PR.AA-05)
  const ddItems = [...gws, ...pols];
  const ddKnown = ddItems.filter((x) => (x as Record<string, unknown>).DenyByDefault != null || (x as Record<string, unknown>).DefaultDeny != null);
  const rDd = ratio(ddKnown, (x) => truthy(x.DenyByDefault) || truthy(x.DefaultDeny));
  add({ id: "deny-default", name: "Deny-by-default", status: tier(rDd, ddKnown.length), weight: 1.2,
    evidence: ddKnown.length ? `${Math.round(rDd * 100)}% of gateways/policies are deny-by-default` : "deny-by-default not asserted",
    recommendation: "Ensure every gateway and policy denies by default; allow only explicitly.",
    frameworks: [{ fw: "owaspapi", ref: "API1:2023" }, { fw: "nistcsf", ref: "PR.AA-05" }] });

  // 4) Object-level authorization / BOLA (OWASP API1) — needs resource-attribute models
  const fga = (g: Record<string, unknown>): boolean => ["abac", "rebac"].includes(String(g.AuthzModel || "").toLowerCase());
  const rObj = ratio(gws, fga);
  add({ id: "object-level", name: "Object-level authorization (BOLA)", status: tier(rObj, gws.length), weight: 1.2,
    evidence: gws.length ? `${Math.round(rObj * 100)}% use attribute/relationship-based models (ABAC/ReBAC)` : "no gateways inventoried",
    recommendation: "Authorize on resource ownership/attributes (ABAC/ReBAC), not just endpoint role — the #1 API risk.",
    frameworks: [{ fw: "owaspapi", ref: "API1:2023" }] });

  // 5) Function-level authorization / BFLA (OWASP API5)
  const fla = (g: Record<string, unknown>): boolean => { const m = String(g.AuthzModel || "").toLowerCase(); return ["rbac", "abac", "rebac", "scopes", "external-pdp"].includes(m); };
  const rFn = ratio(gws, fla);
  add({ id: "function-level", name: "Function-level authorization (BFLA)", status: tier(rFn, gws.length), weight: 1,
    evidence: gws.length ? `${Math.round(rFn * 100)}% enforce a role/scope/PDP model per function` : "no gateways inventoried",
    recommendation: "Enforce role/scope checks per function/operation, denying privileged functions to regular users.",
    frameworks: [{ fw: "owaspapi", ref: "API5:2023" }] });

  // 6) Policy-as-code & versioning
  const rPac = ratio(pols, (p) => truthy(p.Versioned) && truthy(p.Tested));
  add({ id: "policy-as-code", name: "Policy-as-code, versioned & tested", status: tier(rPac, pols.length), weight: 0.8,
    evidence: pols.length ? `${Math.round(rPac * 100)}% of policies are version-controlled and tested` : "no policies registered",
    recommendation: "Manage policies as code: version control, peer review, and automated policy tests in CI.",
    frameworks: [{ fw: "nistcsf", ref: "PR.PS-01" }] });

  // 7) Authorization decision logging
  const dlKnown = gws.filter((g) => (g as Record<string, unknown>).DecisionLogging != null);
  const rDl = ratio(dlKnown, (g) => truthy(g.DecisionLogging));
  add({ id: "decision-logging", name: "Authorization decision logging", status: tier(rDl, dlKnown.length), weight: 0.8,
    evidence: dlKnown.length ? `${Math.round(rDl * 100)}% of gateways log authorization decisions` : "decision logging not asserted",
    recommendation: "Emit decision logs (OPA decision logs / AVP) for every allow/deny to enable audit & detection.",
    frameworks: [{ fw: "nistcsf", ref: "DE.AE-03" }] });

  // 8) PDP availability / fail-closed
  const rHealth = ratio(pdps, (p) => String(p.Status || "").toLowerCase() === "healthy");
  add({ id: "pdp-health", name: "PDP availability (fail-closed)", status: tier(rHealth, pdps.length), weight: 0.7,
    evidence: pdps.length ? `${Math.round(rHealth * 100)}% of PDPs report healthy` : "no PDPs registered",
    recommendation: "Run the PDP highly-available and fail closed (deny) when it is unreachable.",
    frameworks: [{ fw: "zt", ref: "PE availability" }] });

  // 9) Standards interoperability (AuthZEN)
  const rStd = ratio(pdps, (p) => truthy(p.AuthzenCompliant));
  add({ id: "standards", name: "Standard authorization API (AuthZEN)", status: tier(rStd, pdps.length), weight: 0.6,
    evidence: pdps.length ? `${Math.round(rStd * 100)}% of PDPs are AuthZEN-conformant` : "no PDPs registered",
    recommendation: "Prefer an AuthZEN-conformant PDP so any PEP can talk to any PDP (no vendor lock-in).",
    frameworks: [{ fw: "zt", ref: "interop" }] });

  // 10) Governance coverage — every gateway maps to a PDP
  const ungoverned = gws.filter((g) => !ext(g as Record<string, unknown>));
  add({ id: "coverage", name: "Governance coverage", status: tier(gws.length ? 1 - ungoverned.length / gws.length : 0, gws.length), weight: 1,
    evidence: gws.length ? `${gws.length - ungoverned.length}/${gws.length} gateways are governed by a PDP` : "no gateways inventoried",
    recommendation: "Bring every API gateway under a policy decision point — no ungoverned ingress.",
    frameworks: [{ fw: "owaspapi", ref: "API8:2023" }, { fw: "zt", ref: "coverage" }] });

  // score: weighted, proven=1 partial=0.5 gap=0 (na excluded)
  const scored = C.filter((c) => c.status !== "na");
  const totW = scored.reduce((a, c) => a + c.weight, 0);
  const got = scored.reduce((a, c) => a + c.weight * (c.status === "proven" ? 1 : c.status === "partial" ? 0.5 : 0), 0);
  const score = totW ? Math.round((got / totW) * 100) : 0;

  // per-framework readiness
  const fwAgg = new Map<string, { got: number; tot: number }>();
  for (const c of scored) for (const f of c.frameworks) {
    const a = fwAgg.get(f.fw) ?? { got: 0, tot: 0 }; a.tot += 1; a.got += c.status === "proven" ? 1 : c.status === "partial" ? 0.5 : 0; fwAgg.set(f.fw, a);
  }
  const frameworks = [...fwAgg.entries()].map(([fw, a]) => ({ fw, label: FW_LABELS[fw] || fw, readinessPct: a.tot ? Math.round((a.got / a.tot) * 100) : 0 }));

  return { score, controls: C, frameworks, counts: { gateways: gws.length, pdps: pdps.length, policies: pols.length, ungoverned: ungoverned.length }, evaluatedAt: new Date().toISOString().replace("T", " ").slice(0, 19) };
}

// ── BOLA / BFLA authorization test battery (OWASP API1 / API5) ────────────────────────
// A curated set of NEGATIVE authorization tests: a regular user attempting to reach another user's
// object (BOLA) or a privileged function (BFLA). A correct PDP must DENY every one — any "allow" is a
// broken-authorization finding. Run through the decision evaluator against a PDP (PEP test harness).
export interface AuthzTest { id: string; category: "API1" | "API5"; name: string; req: DecisionRequest; expected: Decision; }
export const OWASP_AUTHZ_TESTS: AuthzTest[] = [
  // API1:2023 Broken Object Level Authorization (BOLA) — cross-owner / cross-tenant object access
  { id: "bola-read-other", category: "API1", name: "Read another user's object", expected: "deny",
    req: { subject: "user:alice", action: "read", resource: "document:bob-42", context: { resourceOwner: "bob", callerRole: "user" } } },
  { id: "bola-update-other", category: "API1", name: "Update another user's object", expected: "deny",
    req: { subject: "user:alice", action: "update", resource: "account:bob", context: { resourceOwner: "bob", callerRole: "user" } } },
  { id: "bola-delete-other", category: "API1", name: "Delete another user's object", expected: "deny",
    req: { subject: "user:alice", action: "delete", resource: "order:9001", context: { resourceOwner: "bob", callerRole: "user" } } },
  { id: "bola-cross-tenant", category: "API1", name: "Read another tenant's object", expected: "deny",
    req: { subject: "user:alice", action: "read", resource: "invoice:tenantB-100", context: { callerTenant: "A", resourceTenant: "B", callerRole: "user" } } },
  // API5:2023 Broken Function Level Authorization (BFLA) — privileged function as a regular user
  { id: "bfla-admin-list", category: "API5", name: "Invoke admin function as user", expected: "deny",
    req: { subject: "user:alice", action: "admin:listAllUsers", resource: "users:*", context: { callerRole: "user" } } },
  { id: "bfla-delete-user", category: "API5", name: "Delete a user as a regular user", expected: "deny",
    req: { subject: "user:alice", action: "delete", resource: "user:bob", context: { callerRole: "user", privileged: true } } },
  { id: "bfla-change-config", category: "API5", name: "Change system config as user", expected: "deny",
    req: { subject: "user:alice", action: "update", resource: "config:system", context: { callerRole: "user", privileged: true } } },
  { id: "bfla-grant-role", category: "API5", name: "Grant self an admin role", expected: "deny",
    req: { subject: "user:alice", action: "grant", resource: "role:admin", context: { callerRole: "user", privileged: true } } },
];

export interface AuthzTestResult { id: string; category: string; name: string; decision: Decision; expected: Decision; pass: boolean | null; }
export interface AuthzSuiteReport {
  engine: string; total: number; passed: number; failed: number; errors: number;
  byCategory: Record<string, { total: number; failed: number }>;
  findings: { category: string; ref: string; name: string; severity: string }[];
  results: AuthzTestResult[];
}
/**
 * Run the OWASP authZ test battery. `evaluate` is injected by the caller (the route owns the network /
 * SSRF posture); it returns the PDP decision for a built request, or "error" when not evaluated live.
 * A test that should DENY but is allowed is a High BOLA/BFLA finding.
 */
export async function runAuthzTestSuite(
  tenant: number | null,
  opts: { engine: string; pdpId?: number; evaluate: (engine: string, req: DecisionRequest) => Promise<{ decision: Decision; raw?: unknown }> },
): Promise<AuthzSuiteReport> {
  ensureAuthzTables();
  const rep: AuthzSuiteReport = { engine: opts.engine, total: OWASP_AUTHZ_TESTS.length, passed: 0, failed: 0, errors: 0, byCategory: {}, findings: [], results: [] };
  for (const t of OWASP_AUTHZ_TESTS) {
    const cat = (rep.byCategory[t.category] = rep.byCategory[t.category] || { total: 0, failed: 0 });
    cat.total++;
    const { decision, raw } = await opts.evaluate(opts.engine, t.req);
    const pass = decision === "error" ? null : decision === t.expected;
    if (decision === "error") rep.errors++; else if (pass) rep.passed++; else rep.failed++;
    if (pass === false) { // expected deny, got allow → broken authorization
      cat.failed++;
      rep.findings.push({ category: t.category, ref: `${t.category}:2023`, name: t.name, severity: "High" });
    }
    rep.results.push({ id: t.id, category: t.category, name: t.name, decision, expected: t.expected, pass });
    recordDecisionTest(tenant, { pdpId: opts.pdpId, engine: opts.engine, req: t.req, decision, expected: t.expected, raw });
  }
  return rep;
}
