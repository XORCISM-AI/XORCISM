/**
 * cra.ts — EU Cyber Resilience Act (CRA) conformity cockpit (/cra-compliance).
 *
 * Operationalises the model of CRANE (github.com/cra-norm-engine/crane) on top of XORCISM's existing
 * SBOM (/sca), vulnerability, evidence and audit-trail subsystems: a registry of **products with digital
 * elements (PDE)** and their **releases**, a per-product **Annex I requirement matrix** (Part I product
 * security + Part II vulnerability handling), a **release-readiness gate**, and a conformity score that
 * feeds CE-marking / EU-declaration-of-conformity evidence. Deterministic; reuses [[sca-sbom]],
 * [[reg-incident-reporting]] (Art. 14 24h/72h/14d) and EVIDENCE.
 */
import { randomUUID } from "crypto";
import { getDb, createEvidence } from "./db";
import { sbomVulnSummary } from "./sca";
import { ollamaStatus, ollamaChat } from "./ai";

const now = (): string => new Date().toISOString();
const today = (): string => new Date().toISOString().slice(0, 10);
const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const tw = (tenant: number | null): string => (tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "");
const tp = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);
const s = (v: unknown, n = 400): string | null => (v == null || String(v).trim() === "" ? null : String(v).slice(0, n));

export const CRA_CLASSES = ["default", "class-i", "class-ii", "critical"] as const;
export const CRA_STATUS = ["met", "partial", "gap", "na"] as const;

// Annex I requirement catalogue (mirrors import_cra.py refs) used to seed the per-product matrix.
export interface CraReqDef { ref: string; part: "product" | "vuln-handling" | "conformity"; title: string; }
export const CRA_REQUIREMENTS: CraReqDef[] = [
  { ref: "Annex I.1.(2)(a)", part: "product", title: "No known exploitable vulnerabilities" },
  { ref: "Annex I.1.(2)(b)", part: "product", title: "Secure by default configuration" },
  { ref: "Annex I.1.(2)(c)", part: "product", title: "Security updates" },
  { ref: "Annex I.1.(2)(d)", part: "product", title: "Protection from unauthorised access" },
  { ref: "Annex I.1.(2)(e)", part: "product", title: "Confidentiality of data" },
  { ref: "Annex I.1.(2)(f)", part: "product", title: "Integrity of data" },
  { ref: "Annex I.1.(2)(g)", part: "product", title: "Data minimisation" },
  { ref: "Annex I.1.(2)(h)", part: "product", title: "Availability of essential functions" },
  { ref: "Annex I.1.(2)(i)", part: "product", title: "Minimise impact on other devices" },
  { ref: "Annex I.1.(2)(j)", part: "product", title: "Limit attack surfaces" },
  { ref: "Annex I.1.(2)(k)", part: "product", title: "Reduce impact of incidents" },
  { ref: "Annex I.1.(2)(l)", part: "product", title: "Security-relevant logging & monitoring" },
  { ref: "Annex I.1.(2)(m)", part: "product", title: "Secure data & configuration removal" },
  { ref: "Annex I.2.(1)", part: "vuln-handling", title: "Identify & document components (SBOM)" },
  { ref: "Annex I.2.(2)", part: "vuln-handling", title: "Remediate vulnerabilities without delay" },
  { ref: "Annex I.2.(3)", part: "vuln-handling", title: "Regular security testing & review" },
  { ref: "Annex I.2.(4)", part: "vuln-handling", title: "Publicly disclose fixed vulnerabilities" },
  { ref: "Annex I.2.(5)", part: "vuln-handling", title: "Coordinated vulnerability disclosure policy" },
  { ref: "Annex I.2.(6)", part: "vuln-handling", title: "Facilitate vulnerability reporting" },
  { ref: "Annex I.2.(7)", part: "vuln-handling", title: "Secure update distribution" },
  { ref: "Annex I.2.(8)", part: "vuln-handling", title: "Disseminate free security patches with advisory" },
  { ref: "Annex V", part: "conformity", title: "EU declaration of conformity (CE marking)" },
  { ref: "Annex VII", part: "conformity", title: "Technical documentation" },
];

export function ensureCraTables(): void {
  const db = getDb("XCOMPLIANCE");
  db.exec(`
    CREATE TABLE IF NOT EXISTS CRAPRODUCT(
      ProductID INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT, Description TEXT, Class TEXT, Manufacturer TEXT,
      SupportUntil TEXT, ConformityRoute TEXT, TargetSL TEXT, AssetID INTEGER, Status TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CRARELEASE(
      ReleaseID INTEGER PRIMARY KEY AUTOINCREMENT, ProductID INTEGER, Version TEXT, ReleaseDate TEXT,
      Status TEXT, SbomId INTEGER, Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CRAREQUIREMENT(
      ReqID INTEGER PRIMARY KEY AUTOINCREMENT, ProductID INTEGER, ReqRef TEXT, ReqTitle TEXT, Part TEXT,
      Status TEXT, Evidence TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_craproduct_tn ON CRAPRODUCT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_crareq_prod ON CRAREQUIREMENT(ProductID);
    CREATE INDEX IF NOT EXISTS ix_crarel_prod ON CRARELEASE(ProductID);`);
  // legacy guard: TargetSL added after the table first shipped
  try {
    const cols = new Set((db.prepare("PRAGMA table_info(CRAPRODUCT)").all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("TargetSL")) db.exec("ALTER TABLE CRAPRODUCT ADD COLUMN TargetSL TEXT");
  } catch { /* */ }
}

// Conformity-assessment route required per product class (CRA Art. 32 + Annex VIII; cf. Compass Security
// CRA guidance). Critical / Important Class II need a third party; Class I can self-assess only with
// harmonised standards; default self-assesses. Used to flag a route that is too weak for the class.
export const CRA_ROUTE_BY_CLASS: Record<string, { required: string; needsThirdParty: boolean }> = {
  default: { required: "Self-assessment (internal control, Module A)", needsThirdParty: false },
  "class-i": { required: "Self-assessment if fully covered by harmonised standards, otherwise third-party", needsThirdParty: false },
  "class-ii": { required: "Third-party conformity assessment (notified body)", needsThirdParty: true },
  critical: { required: "Third-party + EU cybersecurity certification (notified body)", needsThirdParty: true },
};
const routeIsThirdParty = (route: string): boolean => /third[- ]?party|notified body|module [bch]|certif/i.test(route || "");

// ── CRUD ──────────────────────────────────────────────────────────────────────────────
function seedRequirements(db: ReturnType<typeof getDb>, productId: number, tenant: number | null): void {
  if (db.prepare("SELECT 1 FROM CRAREQUIREMENT WHERE ProductID=? LIMIT 1").get(productId)) return;
  const ins = db.prepare("INSERT INTO CRAREQUIREMENT (ProductID, ReqRef, ReqTitle, Part, Status, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?)");
  const t = now();
  for (const r of CRA_REQUIREMENTS) ins.run(productId, r.ref, r.title, r.part, "gap", tenant, t);
}

export function registerProduct(tenant: number | null, p: Record<string, unknown>, source = "manual"): { id: number } {
  ensureCraTables();
  const db = getDb("XCOMPLIANCE");
  const cls = CRA_CLASSES.includes(String(p.class) as never) ? String(p.class) : "default";
  const info = db.prepare(`INSERT INTO CRAPRODUCT (Name, Description, Class, Manufacturer, SupportUntil, ConformityRoute, TargetSL, AssetID, Status, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(s(p.name), s(p.description, 2000), cls, s(p.manufacturer), s(p.supportUntil, 30), s(p.conformityRoute, 80), s(p.targetSl, 10), p.assetId != null && p.assetId !== "" ? Number(p.assetId) : null, s(p.status, 30) || "draft", source, tenant, now());
  const id = Number(info.lastInsertRowid);
  seedRequirements(db, id, tenant); // every product starts with the full Annex I matrix (status gap)
  return { id };
}

export function registerRelease(tenant: number | null, p: Record<string, unknown>): { id: number } {
  ensureCraTables();
  const db = getDb("XCOMPLIANCE");
  const info = db.prepare(`INSERT INTO CRARELEASE (ProductID, Version, ReleaseDate, Status, SbomId, Notes, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?)`)
    .run(Number(p.productId), s(p.version, 80), s(p.releaseDate, 30), s(p.status, 30) || "draft", p.sbomId != null && p.sbomId !== "" ? Number(p.sbomId) : null, s(p.notes, 2000), tenant, now());
  return { id: Number(info.lastInsertRowid) };
}

export function assessRequirement(tenant: number | null, reqId: number, status: string, evidence?: string): { ok: boolean } {
  ensureCraTables();
  const st = (CRA_STATUS as readonly string[]).includes(status) ? status : "gap";
  getDb("XCOMPLIANCE").prepare("UPDATE CRAREQUIREMENT SET Status=?, Evidence=? WHERE ReqID=?").run(st, s(evidence, 2000), reqId);
  // a met conformity/vuln-handling requirement is also a discrete audit-evidence artifact
  if (st === "met" && evidence) { try { createEvidence(`CRA evidence: ${evidence}`.slice(0, 300)); } catch { /* */ } }
  return { ok: true };
}

export function deleteProduct(id: number): { ok: boolean } {
  ensureCraTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM CRAREQUIREMENT WHERE ProductID=?").run(id);
  db.prepare("DELETE FROM CRARELEASE WHERE ProductID=?").run(id);
  db.prepare("DELETE FROM CRAPRODUCT WHERE ProductID=?").run(id);
  return { ok: true };
}

// ── Conformity + release gate ───────────────────────────────────────────────────────────
export interface GateItem { id: string; label: string; status: "pass" | "fail" | "unverifiable"; detail: string; ref: string; }
export interface ProductConformity {
  product: Record<string, unknown>;
  annexIPct: number; partI: { met: number; total: number }; partII: { met: number; total: number };
  requirements: { id: number; ref: string; title: string; part: string; status: string; evidence: string }[];
  releases: { id: number; version: string; date: string; status: string; sbom: boolean }[];
  gate: { ready: boolean; items: GateItem[]; passed: number; total: number };
  supportStatus: "active" | "expiring" | "expired" | "undefined";
  requiredRoute: string;
}

const reqMet = (rows: { Part: string; Status: string }[], part: string): { met: number; total: number } => {
  const r = rows.filter((x) => x.Part === part);
  return { met: r.filter((x) => x.Status === "met").length, total: r.length };
};

function supportStatus(supportUntil: string | null): ProductConformity["supportStatus"] {
  if (!supportUntil) return "undefined";
  const d = Date.parse(supportUntil); if (Number.isNaN(d)) return "undefined";
  const days = (d - Date.now()) / 86400000;
  return days < 0 ? "expired" : days < 180 ? "expiring" : "active";
}

export function productConformity(tenant: number | null, productId: number): ProductConformity | null {
  ensureCraTables();
  const db = getDb("XCOMPLIANCE");
  const prod = db.prepare("SELECT * FROM CRAPRODUCT WHERE ProductID=?").get(productId) as Record<string, unknown> | undefined;
  if (!prod) return null;
  const reqs = db.prepare("SELECT ReqID, ReqRef, ReqTitle, Part, Status, Evidence FROM CRAREQUIREMENT WHERE ProductID=? ORDER BY ReqID").all(productId) as Record<string, unknown>[];
  const annexRows = reqs.filter((r) => String(r.Part) === "product" || String(r.Part) === "vuln-handling").map((r) => ({ Part: String(r.Part), Status: String(r.Status) }));
  const partI = reqMet(annexRows, "product"), partII = reqMet(annexRows, "vuln-handling");
  const totalMet = partI.met + partII.met, total = partI.total + partII.total;
  const annexIPct = total ? Math.round((totalMet / total) * 100) : 0;

  const relRows = db.prepare("SELECT ReleaseID, Version, ReleaseDate, Status, SbomId FROM CRARELEASE WHERE ProductID=? ORDER BY ReleaseID DESC").all(productId) as Record<string, unknown>[];
  const releases = relRows.map((r) => ({ id: Number(r.ReleaseID), version: String(r.Version || ""), date: String(r.ReleaseDate || ""), status: String(r.Status || ""), sbom: r.SbomId != null }));
  const latest = releases[0];
  const latestSbomId = relRows.length && relRows[0].SbomId != null ? Number(relRows[0].SbomId) : null;
  // live CVE correlation on the latest release's SBOM (Annex I.1.(2)(a)); falls back to the requirement status
  const sv = latestSbomId != null ? sbomVulnSummary(latestSbomId) : null;
  const sup = supportStatus(String(prod.SupportUntil || "") || null);
  const reqByRef = new Map(reqs.map((r) => [String(r.ReqRef), String(r.Status)]));
  const reqOk = (ref: string): boolean => reqByRef.get(ref) === "met";

  const cls = String(prod.Class || "default");
  const route = CRA_ROUTE_BY_CLASS[cls] || CRA_ROUTE_BY_CLASS.default;
  // CRA release-readiness gate (auto where determinable; otherwise from the requirement matrix)
  const items: GateItem[] = [
    { id: "sbom", ref: "Annex I.2.(1)", label: "SBOM attached to the latest release", status: latest ? (latest.sbom ? "pass" : "fail") : "unverifiable", detail: latest ? (latest.sbom ? `release ${latest.version} has an SBOM` : "no SBOM linked") : "no release yet" },
    { id: "noknownvulns", ref: "Annex I.1.(2)(a)", label: "No known exploitable vulnerabilities",
      status: sv ? ((sv.critical + sv.kev) === 0 ? "pass" : "fail") : (reqOk("Annex I.1.(2)(a)") ? "pass" : "fail"),
      detail: sv ? `SBOM: ${sv.vulnerable}/${sv.components} components vulnerable (${sv.critical} critical, ${sv.kev} KEV)` : "Annex I.1.(2)(a) requirement status (no SBOM linked)" },
    { id: "vulnhandling", ref: "Annex I.2", label: "Vulnerability-handling process in place", status: partII.met >= Math.ceil(partII.total * 0.8) ? "pass" : "fail", detail: `${partII.met}/${partII.total} Part II requirements met` },
    { id: "disclosure", ref: "Annex I.2.(5)", label: "Coordinated vulnerability disclosure policy", status: reqOk("Annex I.2.(5)") ? "pass" : "fail", detail: "Annex I.2.(5) requirement status" },
    { id: "support", ref: "Art. 13", label: "Support period defined (≥ 5 years)", status: sup === "undefined" ? "fail" : sup === "expired" ? "fail" : "pass", detail: sup === "undefined" ? "no support-until date" : `support ${sup} (until ${prod.SupportUntil})` },
    { id: "targetsl", ref: "IEC 62443 SL", label: "Target Security Level defined (IEC 62443 SL)", status: prod.TargetSL ? "pass" : "fail", detail: prod.TargetSL ? `target ${prod.TargetSL}` : "no target Security Level set" },
    { id: "route", ref: "Art. 32", label: "Conformity-assessment route appropriate to class", status: route.needsThirdParty ? (routeIsThirdParty(String(prod.ConformityRoute || "")) ? "pass" : "fail") : (prod.ConformityRoute ? "pass" : "fail"), detail: route.needsThirdParty ? `${cls} requires: ${route.required}` : route.required },
    { id: "doc", ref: "Annex V", label: "EU declaration of conformity / CE", status: reqOk("Annex V") ? "pass" : "fail", detail: "Annex V requirement status" },
    { id: "techdoc", ref: "Annex VII", label: "Technical documentation compiled", status: reqOk("Annex VII") ? "pass" : "fail", detail: "Annex VII requirement status" },
  ];
  const passed = items.filter((i) => i.status === "pass").length;
  const ready = items.every((i) => i.status === "pass");

  return {
    product: prod, annexIPct, partI, partII,
    requirements: reqs.map((r) => ({ id: Number(r.ReqID), ref: String(r.ReqRef), title: String(r.ReqTitle || ""), part: String(r.Part || ""), status: String(r.Status || ""), evidence: String(r.Evidence || "") })),
    releases, gate: { ready, items, passed, total: items.length }, supportStatus: sup, requiredRoute: route.required,
  };
}

export interface CraDashboard {
  products: { id: number; name: string; class: string; annexIPct: number; supportStatus: string; gateReady: boolean; gatePassed: number; gateTotal: number; releases: number; assetId: number | null }[];
  summary: { products: number; conformant: number; avgConformity: number; supportExpiring: number; supportExpired: number; byClass: Record<string, number> };
}
export function craDashboard(tenant: number | null): CraDashboard {
  ensureCraTables();
  const db = getDb("XCOMPLIANCE");
  const prods = db.prepare(`SELECT ProductID FROM CRAPRODUCT ${tw(tenant)} ORDER BY Name`).all(...tp(tenant)) as { ProductID: number }[];
  const products: CraDashboard["products"] = [];
  const byClass: Record<string, number> = {};
  let conformant = 0, sumPct = 0, expiring = 0, expired = 0;
  for (const { ProductID } of prods) {
    const c = productConformity(tenant, ProductID); if (!c) continue;
    const cls = String(c.product.Class || "default"); byClass[cls] = (byClass[cls] || 0) + 1;
    if (c.gate.ready) conformant++; sumPct += c.annexIPct;
    if (c.supportStatus === "expiring") expiring++; if (c.supportStatus === "expired") expired++;
    products.push({ id: ProductID, name: String(c.product.Name || ""), class: cls, annexIPct: c.annexIPct, supportStatus: c.supportStatus, gateReady: c.gate.ready, gatePassed: c.gate.passed, gateTotal: c.gate.total, releases: c.releases.length, assetId: c.product.AssetID == null ? null : Number(c.product.AssetID) });
  }
  return { products, summary: { products: prods.length, conformant, avgConformity: prods.length ? Math.round(sumPct / prods.length) : 0, supportExpiring: expiring, supportExpired: expired, byClass } };
}

// ── AI-narrated CRA conformity report ───────────────────────────────────────────────────
export interface CraReport { generatedAt: string; ai: boolean; model: string; executiveSummary: string; dashboard: CraDashboard; details: ProductConformity[]; }

function offlineCraSummary(d: CraDashboard, details: ProductConformity[]): string {
  const blocked = details.filter((c) => !c.gate.ready).length;
  const topGap = details.flatMap((c) => c.gate.items.filter((i) => i.status === "fail").map((i) => i.label));
  const common = [...new Set(topGap)].slice(0, 3).join("; ");
  return [
    `CRA conformity covers ${d.summary.products} product(s) with digital elements; average Annex I conformity is ${d.summary.avgConformity}%, and ${d.summary.conformant}/${d.summary.products} pass the release-readiness gate.`,
    blocked ? `${blocked} product(s) are blocked from release; the most common gate failures are: ${common || "various"}.` : `All registered products currently pass the release gate.`,
    d.summary.supportExpired ? `${d.summary.supportExpired} product(s) have an expired support period (Art. 13).` : `Support periods are within the required window.`,
    `Priority: close the open Annex I gaps and complete the EU declaration of conformity / technical documentation before CE marking.`,
  ].join(" ");
}

export async function craReport(tenant: number | null): Promise<CraReport> {
  const dashboard = craDashboard(tenant);
  const details = dashboard.products.map((p) => productConformity(tenant, p.id)).filter((c): c is ProductConformity => !!c);
  const r: CraReport = { generatedAt: new Date().toISOString().replace("T", " ").slice(0, 19), ai: false, model: "", executiveSummary: "", dashboard, details };
  const status = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  if (status.reachable) {
    try {
      const facts = JSON.stringify({
        products: dashboard.summary, perProduct: details.map((c) => ({ name: c.product.Name, class: c.product.Class, annexIPct: c.annexIPct, gateReady: c.gate.ready, support: c.supportStatus, gaps: c.gate.items.filter((i) => i.status === "fail").map((i) => i.ref) })),
      });
      const sys = "You are a CRA (EU Cyber Resilience Act) conformity analyst. Using ONLY the supplied JSON facts (do not invent products, numbers or certifications), write 4-6 sentences summarising product conformity to Annex I, release-readiness, support-period status and the single highest-priority action before CE marking. Plain, factual.";
      const out = (await ollamaChat([{ role: "system", content: sys }, { role: "user", content: facts }], 0.2, 60000)).trim();
      if (out) { r.executiveSummary = out; r.ai = true; r.model = status.model || ""; }
    } catch { /* offline below */ }
  }
  if (!r.executiveSummary) r.executiveSummary = offlineCraSummary(dashboard, details);
  return r;
}

export function craReportMarkdown(r: CraReport): string {
  const L: string[] = [];
  L.push(`# EU Cyber Resilience Act — conformity report`, "", `_Generated ${r.generatedAt}${r.ai ? ` · executive summary by local AI (${r.model})` : " · executive summary: offline"}_`, "");
  L.push(`## Executive summary`, "", r.executiveSummary, "");
  const sm = r.dashboard.summary;
  L.push(`## Portfolio`, "", `**${sm.products}** product(s) with digital elements · **${sm.avgConformity}%** average Annex I conformity · **${sm.conformant}/${sm.products}** release-gate ready · ${sm.supportExpiring} support expiring · ${sm.supportExpired} expired.`, "");
  L.push(`| Product | Class | Annex I | Support | Release gate |`, `|---|---|---|---|---|`, ...r.dashboard.products.map((p) => `| ${p.name} | ${p.class} | ${p.annexIPct}% | ${p.supportStatus} | ${p.gatePassed}/${p.gateTotal} ${p.gateReady ? "ready" : "BLOCKED"} |`), "");
  for (const c of r.details) {
    L.push("", `## ${c.product.Name}`, "", `Annex I conformity **${c.annexIPct}%** — Part I ${c.partI.met}/${c.partI.total}, Part II ${c.partII.met}/${c.partII.total}. Support: ${c.supportStatus}.`, "");
    L.push(`### Release-readiness gate`, "", `| Check | Status | Detail |`, `|---|---|---|`, ...c.gate.items.map((i) => `| ${i.label} (${i.ref}) | ${i.status} | ${i.detail} |`));
    const gaps = c.requirements.filter((q) => q.status === "gap" || q.status === "partial");
    if (gaps.length) { L.push("", `### Open Annex I requirements`, "", ...gaps.map((q) => `- ${q.ref} ${q.title} — **${q.status}**${q.evidence ? ` (${q.evidence})` : ""}`)); }
  }
  L.push("", `---`, `_Conformity recomputes from live SBOM / vulnerability / requirement data; the deterministic checks are the source of truth and the local AI only narrates._`);
  return L.join("\n");
}
