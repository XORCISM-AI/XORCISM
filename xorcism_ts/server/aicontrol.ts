/**
 * aicontrol.ts — AI Control Library (/ai-control-library).
 *
 * The operational layer that most AI-governance programmes are missing: policies, principles and risk
 * registers exist, but risks are rarely translated into repeatable, testable, auditable controls. This
 * module is a structured repository of reusable AI controls — each with the fields a mature control
 * library defines (identifier, objective, risk(s) addressed, control type, statement, AI lifecycle phase,
 * owner, required evidence, testing method, monitoring frequency, related policies, framework references).
 *
 * Organised around the six connected layers (AI lifecycle × risk domain × objective × activity × evidence
 * × ownership), it ships an org-tailorable starter library mapped to ISO/IEC 42001, the NIST AI RMF, CSA
 * AICM and the EU AI Act, and surfaces coverage analytics + the common control-library failure modes
 * (no measurable objective, no owner, no evidence, no testing method, no framework mapping). Controls are
 * designed for the org's risk context first and mapped to frameworks — not a mirror of any single one.
 *
 * Reuses XORCISM's CONTROL/VOCABULARY (framework refs), EVIDENCE, POLICY and AI assets (AISYSTEM). The
 * library is the source of truth; assurance/audit consume it.
 */
import { getDb, createEvidence } from "./db";
import { ollamaStatus, ollamaChat } from "./ai";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

const now = (): string => new Date().toISOString();
const tw = (tenant: number | null): string => (tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "");
const tp = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);
const s = (v: unknown, n = 2000): string | null => (v == null || String(v).trim() === "" ? null : String(v).slice(0, n));

// ── The six layers (vocabularies) ───────────────────────────────────────────────────────
export const AI_LIFECYCLE = ["Planning", "Data Acquisition & Preparation", "Model Development", "Validation", "Deployment", "Monitoring", "Retirement"] as const;
export const AI_RISK_DOMAINS = ["Fairness", "Privacy", "Security", "Explainability", "Human Oversight", "Robustness", "Accountability", "Regulatory Compliance"] as const;
export const CONTROL_TYPES = ["Preventive", "Detective", "Corrective"] as const;
export const MONITORING_FREQ = ["Continuous", "Per-release", "Per-system", "Weekly", "Monthly", "Quarterly", "Annual", "Event-driven"] as const;
export const CONTROL_STATUS = ["implemented", "partial", "planned", "na"] as const;
export const CONTROL_OWNERS = ["Business Owner", "Product Owner", "AI System Owner", "Model Owner", "Risk Function", "Information Security", "Compliance", "Internal Audit"] as const;

export interface AiControlDef {
  ref: string; objective: string; statement: string; riskDomains: string[]; type: string; lifecycle: string;
  owner: string; evidence: string; testing: string; frequency: string; frameworks: string[];
}

// Org-tailorable starter library — designed for AI risk context, mapped to external frameworks.
export const AI_CONTROL_SEED: AiControlDef[] = [
  { ref: "AI-GOV-01", objective: "Establish accountable AI governance.", statement: "An approved AI policy and a governance body with defined roles and decision rights are in place and reviewed.", riskDomains: ["Accountability"], type: "Preventive", lifecycle: "Planning", owner: "Risk Function", evidence: "AI policy; governance committee minutes", testing: "Governance review", frequency: "Annual", frameworks: ["ISO 42001 5.2/A.2", "NIST AI RMF GOVERN-1", "EU AI Act Art.4"] },
  { ref: "AI-ACC-01", objective: "Maintain an inventory and ownership of all AI systems.", statement: "Every AI system/model/agent is registered with a named owner, purpose, data and risk tier before development.", riskDomains: ["Accountability"], type: "Preventive", lifecycle: "Planning", owner: "AI System Owner", evidence: "AI system register; ownership records", testing: "Inventory review", frequency: "Quarterly", frameworks: ["ISO 42001 A.6.2.2", "NIST AI RMF MAP-1", "EU AI Act Art.11"] },
  { ref: "AI-REG-01", objective: "Classify AI risk tier and regulatory obligations.", statement: "Each AI system's risk tier and applicable regulatory obligations (e.g. EU AI Act) are classified and documented.", riskDomains: ["Regulatory Compliance"], type: "Preventive", lifecycle: "Planning", owner: "Compliance", evidence: "Risk-classification record", testing: "Classification review", frequency: "Per-system", frameworks: ["EU AI Act Art.6/Annex III", "ISO 42001 A.5.2", "NIST AI RMF MAP-1"] },
  { ref: "AI-PRIV-01", objective: "Ensure lawful, minimised data for AI.", statement: "Data acquisition uses a lawful basis and data minimisation; a DPIA is performed where required, with data lineage recorded.", riskDomains: ["Privacy"], type: "Preventive", lifecycle: "Data Acquisition & Preparation", owner: "Compliance", evidence: "DPIA; data-lineage records", testing: "Data-governance review", frequency: "Per-system", frameworks: ["ISO 42001 A.7.2", "NIST AI RMF MAP-3", "GDPR Art.35", "EU AI Act Art.10"] },
  { ref: "AI-DATA-01", objective: "Assure training-data quality.", statement: "Datasets undergo documented quality reviews for representativeness, accuracy and completeness before training.", riskDomains: ["Robustness", "Fairness"], type: "Detective", lifecycle: "Data Acquisition & Preparation", owner: "Model Owner", evidence: "Dataset quality-review records", testing: "Dataset quality review", frequency: "Per-release", frameworks: ["ISO 42001 A.7.4", "NIST AI RMF MEASURE-2.7", "EU AI Act Art.10"] },
  { ref: "AI-FAIR-01", objective: "Test models for unfair bias before release.", statement: "Bias/fairness testing is performed across protected attributes against documented thresholds prior to release.", riskDomains: ["Fairness"], type: "Detective", lifecycle: "Model Development", owner: "Model Owner", evidence: "Bias test results; model card", testing: "Bias / fairness testing", frequency: "Per-release", frameworks: ["ISO 42001 A.6.2.4", "NIST AI RMF MEASURE-2.11", "EU AI Act Art.10"] },
  { ref: "AI-SEC-01", objective: "Secure the AI supply chain and artifacts.", statement: "Access control, provenance and an AI-BOM protect models, data and the training/serving pipeline.", riskDomains: ["Security"], type: "Preventive", lifecycle: "Model Development", owner: "Information Security", evidence: "Access logs; AI-BOM; SBOM", testing: "Security review / pentest", frequency: "Per-release", frameworks: ["ISO 42001 A.6.2.6", "NIST AI RMF MANAGE-2", "CSA AICM"] },
  { ref: "AI-ROB-01", objective: "Independently validate accuracy and robustness.", statement: "Independent validation — including adversarial/robustness testing — confirms the model meets acceptance criteria before deployment.", riskDomains: ["Robustness"], type: "Detective", lifecycle: "Validation", owner: "Risk Function", evidence: "Validation report; test results", testing: "Independent model validation", frequency: "Per-release", frameworks: ["ISO 42001 A.6.2.4", "NIST AI RMF MEASURE-2.5", "EU AI Act Art.15"] },
  { ref: "AI-EXPL-01", objective: "Provide explanations appropriate to users.", statement: "An explainability method and a model card documenting intended use, limitations and performance are available to intended users and governance.", riskDomains: ["Explainability"], type: "Detective", lifecycle: "Validation", owner: "Model Owner", evidence: "Model card; explainability report", testing: "Explainability review", frequency: "Per-release", frameworks: ["ISO 42001 A.6.2.8", "NIST AI RMF MEASURE-2.9", "EU AI Act Art.13"] },
  { ref: "AI-HUM-01", objective: "Human approval gate for high-impact decisions.", statement: "A human-in-the-loop approval gate and override exist for high-risk AI outputs/decisions.", riskDomains: ["Human Oversight"], type: "Preventive", lifecycle: "Deployment", owner: "Business Owner", evidence: "Approval records", testing: "Control walkthrough", frequency: "Continuous", frameworks: ["ISO 42001 A.9", "NIST AI RMF GOVERN-3", "EU AI Act Art.14"] },
  { ref: "AI-SEC-02", objective: "Guardrails against prompt injection and abuse.", statement: "Deployed generative AI enforces input/output guardrails, rate limits and abuse monitoring.", riskDomains: ["Security"], type: "Preventive", lifecycle: "Deployment", owner: "Information Security", evidence: "Guardrail config; monitoring dashboard", testing: "AI red-team / BAS", frequency: "Continuous", frameworks: ["OWASP LLM Top 10", "NIST AI RMF MANAGE-4", "CSA AICM"] },
  { ref: "AI-MON-01", objective: "Monitor for model and data drift.", statement: "Drift and performance monitoring with alerting thresholds runs continuously on deployed models.", riskDomains: ["Robustness"], type: "Detective", lifecycle: "Monitoring", owner: "AI System Owner", evidence: "Monitoring dashboards; drift alerts", testing: "Drift-monitoring review", frequency: "Continuous", frameworks: ["ISO 42001 A.6.2.6", "NIST AI RMF MEASURE-2.12"] },
  { ref: "AI-MON-02", objective: "Log AI decisions and access for audit.", statement: "Inputs, outputs, decisions and access are logged immutably to support audit and incident investigation.", riskDomains: ["Accountability"], type: "Detective", lifecycle: "Monitoring", owner: "Information Security", evidence: "Audit logs", testing: "Log review", frequency: "Continuous", frameworks: ["ISO 42001 A.6.2.8", "NIST AI RMF MEASURE-2.8", "EU AI Act Art.12"] },
  { ref: "AI-INC-01", objective: "AI incident response and reporting.", statement: "An AI-specific incident-response process — including regulatory reporting of serious incidents — is defined and exercised.", riskDomains: ["Security", "Regulatory Compliance"], type: "Corrective", lifecycle: "Monitoring", owner: "Information Security", evidence: "IR runbook; incident records", testing: "Tabletop exercise", frequency: "Annual", frameworks: ["ISO 42001 A.10", "NIST AI RMF MANAGE-4", "EU AI Act Art.73"] },
  { ref: "AI-ACC-02", objective: "Securely retire AI systems and data.", statement: "Decommissioning includes secure deletion of models/data and documentation of the retirement decision.", riskDomains: ["Accountability", "Privacy"], type: "Corrective", lifecycle: "Retirement", owner: "AI System Owner", evidence: "Retirement record", testing: "Retirement review", frequency: "Event-driven", frameworks: ["ISO 42001 A.6.2.6"] },
];

export function ensureAiControlTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS AICONTROL(
      AiControlID INTEGER PRIMARY KEY AUTOINCREMENT, Ref TEXT, Objective TEXT, Statement TEXT,
      RiskDomains TEXT, ControlType TEXT, LifecyclePhase TEXT, Owner TEXT, RequiredEvidence TEXT,
      TestingMethod TEXT, MonitoringFrequency TEXT, RelatedPolicies TEXT, FrameworkRefs TEXT,
      Status TEXT, Scope TEXT, Source TEXT, TenantID INTEGER, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AICONTROLSYSTEM(
      LinkID INTEGER PRIMARY KEY AUTOINCREMENT, AiControlID INTEGER, AISystemID INTEGER,
      Status TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_aicontrol_tn ON AICONTROL(TenantID);
    CREATE INDEX IF NOT EXISTS ix_aicontrolsys ON AICONTROLSYSTEM(AISystemID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_aicontrol_ref ON AICONTROL(Ref, TenantID);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_aicontrolsys ON AICONTROLSYSTEM(AiControlID, AISystemID);`);
}

const csv = (v: unknown): string | null => (Array.isArray(v) ? v.join(",") : s(v, 600));
const arr = (v: unknown): string[] => String(v ?? "").split(",").map((x) => x.trim()).filter(Boolean);

export function createAiControl(tenant: number | null, p: Record<string, unknown>, source = "manual"): { id: number; created: boolean } {
  ensureAiControlTables();
  const db = getDb("XCOMPLIANCE");
  const ref = s(p.ref, 40);
  // idempotent by (Ref, tenant) — explicit check because SQLite treats NULL tenants as distinct in a UNIQUE index
  const existing = db.prepare("SELECT AiControlID FROM AICONTROL WHERE Ref=? AND COALESCE(TenantID,-1)=COALESCE(?,-1)").get(ref, tenant) as { AiControlID: number } | undefined;
  if (existing) return { id: Number(existing.AiControlID), created: false };
  const info = db.prepare(`INSERT INTO AICONTROL (Ref, Objective, Statement, RiskDomains, ControlType, LifecyclePhase, Owner, RequiredEvidence, TestingMethod, MonitoringFrequency, RelatedPolicies, FrameworkRefs, Status, Scope, Source, TenantID, CreatedDate, UpdatedDate)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(ref, s(p.objective), s(p.statement), csv(p.riskDomains), s(p.type, 30), s(p.lifecycle, 60), s(p.owner, 60), s(p.evidence || p.requiredEvidence), s(p.testing || p.testingMethod, 600), s(p.frequency || p.monitoringFrequency, 30), s(p.relatedPolicies, 600), csv(p.frameworks || p.frameworkRefs), s(p.status, 20) || "planned", s(p.scope, 200), source, tenant, now(), now());
  return { id: Number(info.lastInsertRowid), created: true };
}

export function seedAiControlLibrary(tenant: number | null): { created: number } {
  ensureAiControlTables();
  let created = 0;
  for (const c of AI_CONTROL_SEED) {
    if (createAiControl(tenant, { ...c, status: "planned" }, "starter-library").created) created++;
  }
  return { created };
}

export function updateAiControl(tenant: number | null, id: number, patch: Record<string, unknown>): { ok: boolean } {
  ensureAiControlTables();
  const db = getDb("XCOMPLIANCE");
  const fields: Record<string, unknown> = {};
  const map: Record<string, string> = { objective: "Objective", statement: "Statement", type: "ControlType", lifecycle: "LifecyclePhase", owner: "Owner", evidence: "RequiredEvidence", testing: "TestingMethod", frequency: "MonitoringFrequency", relatedPolicies: "RelatedPolicies", status: "Status", scope: "Scope" };
  for (const [k, col] of Object.entries(map)) if (patch[k] !== undefined) fields[col] = s(patch[k]);
  if (patch.riskDomains !== undefined) fields.RiskDomains = csv(patch.riskDomains);
  if (patch.frameworks !== undefined) fields.FrameworkRefs = csv(patch.frameworks);
  if (!Object.keys(fields).length) return { ok: false };
  fields.UpdatedDate = now();
  const set = Object.keys(fields).map((c) => `${c}=?`).join(", ");
  db.prepare(`UPDATE AICONTROL SET ${set} WHERE AiControlID=?`).run(...Object.values(fields), id);
  // an implemented control with its required evidence becomes a discrete audit artifact
  if (patch.status === "implemented") { const row = db.prepare("SELECT Ref, RequiredEvidence FROM AICONTROL WHERE AiControlID=?").get(id) as { Ref: string; RequiredEvidence: string } | undefined; if (row?.RequiredEvidence) { try { createEvidence(`AI control ${row.Ref}: ${row.RequiredEvidence}`.slice(0, 300)); } catch { /* */ } } }
  return { ok: true };
}

export function deleteAiControl(id: number): { ok: boolean } {
  ensureAiControlTables();
  getDb("XCOMPLIANCE").prepare("DELETE FROM AICONTROL WHERE AiControlID=?").run(id);
  return { ok: true };
}

// ── AI-system mapping (apply library controls to specific AI systems) ────────────────────
export function listAiSystems(tenant: number | null): { id: number; name: string; riskTier: string; lifecycle: string; owner: string }[] {
  const db = getDb("XORCISM");
  if (!has(db, "AISYSTEM")) return [];
  const tw2 = tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  return (db.prepare(`SELECT AISystemID id, Name, RiskTier, Lifecycle, Owner FROM AISYSTEM ${tw2} ORDER BY Name`).all(...(tenant != null ? [tenant] : [])) as Record<string, unknown>[])
    .map((r) => ({ id: Number(r.id), name: String(r.Name || ""), riskTier: String(r.RiskTier || ""), lifecycle: String(r.Lifecycle || ""), owner: String(r.Owner || "") }));
}

export function applyControlToSystem(tenant: number | null, aiControlId: number, aiSystemId: number, status?: string): { ok: boolean } {
  ensureAiControlTables();
  if (!Number.isFinite(aiControlId) || !Number.isFinite(aiSystemId)) return { ok: false };
  getDb("XCOMPLIANCE").prepare("INSERT OR IGNORE INTO AICONTROLSYSTEM (AiControlID, AISystemID, Status, TenantID, CreatedDate) VALUES (?,?,?,?,?)")
    .run(aiControlId, aiSystemId, s(status, 20) || "planned", tenant, now());
  return { ok: true };
}
export function unapplyControl(linkId: number): { ok: boolean } {
  ensureAiControlTables();
  getDb("XCOMPLIANCE").prepare("DELETE FROM AICONTROLSYSTEM WHERE LinkID=?").run(linkId);
  return { ok: true };
}

export interface SystemCoverage { aiSystemId: number; name: string; riskTier: string; applied: number; implemented: number; coveragePct: number; }
/** Per-AI-system control coverage: how many library controls are applied / implemented on each system. */
export function systemCoverage(tenant: number | null): { systems: SystemCoverage[]; summary: { systems: number; governed: number; avgCoverage: number } } {
  ensureAiControlTables();
  const cc = getDb("XCOMPLIANCE");
  const systems = listAiSystems(tenant);
  // applied links + the library status of each linked control
  const links = cc.prepare(`SELECT l.AISystemID sys, c.Status st FROM AICONTROLSYSTEM l JOIN AICONTROL c ON c.AiControlID=l.AiControlID`).all() as { sys: number; st: string }[];
  const bySys = new Map<number, { applied: number; implemented: number }>();
  for (const l of links) { const a = bySys.get(Number(l.sys)) ?? { applied: 0, implemented: 0 }; a.applied++; if (l.st === "implemented") a.implemented++; bySys.set(Number(l.sys), a); }
  const cov: SystemCoverage[] = systems.map((s2) => {
    const a = bySys.get(s2.id) ?? { applied: 0, implemented: 0 };
    return { aiSystemId: s2.id, name: s2.name, riskTier: s2.riskTier, applied: a.applied, implemented: a.implemented, coveragePct: a.applied ? Math.round((a.implemented / a.applied) * 100) : 0 };
  });
  const governed = cov.filter((c) => c.applied > 0).length;
  const avg = cov.length ? Math.round(cov.reduce((s2, c) => s2 + c.coveragePct, 0) / cov.length) : 0;
  return { systems: cov, summary: { systems: systems.length, governed, avgCoverage: avg } };
}

export interface AiControlLibrary {
  controls: Record<string, unknown>[];
  coverage: { byLifecycle: Record<string, number>; byDomain: Record<string, number>; byType: Record<string, number>; byStatus: Record<string, number> };
  matrix: { lifecycle: string; domains: Record<string, number> }[];
  gaps: { noObjective: number; noOwner: number; noEvidence: number; noTesting: number; noFramework: number; noFrequency: number; lifecycleUncovered: string[]; domainUncovered: string[] };
  summary: { total: number; implemented: number; partial: number; planned: number; ownershipPct: number; evidencePct: number; testablePct: number; mappedPct: number; maturityPct: number };
  vocab: { lifecycle: string[]; domains: string[]; types: string[]; frequency: string[]; owners: string[]; status: string[] };
}

export function aiControlLibrary(tenant: number | null): AiControlLibrary {
  ensureAiControlTables();
  const db = getDb("XCOMPLIANCE");
  const rows = db.prepare(`SELECT * FROM AICONTROL ${tw(tenant)} ORDER BY Ref`).all(...tp(tenant)) as Record<string, unknown>[];
  const inc = (m: Record<string, number>, k: string) => { if (k) m[k] = (m[k] || 0) + 1; };
  const byLifecycle: Record<string, number> = {}, byDomain: Record<string, number> = {}, byType: Record<string, number> = {}, byStatus: Record<string, number> = {};
  const matrixMap = new Map<string, Record<string, number>>();
  AI_LIFECYCLE.forEach((lc) => matrixMap.set(lc, {}));
  let noObjective = 0, noOwner = 0, noEvidence = 0, noTesting = 0, noFramework = 0, noFrequency = 0;
  let withOwner = 0, withEvidence = 0, withTesting = 0, withFramework = 0, implemented = 0, partial = 0, planned = 0;

  for (const r of rows) {
    const lc = String(r.LifecyclePhase || ""), type = String(r.ControlType || ""), st = String(r.Status || "");
    const domains = arr(r.RiskDomains);
    inc(byLifecycle, lc); inc(byType, type); inc(byStatus, st);
    for (const d of domains) { inc(byDomain, d); const row = matrixMap.get(lc); if (row) inc(row, d); }
    if (!String(r.Objective || "").trim()) noObjective++;
    if (!String(r.Owner || "").trim()) noOwner++; else withOwner++;
    if (!String(r.RequiredEvidence || "").trim()) noEvidence++; else withEvidence++;
    if (!String(r.TestingMethod || "").trim()) noTesting++; else withTesting++;
    if (!arr(r.FrameworkRefs).length) noFramework++; else withFramework++;
    if (!String(r.MonitoringFrequency || "").trim()) noFrequency++;
    if (st === "implemented") implemented++; else if (st === "partial") partial++; else if (st === "planned") planned++;
  }
  const n = rows.length || 1;
  const pct = (x: number): number => Math.round((x / n) * 100);
  const lifecycleUncovered = AI_LIFECYCLE.filter((lc) => !byLifecycle[lc]);
  const domainUncovered = AI_RISK_DOMAINS.filter((d) => !byDomain[d]);
  // maturity = blend of implementation, ownership, evidence, testability and framework mapping
  const maturityPct = rows.length ? Math.round((pct(implemented) * 0.4 + pct(withOwner) * 0.15 + pct(withEvidence) * 0.2 + pct(withTesting) * 0.15 + pct(withFramework) * 0.1)) : 0;

  return {
    controls: rows.map((r) => ({ id: r.AiControlID, ref: r.Ref, objective: r.Objective, statement: r.Statement, riskDomains: arr(r.RiskDomains), type: r.ControlType, lifecycle: r.LifecyclePhase, owner: r.Owner, evidence: r.RequiredEvidence, testing: r.TestingMethod, frequency: r.MonitoringFrequency, relatedPolicies: r.RelatedPolicies, frameworks: arr(r.FrameworkRefs), status: r.Status, scope: r.Scope })),
    coverage: { byLifecycle, byDomain, byType, byStatus },
    matrix: AI_LIFECYCLE.map((lc) => ({ lifecycle: lc, domains: matrixMap.get(lc) || {} })),
    gaps: { noObjective, noOwner, noEvidence, noTesting, noFramework, noFrequency, lifecycleUncovered, domainUncovered },
    summary: { total: rows.length, implemented, partial, planned, ownershipPct: rows.length ? pct(withOwner) : 0, evidencePct: rows.length ? pct(withEvidence) : 0, testablePct: rows.length ? pct(withTesting) : 0, mappedPct: rows.length ? pct(withFramework) : 0, maturityPct },
    vocab: { lifecycle: [...AI_LIFECYCLE], domains: [...AI_RISK_DOMAINS], types: [...CONTROL_TYPES], frequency: [...MONITORING_FREQ], owners: [...CONTROL_OWNERS], status: [...CONTROL_STATUS] },
  };
}

// ── AI-narrated AI-control-library report ─────────────────────────────────────────────────
export interface AiControlReport { generatedAt: string; ai: boolean; model: string; executiveSummary: string; library: AiControlLibrary; coverage: ReturnType<typeof systemCoverage>; }

function offlineAiSummary(lib: AiControlLibrary, cov: ReturnType<typeof systemCoverage>): string {
  const g = lib.gaps;
  const issues = [g.noObjective && `${g.noObjective} without a measurable objective`, g.noOwner && `${g.noOwner} without an owner`, g.noEvidence && `${g.noEvidence} without evidence`, g.noTesting && `${g.noTesting} without a testing method`].filter(Boolean).join(", ");
  return [
    `The AI control library holds ${lib.summary.total} reusable controls at ${lib.summary.maturityPct}% maturity (${lib.summary.implemented} implemented), covering ${7 - g.lifecycleUncovered.length}/7 lifecycle phases and ${8 - g.domainUncovered.length}/8 risk domains.`,
    issues ? `Control-library hygiene gaps: ${issues}.` : `Every control has a measurable objective, an owner, evidence and a testing method.`,
    g.lifecycleUncovered.length || g.domainUncovered.length ? `Coverage gaps remain in ${[...g.lifecycleUncovered, ...g.domainUncovered].slice(0, 4).join(", ")}.` : `All lifecycle phases and risk domains have at least one control.`,
    cov.summary.systems ? `Across ${cov.summary.systems} inventoried AI system(s), ${cov.summary.governed} have controls applied (avg ${cov.summary.avgCoverage}% implemented).` : `No AI systems are inventoried yet — apply controls to systems to track per-system coverage.`,
    `Priority: close the hygiene gaps and raise implementation on high-risk AI systems before scaling adoption.`,
  ].join(" ");
}

export async function aiControlReport(tenant: number | null): Promise<AiControlReport> {
  const library = aiControlLibrary(tenant);
  const coverage = systemCoverage(tenant);
  const r: AiControlReport = { generatedAt: new Date().toISOString().replace("T", " ").slice(0, 19), ai: false, model: "", executiveSummary: "", library, coverage };
  const status = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  if (status.reachable) {
    try {
      const facts = JSON.stringify({ summary: library.summary, gaps: library.gaps, byType: library.coverage.byType, systems: coverage.summary });
      const sys = "You are an AI-governance analyst summarising an AI Control Library. Using ONLY the supplied JSON facts (invent nothing), write 4-6 sentences on library maturity, lifecycle/risk-domain coverage, control-library hygiene gaps, per-AI-system coverage and the single highest-priority action. Plain, factual.";
      const out = (await ollamaChat([{ role: "system", content: sys }, { role: "user", content: facts }], 0.2, 60000)).trim();
      if (out) { r.executiveSummary = out; r.ai = true; r.model = status.model || ""; }
    } catch { /* offline below */ }
  }
  if (!r.executiveSummary) r.executiveSummary = offlineAiSummary(library, coverage);
  return r;
}

export function aiControlReportMarkdown(r: AiControlReport): string {
  const L: string[] = []; const lib = r.library, s2 = lib.summary;
  L.push(`# AI Control Library — governance report`, "", `_Generated ${r.generatedAt}${r.ai ? ` · executive summary by local AI (${r.model})` : " · executive summary: offline"}_`, "");
  L.push(`## Executive summary`, "", r.executiveSummary, "");
  L.push(`## Library maturity`, "", `**${s2.total}** controls · **${s2.maturityPct}%** maturity · ${s2.implemented} implemented / ${s2.partial} partial / ${s2.planned} planned · ${s2.ownershipPct}% owned · ${s2.evidencePct}% evidenced · ${s2.mappedPct}% framework-mapped.`, "");
  L.push(`Hygiene gaps — no objective: ${lib.gaps.noObjective}, no owner: ${lib.gaps.noOwner}, no evidence: ${lib.gaps.noEvidence}, no testing: ${lib.gaps.noTesting}, no framework: ${lib.gaps.noFramework}.`, "");
  if (lib.gaps.lifecycleUncovered.length) L.push(`Uncovered lifecycle phases: ${lib.gaps.lifecycleUncovered.join(", ")}.`, "");
  if (lib.gaps.domainUncovered.length) L.push(`Uncovered risk domains: ${lib.gaps.domainUncovered.join(", ")}.`, "");
  L.push(`## Controls`, "", `| ID | Objective | Type | Lifecycle | Domains | Owner | Status | Frameworks |`, `|---|---|---|---|---|---|---|---|`,
    ...lib.controls.map((c) => `| ${c.ref} | ${c.objective} | ${c.type} | ${c.lifecycle} | ${(c.riskDomains as string[]).join(", ")} | ${c.owner || "—"} | ${c.status} | ${(c.frameworks as string[]).join("; ")} |`));
  if (r.coverage.summary.systems) {
    L.push("", `## Per-AI-system coverage`, "", `${r.coverage.summary.governed}/${r.coverage.summary.systems} systems governed · avg ${r.coverage.summary.avgCoverage}% implemented.`, "",
      `| AI system | Risk tier | Applied | Implemented | Coverage |`, `|---|---|---|---|---|`, ...r.coverage.systems.map((s3) => `| ${s3.name} | ${s3.riskTier || "—"} | ${s3.applied} | ${s3.implemented} | ${s3.coveragePct}% |`));
  }
  L.push("", `---`, `_Controls are the source of truth; figures recompute live and the local AI only narrates._`);
  return L.join("\n");
}
