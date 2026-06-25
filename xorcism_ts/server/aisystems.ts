/**
 * aisystems.ts — AI system inventory + AI-BOM + model-risk register (/ai-systems).
 *
 * The "asset inventory" for the org's AI/LLM systems — the operational layer under the AI-TRiSM
 * brand (sibling of asset-management / identities). Each AI system records purpose, model/provider,
 * hosting, data sensitivity, guardrails, governing frameworks (NIST AI RMF / ISO 42001 / CSA AICM)
 * and an EU-AI-Act risk tier; components form an AI-BOM (models, datasets, libraries, agent tools).
 * Produces a risk-ranked worklist (high-risk / production / personal-data systems lacking guardrails
 * or governance). XORCISM.AISYSTEM + AISYSTEMCOMPONENT. Feeds the EU AI Act regulatory calendar.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();

export function ensureAiSystemTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS AISYSTEM (
      AISystemID INTEGER PRIMARY KEY, AISystemGUID TEXT, Name TEXT, Description TEXT, Purpose TEXT,
      Owner TEXT, Provider TEXT, ModelName TEXT, ModelType TEXT, Hosting TEXT,
      DataClassification TEXT, UsesPersonalData INTEGER DEFAULT 0, RiskTier TEXT, Lifecycle TEXT,
      Guardrails TEXT, Frameworks TEXT, Notes TEXT, Status TEXT, Endpoint TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS AISYSTEMCOMPONENT (
      ComponentID INTEGER PRIMARY KEY, ComponentGUID TEXT, AISystemID INTEGER, ComponentType TEXT,
      Name TEXT, Version TEXT, Provider TEXT, Source TEXT, License TEXT, Notes TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_aisys_tenant ON AISYSTEM(TenantID);
    CREATE INDEX IF NOT EXISTS ix_aiscomp_sys ON AISYSTEMCOMPONENT(AISystemID);
  `);
  // Endpoint (for live AI-BAS probing) added after the initial release — backfill on existing installs.
  try {
    const cols = new Set((getDb("XORCISM").prepare('PRAGMA table_info(AISYSTEM)').all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("Endpoint")) getDb("XORCISM").exec("ALTER TABLE AISYSTEM ADD COLUMN Endpoint TEXT");
  } catch { /* */ }
}

const RISK_TIERS = ["Prohibited", "High", "GPAI", "Limited", "Minimal"];

export interface AiSystem {
  id: number; name: string; description: string; purpose: string; owner: string; provider: string;
  modelName: string; modelType: string; hosting: string; dataClassification: string; usesPersonalData: boolean;
  riskTier: string; lifecycle: string; guardrails: string[]; frameworks: string[]; notes: string; status: string;
  endpoint: string;
}

/** Heuristic model-risk score 0-100 (higher = more attention). */
export function scoreSystem(s: AiSystem): { score: number; severity: string; gaps: string[] } {
  let score = 0; const gaps: string[] = [];
  const tierW: Record<string, number> = { Prohibited: 100, High: 55, GPAI: 40, Limited: 20, Minimal: 8 };
  score += tierW[s.riskTier] ?? 25;
  const prod = /prod/i.test(s.lifecycle);
  if (prod) score += 12;
  if (s.usesPersonalData) { score += 12; }
  if (/restricted|confidential|secret|pii|phi/i.test(s.dataClassification)) score += 10;
  if (!s.guardrails.length) { score += 18; gaps.push("No guardrails recorded"); }
  if (!s.frameworks.length) { score += 14; gaps.push("No governing framework (NIST AI RMF / ISO 42001 / AICM)"); }
  if (s.riskTier === "High" && !s.guardrails.length) gaps.push("High-risk AI Act system without guardrails");
  if (s.usesPersonalData && !/dpia|gdpr|27701/i.test(s.frameworks.join(" ") + " " + s.notes)) gaps.push("Personal data — DPIA / GDPR linkage not evidenced");
  if (s.riskTier === "Prohibited") gaps.push("Flagged as a prohibited AI practice (EU AI Act Art. 5) — review immediately");
  score = Math.max(0, Math.min(100, Math.round(score)));
  const severity = score >= 85 ? "Critical" : score >= 60 ? "High" : score >= 35 ? "Medium" : score >= 15 ? "Low" : "Info";
  return { score, severity, gaps };
}

const splitList = (s: string): string[] => (s || "").split(/[,;]/).map((x) => x.trim()).filter(Boolean);
function rowToSys(r: any): AiSystem {
  return {
    id: r.AISystemID, name: r.Name, description: r.Description, purpose: r.Purpose, owner: r.Owner,
    provider: r.Provider, modelName: r.ModelName, modelType: r.ModelType, hosting: r.Hosting,
    dataClassification: r.DataClassification, usesPersonalData: !!r.UsesPersonalData, riskTier: r.RiskTier,
    lifecycle: r.Lifecycle, guardrails: splitList(r.Guardrails), frameworks: splitList(r.Frameworks),
    notes: r.Notes || "", status: r.Status || "Active", endpoint: r.Endpoint || "",
  };
}

export function listSystems(tenant: number | null): any[] {
  ensureAiSystemTables();
  return (getDb("XORCISM").prepare(
    "SELECT * FROM AISYSTEM WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY Name"
  ).all(tenant) as any[]).map((r) => { const s = rowToSys(r); return { ...s, ...scoreSystem(s) }; });
}

export function aiSystemDashboard(tenant: number | null): any {
  const sys = listSystems(tenant);
  const count = (f: (s: any) => boolean): number => sys.filter(f).length;
  const byTier: Record<string, number> = {};
  for (const t of RISK_TIERS) byTier[t] = 0;
  for (const s of sys) byTier[s.riskTier] = (byTier[s.riskTier] || 0) + 1;
  const summary = {
    systems: sys.length,
    highRisk: count((s) => s.riskTier === "High" || s.riskTier === "Prohibited"),
    production: count((s) => /prod/i.test(s.lifecycle)),
    personalData: count((s) => s.usesPersonalData),
    ungoverned: count((s) => !s.frameworks.length),
    noGuardrails: count((s) => !s.guardrails.length),
    avgRisk: sys.length ? Math.round(sys.reduce((a, s) => a + s.score, 0) / sys.length) : 0,
  };
  const worklist = sys.filter((s) => s.gaps.length).sort((a, b) => b.score - a.score);
  return { summary, byTier, worklist, systems: sys.sort((a, b) => b.score - a.score), riskTiers: RISK_TIERS };
}

export function getSystem(id: number, tenant: number | null): any | null {
  ensureAiSystemTables();
  const r = getDb("XORCISM").prepare("SELECT * FROM AISYSTEM WHERE AISystemID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant) as any;
  if (!r) return null;
  const s = rowToSys(r);
  const comps = getDb("XORCISM").prepare("SELECT * FROM AISYSTEMCOMPONENT WHERE AISystemID=? ORDER BY ComponentType, Name").all(id) as any[];
  return { ...s, ...scoreSystem(s), components: comps.map((c) => ({ id: c.ComponentID, type: c.ComponentType, name: c.Name, version: c.Version, provider: c.Provider, source: c.Source, license: c.License, notes: c.Notes })) };
}

export function createSystem(tenant: number | null, b: Record<string, any>): number {
  ensureAiSystemTables();
  const db = getDb("XORCISM");
  const id = allocId(db, "AISYSTEM", "AISystemID");
  db.prepare(
    `INSERT INTO AISYSTEM (AISystemID, AISystemGUID, Name, Description, Purpose, Owner, Provider, ModelName, ModelType,
       Hosting, DataClassification, UsesPersonalData, RiskTier, Lifecycle, Guardrails, Frameworks, Notes, Status, Endpoint, TenantID, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(id, randomUUID(), String(b.name || "AI system").slice(0, 200), String(b.description || "").slice(0, 2000),
    String(b.purpose || "").slice(0, 500), String(b.owner || "").slice(0, 200), String(b.provider || "").slice(0, 200),
    String(b.modelName || "").slice(0, 200), String(b.modelType || "").slice(0, 80), String(b.hosting || "").slice(0, 80),
    String(b.dataClassification || "").slice(0, 80), b.usesPersonalData ? 1 : 0, String(b.riskTier || "Limited").slice(0, 40),
    String(b.lifecycle || "Development").slice(0, 40), String(b.guardrails || "").slice(0, 1000), String(b.frameworks || "").slice(0, 500),
    String(b.notes || "").slice(0, 2000), "Active", String(b.endpoint || "").slice(0, 500), tenant, now());
  return id;
}

export function addComponent(systemId: number, tenant: number | null, b: Record<string, any>): number | null {
  ensureAiSystemTables();
  const db = getDb("XORCISM");
  const owns = db.prepare("SELECT 1 FROM AISYSTEM WHERE AISystemID=? AND (TenantID = ? OR TenantID IS NULL)").get(systemId, tenant);
  if (!owns) return null;
  const id = allocId(db, "AISYSTEMCOMPONENT", "ComponentID");
  db.prepare(
    `INSERT INTO AISYSTEMCOMPONENT (ComponentID, ComponentGUID, AISystemID, ComponentType, Name, Version, Provider, Source, License, Notes, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  ).run(id, randomUUID(), systemId, String(b.type || "library").slice(0, 60), String(b.name || "component").slice(0, 200),
    String(b.version || "").slice(0, 80), String(b.provider || "").slice(0, 200), String(b.source || "").slice(0, 500),
    String(b.license || "").slice(0, 120), String(b.notes || "").slice(0, 1000), now());
  return id;
}

/** Export a system's AI-BOM as CycloneDX-flavoured JSON (ML-BOM components + metadata). */
export function exportAiBom(systemId: number, tenant: number | null): any | null {
  const s = getSystem(systemId, tenant);
  if (!s) return null;
  const typeMap: Record<string, string> = { model: "machine-learning-model", dataset: "data", library: "library", api: "library", "agent-tool": "application" };
  return {
    bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: {
      timestamp: now(),
      component: { type: "application", name: s.name, description: s.purpose || s.description },
      properties: [
        { name: "xorcism:riskTier", value: s.riskTier }, { name: "xorcism:lifecycle", value: s.lifecycle },
        { name: "xorcism:hosting", value: s.hosting }, { name: "xorcism:usesPersonalData", value: String(s.usesPersonalData) },
        { name: "xorcism:frameworks", value: s.frameworks.join(", ") }, { name: "xorcism:guardrails", value: s.guardrails.join(", ") },
      ],
    },
    components: [
      ...(s.modelName ? [{ type: "machine-learning-model", name: s.modelName, publisher: s.provider, properties: [{ name: "modelType", value: s.modelType }] }] : []),
      ...s.components.map((c: any) => ({ type: typeMap[c.type] || "library", name: c.name, version: c.version || undefined, publisher: c.provider || undefined, licenses: c.license ? [{ license: { name: c.license } }] : undefined, externalReferences: c.source ? [{ type: "distribution", url: c.source }] : undefined })),
    ],
  };
}

/** Demo seed (tenant only). */
export function seedAiSystemsDemo(tenant: number): number {
  ensureAiSystemTables();
  const demo = [
    { name: "Support copilot", purpose: "Customer-support answer drafting", provider: "OpenAI", modelName: "gpt-4o", modelType: "LLM", hosting: "SaaS", dataClassification: "Confidential", usesPersonalData: true, riskTier: "Limited", lifecycle: "Production", guardrails: "input filter, PII redaction", frameworks: "ISO 42001" },
    { name: "CV screening model", purpose: "Rank job applicants", provider: "In-house", modelName: "xgboost-hr-v3", modelType: "Classifier", hosting: "Self-hosted", dataClassification: "Restricted", usesPersonalData: true, riskTier: "High", lifecycle: "Production", guardrails: "", frameworks: "" },
    { name: "Fraud scoring", purpose: "Transaction fraud likelihood", provider: "In-house", modelName: "fraud-net", modelType: "Classifier", hosting: "Self-hosted", dataClassification: "Restricted", usesPersonalData: true, riskTier: "High", lifecycle: "Production", guardrails: "drift monitor, human review", frameworks: "NIST AI RMF" },
    { name: "Marketing image gen", purpose: "Generate campaign imagery", provider: "Stability", modelName: "sdxl", modelType: "Diffusion", hosting: "SaaS", dataClassification: "Public", usesPersonalData: false, riskTier: "Minimal", lifecycle: "Staging", guardrails: "content filter", frameworks: "AICM" },
  ];
  let n = 0;
  for (const d of demo) { createSystem(tenant, d); n++; }
  return n;
}
