/**
 * aiskills.ts — AI Operations: a governed Skills & Prompt Library, an AI activity / decision
 * provenance log, and the CROC agent handover routing (/ai-skills).
 *
 * Inspired by Filigran XTM One's agentic layer (Skills / Agentic-Flow / Work-history), this is the
 * "govern your OWN agentic AI" surface for XORCISM — the counterpart to the AI inventory (other people's
 * models, aisystems.ts) and AI-BAS (red-team). Three things, one cockpit:
 *
 *   1. Skills & Prompt Library (AISKILL) — reusable, markdown-defined analyst skills/prompts with
 *      tags, source (inline / URL), enable-disable (so they inject into copilot prompts), visibility
 *      and a usage count. Turns the hardcoded aiassist copilots into an extensible, governable library.
 *   2. AI Activity Log (AIACTIVITY) — a record of every AI copilot/agent decision: actor, action,
 *      model/provider, linked entity, tokens, outcome. EU AI Act Art. 12 (record-keeping) + ISO 42001 /
 *      NIST AI RMF MANAGE-4 evidence. recordAiActivity() is the shared logging helper other modules call.
 *   3. Agent handover routing (AIHANDOVER + the orchestrator's default routes) — the "agentic flow":
 *      which loop-event type the CROC orchestrator delegates to which analyst copilot, with
 *      delegate / consult / transfer / escalate semantics, as an editable graph.
 *
 * The AI provider (local Ollama by default) is surfaced from ai.ts. XORCISM.AISKILL/AIACTIVITY/AIHANDOVER.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { aiProviderInfo } from "./ai";

const now = (): string => new Date().toISOString();

export const HANDOVER_TYPES = ["delegate", "consult", "transfer", "mandatory", "escalate"] as const;
export const SKILL_VISIBILITY = ["private", "tenant", "public"] as const;

/** The CROC orchestrator's built-in routing (propose() in orchestrator.ts), surfaced as the default
 *  handover graph: the orchestrator hub delegates each loop-event class to an analyst copilot. */
export const DEFAULT_ROUTES: { from: string; to: string; type: string; trigger: string }[] = [
  { from: "croc-orchestrator", to: "itdr-investigate", type: "delegate", trigger: "identity / signin / kerberos / account / mfa / cred" },
  { from: "croc-orchestrator", to: "exposure-brief", type: "delegate", trigger: "exposure / kev / exploit / vuln / cve / surface / drift" },
  { from: "croc-orchestrator", to: "incident-copilot", type: "delegate", trigger: "incident / alert / breach / ransom" },
  { from: "croc-orchestrator", to: "compliance-impl", type: "delegate", trigger: "compliance / control / finding / audit / policy / obligation" },
  { from: "croc-orchestrator", to: "ai-incident-response", type: "delegate", trigger: "anomaly / extraction / jailbreak / poison / prompt-injection" },
  { from: "croc-orchestrator", to: "ai-governance", type: "delegate", trigger: "ai / model / llm / prompt / guardrail" },
  { from: "croc-orchestrator", to: "threatdebt-paydown", type: "delegate", trigger: "threatdebt / adversary / opportunity / paydown" },
  { from: "croc-orchestrator", to: "soc-triage", type: "delegate", trigger: "(everything else — default)" },
  { from: "soc-triage", to: "incident-copilot", type: "transfer", trigger: "warrants an incident" },
  { from: "exposure-brief", to: "threatdebt-paydown", type: "consult", trigger: "price the fix" },
  { from: "incident-copilot", to: "human", type: "escalate", trigger: "scope grows / critical" },
];

export function ensureAiSkillsTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS AISKILL (
      SkillID INTEGER PRIMARY KEY, SkillGUID TEXT, Kind TEXT, Name TEXT, Description TEXT, Tags TEXT,
      Content TEXT, Source TEXT, Enabled INTEGER DEFAULT 1, Visibility TEXT, Version INTEGER DEFAULT 1,
      UsedCount INTEGER DEFAULT 0, Category TEXT, CreatedDate TEXT, UpdatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS AIACTIVITY (
      ActivityID INTEGER PRIMARY KEY, ActivityGUID TEXT, Actor TEXT, Action TEXT, Model TEXT, Provider TEXT,
      SkillID INTEGER, EntityType TEXT, EntityKey TEXT, Summary TEXT, TokensIn INTEGER, TokensOut INTEGER,
      Outcome TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS AIHANDOVER (
      RouteID INTEGER PRIMARY KEY, RouteGUID TEXT, FromAgent TEXT, ToAgent TEXT, Type TEXT, Trigger TEXT,
      Enabled INTEGER DEFAULT 1, Notes TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_aiskill_tenant ON AISKILL(TenantID);
    CREATE INDEX IF NOT EXISTS ix_aiactivity_tenant ON AIACTIVITY(TenantID, ActivityID);
    CREATE INDEX IF NOT EXISTS ix_aihandover_tenant ON AIHANDOVER(TenantID);
  `);
}

// ── Activity log (the shared helper other modules call) ──────────────────────
export interface AiActivity {
  actor: string; action: string; model?: string; provider?: string; skillId?: number | null;
  entityType?: string; entityKey?: string; summary?: string; tokensIn?: number; tokensOut?: number; outcome?: string;
}
/** Record one AI decision/invocation (best-effort; never throws into the caller). */
export function recordAiActivity(tenant: number | null, r: AiActivity): void {
  try {
    ensureAiSkillsTables();
    const db = getDb("XORCISM");
    const prov = r.provider || aiProviderInfo().provider;
    const id = allocId(db, "AIACTIVITY", "ActivityID");
    db.prepare(
      `INSERT INTO AIACTIVITY (ActivityID, ActivityGUID, Actor, Action, Model, Provider, SkillID, EntityType, EntityKey, Summary, TokensIn, TokensOut, Outcome, CreatedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(id, randomUUID(), String(r.actor || "ai").slice(0, 80), String(r.action || "invoke").slice(0, 80),
      String(r.model || aiProviderInfo().model).slice(0, 80), String(prov).slice(0, 60), r.skillId ?? null,
      String(r.entityType || "").slice(0, 60), String(r.entityKey || "").slice(0, 120), String(r.summary || "").slice(0, 600),
      r.tokensIn ?? null, r.tokensOut ?? null, String(r.outcome || "ok").slice(0, 40), now(), tenant);
  } catch { /* logging must never break the caller */ }
}

// ── Skills & Prompt library ──────────────────────────────────────────────────
function skillRow(r: any): any {
  return {
    id: r.SkillID, kind: r.Kind, name: r.Name, description: r.Description, tags: (r.Tags || "").split(",").map((x: string) => x.trim()).filter(Boolean),
    content: r.Content || "", source: r.Source || "inline", enabled: !!r.Enabled, visibility: r.Visibility || "tenant",
    version: r.Version || 1, usedCount: r.UsedCount || 0, category: r.Category || "", createdDate: r.CreatedDate, updatedDate: r.UpdatedDate,
  };
}

export function listSkills(tenant: number | null): any[] {
  ensureAiSkillsTables();
  return (getDb("XORCISM").prepare(
    "SELECT * FROM AISKILL WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY Kind, Name"
  ).all(tenant) as any[]).map(skillRow);
}

export function getSkill(id: number, tenant: number | null): any | null {
  ensureAiSkillsTables();
  const r = getDb("XORCISM").prepare("SELECT * FROM AISKILL WHERE SkillID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant) as any;
  return r ? skillRow(r) : null;
}

export function upsertSkill(tenant: number | null, b: Record<string, any>): { id: number } {
  ensureAiSkillsTables();
  const db = getDb("XORCISM");
  const kind = b.kind === "prompt" ? "prompt" : "skill";
  const vis = (SKILL_VISIBILITY as readonly string[]).includes(b.visibility) ? b.visibility : "tenant";
  const id = Number(b.id) > 0 ? Number(b.id) : 0;
  if (id) {
    const existing = db.prepare("SELECT Version FROM AISKILL WHERE SkillID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant) as any;
    if (!existing) return { id: 0 };
    db.prepare(
      `UPDATE AISKILL SET Kind=?, Name=?, Description=?, Tags=?, Content=?, Source=?, Visibility=?, Category=?, Version=?, UpdatedDate=? WHERE SkillID=?`
    ).run(kind, String(b.name || "").slice(0, 200), String(b.description || "").slice(0, 500), String(b.tags || "").slice(0, 300),
      String(b.content || "").slice(0, 20000), String(b.source || "inline").slice(0, 500), vis, String(b.category || "").slice(0, 80),
      (existing.Version || 1) + 1, now(), id);
    return { id };
  }
  const nid = allocId(db, "AISKILL", "SkillID");
  db.prepare(
    `INSERT INTO AISKILL (SkillID, SkillGUID, Kind, Name, Description, Tags, Content, Source, Enabled, Visibility, Version, UsedCount, Category, CreatedDate, UpdatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(nid, randomUUID(), kind, String(b.name || "Untitled skill").slice(0, 200), String(b.description || "").slice(0, 500),
    String(b.tags || "").slice(0, 300), String(b.content || "").slice(0, 20000), String(b.source || "inline").slice(0, 500),
    b.enabled === false ? 0 : 1, vis, 1, 0, String(b.category || "").slice(0, 80), now(), now(), tenant);
  return { id: nid };
}

export function toggleSkill(id: number, tenant: number | null, enabled: boolean): boolean {
  ensureAiSkillsTables();
  const r = getDb("XORCISM").prepare("UPDATE AISKILL SET Enabled=?, UpdatedDate=? WHERE SkillID=? AND (TenantID = ? OR TenantID IS NULL)")
    .run(enabled ? 1 : 0, now(), id, tenant);
  return r.changes > 0;
}

/** Mark a skill as invoked — bumps usage and writes an activity record. */
export function useSkill(id: number, tenant: number | null, by: string): { ok: boolean } {
  ensureAiSkillsTables();
  const db = getDb("XORCISM");
  const s = db.prepare("SELECT Name, Enabled FROM AISKILL WHERE SkillID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant) as any;
  if (!s) return { ok: false };
  db.prepare("UPDATE AISKILL SET UsedCount=COALESCE(UsedCount,0)+1, UpdatedDate=? WHERE SkillID=?").run(now(), id);
  recordAiActivity(tenant, { actor: by || "copilot", action: "skill.invoked", skillId: id, entityType: "AISKILL", entityKey: String(id), summary: `Skill used: ${s.Name}`, outcome: s.Enabled ? "ok" : "disabled" });
  return { ok: true };
}

// ── Handover routing (the agentic flow graph) ────────────────────────────────
export function handoverGraph(tenant: number | null): any {
  ensureAiSkillsTables();
  const custom = (getDb("XORCISM").prepare(
    "SELECT * FROM AIHANDOVER WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY RouteID"
  ).all(tenant) as any[]).map((r) => ({ id: r.RouteID, from: r.FromAgent, to: r.ToAgent, type: r.Type, trigger: r.Trigger, enabled: !!r.Enabled, source: "custom" }));
  const def = DEFAULT_ROUTES.map((r) => ({ ...r, enabled: true, source: "default" }));
  const edges = [...def, ...custom];
  const nodes = [...new Set(edges.flatMap((e) => [e.from, e.to]))].map((n) => ({
    id: n, role: n === "croc-orchestrator" ? "hub" : n === "human" ? "human" : "copilot",
  }));
  return { nodes, edges, types: HANDOVER_TYPES };
}

export function addHandover(tenant: number | null, b: Record<string, any>): { id: number } | null {
  ensureAiSkillsTables();
  const type = (HANDOVER_TYPES as readonly string[]).includes(b.type) ? b.type : "delegate";
  if (!b.from || !b.to) return null;
  const db = getDb("XORCISM");
  const id = allocId(db, "AIHANDOVER", "RouteID");
  db.prepare(
    "INSERT INTO AIHANDOVER (RouteID, RouteGUID, FromAgent, ToAgent, Type, Trigger, Enabled, Notes, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)"
  ).run(id, randomUUID(), String(b.from).slice(0, 80), String(b.to).slice(0, 80), type, String(b.trigger || "").slice(0, 200), b.enabled === false ? 0 : 1, String(b.notes || "").slice(0, 500), now(), tenant);
  return { id };
}

export function deleteHandover(id: number, tenant: number | null): boolean {
  ensureAiSkillsTables();
  return getDb("XORCISM").prepare("DELETE FROM AIHANDOVER WHERE RouteID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant).changes > 0;
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export function aiSkillsDashboard(tenant: number | null): any {
  ensureAiSkillsTables();
  const db = getDb("XORCISM");
  const skills = listSkills(tenant);
  const activity = (db.prepare(
    "SELECT * FROM AIACTIVITY WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY ActivityID DESC LIMIT 100"
  ).all(tenant) as any[]).map((r) => ({
    id: r.ActivityID, actor: r.Actor, action: r.Action, model: r.Model, provider: r.Provider, skillId: r.SkillID,
    entityType: r.EntityType, entityKey: r.EntityKey, summary: r.Summary, tokensIn: r.TokensIn, tokensOut: r.TokensOut,
    outcome: r.Outcome, createdDate: r.CreatedDate,
  }));
  const total = db.prepare("SELECT COUNT(*) n FROM AIACTIVITY WHERE (TenantID = ? OR TenantID IS NULL)").get(tenant) as { n: number };
  const byActor: Record<string, number> = {};
  for (const a of activity) byActor[a.actor] = (byActor[a.actor] || 0) + 1;
  const summary = {
    skills: skills.filter((s) => s.kind === "skill").length,
    prompts: skills.filter((s) => s.kind === "prompt").length,
    enabled: skills.filter((s) => s.enabled).length,
    activity: total.n,
    routes: DEFAULT_ROUTES.length + (db.prepare("SELECT COUNT(*) n FROM AIHANDOVER WHERE (TenantID = ? OR TenantID IS NULL)").get(tenant) as { n: number }).n,
  };
  return {
    summary, skills, activity, byActor,
    handover: handoverGraph(tenant),
    provider: aiProviderInfo(),
    visibilities: SKILL_VISIBILITY,
  };
}

/** Demo seed (tenant only): a few skills/prompts mirroring real copilots + sample activity. */
export function seedAiSkillsDemo(tenant: number): { skills: number } | null {
  ensureAiSkillsTables();
  const db = getDb("XORCISM");
  if ((db.prepare("SELECT COUNT(*) n FROM AISKILL WHERE TenantID=?").get(tenant) as { n: number }).n > 0) return null;
  const demo = [
    { kind: "skill", name: "Attack-chain analyst", category: "Exposure", tags: "attack-path,red-team,blue-team", description: "Read a tool-chain run and explain the exploitation path + the blue-team detection/mitigation per step.", content: "# Attack-chain analyst\nGiven a chain run, for each step state: the technique (ATT&CK), what an attacker gains, and the single highest-leverage detection or mitigation. End with the one choke point to fix first." },
    { kind: "skill", name: "Exposure brief (CISO)", category: "Exposure", tags: "ciso,board,exposure", description: "Turn the prioritized exposure worklist into a 5-line CISO brief.", content: "# Exposure brief\nSummarize the top exposures by fused score (EPSS+KEV+exploit+blast). Lead with business impact, then the few fixes that cut the most risk. No jargon." },
    { kind: "skill", name: "Incident report (NIST 800-61)", category: "SOC", tags: "incident,ir,soc", description: "Draft a contain→eradicate→recover incident write-up from the alert + asset context.", content: "# Incident report\nProduce: summary, timeline, impacted assets, containment actions, eradication, recovery, lessons learned. Map actions to NIST 800-61 phases." },
    { kind: "skill", name: "Threat model (STRIDE)", category: "AppSec", tags: "threat-model,stride,design", description: "Generate a STRIDE threat model for a described system/data-flow.", content: "# STRIDE threat model\nFor each element and trust boundary, enumerate Spoofing/Tampering/Repudiation/Info-disclosure/DoS/Elevation threats with a mitigation and a residual-risk note." },
    { kind: "prompt", name: "Phishing triage", category: "SOC", tags: "phishing,triage,prompt", description: "Verdict a reported email as phish / spam / benign with indicators and a user-coaching line.", content: "You are a SOC analyst. Given a reported email (headers, body, URLs), return: verdict, the indicators that drove it, recommended action, and one coaching sentence for the reporter." },
    { kind: "prompt", name: "Compliance gap explainer", category: "GRC", tags: "compliance,grc,prompt", description: "Explain a failing control and a concrete remediation an owner can action.", content: "You are a GRC analyst. Given a failing control and its evidence, explain the gap in plain language and propose a concrete, assignable remediation with a due-date suggestion." },
  ];
  for (const d of demo) upsertSkill(tenant, d);
  // a little activity history so the log isn't empty
  recordAiActivity(tenant, { actor: "exposure-brief", action: "copilot.run", entityType: "EXPOSURE", summary: "Generated CISO exposure brief (top 8 exposures).", tokensIn: 1840, tokensOut: 420 });
  recordAiActivity(tenant, { actor: "incident-copilot", action: "copilot.run", entityType: "INCIDENT", summary: "Drafted incident report for a high-severity alert.", tokensIn: 2100, tokensOut: 680 });
  recordAiActivity(tenant, { actor: "croc-orchestrator", action: "orchestrator.propose", entityType: "LOOPEVENT", summary: "Proposed containment for an AI runtime anomaly (delegate → ai-incident-response).", outcome: "proposed" });
  return { skills: demo.length };
}
