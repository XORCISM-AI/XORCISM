/**
 * aveassess.ts — AVE behavioral assessment (a replication of the bawbel-scanner's intent).
 *
 * The AVE reference scanner inspects agentic-AI components (skill files, MCP manifests, system
 * prompts, agents) for behavioral vulnerability classes. XORCISM doesn't have the raw component
 * artifacts, but it DOES have a live inventory of discovered AI agents ([[ai-guardrails-management]]
 * / [[aware-agent-governance]] — XAGENT.AIAGENT, each with autonomy / tool-use / constraint-tier /
 * revoked flags). So we replicate the scanner's *mapping* step: derive each agent's behavioral
 * profile from its properties, match the applicable AVE classes (XVULNERABILITY.AVERECORD), and
 * decide exposed-vs-mitigated by the agent's AVE/AWARE governance tier. Results → XAGENT.AVEFINDING
 * (AIVSS-scored), surfaced as the "Agent exposure" view on /ave.
 */
import { getDb } from "./db";
import { getAgentDb } from "./agents";

const s = (v: unknown): string => (v == null ? "" : String(v));
const TIER_RANK: Record<string, number> = { "": 0, none: 0, T0: 0, T1: 1, T2: 2, T3: 3, T4: 4 };

/** Derive the behavioral-vector tags an agent exhibits, from its discovered properties. */
export function deriveAgentBehaviors(a: Record<string, any>): string[] {
  const tags = new Set<string>(["prompt-injection", "natural-language-input", "indirect"]);
  const autonomous = !!(a.autonomous && Number(a.autonomous) !== 0);
  const tools = !!(a.uses_tools && Number(a.uses_tools) !== 0);
  if (autonomous) { ["autonomy", "resource-abuse", "denial-of-wallet", "loop", "memory-poisoning", "persistence"].forEach((t) => tags.add(t)); }
  if (tools) { ["tool-use", "tool-misuse", "external-fetch", "confused-deputy", "tool-allowlist", "info-disclosure", "context-leak", "data-egress"].forEach((t) => tags.add(t)); }
  if (autonomous && tools) { ["supply-chain", "self-modification", "metamorphic", "privilege-escalation"].forEach((t) => tags.add(t)); }
  if (autonomous || s(a.parent_agent)) tags.add("multi-agent");
  return Array.from(tags);
}

/** The governance tier an AVE class of this severity needs to be considered mitigated. */
function requiredTier(severity: string): string {
  const sv = severity.toUpperCase();
  return sv === "CRITICAL" ? "T3" : sv === "HIGH" ? "T2" : "T1";
}

function ensureFindingTable(db: ReturnType<typeof getAgentDb>): void {
  db.exec(`CREATE TABLE IF NOT EXISTS AVEFINDING (
    FindingID INTEGER PRIMARY KEY AUTOINCREMENT, Agent TEXT, AgentName TEXT, AveId TEXT, Title TEXT,
    Severity TEXT, AivssScore REAL, ComponentType TEXT, BehavioralMatch TEXT, Status TEXT,
    RequiredTier TEXT, AgentTier TEXT, Rationale TEXT, AssessedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_avefind_agent ON AVEFINDING(Agent);
    CREATE INDEX IF NOT EXISTS ix_avefind_status ON AVEFINDING(Status);`);
}

const has = (db: any, t: string): boolean => { try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; } };

/** Run the assessment: discovered agents × applicable AVE classes → AVEFINDING (full snapshot). */
export function assessAgents(tenant: number | null): { assessed: number; findings: number; exposed: number; agents: number } {
  const xv = getDb("XVULNERABILITY");
  if (!has(xv, "AVERECORD")) return { assessed: 0, findings: 0, exposed: 0, agents: 0 };
  const records = xv.prepare("SELECT AveId, Title, Severity, AivssScore, ComponentType, BehavioralVector FROM AVERECORD").all() as any[];
  if (!records.length) return { assessed: 0, findings: 0, exposed: 0, agents: 0 };

  const db = getAgentDb();
  if (!has(db, "AIAGENT")) return { assessed: 0, findings: 0, exposed: 0, agents: 0 };
  ensureFindingTable(db);
  // latest row per agent name
  const agents = db.prepare(`SELECT a.* FROM AIAGENT a JOIN (SELECT name, MAX(AiAgentID) mx FROM AIAGENT WHERE name IS NOT NULL AND name<>'' GROUP BY name) g ON a.AiAgentID=g.mx`).all() as Record<string, any>[];
  const now = new Date().toISOString();

  db.prepare("DELETE FROM AVEFINDING WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").run(tenant);
  const ins = db.prepare(`INSERT INTO AVEFINDING (Agent, AgentName, AveId, Title, Severity, AivssScore, ComponentType, BehavioralMatch, Status, RequiredTier, AgentTier, Rationale, AssessedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  let findings = 0, exposed = 0;
  const tx = db.transaction(() => {
    for (const a of agents) {
      const behaviors = new Set(deriveAgentBehaviors(a));
      const tier = s(a.constraint_tier) || "none";
      const tierRank = TIER_RANK[tier] ?? 0;
      const revoked = !!(a.revoked && Number(a.revoked) !== 0);
      for (const r of records) {
        const ctype = s(r.ComponentType).toLowerCase();
        const vec = s(r.BehavioralVector).split(/,\s*/).map((x) => x.trim()).filter(Boolean);
        const match = vec.filter((v) => behaviors.has(v));
        const applies = ctype === "agent" || match.length > 0;
        if (!applies) continue;
        const req = requiredTier(s(r.Severity));
        let status: string, rationale: string;
        if (revoked) { status = "mitigated"; rationale = "agent revoked (kill-switch) — contained"; }
        else if (tierRank >= (TIER_RANK[req] ?? 1)) { status = "mitigated"; rationale = `governed at ${tier} ≥ required ${req}`; }
        else { status = "exposed"; rationale = `governance ${tier === "none" ? "ungoverned" : tier} < required ${req}`; }
        ins.run(s(a.agent) || s(a.name), s(a.name), s(r.AveId), s(r.Title), s(r.Severity), Number(r.AivssScore) || null,
          s(r.ComponentType), match.join(", ") || (ctype === "agent" ? "agent-class" : ""), status, req, tier, rationale, now, tenant);
        findings++; if (status === "exposed") exposed++;
      }
    }
  });
  tx();
  return { assessed: agents.length, findings, exposed, agents: agents.length };
}

/** Read the AVE exposure posture (run assessAgents first to populate). */
export function aveExposure(tenant: number | null): any {
  const db = getAgentDb();
  if (!has(db, "AVEFINDING")) return { summary: { agents: 0, findings: 0, exposed: 0 }, perAgent: [], byClass: [], topExposed: [] };
  const rows = db.prepare("SELECT * FROM AVEFINDING WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").all(tenant) as any[];
  const exposed = rows.filter((r) => r.Status === "exposed");
  const sev = (r: any) => s(r.Severity).toUpperCase();
  const agentsMap = new Map<string, any>();
  for (const r of rows) {
    const k = r.AgentName || r.Agent;
    if (!agentsMap.has(k)) agentsMap.set(k, { name: k, tier: r.AgentTier, exposed: 0, mitigated: 0, aivssRisk: 0, worst: "" });
    const m = agentsMap.get(k);
    if (r.Status === "exposed") { m.exposed++; m.aivssRisk += Number(r.AivssScore) || 0; if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(sev(r)) < ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(m.worst || "LOW")) m.worst = sev(r); }
    else m.mitigated++;
  }
  const perAgent = Array.from(agentsMap.values()).map((m) => ({ ...m, aivssRisk: Math.round(m.aivssRisk * 10) / 10 })).sort((a, b) => b.aivssRisk - a.aivssRisk);
  const classMap = new Map<string, any>();
  for (const r of exposed) {
    if (!classMap.has(r.AveId)) classMap.set(r.AveId, { aveId: r.AveId, title: r.Title, severity: r.Severity, exposedCount: 0 });
    classMap.get(r.AveId).exposedCount++;
  }
  const byClass = Array.from(classMap.values()).sort((a, b) => b.exposedCount - a.exposedCount);
  const topExposed = exposed.slice().sort((a, b) => (Number(b.AivssScore) || 0) - (Number(a.AivssScore) || 0)).slice(0, 20)
    .map((r) => ({ agent: r.AgentName, aveId: r.AveId, title: r.Title, severity: r.Severity, aivss: r.AivssScore, tier: r.AgentTier, match: r.BehavioralMatch, rationale: r.Rationale }));
  return {
    summary: {
      agents: agentsMap.size, findings: rows.length, exposed: exposed.length, mitigated: rows.length - exposed.length,
      criticalExposed: exposed.filter((r) => sev(r) === "CRITICAL").length,
      highExposed: exposed.filter((r) => sev(r) === "HIGH").length,
      aivssRisk: Math.round(exposed.reduce((n, r) => n + (Number(r.AivssScore) || 0), 0) * 10) / 10,
      worstAgent: perAgent[0]?.name || "",
    },
    perAgent, byClass, topExposed,
  };
}
