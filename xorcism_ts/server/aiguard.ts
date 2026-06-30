/**
 * aiguard.ts — AI-agent guardrails management.
 *
 * The operational layer for guarding LLM apps / autonomous AI agents, fed by the XOR endpoint
 * agent (kind "aiguard") and an optional inline gateway connector. It covers four of the five
 * guardrail-lifecycle functions (enforcement stays with an in-band gateway, not the endpoint agent):
 *   1. DISCOVER  — AI agents/LLM apps/MCP servers/local models running on each host (signals).
 *   2. ASSESS    — score each discovered agent against the AI Guardrail Baseline (12 controls,
 *                  cross-mapped to OWASP AI Exchange, SAIF, ISO/IEC 42001, OWASP LLM Top 10, MITRE
 *                  ATLAS, NIST AI RMF).
 *   3. MONITOR   — analyse AI-agent traces (prompts/responses/tool-calls) with heuristics + the
 *                  LOCAL AI for guardrail violations (prompt injection, jailbreak, exfil, excessive
 *                  agency) → AIGUARDRAILVIOLATION + a spawned hunt.
 *   4. GOVERN    — roll the posture up to the baseline + framework coverage (the cockpit).
 *
 * Tables (XAGENT): AIAGENT, AIGUARDRAILRESULT, AIGUARDRAILVIOLATION. Privacy: AI traces are analysed
 * by the LOCAL Ollama; only verdicts are stored, never the raw prompts.
 */
import { createHash } from "crypto";
import { getAgentDb, addAgentEvent, listAgents } from "./agents";
import { ollamaChat } from "./ai";
import { saveHunt } from "./hunting";
import { getDb } from "./db";

const nowSql = (): string => new Date().toISOString().slice(0, 19).replace("T", " ");

// ── The AI Guardrail Baseline (a "CIS Benchmark for AI agents") ──────────────────
export interface GuardrailControl {
  id: string; title: string; category: string; description: string; weight: number;
  frameworks: { aix?: string; saif?: string; iso42001?: string; llm?: string; atlas?: string; nist?: string };
}
export const GUARDRAIL_BASELINE: GuardrailControl[] = [
  { id: "guardrail-runtime", title: "Runtime guardrail engine deployed", category: "Enforcement", weight: 3,
    description: "Inputs/outputs pass through a guardrail engine (NeMo Guardrails, LLM Guard, Llama Guard, Lakera…) rather than reaching the model unfiltered.",
    frameworks: { aix: "AIX-01", saif: "Input validation & sanitization", iso42001: "A.6.2.4", llm: "LLM01 Prompt Injection", atlas: "AML.M0015", nist: "MANAGE-2.2" } },
  { id: "input-filter", title: "Input filtering / prompt-injection detection", category: "Input", weight: 3,
    description: "User and tool inputs are screened for prompt-injection / jailbreak patterns before they reach the model.",
    frameworks: { aix: "AIX-01/02", saif: "Input validation", iso42001: "A.6.2.4", llm: "LLM01 Prompt Injection", atlas: "AML.T0051", nist: "MEASURE-2.7" } },
  { id: "output-filter", title: "Output filtering & PII/secret redaction", category: "Output", weight: 2,
    description: "Model outputs are filtered for sensitive-data disclosure, secrets, and unsafe content before use or display.",
    frameworks: { aix: "AIX-29", iso42001: "A.8.3", llm: "LLM02 Sensitive Info Disclosure / LLM05 Improper Output Handling", atlas: "AML.T0024" } },
  { id: "tool-allowlist", title: "Tool-use allow-listing & least privilege", category: "Agency", weight: 3,
    description: "The agent can only call an explicit allow-list of tools/APIs, each scoped to least privilege.",
    frameworks: { aix: "AIX-03", saif: "Agent permissions", iso42001: "A.6.2.2", llm: "LLM06 Excessive Agency", atlas: "AML.M0015" } },
  { id: "hitl", title: "Human-in-the-loop for high-impact actions", category: "Agency", weight: 2,
    description: "Irreversible/high-impact actions (payments, data deletion, external sends) require human approval.",
    frameworks: { aix: "AIX-03/06", iso42001: "A.9.2", llm: "LLM06 Excessive Agency", nist: "GOVERN-1.2" } },
  { id: "prompt-hardening", title: "System-prompt hardening & no secrets in prompts", category: "Input", weight: 1,
    description: "System prompts are hardened against override/leak and contain no credentials or secrets.",
    frameworks: { aix: "AIX-29", llm: "LLM07 System Prompt Leakage" } },
  { id: "rag-provenance", title: "Untrusted-content handling for RAG/memory", category: "Data", weight: 2,
    description: "Retrieved/external content (web, docs, tool output) is treated as untrusted (indirect-injection defenses, provenance).",
    frameworks: { aix: "AIX-02", saif: "Data provenance", llm: "LLM08 Vector/Embedding Weaknesses", atlas: "AML.T0051" } },
  { id: "rate-cost-limits", title: "Rate / cost / loop limits", category: "Availability", weight: 1,
    description: "Token/cost budgets, request rate limits and recursion/step caps bound denial-of-wallet & runaway loops.",
    frameworks: { llm: "LLM10 Unbounded Consumption", iso42001: "A.6.2.6", nist: "MANAGE-2.1" } },
  { id: "audit-logging", title: "Prompt/response/tool-call audit logging", category: "Observability", weight: 2,
    description: "All prompts, responses and tool calls are logged for monitoring, investigation and accountability.",
    frameworks: { iso42001: "A.9.2", saif: "Logging & monitoring", nist: "MEASURE-2.6" } },
  { id: "model-pinning", title: "Model & dependency pinning (supply chain)", category: "Supply chain", weight: 1,
    description: "Model versions and AI dependencies are pinned/verified against tampering and poisoning.",
    frameworks: { llm: "LLM03 Supply Chain / LLM04 Data & Model Poisoning", saif: "Model provenance", atlas: "AML.T0010" } },
  { id: "sandboxing", title: "Tool/code-execution sandboxing & egress control", category: "Containment", weight: 2,
    description: "Code-execution and tool calls run sandboxed with controlled network egress (no arbitrary outbound).",
    frameworks: { aix: "AIX-03", iso42001: "A.6.2.6", llm: "LLM06 Excessive Agency" } },
  { id: "secrets-hygiene", title: "Secrets out of the agent environment", category: "Secrets", weight: 2,
    description: "API keys / credentials are not exposed in the agent's environment, config or prompts (use a secret manager).",
    frameworks: { aix: "AIX-29", llm: "LLM02 Sensitive Info Disclosure", iso42001: "A.6.2.4" } },
];
const BASELINE_BY_ID = new Map(GUARDRAIL_BASELINE.map((c) => [c.id, c]));

// Known guardrail tools/gateways (inventory + signal matching + the TOOL catalogue seed).
export const GUARDRAIL_TOOLS: { name: string; pkg: string[]; kind: string; url: string }[] = [
  { name: "NVIDIA NeMo Guardrails", pkg: ["nemoguardrails"], kind: "Guardrail engine", url: "https://github.com/NVIDIA/NeMo-Guardrails" },
  { name: "LLM Guard", pkg: ["llm-guard", "llm_guard"], kind: "Guardrail engine", url: "https://github.com/protectai/llm-guard" },
  { name: "Guardrails AI", pkg: ["guardrails-ai", "guardrails"], kind: "Guardrail framework", url: "https://github.com/guardrails-ai/guardrails" },
  { name: "Meta Llama Guard", pkg: ["llama-guard", "llamaguard"], kind: "Safety classifier", url: "https://github.com/meta-llama/PurpleLlama" },
  { name: "Rebuff", pkg: ["rebuff"], kind: "Prompt-injection detector", url: "https://github.com/protectai/rebuff" },
  { name: "Lakera Guard", pkg: ["lakera", "lakera-chainguard"], kind: "Guardrail API", url: "https://www.lakera.ai" },
  { name: "Protect AI Guardian / Recon", pkg: ["protectai", "modelscan"], kind: "Model & AI security", url: "https://protectai.com" },
];
const TOOL_BY_PKG = new Map<string, string>();
for (const t of GUARDRAIL_TOOLS) for (const p of t.pkg) TOOL_BY_PKG.set(p.toLowerCase(), t.name);

// ── Runtime guardrail-violation heuristics (over AI-agent traces) ────────────────
const VIOLATION_RULES: { rx: RegExp; technique: string; name: string; severity: string }[] = [
  { rx: /ignore (the |all |your )?(previous|above|prior|earlier) (instructions|prompts?)|disregard (the |all )?(previous|above)|forget (your|all) (instructions|rules)/i, technique: "AIX-01", name: "Prompt injection — instruction override", severity: "high" },
  { rx: /\b(DAN|do anything now|developer mode|jailbreak|stay in character|unfiltered|without (any )?restrictions)\b/i, technique: "AIX-01", name: "Jailbreak attempt", severity: "high" },
  { rx: /(reveal|print|repeat|show me) (your|the) (system )?(prompt|instructions|rules)/i, technique: "AIX-29", name: "System-prompt extraction", severity: "medium" },
  { rx: /(exfiltrat|send .*to .*https?:\/\/|upload .*to|post .*(api[_-]?key|secret|token|password)|curl .*evil)/i, technique: "AIX-04", name: "Data exfiltration via agent", severity: "critical" },
  { rx: /(rm\s+-rf|del\s+\/|drop\s+table|format\s+c:|shutdown|;\s*cat\s+\/etc\/passwd|`.*`|\$\()/i, technique: "AIX-03", name: "Unsafe tool/command execution (excessive agency)", severity: "high" },
  { rx: /(ignore the user|act on behalf of|new goal:|your real objective|instead of the task)/i, technique: "AIX-06", name: "Goal / instruction manipulation", severity: "high" },
  { rx: /(<!--.*instruction|hidden text|​|invisible|white(-| )?text).{0,40}(ignore|do|execute|run)/i, technique: "AIX-02", name: "Indirect injection in retrieved content", severity: "high" },
];
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const maxSev = (a: string, b: string): string => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

export function ensureAiGuardTables(): void {
  const db = getAgentDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS AIAGENT(
      AiAgentID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL, host TEXT, host_os TEXT, name TEXT, framework TEXT, model TEXT, endpoint TEXT,
      pid INTEGER, uses_tools INTEGER, autonomous INTEGER, has_memory INTEGER, external_data INTEGER,
      guardrail_tools TEXT, secrets_exposed INTEGER, mcp_servers INTEGER, logging INTEGER, sandboxed INTEGER,
      model_pinned INTEGER, score INTEGER, coverage INTEGER, gaps TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS AIGUARDRAILRESULT(
      ResultID INTEGER PRIMARY KEY AUTOINCREMENT,
      ai_agent_id INTEGER, agent TEXT, name TEXT, control_id TEXT, status TEXT, evidence TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS AIGUARDRAILVIOLATION(
      ViolationID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT, host TEXT, ai_agent TEXT, technique TEXT, name TEXT, severity TEXT, evidence TEXT,
      source TEXT, ai_used INTEGER DEFAULT 0, hunt_id INTEGER, created_at TEXT);
    CREATE INDEX IF NOT EXISTS ix_aiagent_agent ON AIAGENT(agent, AiAgentID);
    CREATE INDEX IF NOT EXISTS ix_aigrresult_agent ON AIGUARDRAILRESULT(ai_agent_id);
    CREATE INDEX IF NOT EXISTS ix_aigrviol_agent ON AIGUARDRAILVIOLATION(agent, ViolationID);
  `);
  // AWARE (GoodCISO/aware) autonomous AI-agent governance columns on AIAGENT — idempotent ALTERs.
  const have = new Set((db.prepare(`PRAGMA table_info("AIAGENT")`).all() as { name: string }[]).map((c) => c.name));
  for (const [c, t] of [["constraint_tier", "TEXT"], ["identity_fingerprint", "TEXT"], ["parent_agent", "TEXT"], ["revoked", "INTEGER DEFAULT 0"], ["revoked_reason", "TEXT"], ["governance_source", "TEXT"]] as [string, string][]) {
    if (!have.has(c)) { try { db.prepare(`ALTER TABLE AIAGENT ADD COLUMN ${c} ${t}`).run(); } catch { /* best-effort */ } }
  }
}

export interface AiAgentSignal {
  name?: string; framework?: string; model?: string; endpoint?: string; pid?: number;
  tools?: boolean | string[]; autonomous?: boolean; memory?: boolean; external?: boolean;
  guardrailLibs?: string[]; secretsExposed?: number; mcpServers?: number; logging?: boolean;
  sandboxed?: boolean; modelPinned?: boolean;
}

/** Evaluate one discovered AI agent against the baseline from its discovery signals. */
function deriveChecks(s: AiAgentSignal): { control_id: string; status: string; evidence: string }[] {
  const libs = (s.guardrailLibs || []).map((l) => String(l).toLowerCase());
  const hasGuard = libs.length > 0;
  const guardNames = [...new Set(libs.map((l) => TOOL_BY_PKG.get(l) || l))];
  const usesTools = Array.isArray(s.tools) ? s.tools.length > 0 : !!s.tools;
  const secrets = Number(s.secretsExposed || 0);
  const U = "unknown";
  const out: Record<string, { status: string; evidence: string }> = {};
  out["guardrail-runtime"] = hasGuard ? { status: "pass", evidence: "guardrail lib detected: " + guardNames.join(", ") } : { status: "fail", evidence: "no guardrail engine detected on this agent" };
  out["input-filter"] = hasGuard ? { status: "pass", evidence: "guardrail (" + guardNames.join(", ") + ") can screen inputs" } : { status: usesTools || s.autonomous ? "fail" : U, evidence: hasGuard ? "" : "no input-screening guardrail detected" };
  out["output-filter"] = hasGuard ? { status: "pass", evidence: "guardrail can redact/filter outputs" } : { status: U, evidence: "output filtering not determinable from the host" };
  out["tool-allowlist"] = usesTools ? { status: U, evidence: "agent uses tools — verify an explicit allow-list & least privilege" } : { status: "pass", evidence: "no tool use detected (no agency to over-scope)" };
  out["hitl"] = (usesTools && s.autonomous) ? { status: "fail", evidence: "autonomous + tool-using — confirm human approval for high-impact actions" } : { status: U, evidence: "approval workflow not determinable from the host" };
  out["prompt-hardening"] = { status: U, evidence: "system-prompt hardening is an app-design check" };
  out["rag-provenance"] = s.external ? { status: "fail", evidence: "ingests external data — apply indirect-injection defenses & provenance" } : { status: U, evidence: "external-data ingestion not detected" };
  out["rate-cost-limits"] = { status: U, evidence: "rate/cost limits are an app/gateway config check" };
  out["audit-logging"] = { status: s.logging ? "pass" : "fail", evidence: s.logging ? "trace/log configuration detected" : "no prompt/response/tool-call logging detected" };
  out["model-pinning"] = { status: s.modelPinned ? "pass" : U, evidence: s.modelPinned ? "model/deps pinned" : "model pinning not determinable" };
  out["sandboxing"] = { status: s.sandboxed ? "pass" : (usesTools ? "fail" : U), evidence: s.sandboxed ? "runs sandboxed (container)" : usesTools ? "tool-using and not sandboxed" : "no tool execution to sandbox" };
  out["secrets-hygiene"] = { status: secrets > 0 ? "fail" : "pass", evidence: secrets > 0 ? secrets + " API key(s)/secret(s) exposed in the agent environment" : "no plaintext secrets detected in the environment" };
  return GUARDRAIL_BASELINE.map((c) => ({ control_id: c.id, status: out[c.id]?.status ?? U, evidence: out[c.id]?.evidence ?? "" }));
}

function scoreOf(checks: { control_id: string; status: string }[]): { score: number; coverage: number; gaps: string[] } {
  let wTotal = 0, wPass = 0, assessed = 0;
  const gaps: string[] = [];
  for (const c of checks) {
    const ctl = BASELINE_BY_ID.get(c.control_id); if (!ctl) continue;
    if (c.status === "pass" || c.status === "fail") { wTotal += ctl.weight; assessed++; if (c.status === "pass") wPass += ctl.weight; else gaps.push(c.control_id); }
  }
  const score = wTotal ? Math.round((wPass / wTotal) * 100) : 0;
  const coverage = Math.round((assessed / GUARDRAIL_BASELINE.length) * 100);
  return { score, coverage, gaps };
}

export interface AiGuardPayload { host?: string; os?: string; agents?: AiAgentSignal[]; traces?: { raw?: string }[] }

/** Ingest an agent's AI-guardrail discovery + posture + (optional) trace monitoring. */
export async function recordAiGuardScan(agent: string, payload: AiGuardPayload): Promise<{ discovered: number; violations: number; avgScore: number | null }> {
  ensureAiGuardTables();
  const db = getAgentDb();
  const meta = listAgents().find((x) => x.name === agent);
  const host = String(payload.host || meta?.asset_name || agent).slice(0, 200);
  const os = String(payload.os || meta?.os || "").slice(0, 120);
  const discovered = Array.isArray(payload.agents) ? payload.agents.slice(0, 200) : [];

  const insAgent = db.prepare(`INSERT INTO AIAGENT(agent,host,host_os,name,framework,model,endpoint,pid,uses_tools,autonomous,has_memory,external_data,guardrail_tools,secrets_exposed,mcp_servers,logging,sandboxed,model_pinned,score,coverage,gaps,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insRes = db.prepare(`INSERT INTO AIGUARDRAILRESULT(ai_agent_id,agent,name,control_id,status,evidence,created_at) VALUES (?,?,?,?,?,?,?)`);
  const scores: number[] = [];
  const tx = db.transaction(() => {
    for (const s of discovered) {
      const checks = deriveChecks(s);
      const { score, coverage, gaps } = scoreOf(checks);
      scores.push(score);
      const libs = (s.guardrailLibs || []).map((l) => TOOL_BY_PKG.get(String(l).toLowerCase()) || l);
      const usesTools = Array.isArray(s.tools) ? s.tools.length > 0 : !!s.tools;
      const r = insAgent.run(agent, host, os, String(s.name || s.framework || "ai-agent").slice(0, 200),
        String(s.framework || "").slice(0, 80), String(s.model || "").slice(0, 120), String(s.endpoint || "").slice(0, 120),
        s.pid != null ? Number(s.pid) : null, usesTools ? 1 : 0, s.autonomous ? 1 : 0, s.memory ? 1 : 0, s.external ? 1 : 0,
        libs.join(", ") || null, Number(s.secretsExposed || 0), Number(s.mcpServers || 0), s.logging ? 1 : 0,
        s.sandboxed ? 1 : 0, s.modelPinned ? 1 : 0, score, coverage, gaps.join(", "), nowSql());
      const aid = Number(r.lastInsertRowid);
      for (const c of checks) insRes.run(aid, agent, String(s.name || "ai-agent"), c.control_id, c.status, c.evidence.slice(0, 500), nowSql());
    }
  });
  tx();

  // Runtime monitoring of any submitted traces (heuristics + local AI).
  let violations = 0;
  if (Array.isArray(payload.traces) && payload.traces.length) {
    violations = await monitorTraces(agent, host, payload.traces);
  }

  const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
  const worst = Math.min(...(scores.length ? scores : [100]));
  addAgentEvent(agent, {
    type: "ai_guardrail_scan",
    severity: worst < 40 || violations ? "high" : worst < 70 ? "medium" : "info",
    title: `AI guardrails: ${discovered.length} agent(s) discovered, avg posture ${avgScore ?? "n/a"}%${violations ? `, ${violations} runtime violation(s)` : ""}`,
    detail: { discovered: discovered.length, avgScore, violations, host },
  });
  return { discovered: discovered.length, violations, avgScore };
}

/** Analyse AI-agent traces for guardrail violations (heuristics + local AI); spawn a hunt if severe. */
async function monitorTraces(agent: string, host: string, traces: { raw?: string }[]): Promise<number> {
  const db = getAgentDb();
  const lines = traces.slice(0, 400).map((t) => String(t.raw || "")).filter(Boolean);
  const hits: { technique: string; name: string; severity: string; evidence: string }[] = [];
  let severity = "info";
  for (const line of lines) for (const r of VIOLATION_RULES) if (r.rx.test(line)) { hits.push({ technique: r.technique, name: r.name, severity: r.severity, evidence: line.slice(0, 240) }); severity = maxSev(severity, r.severity); }
  const seen = new Set<string>();
  const uniq = hits.filter((h) => { const k = `${h.technique}|${h.evidence}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 60);
  if (!uniq.length) return 0;

  let ai = false;
  try {
    const sys = "You are an AI-security analyst. Given AI agent traces (prompts/responses/tool-calls) and heuristic flags, confirm in one line whether a guardrail was violated (prompt injection, jailbreak, data exfiltration, excessive agency) and name the responsible technique. Be terse; do not invent.";
    const user = `HOST ${host}\nFLAGS:\n${uniq.slice(0, 20).map((h) => `- ${h.severity.toUpperCase()} ${h.technique} ${h.name}: ${h.evidence}`).join("\n")}\nTRACES:\n${lines.slice(0, 60).map((l) => l.slice(0, 240)).join("\n").slice(0, 6000)}`;
    const out = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user }], 0.2, 60000);
    ai = !!out;
  } catch { ai = false; }

  let huntId: number | null = null;
  if (SEV_RANK[severity] >= SEV_RANK.high) {
    try {
      const sv = saveHunt({
        name: `AI guardrail violation: ${host}`.slice(0, 200),
        description: `Guardrail violations detected in AI-agent traces on ${host}: ${uniq.map((h) => h.name).join("; ")}`.slice(0, 8000),
        status: "In progress", tool: "AI guardrail monitor", source: `agent:${host}`,
        findings: uniq.map((h) => `${h.severity.toUpperCase()} ${h.technique} ${h.name}: ${h.evidence}`).join("\n").slice(0, 8000),
        techniques: [],
      });
      huntId = sv.huntId;
      try {
        const xt = getDb("XTHREAT");
        const cols = new Set((xt.prepare(`PRAGMA table_info("HUNT")`).all() as { name: string }[]).map((c) => c.name));
        if (cols.has("TahitiTrigger")) xt.prepare(`UPDATE HUNT SET TahitiPhase=?, TahitiTrigger=? WHERE HuntID=?`).run("Hunt", "Security Monitoring", huntId);
      } catch { /* */ }
    } catch { huntId = null; }
  }
  const ins = db.prepare(`INSERT INTO AIGUARDRAILVIOLATION(agent,host,ai_agent,technique,name,severity,evidence,source,ai_used,hunt_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
  const tx = db.transaction(() => { for (const h of uniq) ins.run(agent, host, null, h.technique, h.name, h.severity, h.evidence, "agent-trace", ai ? 1 : 0, huntId, nowSql()); });
  tx();
  addAgentEvent(agent, {
    type: "ai_guardrail_violation", severity: SEV_RANK[severity] >= SEV_RANK.high ? "high" : "medium",
    title: `AI guardrail: ${uniq.length} violation(s) — ${severity.toUpperCase()}${huntId ? ` → hunt #${huntId}` : ""}`,
    detail: { violations: uniq.length, severity, techniques: [...new Set(uniq.map((h) => h.technique))], ai, huntId },
  });
  return uniq.length;
}

/** Ingest inline-gateway telemetry (blocked/allowed prompts) as guardrail violations. Used by the
 *  guardrail-gateway connectors so enforcement events land alongside the agent's posture data. */
export function ingestGatewayTelemetry(source: string, host: string, events: { rule?: string; action?: string; severity?: string; detail?: string; technique?: string }[]): { stored: number } {
  ensureAiGuardTables();
  const db = getAgentDb();
  const ins = db.prepare(`INSERT INTO AIGUARDRAILVIOLATION(agent,host,ai_agent,technique,name,severity,evidence,source,ai_used,hunt_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
  let stored = 0;
  const tx = db.transaction(() => {
    for (const e of events.slice(0, 5000)) {
      const action = String(e.action || "blocked").toLowerCase();
      if (action !== "blocked" && action !== "flagged") continue;   // allowed = nothing to record
      ins.run(`gateway:${source}`, host, null, String(e.technique || "AIX-01").slice(0, 40),
        `Gateway ${action}: ${String(e.rule || "guardrail rule")}`.slice(0, 200),
        String(e.severity || "medium").toLowerCase(), String(e.detail || "").slice(0, 240), `gateway:${source}`, 0, null, nowSql());
      stored++;
    }
  });
  tx();
  return { stored };
}

// ── Cockpit aggregation ──────────────────────────────────────────────────────────
export interface AiGuardrailsCockpit {
  baseline: { control: GuardrailControl; pass: number; fail: number; coverage: number }[];
  agents: { id: number; agent: string; host: string; name: string; framework: string; model: string; endpoint: string; usesTools: boolean; autonomous: boolean; guardrails: string; secretsExposed: number; score: number; coverage: number; gaps: string[] }[];
  violations: { id: number; agent: string; host: string; technique: string; name: string; severity: string; evidence: string; source: string; huntId: number | null; at: string }[];
  tools: { name: string; kind: string; url: string; deployedOn: number }[];
  frameworks: { name: string; controls: number }[];
  summary: { agents: number; avgScore: number | null; atRisk: number; controlsCovered: number; openViolations: number; runtimeCoverage: number; gateways: number };
}

export function aiGuardrailsCockpit(): AiGuardrailsCockpit {
  ensureAiGuardTables();
  const db = getAgentDb();
  // latest AIAGENT row per (agent,name) so re-scans don't double count.
  const agentsRaw = db.prepare(`SELECT a.* FROM AIAGENT a JOIN (SELECT agent,name,MAX(AiAgentID) mx FROM AIAGENT GROUP BY agent,name) g ON a.AiAgentID=g.mx ORDER BY a.score ASC`).all() as Record<string, any>[];
  const agents = agentsRaw.map((a) => ({
    id: Number(a.AiAgentID), agent: String(a.agent), host: String(a.host || ""), name: String(a.name || ""),
    framework: String(a.framework || ""), model: String(a.model || ""), endpoint: String(a.endpoint || ""),
    usesTools: !!a.uses_tools, autonomous: !!a.autonomous, guardrails: String(a.guardrail_tools || ""),
    secretsExposed: Number(a.secrets_exposed || 0), score: Number(a.score || 0), coverage: Number(a.coverage || 0),
    gaps: String(a.gaps || "").split(",").map((s: string) => s.trim()).filter(Boolean),
  }));
  const aidSet = new Set(agents.map((a) => a.id));
  // per-control pass/fail across the current agents.
  const resRows = db.prepare(`SELECT ai_agent_id, control_id, status FROM AIGUARDRAILRESULT`).all() as { ai_agent_id: number; control_id: string; status: string }[];
  const tally = new Map<string, { pass: number; fail: number; assessed: number }>();
  for (const c of GUARDRAIL_BASELINE) tally.set(c.id, { pass: 0, fail: 0, assessed: 0 });
  for (const r of resRows) {
    if (!aidSet.has(Number(r.ai_agent_id))) continue;
    const t = tally.get(r.control_id); if (!t) continue;
    if (r.status === "pass") { t.pass++; t.assessed++; } else if (r.status === "fail") { t.fail++; t.assessed++; }
  }
  const baseline = GUARDRAIL_BASELINE.map((control) => { const t = tally.get(control.id)!; return { control, pass: t.pass, fail: t.fail, coverage: agents.length ? Math.round((t.assessed / agents.length) * 100) : 0 }; });
  const violations = (db.prepare(`SELECT * FROM AIGUARDRAILVIOLATION ORDER BY ViolationID DESC LIMIT 100`).all() as Record<string, any>[]).map((v) => ({
    id: Number(v.ViolationID), agent: String(v.agent || ""), host: String(v.host || ""), technique: String(v.technique || ""),
    name: String(v.name || ""), severity: String(v.severity || "info"), evidence: String(v.evidence || ""),
    source: String(v.source || ""), huntId: v.hunt_id != null ? Number(v.hunt_id) : null, at: String(v.created_at || ""),
  }));
  // deployed guardrail tools = those matched across discovered agents.
  const deployed = new Map<string, number>();
  for (const a of agents) for (const g of a.guardrails.split(",").map((s) => s.trim()).filter(Boolean)) deployed.set(g, (deployed.get(g) || 0) + 1);
  const tools = GUARDRAIL_TOOLS.map((t) => ({ name: t.name, kind: t.kind, url: t.url, deployedOn: deployed.get(t.name) || 0 }));
  // framework coverage roll-up.
  const fwCount: Record<string, number> = {};
  for (const c of GUARDRAIL_BASELINE) for (const [k, v] of Object.entries(c.frameworks)) if (v) { const n = { aix: "OWASP AI Exchange", saif: "Google SAIF", iso42001: "ISO/IEC 42001", llm: "OWASP LLM Top 10", atlas: "MITRE ATLAS", nist: "NIST AI RMF" }[k] || k; fwCount[n] = (fwCount[n] || 0) + 1; }
  const frameworks = Object.entries(fwCount).map(([name, controls]) => ({ name, controls })).sort((a, b) => b.controls - a.controls);

  const scores = agents.map((a) => a.score);
  const gateways = [...deployed.keys()].length;
  return {
    baseline, agents, violations, tools, frameworks,
    summary: {
      agents: agents.length, avgScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
      atRisk: agents.filter((a) => a.score < 50).length,
      controlsCovered: baseline.filter((b) => b.pass + b.fail > 0).length,
      openViolations: violations.length, runtimeCoverage: deployed.size ? Math.round((deployed.size ? agents.filter((a) => a.guardrails).length / Math.max(1, agents.length) : 0) * 100) : 0,
      gateways,
    },
  };
}

// ── AWARE (GoodCISO/aware) — autonomous AI-agent governance on AIAGENT ─────────
// Integrates the AWARE model: constraint-enforcement tiers T0–T4, a cryptographic agent identity, a
// parent→child hierarchy with REVOCATION CASCADE (kill-switch), each tier mapped to AICM / NIST AI RMF /
// ISO 27001 / DORA / OWASP-LLM. Enforcement of T2/T3 lives in the Agent Policy Firewall (agentfw.ts);
// AWARE here is the governance posture + cascade authority over the discovered AI agents.
export const AWARE_TIERS = [
  { id: "T0", name: "Audit-only", enforces: "Audit trail of every action and decision", frameworks: { aicm: "AI Operations", airmf: "Measure", iso27001: "A.8.15 Logging", dora: "ICT Incident logging", llm: "LLM08 Excessive Agency (visibility)" } },
  { id: "T1", name: "Cryptographic identity", enforces: "A non-human identity that cannot be spoofed", frameworks: { aicm: "AI Identity", airmf: "Map", iso27001: "A.5.16 Identity management", dora: "Internal Controls", llm: "LLM03 Supply chain (provenance)" } },
  { id: "T2", name: "Guardrailed operations", enforces: "Policy constraints on operations (input/output/tool allow-list)", frameworks: { aicm: "AI Operations", airmf: "Manage", iso27001: "A.8 Operations security", dora: "Internal Controls", llm: "LLM01 Prompt injection / LLM02 Output handling" } },
  { id: "T3", name: "Policy-driven governance", enforces: "Rate limits, decision routing and kill switch", frameworks: { aicm: "AI Operations", airmf: "Govern", iso27001: "A.5 Access control", dora: "Threat Intelligence", llm: "LLM04 Model DoS / LLM08 Excessive Agency" } },
  { id: "T4", name: "Autonomous self-operation", enforces: "Self-operates under declared constraints (continuous, revocable)", frameworks: { aicm: "AI Maintenance", airmf: "Govern + Manage", iso27001: "Incident management", dora: "ICT Incidents", llm: "LLM10 Model theft (containment)" } },
] as const;
const TIER_RANK: Record<string, number> = { T0: 0, T1: 1, T2: 2, T3: 3, T4: 4 };
const AWARE_FW: Record<string, string> = { aicm: "CSA AI Controls Matrix", airmf: "NIST AI RMF", iso27001: "ISO/IEC 27001:2022", dora: "DORA", llm: "OWASP Top 10 for LLM" };

/** Stable cryptographic fingerprint for an AI agent's non-human identity (T1+). */
function agentFingerprint(name: string, framework: string, endpoint: string): string {
  return createHash("sha256").update(`aware|${name}|${framework}|${endpoint || ""}`).digest("hex").slice(0, 32);
}

/** Latest AIAGENT row per logical agent name (the governance subject). */
function latestAgents(): Record<string, any>[] {
  const db = getAgentDb();
  return db.prepare(`SELECT a.* FROM AIAGENT a JOIN (SELECT name, MAX(AiAgentID) mx FROM AIAGENT WHERE name IS NOT NULL AND name<>'' GROUP BY name) g ON a.AiAgentID=g.mx`).all() as Record<string, any>[];
}

/** Assign AWARE governance (tier, identity, parent) to an agent (by name). Auto-mints a fingerprint at T1+. */
export function setAgentGovernance(name: string, p: { tier?: string; parentAgent?: string; fingerprint?: string; source?: string }): { ok: boolean; fingerprint?: string; error?: string } {
  ensureAiGuardTables();
  const db = getAgentDb();
  const rows = db.prepare("SELECT AiAgentID, framework, endpoint, identity_fingerprint FROM AIAGENT WHERE name=?").all(name) as any[];
  if (!rows.length) return { ok: false, error: "agent not found" };
  const tier = p.tier && TIER_RANK[p.tier] != null ? p.tier : undefined;
  let fp = p.fingerprint || rows[0].identity_fingerprint || undefined;
  if (!fp && tier && TIER_RANK[tier] >= 1) fp = agentFingerprint(name, String(rows[0].framework || ""), String(rows[0].endpoint || ""));
  const sets: string[] = [], vals: any[] = [];
  if (tier) { sets.push("constraint_tier=?"); vals.push(tier); }
  if (fp) { sets.push("identity_fingerprint=?"); vals.push(fp); }
  if (p.parentAgent !== undefined) { sets.push("parent_agent=?"); vals.push(p.parentAgent || null); }
  sets.push("governance_source=?"); vals.push(p.source || "aware");
  db.prepare(`UPDATE AIAGENT SET ${sets.join(", ")} WHERE name=?`).run(...vals, name);
  try { addAgentEvent("aware", { type: "aware_govern", title: `${name} -> ${tier || "(no tier change)"}`, detail: p.parentAgent ? `parent=${p.parentAgent}` : undefined }); } catch { /* */ }
  return { ok: true, fingerprint: fp };
}

/** AWARE revocation cascade: revoke an agent and ALL its descendants (kill-switch over the parent->child tree). */
export function revokeAgentCascade(name: string, reason: string): { ok: boolean; revoked: number; agents: string[]; error?: string } {
  ensureAiGuardTables();
  const db = getAgentDb();
  const all = latestAgents();
  if (!all.some((a) => String(a.name) === name)) return { ok: false, revoked: 0, agents: [], error: "agent not found" };
  const childrenOf = new Map<string, string[]>();
  for (const a of all) { const par = String(a.parent_agent || ""); if (par) { const arr = childrenOf.get(par) || []; arr.push(String(a.name)); childrenOf.set(par, arr); } }
  const targets: string[] = []; const seen = new Set<string>(); const stack = [name];
  while (stack.length) { const n = stack.pop()!; if (seen.has(n)) continue; seen.add(n); targets.push(n); for (const c of childrenOf.get(n) || []) stack.push(c); }
  const upd = db.prepare("UPDATE AIAGENT SET revoked=1, revoked_reason=? WHERE name=?");
  const tx = db.transaction(() => { for (const n of targets) upd.run(`${reason || "revoked"} (cascade from ${name})`, n); });
  tx();
  try { addAgentEvent("aware", { type: "aware_revoke_cascade", severity: "high", title: `revoked ${targets.length} agent(s) from ${name}`, detail: targets.join(", ") }); } catch { /* */ }
  return { ok: true, revoked: targets.length, agents: targets };
}

/** Reinstate (un-revoke) an agent. */
export function reinstateAgent(name: string): { ok: boolean } {
  ensureAiGuardTables();
  getAgentDb().prepare("UPDATE AIAGENT SET revoked=0, revoked_reason=NULL WHERE name=?").run(name);
  try { addAgentEvent("aware", { type: "aware_reinstate", title: `reinstated ${name}` }); } catch { /* */ }
  return { ok: true };
}

/** AWARE governance posture over the discovered AI agents. */
export function awareGovernance(): any {
  ensureAiGuardTables();
  const rows = latestAgents();
  const agents = rows.map((a) => ({
    id: Number(a.AiAgentID), name: String(a.name || ""), framework: String(a.framework || ""), host: String(a.host || ""),
    tier: a.constraint_tier ? String(a.constraint_tier) : null, fingerprint: a.identity_fingerprint ? String(a.identity_fingerprint).slice(0, 16) : null,
    parent: a.parent_agent ? String(a.parent_agent) : null, revoked: Number(a.revoked || 0) === 1, revokedReason: String(a.revoked_reason || ""),
    autonomous: !!a.autonomous, score: Number(a.score || 0), source: String(a.governance_source || ""),
  }));
  const names = new Set(agents.map((a) => a.name));
  const tierDist = AWARE_TIERS.map((t) => ({ tier: t.id, name: t.name, enforces: t.enforces, count: agents.filter((a) => a.tier === t.id).length, frameworks: t.frameworks }));
  const ungoverned = agents.filter((a) => !a.tier);
  const roots = agents.filter((a) => !a.parent || !names.has(a.parent));
  const edges = agents.filter((a) => a.parent && names.has(a.parent)).map((a) => ({ parent: a.parent as string, child: a.name, childRevoked: a.revoked }));
  const fwCovered = new Set<string>();
  for (const a of agents) { if (!a.tier) continue; const t = AWARE_TIERS.find((x) => x.id === a.tier); if (t) for (const k of Object.keys(t.frameworks)) fwCovered.add(k); }
  const frameworks = Object.entries(AWARE_FW).map(([k, name]) => ({ key: k, name, covered: fwCovered.has(k) }));
  const summary = {
    agents: agents.length, governed: agents.filter((a) => a.tier).length, ungoverned: ungoverned.length,
    withIdentity: agents.filter((a) => a.fingerprint).length, revoked: agents.filter((a) => a.revoked).length,
    autonomousGoverned: agents.filter((a) => a.autonomous && a.tier && TIER_RANK[a.tier] >= 3).length,
    autonomousUngoverned: agents.filter((a) => a.autonomous && (!a.tier || TIER_RANK[a.tier] < 3)).length,
    hierarchyRoots: roots.length, frameworksCovered: frameworks.filter((f) => f.covered).length,
  };
  return { tiers: AWARE_TIERS, tierDist, agents, ungoverned, roots, edges, frameworks, summary };
}

/** Demo: a parent->child agent fleet with mixed AWARE tiers (one ungoverned, populating the worklist). */
export function seedAwareDemo(): { created: number } {
  ensureAiGuardTables();
  const db = getAgentDb();
  if (db.prepare("SELECT 1 FROM AIAGENT WHERE agent='aware-demo' LIMIT 1").get()) return { created: 0 };
  const ts = new Date().toISOString();
  const ins = db.prepare(`INSERT INTO AIAGENT(agent,host,name,framework,model,autonomous,uses_tools,score,coverage,gaps,created_at,governance_source) VALUES ('aware-demo','agent-host',?,?,?,?,?,?,?,'',?,'aware')`);
  const fleet: [string, string, string, number, number, number][] = [
    ["orchestrator-prime", "crewai", "gpt-4o", 1, 1, 78],
    ["retrieval-worker", "langchain", "qwen2.5:7b", 0, 1, 64],
    ["payments-agent", "autogen", "claude-3.5", 1, 1, 41],
    ["log-summariser", "llamaindex", "llama3.1:8b", 0, 0, 55],
    ["shadow-agent", "openai", "gpt-4o-mini", 1, 1, 28],
  ];
  for (const [name, fw, model, auto, tools, score] of fleet) ins.run(name, fw, model, auto, tools, score, score >= 70 ? 80 : 40, ts);
  setAgentGovernance("orchestrator-prime", { tier: "T4" });
  setAgentGovernance("retrieval-worker", { tier: "T2", parentAgent: "orchestrator-prime" });
  setAgentGovernance("payments-agent", { tier: "T3", parentAgent: "orchestrator-prime" });
  setAgentGovernance("log-summariser", { tier: "T0", parentAgent: "orchestrator-prime" });
  return { created: 1 };
}
