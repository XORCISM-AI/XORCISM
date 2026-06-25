/**
 * aiexchange.ts — OWASP AI Exchange "agent threat advisor" for threat modeling.
 *
 * A catalogue of AI / agentic-AI threats (aligned to the OWASP AI Exchange, owaspai.org, and the
 * agentic-AI threat space) each with its lifecycle phase, impact, mitigating controls and which AI
 * system shapes it applies to. The advisor takes a short description of an AI system (LLM app /
 * autonomous agent / ML model; whether it uses tools, has memory, is autonomous, ingests external
 * data, handles sensitive data) and returns the applicable, prioritized threats + controls.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export type Shape = "llm" | "agent" | "ml" | "tools" | "memory" | "autonomous" | "external" | "sensitive";
type Threat = { ref: string; name: string; category: string; lifecycle: string; impact: string; desc: string; controls: string; appliesTo: Shape[] };
const t = (ref: string, name: string, category: string, lifecycle: string, impact: string, desc: string, controls: string, appliesTo: Shape[]): Threat => ({ ref, name, category, lifecycle, impact, desc, controls, appliesTo });

export const AI_THREATS: Threat[] = [
  t("AIX-01", "Direct prompt injection", "Prompt injection", "Runtime / use", "High", "A user crafts input that overrides the model's instructions to bypass guardrails or change behavior.", "Input/instruction separation, system-prompt hardening, output filtering, least-privilege tools, human approval for sensitive actions.", ["llm", "agent"]),
  t("AIX-02", "Indirect prompt injection", "Prompt injection", "Runtime / use", "High", "Malicious instructions hidden in external content (web pages, docs, emails, tool results) the model ingests.", "Treat all retrieved content as untrusted, content sanitization, provenance tagging, sandboxed tool output, dual-LLM/quarantine patterns.", ["llm", "agent", "external"]),
  t("AIX-03", "Excessive agency", "Excessive agency", "Design / runtime", "High", "An agent is granted more capability, autonomy or permissions than its task requires, amplifying any compromise.", "Least-privilege tools/scopes, allow-list actions, human-in-the-loop for high-impact ops, per-action authorization.", ["agent", "autonomous", "tools"]),
  t("AIX-04", "Tool / function misuse", "Tool misuse", "Runtime", "High", "The agent is manipulated into invoking tools (code exec, payments, email, infra) with attacker-controlled arguments.", "Strict tool schemas + validation, output encoding, scoped credentials, rate limits, confirmation for irreversible actions.", ["agent", "tools"]),
  t("AIX-05", "Memory / context poisoning", "Memory poisoning", "Runtime", "Medium", "Persistent memory or RAG store is poisoned so future decisions are influenced by attacker-planted content.", "Authenticate writes to memory, provenance + integrity checks, segregate trusted/untrusted memory, expiry & review.", ["agent", "memory"]),
  t("AIX-06", "Goal / instruction manipulation", "Goal manipulation", "Runtime", "High", "An adversary subtly redirects the agent's objective so it pursues harmful or unintended goals.", "Immutable goal anchoring, plan validation, guardrail policies, monitoring for goal drift, human review of plans.", ["agent", "autonomous"]),
  t("AIX-07", "Cascading / multi-agent failures", "Cascading failures", "Runtime", "High", "Errors or compromise in one agent propagate across a multi-agent system, amplifying impact.", "Circuit breakers, isolation between agents, output validation between hops, blast-radius limits, kill-switch.", ["agent", "autonomous"]),
  t("AIX-08", "Rogue / impersonated agent", "Identity & permissions", "Runtime", "High", "An unauthorized or spoofed agent participates in the workflow or assumes another agent's identity.", "Strong agent identity (mTLS/signed), authn/authz between agents, registry of trusted agents, anomaly detection.", ["agent", "autonomous"]),
  t("AIX-09", "Identity & privilege abuse (NHI)", "Identity & permissions", "Runtime", "High", "The agent's non-human identity / tokens are abused for lateral movement or privilege escalation.", "Short-lived scoped credentials, secret vaulting, per-tool identities, just-in-time access, monitor NHI usage.", ["agent", "autonomous", "tools"]),
  t("AIX-10", "Sensitive information disclosure", "Sensitive data disclosure", "Runtime / use", "High", "The model leaks training data, secrets, PII or other context through its outputs.", "Data minimization, output DLP/redaction, no secrets in prompts, retrieval scoping, response review.", ["llm", "agent", "sensitive"]),
  t("AIX-11", "Insecure output handling", "Insecure output handling", "Runtime", "Medium", "Downstream systems trust model output and execute it (XSS, SQLi, command injection, unsafe code).", "Treat output as untrusted, contextual encoding, sandbox generated code, validate before execution.", ["llm", "agent", "tools"]),
  t("AIX-12", "Training-data poisoning", "Data poisoning", "Development", "High", "Manipulated training/fine-tuning data introduces backdoors or biased behavior.", "Data provenance & curation, anomaly detection, dataset signing, robust training, evaluation for backdoors.", ["ml", "llm"]),
  t("AIX-13", "Model / IP theft", "Model theft", "Use / development", "Medium", "The model or its weights are extracted via query access or exfiltrated from storage.", "Rate limiting, output watermarking, access control on weights, detect extraction patterns.", ["ml", "llm"]),
  t("AIX-14", "Evasion / adversarial examples", "Evasion", "Use", "Medium", "Crafted inputs cause the model to misclassify or behave incorrectly at inference time.", "Adversarial training, input validation, ensembles, confidence thresholds + human review.", ["ml"]),
  t("AIX-15", "Supply-chain compromise (models/plugins)", "Supply chain", "Development", "High", "A poisoned base model, dataset, library or agent plugin introduces malicious behavior.", "SBOM/AIBOM, source verification, signed models/plugins, dependency scanning, plugin allow-listing.", ["ml", "llm", "agent", "tools"]),
  t("AIX-16", "Model denial of service / unbounded consumption", "Denial of service", "Use", "Medium", "Expensive prompts, recursive agent loops or tool storms exhaust compute, budget or rate limits.", "Rate/cost limits, loop/recursion caps, timeouts, budget guards, input size limits.", ["llm", "agent", "autonomous"]),
  t("AIX-17", "Over-reliance / hallucination", "Hallucination & over-reliance", "Use", "Medium", "Users or downstream automation act on confident but incorrect model output.", "Cite sources, confidence signals, human review for consequential decisions, ground with retrieval.", ["llm", "agent"]),
  // ── Through use (runtime) ──
  t("AIX-18", "Model inversion / membership inference", "Sensitive data disclosure", "Use", "Medium", "Reconstructing training data, or inferring whether a record was in the training set, from model outputs/confidence.", "Obscure confidence scores, output privacy (DP), rate limiting, restrict access to logits.", ["ml", "llm", "sensitive"]),
  t("AIX-29", "System-prompt / prompt leak", "Sensitive data disclosure", "Use", "Medium", "An attacker extracts the hidden system prompt, instructions or guardrails to bypass or replicate them.", "No secrets in prompts, prompt-leak resistant design, output filtering, treat the system prompt as non-secret.", ["llm", "agent"]),
  // ── Development-time ──
  t("AIX-19", "Development-time model poisoning", "Model poisoning", "Development", "High", "An attacker alters model parameters/weights directly in the engineering/training environment (backdoor).", "Development-environment security, segregation of duties, model signing, backdoor evaluation.", ["ml", "llm"]),
  t("AIX-20", "Development-time data leak", "Sensitive data disclosure", "Development", "High", "Training / fine-tuning / augmentation data is breached from the development infrastructure.", "Dev-environment security, data segregation, encryption at rest, access control & monitoring.", ["ml", "llm", "sensitive"]),
  t("AIX-21", "Model theft at rest", "Model theft", "Development", "Medium", "Model weights / IP are exfiltrated from storage or the training environment (vs. theft through querying).", "Access control on weights, encryption, DLP, segregation, monitor large transfers.", ["ml", "llm"]),
  t("AIX-30", "Development-environment / pipeline compromise", "Supply chain", "Development", "High", "The ML build pipeline, notebooks or training infra are compromised to tamper with model or data.", "Harden CI/CD & notebooks, signed artifacts, provenance/SLSA, least privilege, secrets management.", ["ml", "llm", "agent"]),
  // ── Runtime application security ──
  t("AIX-22", "Runtime model poisoning / reprogramming", "Model poisoning", "Runtime", "High", "Parameters of the deployed model are modified at runtime to change its behavior.", "Runtime model integrity checks, signed weights, access control on the serving layer, monitoring.", ["ml", "llm", "agent"]),
  t("AIX-23", "Runtime model leak", "Model theft", "Runtime", "Medium", "Model parameters are extracted from the running, deployed serving system.", "Runtime model confidentiality, hardware/enclave protection, access control, obfuscation.", ["ml", "llm"]),
  t("AIX-24", "Model input data leak", "Sensitive data disclosure", "Runtime", "Medium", "Sensitive user input is exposed during processing, logging or to third-party model providers.", "Input confidentiality, redact before logging, encryption in transit, data-residency controls.", ["llm", "agent", "sensitive"]),
  t("AIX-25", "RAG / augmentation data poisoning", "Memory poisoning", "Runtime", "Medium", "Content in a retrieval (RAG) store or system-prompt augmentation is poisoned to steer the model.", "Authenticate writes, provenance & integrity on the corpus, segregate trusted/untrusted, review.", ["llm", "agent", "memory", "external"]),
  t("AIX-26", "RAG / augmentation data leak", "Sensitive data disclosure", "Runtime", "Medium", "Sensitive data in a RAG repository or system prompt is exposed through retrieval or output.", "Per-user retrieval scoping & access control on the corpus, output DLP, minimize what is indexed.", ["llm", "agent", "memory", "sensitive"]),
  // ── Agentic-specific ──
  t("AIX-27", "Lethal trifecta — agentic data exfiltration", "Excessive agency", "Runtime", "High", "An agent that can be influenced + can send data + has access to sensitive data becomes an exfiltration path.", "Break the trifecta: isolate untrusted input, restrict egress, least-privilege data access, human approval.", ["agent", "autonomous", "tools", "external", "sensitive"]),
  t("AIX-28", "Autonomous action manipulation", "Goal manipulation", "Runtime", "High", "Injected content triggers the agent to take unintended autonomous actions (the confused-deputy effect).", "Oversight rules, human-in-the-loop for high-impact actions, action allow-lists, plan validation.", ["agent", "autonomous", "tools"]),
];

const SHAPE_LABEL: Record<string, string> = { llm: "LLM application", agent: "Autonomous agent", ml: "ML model", tools: "Uses tools/functions", memory: "Has persistent memory", autonomous: "Acts autonomously", external: "Ingests external content", sensitive: "Handles sensitive data" };
export function shapeLabels() { return SHAPE_LABEL; }

/** The advisor: given the AI system's shapes, return the applicable threats, most-relevant first. */
export function advise(shapes: Shape[]): { threats: any[]; summary: any } {
  const set = new Set(shapes);
  const scored = AI_THREATS.map((th) => {
    const overlap = th.appliesTo.filter((s) => set.has(s)).length;
    const relevant = overlap > 0 || (set.has("llm") && th.appliesTo.includes("llm")) || (set.has("agent") && th.appliesTo.includes("agent"));
    const impactW = th.impact === "High" ? 3 : th.impact === "Medium" ? 2 : 1;
    return { ...th, relevance: overlap, score: overlap * 2 + impactW, relevant };
  }).filter((x) => x.relevant).sort((a, b) => b.score - a.score || (a.impact < b.impact ? 1 : -1));
  return {
    threats: scored.map((s) => ({ ref: s.ref, name: s.name, category: s.category, lifecycle: s.lifecycle, impact: s.impact, description: s.desc, controls: s.controls })),
    summary: { applicable: scored.length, high: scored.filter((s) => s.impact === "High").length, categories: [...new Set(scored.map((s) => s.category))].length, shapes },
  };
}

export function aiThreatCatalogue(tenant: number | null): any {
  const db = getDb("XTHREAT");
  let rows: any[] = [];
  try { rows = db.prepare("SELECT Ref, Name, Category, Lifecycle, Impact, Description, Controls, AppliesTo FROM AIEXCHANGETHREAT ORDER BY Ref").all() as any[]; } catch { rows = []; }
  if (!rows.length) rows = AI_THREATS.map((th) => ({ Ref: th.ref, Name: th.name, Category: th.category, Lifecycle: th.lifecycle, Impact: th.impact, Description: th.desc, Controls: th.controls, AppliesTo: th.appliesTo.join(",") }));
  const byCat = new Map<string, any[]>();
  for (const r of rows) { const a = byCat.get(String(r.Category)) || []; a.push({ ref: String(r.Ref), name: String(r.Name), lifecycle: String(r.Lifecycle ?? ""), impact: String(r.Impact ?? ""), description: String(r.Description ?? ""), controls: String(r.Controls ?? ""), appliesTo: String(r.AppliesTo ?? "").split(",").filter(Boolean) }); byCat.set(String(r.Category), a); }
  return { categories: [...byCat.entries()].map(([category, threats]) => ({ category, threats })), total: rows.length, shapes: SHAPE_LABEL, source: "OWASP AI Exchange (owaspai.org)" };
}

export function seedAiThreats(tenant: number | null): { threats: number } {
  const db = getDb("XTHREAT");
  // Additive: insert any catalogue threat whose Ref is not yet present (so expanding AI_THREATS adds them).
  const existing = new Set((db.prepare("SELECT Ref FROM AIEXCHANGETHREAT").all() as { Ref: string }[]).map((r) => String(r.Ref)));
  const toAdd = AI_THREATS.filter((th) => !existing.has(th.ref));
  if (!toAdd.length) return { threats: 0 };
  let id = allocId(db, "AIEXCHANGETHREAT", "ThreatID");
  const now = new Date().toISOString();
  const ins = db.prepare("INSERT INTO AIEXCHANGETHREAT (ThreatID, ThreatGUID, Ref, Name, Category, Lifecycle, Impact, Description, Controls, AppliesTo, Source, URL, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
  for (const th of toAdd) ins.run(id++, randomUUID(), th.ref, th.name, th.category, th.lifecycle, th.impact, th.desc, th.controls, th.appliesTo.join(","), "OWASP AI Exchange", "https://owaspai.org/", null, now);
  return { threats: toAdd.length };
}
