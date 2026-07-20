/**
 * miniciso.ts — Evidence-driven security assessment cockpit (/miniciso), a native replication of
 * miniCISO (github.com/icidade/miniCISO, MIT, by Irlan Cidade — "agentic security staff").
 *
 * miniCISO's thesis: assessments collapse when evidence is scattered and early signals become
 * premature findings. It imposes an operating discipline — evidence before narrative, specialist
 * delegation, validation gates, visible uncertainty, human accountability — run by nine security
 * "staff" roles across a disciplined workflow, classifying every output as a Finding, Observation,
 * Hypothesis or Missing-Evidence. This module replicates that discipline natively:
 *
 *   • the nine roles (a Chief-of-Staff coordinator + eight specialists) as a baked catalogue;
 *   • an assessment with an explicit scope + objective, moving through the workflow stages;
 *   • Evidence items tiered by quality (declared → runtime → validated) — "confidence depends on
 *     evidence quality, not presentation quality";
 *   • Outputs classified Finding / Observation / Hypothesis / Missing-Evidence, each with a role,
 *     a GO / RESEARCH / NO-GO pre-submission gate, a confidence, residual risk and linked evidence;
 *   • the mandatory Security-QA gate — synthesis is BLOCKED while any Finding is unreviewed
 *     (recon output never auto-escalates to a Finding);
 *   • an optional local-AI "suggest candidate outputs from evidence" pass (Ollama; offline
 *     heuristic fallback) that only ever proposes hypotheses/observations — never findings.
 *
 * Tables live in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like cra.ts / cc.ts / smematurity.ts). A
 * maturity/assessment discipline tool — human judgment and authorization stay with the operator.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { ollamaChat, ollamaStatus } from "./ai";

const now = (): string => new Date().toISOString();

export interface McRole { id: string; name: string; mission: string; kind: "coordinator" | "specialist" }
/** The nine roles, verbatim from miniCISO's "Meet the Staff". */
export const MC_ROLES: McRole[] = [
  { id: "chief-of-staff", name: "Chief of Staff", kind: "coordinator", mission: "Coordinate intake, routing, handoffs, QA enforcement, and final synthesis." },
  { id: "threat-modeling", name: "Threat Modeling", kind: "specialist", mission: "Model assets, trust boundaries, abuse cases, and likely control priorities." },
  { id: "security-architecture", name: "Security Architecture", kind: "specialist", mission: "Review design choices involving IAM, secrets, logging, segmentation, crypto, and resilience." },
  { id: "code-review", name: "Code Review", kind: "specialist", mission: "Inspect code or diffs for security-relevant defects with file/line evidence." },
  { id: "appsec-assessment", name: "AppSec Assessment", kind: "specialist", mission: "Assess application security posture across authn/authz, APIs, web flows, and abuse paths." },
  { id: "compliance-mapper", name: "Compliance Mapper", kind: "specialist", mission: "Map technical findings to governance, audit, and control frameworks." },
  { id: "offensive-security", name: "Offensive Security", kind: "specialist", mission: "Perform authorized offensive validation within defined scope and limits." },
  { id: "recon-attack-surface", name: "Recon & Attack Surface", kind: "specialist", mission: "Perform authorized passive or low-noise discovery and prioritize hypotheses for deeper review." },
  { id: "security-qa", name: "Security QA", kind: "specialist", mission: "Apply the final quality gate for scope, evidence, severity, clarity, safety, and actionability." },
];
const ROLE_IDS = new Set(MC_ROLES.map((r) => r.id));

/** The disciplined assessment workflow (miniCISO's nine stages). */
export const MC_STAGES = [
  { key: "intake", name: "Intake & Scope", detail: "Define boundaries, objective and success criteria." },
  { key: "evidence", name: "Evidence Collection", detail: "Gather artifacts and baselines; keep provenance." },
  { key: "hypothesis", name: "Hypothesis Formation", detail: "Develop candidate paths — not yet findings." },
  { key: "retrieval", name: "Selective Retrieval", detail: "Knowledge-aware retrieval connects scope with context." },
  { key: "sme", name: "SME Analysis", detail: "Specialists investigate within their domains." },
  { key: "correlation", name: "Cross-SME Correlation", detail: "Synthesize evidence across roles." },
  { key: "qa", name: "Security QA", detail: "Adversarial challenge of every candidate conclusion." },
  { key: "synthesis", name: "Final Synthesis", detail: "Chief of Staff produces the accountable report." },
  { key: "followup", name: "Follow-up & Lessons", detail: "Capture residual risk and next actions." },
] as const;

export const MC_CLASSES = ["finding", "observation", "hypothesis", "missing-evidence"] as const;
export const MC_GATES = ["go", "research", "no-go"] as const;       // pre-submission decision gate
/** Evidence tiers — confidence follows evidence quality, not presentation. */
export const MC_EVIDENCE_TIERS = [
  { key: "declared", name: "Declared configuration", weight: 1 },
  { key: "runtime", name: "Runtime / effective configuration", weight: 2 },
  { key: "validated", name: "Validated behavior", weight: 3 },
] as const;
export const MC_QA = ["pending", "passed", "rejected"] as const;
export const MC_STATUS = ["scoping", "in-progress", "qa", "delivered", "archived"] as const;
export const MC_SEVERITY = ["critical", "high", "medium", "low", "info"] as const;

export function ensureMcTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS MINICISOASSESSMENT(
      AssessmentID INTEGER PRIMARY KEY, AssessmentGUID TEXT, TenantID INTEGER,
      Name TEXT, Objective TEXT, Scope TEXT, Boundaries TEXT, Operator TEXT,
      Stage TEXT, Status TEXT, Synthesis TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS MINICISOEVIDENCE(
      EvidenceID INTEGER PRIMARY KEY, AssessmentID INTEGER, Title TEXT, Tier TEXT,
      Source TEXT, Content TEXT, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS MINICISOOUTPUT(
      OutputID INTEGER PRIMARY KEY, AssessmentID INTEGER, Role TEXT, Class TEXT, Title TEXT,
      Detail TEXT, Severity TEXT, Confidence INTEGER, ResidualRisk TEXT, Gate TEXT,
      EvidenceRefs TEXT, QaStatus TEXT, QaNote TEXT, Source TEXT, CreatedDate TEXT, UpdatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_mcassess_tenant ON MINICISOASSESSMENT(TenantID);
    CREATE INDEX IF NOT EXISTS ix_mcevidence_assess ON MINICISOEVIDENCE(AssessmentID);
    CREATE INDEX IF NOT EXISTS ix_mcoutput_assess ON MINICISOOUTPUT(AssessmentID);
  `);
}

const tw = (tenant: number | null): string => (tenant == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");

export function mcCatalogue(): { roles: McRole[]; stages: typeof MC_STAGES; classes: readonly string[];
  gates: readonly string[]; tiers: typeof MC_EVIDENCE_TIERS; severities: readonly string[] } {
  return { roles: MC_ROLES, stages: MC_STAGES, classes: MC_CLASSES, gates: MC_GATES,
    tiers: MC_EVIDENCE_TIERS, severities: MC_SEVERITY };
}

// ── scoring / gate logic ──────────────────────────────────────────────────────
export interface McOutputRow {
  id: number; role: string; roleName: string; cls: string; title: string; detail: string;
  severity: string; confidence: number; residualRisk: string; gate: string;
  evidenceRefs: number[]; qaStatus: string; qaNote: string; source: string;
}
const roleName = (id: string): string => MC_ROLES.find((r) => r.id === id)?.name || id;

/** miniCISO's readiness rule: a report can be delivered only when every FINDING has passed QA and
 * carries at least one linked evidence item and a GO gate. Returns the blockers. */
export function deliveryReadiness(outputs: McOutputRow[]): {
  ready: boolean; findings: number; qaPassed: number; blockers: { id: number; title: string; reason: string }[];
} {
  const findings = outputs.filter((o) => o.cls === "finding");
  const blockers: { id: number; title: string; reason: string }[] = [];
  for (const f of findings) {
    if (f.qaStatus !== "passed") blockers.push({ id: f.id, title: f.title, reason: "not passed through Security QA" });
    else if (!f.evidenceRefs.length) blockers.push({ id: f.id, title: f.title, reason: "no linked evidence (evidence before narrative)" });
    else if (f.gate !== "go") blockers.push({ id: f.id, title: f.title, reason: `gate is '${f.gate}', not GO` });
  }
  return { ready: findings.length > 0 && blockers.length === 0, findings: findings.length,
    qaPassed: findings.filter((f) => f.qaStatus === "passed").length, blockers };
}

function rowToOutput(r: any): McOutputRow {
  return {
    id: r.OutputID, role: r.Role || "", roleName: roleName(r.Role || ""), cls: r.Class || "hypothesis",
    title: r.Title || "", detail: r.Detail || "", severity: r.Severity || "info",
    confidence: r.Confidence ?? 0, residualRisk: r.ResidualRisk || "", gate: r.Gate || "research",
    evidenceRefs: r.EvidenceRefs ? String(r.EvidenceRefs).split(",").filter(Boolean).map(Number) : [],
    qaStatus: r.QaStatus || "pending", qaNote: r.QaNote || "", source: r.Source || "",
  };
}

export interface McAssessmentRow {
  id: number; name: string; objective: string; scope: string; boundaries: string; operator: string;
  stage: string; stageName: string; status: string; synthesis: string;
  evidence: number; outputs: number; findings: number; hypotheses: number; observations: number;
  missingEvidence: number; qaPassed: number; ready: boolean; createdDate: string; updatedDate: string;
}

function rowToAssessment(db: ReturnType<typeof getDb>, r: any): McAssessmentRow {
  const ev = (db.prepare("SELECT COUNT(*) n FROM MINICISOEVIDENCE WHERE AssessmentID=?").get(r.AssessmentID) as { n: number }).n;
  const outs = (db.prepare("SELECT * FROM MINICISOOUTPUT WHERE AssessmentID=?").all(r.AssessmentID) as any[]).map(rowToOutput);
  const rd = deliveryReadiness(outs);
  return {
    id: r.AssessmentID, name: r.Name || "", objective: r.Objective || "", scope: r.Scope || "",
    boundaries: r.Boundaries || "", operator: r.Operator || "", stage: r.Stage || "intake",
    stageName: MC_STAGES.find((s) => s.key === (r.Stage || "intake"))?.name || (r.Stage || "intake"),
    status: r.Status || "scoping", synthesis: r.Synthesis || "", evidence: ev, outputs: outs.length,
    findings: outs.filter((o) => o.cls === "finding").length,
    hypotheses: outs.filter((o) => o.cls === "hypothesis").length,
    observations: outs.filter((o) => o.cls === "observation").length,
    missingEvidence: outs.filter((o) => o.cls === "missing-evidence").length,
    qaPassed: rd.qaPassed, ready: rd.ready, createdDate: r.CreatedDate || "", updatedDate: r.UpdatedDate || "",
  };
}

export function mcDashboard(tenant: number | null): {
  assessments: McAssessmentRow[];
  summary: { assessments: number; delivered: number; openFindings: number; readyToDeliver: number; hypotheses: number };
} {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM MINICISOASSESSMENT WHERE ${tw(tenant)} ORDER BY AssessmentID DESC`).all(...args) as any[];
  const assessments = rows.map((r) => rowToAssessment(db, r));
  return {
    assessments,
    summary: {
      assessments: assessments.length,
      delivered: assessments.filter((a) => a.status === "delivered").length,
      openFindings: assessments.reduce((n, a) => n + a.findings, 0),
      readyToDeliver: assessments.filter((a) => a.ready && a.status !== "delivered").length,
      hypotheses: assessments.reduce((n, a) => n + a.hypotheses, 0),
    },
  };
}

export function mcDetail(id: number, tenant: number | null): {
  assessment: McAssessmentRow; evidence: any[]; outputs: McOutputRow[];
  readiness: ReturnType<typeof deliveryReadiness>; stages: typeof MC_STAGES;
} | null {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM MINICISOASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const evidence = db.prepare("SELECT EvidenceID AS id, Title AS title, Tier AS tier, Source AS source, Content AS content, CreatedDate AS createdDate FROM MINICISOEVIDENCE WHERE AssessmentID=? ORDER BY EvidenceID").all(id);
  const outputs = (db.prepare("SELECT * FROM MINICISOOUTPUT WHERE AssessmentID=? ORDER BY OutputID").all(id) as any[]).map(rowToOutput);
  return { assessment: rowToAssessment(db, r), evidence, outputs, readiness: deliveryReadiness(outputs), stages: MC_STAGES };
}

export function createAssessment(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "MINICISOASSESSMENT", "AssessmentID");
  const s = (k: string, max = 4000): string => String(b[k] ?? "").slice(0, max);
  db.prepare(
    `INSERT INTO MINICISOASSESSMENT (AssessmentID, AssessmentGUID, TenantID, Name, Objective, Scope,
       Boundaries, Operator, Stage, Status, Synthesis, CreatedDate, UpdatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "Security assessment", s("objective"), s("scope"),
    s("boundaries"), s("operator", 200), "intake", "scoping", "", now(), now());
  return { id };
}

export function deleteAssessment(id: number): { ok: boolean } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM MINICISOEVIDENCE WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM MINICISOOUTPUT WHERE AssessmentID=?").run(id);
  db.prepare("DELETE FROM MINICISOASSESSMENT WHERE AssessmentID=?").run(id);
  return { ok: true };
}

const touch = (db: ReturnType<typeof getDb>, id: number): void => {
  db.prepare("UPDATE MINICISOASSESSMENT SET UpdatedDate=? WHERE AssessmentID=?").run(now(), id);
};

export function updateAssessment(id: number, tenant: number | null, b: Record<string, unknown>): { ok: boolean } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  if (!db.prepare(`SELECT 1 FROM MINICISOASSESSMENT WHERE AssessmentID=? AND ${tw(tenant)}`).get(...args)) return { ok: false };
  const map: Record<string, string> = { name: "Name", objective: "Objective", scope: "Scope", boundaries: "Boundaries", operator: "Operator" };
  const sets: string[] = [], vals: unknown[] = [];
  for (const [k, col] of Object.entries(map)) if (k in b) { sets.push(`${col}=?`); vals.push(String(b[k] ?? "").slice(0, 4000)); }
  if ("stage" in b && MC_STAGES.some((s) => s.key === String(b.stage))) { sets.push("Stage=?"); vals.push(String(b.stage)); }
  if ("status" in b && (MC_STATUS as readonly string[]).includes(String(b.status))) { sets.push("Status=?"); vals.push(String(b.status)); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE MINICISOASSESSMENT SET ${sets.join(", ")} WHERE AssessmentID=?`).run(...vals, id);
  return { ok: true };
}

export function addEvidence(id: number, b: Record<string, unknown>): { id: number } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const eid = allocId(db, "MINICISOEVIDENCE", "EvidenceID");
  const tier = MC_EVIDENCE_TIERS.some((t) => t.key === String(b.tier)) ? String(b.tier) : "declared";
  db.prepare("INSERT INTO MINICISOEVIDENCE (EvidenceID, AssessmentID, Title, Tier, Source, Content, CreatedDate) VALUES (?,?,?,?,?,?,?)")
    .run(eid, id, String(b.title ?? "Evidence").slice(0, 300), tier, String(b.source ?? "").slice(0, 300), String(b.content ?? "").slice(0, 8000), now());
  touch(db, id);
  return { id: eid };
}

export function removeEvidence(id: number, evidenceId: number): { ok: boolean } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM MINICISOEVIDENCE WHERE EvidenceID=? AND AssessmentID=?").run(evidenceId, id);
  touch(db, id);
  return { ok: true };
}

/** Suggested confidence (0-100) from the strongest evidence tier linked to an output. */
function confFromEvidence(db: ReturnType<typeof getDb>, evidenceRefs: number[]): number {
  if (!evidenceRefs.length) return 25;
  const tiers = db.prepare(`SELECT Tier FROM MINICISOEVIDENCE WHERE EvidenceID IN (${evidenceRefs.map(() => "?").join(",")})`).all(...evidenceRefs) as { Tier: string }[];
  const best = Math.max(0, ...tiers.map((t) => MC_EVIDENCE_TIERS.find((x) => x.key === t.Tier)?.weight || 1));
  return best >= 3 ? 90 : best === 2 ? 65 : 40;   // validated → 90, runtime → 65, declared → 40
}

export function addOutput(id: number, b: Record<string, unknown>): { id: number; error?: string } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const role = ROLE_IDS.has(String(b.role)) ? String(b.role) : "recon-attack-surface";
  let cls = (MC_CLASSES as readonly string[]).includes(String(b.cls)) ? String(b.cls) : "hypothesis";
  const refs = Array.isArray(b.evidenceRefs) ? (b.evidenceRefs as unknown[]).map(Number).filter((n) => Number.isInteger(n)) : [];
  // Discipline: recon output never auto-escalates to a finding; a finding needs linked evidence.
  if (role === "recon-attack-surface" && cls === "finding") cls = "hypothesis";
  if (cls === "finding" && !refs.length) cls = "hypothesis";
  const gate = (MC_GATES as readonly string[]).includes(String(b.gate)) ? String(b.gate) : (cls === "finding" ? "go" : "research");
  const conf = Number.isInteger(Number(b.confidence)) && Number(b.confidence) >= 0 && Number(b.confidence) <= 100
    ? Number(b.confidence) : confFromEvidence(db, refs);
  const sev = (MC_SEVERITY as readonly string[]).includes(String(b.severity)) ? String(b.severity) : "info";
  const oid = allocId(db, "MINICISOOUTPUT", "OutputID");
  db.prepare(
    `INSERT INTO MINICISOOUTPUT (OutputID, AssessmentID, Role, Class, Title, Detail, Severity, Confidence,
       ResidualRisk, Gate, EvidenceRefs, QaStatus, QaNote, Source, CreatedDate, UpdatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(oid, id, role, cls, String(b.title ?? "Candidate").slice(0, 300), String(b.detail ?? "").slice(0, 8000),
    sev, conf, String(b.residualRisk ?? "").slice(0, 2000), gate, refs.join(","), "pending", "",
    String(b.source ?? "").slice(0, 120), now(), now());
  touch(db, id);
  return { id: oid };
}

export function updateOutput(id: number, outputId: number, b: Record<string, unknown>): { ok: boolean } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const cur = db.prepare("SELECT * FROM MINICISOOUTPUT WHERE OutputID=? AND AssessmentID=?").get(outputId, id) as any;
  if (!cur) return { ok: false };
  const sets: string[] = [], vals: unknown[] = [];
  if ("cls" in b && (MC_CLASSES as readonly string[]).includes(String(b.cls))) {
    let cls = String(b.cls);
    const refs = "evidenceRefs" in b ? (b.evidenceRefs as unknown[]).map(Number) : String(cur.EvidenceRefs || "").split(",").filter(Boolean).map(Number);
    if (cur.Role === "recon-attack-surface" && cls === "finding") cls = "hypothesis";
    if (cls === "finding" && !refs.length) cls = "hypothesis";
    sets.push("Class=?"); vals.push(cls);
    if (cls !== cur.Class) { sets.push("QaStatus=?"); vals.push("pending"); }   // reclassification needs re-QA
  }
  if ("title" in b) { sets.push("Title=?"); vals.push(String(b.title).slice(0, 300)); }
  if ("detail" in b) { sets.push("Detail=?"); vals.push(String(b.detail).slice(0, 8000)); }
  if ("severity" in b && (MC_SEVERITY as readonly string[]).includes(String(b.severity))) { sets.push("Severity=?"); vals.push(String(b.severity)); }
  if ("gate" in b && (MC_GATES as readonly string[]).includes(String(b.gate))) { sets.push("Gate=?"); vals.push(String(b.gate)); }
  if ("confidence" in b && Number.isInteger(Number(b.confidence))) { sets.push("Confidence=?"); vals.push(Math.max(0, Math.min(100, Number(b.confidence)))); }
  if ("residualRisk" in b) { sets.push("ResidualRisk=?"); vals.push(String(b.residualRisk).slice(0, 2000)); }
  if ("evidenceRefs" in b && Array.isArray(b.evidenceRefs)) { sets.push("EvidenceRefs=?"); vals.push((b.evidenceRefs as unknown[]).map(Number).filter((n) => Number.isInteger(n)).join(",")); }
  if (!sets.length) return { ok: true };
  sets.push("UpdatedDate=?"); vals.push(now());
  db.prepare(`UPDATE MINICISOOUTPUT SET ${sets.join(", ")} WHERE OutputID=?`).run(...vals, outputId);
  touch(db, id);
  return { ok: true };
}

export function removeOutput(id: number, outputId: number): { ok: boolean } {
  ensureMcTables();
  getDb("XCOMPLIANCE").prepare("DELETE FROM MINICISOOUTPUT WHERE OutputID=? AND AssessmentID=?").run(outputId, id);
  return { ok: true };
}

/** The mandatory Security-QA gate: only security-qa marks an output passed/rejected. */
export function setQa(id: number, outputId: number, status: string, note?: string): { ok: boolean; error?: string } {
  ensureMcTables();
  if (!(MC_QA as readonly string[]).includes(status)) return { ok: false, error: "status must be pending|passed|rejected" };
  const db = getDb("XCOMPLIANCE");
  db.prepare("UPDATE MINICISOOUTPUT SET QaStatus=?, QaNote=?, UpdatedDate=? WHERE OutputID=? AND AssessmentID=?")
    .run(status, String(note ?? "").slice(0, 2000), now(), outputId, id);
  touch(db, id);
  return { ok: true };
}

/** Chief-of-Staff final synthesis — refused while any Finding is unreviewed (evidence-before-narrative). */
export function synthesize(id: number, tenant: number | null): { ok: boolean; blocked?: boolean; readiness?: any; synthesis?: string } {
  const d = mcDetail(id, tenant);
  if (!d) return { ok: false };
  if (!d.readiness.ready) return { ok: false, blocked: true, readiness: d.readiness };
  const db = getDb("XCOMPLIANCE");
  const findings = d.outputs.filter((o) => o.cls === "finding").sort((a, b) => MC_SEVERITY.indexOf(a.severity as any) - MC_SEVERITY.indexOf(b.severity as any));
  const lines = [
    `# Security assessment synthesis — ${d.assessment.name}`,
    `Objective: ${d.assessment.objective || "(unspecified)"}`,
    `Scope: ${d.assessment.scope || "(unspecified)"}`,
    ``,
    `## Findings (${findings.length}) — QA-passed, evidence-backed`,
    ...findings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title} — ${f.roleName}, confidence ${f.confidence}% (${f.evidenceRefs.length} evidence item(s)).${f.residualRisk ? " Residual risk: " + f.residualRisk : ""}`),
    ``,
    `## Observations (${d.outputs.filter((o) => o.cls === "observation").length})`,
    ...d.outputs.filter((o) => o.cls === "observation").map((o) => `- ${o.title} — ${o.roleName}`),
    ``,
    `## Open hypotheses (${d.outputs.filter((o) => o.cls === "hypothesis").length}) — need validation`,
    ...d.outputs.filter((o) => o.cls === "hypothesis").map((o) => `- ${o.title} — ${o.roleName} [gate: ${o.gate}]`),
    ``,
    `## Missing evidence (${d.outputs.filter((o) => o.cls === "missing-evidence").length})`,
    ...d.outputs.filter((o) => o.cls === "missing-evidence").map((o) => `- ${o.title}`),
    ``,
    `_Accountable synthesis by the Chief of Staff. Human judgment and authorization remain with the operator; an assessment is not a guarantee of security._`,
  ];
  const synthesis = lines.join("\n");
  db.prepare("UPDATE MINICISOASSESSMENT SET Synthesis=?, Status='delivered', Stage='synthesis', UpdatedDate=? WHERE AssessmentID=?").run(synthesis, now(), id);
  return { ok: true, synthesis };
}

// ── local-AI suggestion (Ollama; offline heuristic fallback) ──────────────────
/** Keyword heuristics per role — used offline to surface candidate hypotheses from the evidence. */
const HEURISTICS: { role: string; re: RegExp; title: string; sev: string }[] = [
  { role: "appsec-assessment", re: /\b(sql\s?inject|sqli|union\s+select)\b/i, title: "Possible SQL injection exposure", sev: "high" },
  { role: "appsec-assessment", re: /\b(xss|cross[-\s]?site\s+script|<script)\b/i, title: "Possible cross-site scripting (XSS)", sev: "medium" },
  { role: "appsec-assessment", re: /\b(idor|bola|broken\s+object|authorization\s+bypass)\b/i, title: "Possible broken object-level authorization", sev: "high" },
  { role: "security-architecture", re: /\b(hardcoded|secret|api[_\s-]?key|password\s*=|private\s+key)\b/i, title: "Possible hardcoded secret / credential", sev: "high" },
  { role: "security-architecture", re: /\b(http:\/\/|tls\s*1\.0|ssl\s*v3|no\s+encryption|plaintext)\b/i, title: "Possible weak/absent transport encryption", sev: "medium" },
  { role: "security-architecture", re: /\b(s3|bucket|0\.0\.0\.0\/0|public\s+access|anonymous)\b/i, title: "Possible over-permissive exposure / public access", sev: "medium" },
  { role: "code-review", re: /\b(eval\(|exec\(|deserialize|pickle\.load|os\.system|subprocess)\b/i, title: "Possible unsafe code execution / injection sink", sev: "high" },
  { role: "appsec-assessment", re: /\b(ssrf|server[-\s]?side\s+request|fetch\s*\(\s*url)\b/i, title: "Possible SSRF exposure", sev: "high" },
  { role: "security-architecture", re: /\b(no\s+mfa|single\s+factor|missing\s+auth|unauthenticated)\b/i, title: "Possible missing authentication / MFA gap", sev: "high" },
  { role: "recon-attack-surface", re: /\b(open\s+port|exposed|shodan|subdomain|admin\s+panel|\.git\b)\b/i, title: "Exposed surface worth deeper review", sev: "low" },
];

export async function suggestOutputs(id: number, tenant: number | null): Promise<{ suggestions: any[]; via: string }> {
  const d = mcDetail(id, tenant);
  if (!d) return { suggestions: [], via: "none" };
  const evText = d.evidence.map((e: any) => `[${e.tier}] ${e.title}: ${e.content}`).join("\n").slice(0, 6000);
  if (!evText.trim()) return { suggestions: [], via: "no-evidence" };

  const st = await ollamaStatus().catch(() => ({ reachable: false } as any));
  if (st.reachable) {
    const roleList = MC_ROLES.filter((r) => r.kind === "specialist" && r.id !== "security-qa").map((r) => `${r.id}: ${r.mission}`).join("\n");
    const sys = "You are miniCISO's specialist staff. From the provided EVIDENCE only, propose candidate security outputs. " +
      "Follow the discipline: evidence before narrative, recon surfaces candidates not findings. Never output a 'finding' — only 'hypothesis' or 'observation' or 'missing-evidence'. " +
      "Return STRICT JSON: {\"suggestions\":[{\"role\":\"<role-id>\",\"cls\":\"hypothesis|observation|missing-evidence\",\"title\":\"...\",\"detail\":\"...\",\"severity\":\"critical|high|medium|low|info\",\"residualRisk\":\"...\"}]}. Roles:\n" + roleList;
    try {
      const raw = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: "EVIDENCE:\n" + evText }], 0.2, 60000);
      const m = raw.match(/\{[\s\S]*\}/);
      if (m) {
        const parsed = JSON.parse(m[0]);
        const sugg = (parsed.suggestions || []).filter((s: any) => ROLE_IDS.has(s.role) && s.cls !== "finding").slice(0, 12);
        if (sugg.length) return { suggestions: sugg, via: "ollama" };
      }
    } catch { /* fall through to heuristic */ }
  }

  // offline deterministic heuristic
  const seen = new Set<string>();
  const suggestions: any[] = [];
  for (const h of HEURISTICS) {
    if (h.re.test(evText) && !seen.has(h.title)) {
      seen.add(h.title);
      suggestions.push({ role: h.role, cls: "hypothesis", title: h.title, severity: h.sev,
        detail: "Keyword signal in the collected evidence — a candidate path that needs validation before it can become a finding.", residualRisk: "" });
    }
  }
  return { suggestions, via: "heuristic" };
}

/** Adopt suggestions as hypothesis outputs (never findings), stamped with their source. */
export function adoptSuggestions(id: number, suggestions: any[], source = "AI suggestion"): { added: number } {
  let added = 0;
  for (const s of suggestions || []) {
    if (!s || typeof s !== "object") continue;
    addOutput(id, { role: s.role, cls: s.cls === "observation" || s.cls === "missing-evidence" ? s.cls : "hypothesis",
      title: s.title, detail: s.detail, severity: s.severity, residualRisk: s.residualRisk, source });
    added++;
  }
  return { added };
}

// ── connector ingest ──────────────────────────────────────────────────────────
export function importAssessment(tenant: number | null, payload: {
  name?: string; objective?: string; scope?: string; operator?: string;
  evidence?: { title?: string; tier?: string; source?: string; content?: string }[];
  outputs?: any[];
}): { id: number; evidence: number; outputs: number; created: boolean } {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const name = (payload.name || "miniCISO assessment").slice(0, 300);
  const args = tenant == null ? [name] : [name, tenant];
  const found = db.prepare(`SELECT AssessmentID FROM MINICISOASSESSMENT WHERE Name=? AND ${tw(tenant)}`).get(...args) as { AssessmentID: number } | undefined;
  const id = found ? found.AssessmentID : createAssessment(tenant, payload).id;
  if (found) { db.prepare("DELETE FROM MINICISOEVIDENCE WHERE AssessmentID=?").run(id); db.prepare("DELETE FROM MINICISOOUTPUT WHERE AssessmentID=?").run(id); updateAssessment(id, tenant, payload); }
  const evMap = new Map<string, number>();
  let ev = 0;
  for (const e of payload.evidence || []) { const r = addEvidence(id, e as any); evMap.set(String(e.title || ev), r.id); ev++; }
  let outs = 0;
  for (const o of payload.outputs || []) {
    if (!o || typeof o !== "object") continue;
    const refs = Array.isArray(o.evidence) ? o.evidence.map((t: any) => evMap.get(String(t))).filter(Boolean) : [];
    const r = addOutput(id, { ...o, evidenceRefs: refs, source: o.source || "miniCISO" });
    if (o.qaStatus && (MC_QA as readonly string[]).includes(String(o.qaStatus))) setQa(id, r.id, String(o.qaStatus), o.qaNote);
    outs++;
  }
  return { id, evidence: ev, outputs: outs, created: !found };
}

// ── demo ────────────────────────────────────────────────────────────────────
export function seedMcDemo(tenant: number): void {
  ensureMcTables();
  const db = getDb("XCOMPLIANCE");
  const name = "Demo — Acme checkout service review";
  if (db.prepare("SELECT 1 FROM MINICISOASSESSMENT WHERE Name=? AND TenantID=?").get(name, tenant)) return;
  const { id } = createAssessment(tenant, {
    name, objective: "Assess the checkout microservice before its public launch.",
    scope: "checkout-svc repo + staging API (api.staging.acme.test)", operator: "Head of Security",
  });
  updateAssessment(id, tenant, { stage: "qa", status: "qa" });
  const e1 = addEvidence(id, { title: "Staging API responses", tier: "validated", source: "authorized recon", content: "GET /v1/orders/1042 returns another tenant's order without an ownership check. Confirmed across two accounts." }).id;
  const e2 = addEvidence(id, { title: "Terraform for the API gateway", tier: "declared", source: "repo: infra/gateway.tf", content: "security group ingress 0.0.0.0/0 on port 8080; TLS termination off for the internal listener (http://)." }).id;
  const e3 = addEvidence(id, { title: "checkout handler source", tier: "runtime", source: "repo: src/pay.py", content: "os.system(f\"receipt {order_id}\") builds a shell command from a request field." }).id;
  // a QA-passed, evidence-backed finding
  const f1 = addOutput(id, { role: "appsec-assessment", cls: "finding", title: "Broken object-level authorization on /v1/orders", severity: "high",
    detail: "Sequential order IDs are readable across tenants with no ownership check (BOLA).", evidenceRefs: [e1], gate: "go",
    residualRisk: "Order PII of all customers is enumerable until an ownership check is enforced." }).id;
  setQa(id, f1, "passed", "Reproduced across two accounts; impact and scope confirmed.");
  // a code-review finding still pending QA (blocks delivery — the discipline in action)
  addOutput(id, { role: "code-review", cls: "finding", title: "Command injection in the receipt handler", severity: "critical",
    detail: "os.system() builds a shell command from an untrusted request field in src/pay.py.", evidenceRefs: [e3], gate: "go" });
  // architecture hypothesis + observation + missing evidence
  addOutput(id, { role: "security-architecture", cls: "hypothesis", title: "Internet-exposed gateway with cleartext internal listener", severity: "medium",
    detail: "0.0.0.0/0 ingress + http:// internal listener suggest exposure, but runtime reachability is unconfirmed.", evidenceRefs: [e2], gate: "research" });
  addOutput(id, { role: "recon-attack-surface", cls: "observation", title: "Staging API is internet-reachable", severity: "low",
    detail: "api.staging.acme.test resolves publicly. Not a finding on its own.", evidenceRefs: [e2] });
  addOutput(id, { role: "appsec-assessment", cls: "missing-evidence", title: "No evidence on session/token handling", severity: "info",
    detail: "Need auth flow captures to assess session fixation / token scope before drawing conclusions." });
}
