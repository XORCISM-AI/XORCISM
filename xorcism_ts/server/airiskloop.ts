/**
 * airiskloop.ts — Operational AI Risk Management loop (/ai-risk-loop).
 *
 * Turns AI governance from policy into an operating capability: the continuous, closed loop
 *   IDENTIFY -> ASSESS -> MITIGATE -> MONITOR -> (feeds back to IDENTIFY)
 * with end-to-end traceability:
 *   AI System -> Context -> Risk -> Assessment -> Control -> Owner -> Evidence -> Monitoring -> Decision
 *
 * Sits WITHIN the broader frameworks (ISO/IEC 42001, NIST AI RMF GOVERN/MAP/MEASURE/MANAGE, EU AI Act)
 * rather than replacing them. Reuses the AI system inventory (AISYSTEM), the reusable AI controls of the
 * [[ai-control-library]] (link controls to risks with DESIGN vs OPERATING effectiveness + evidence), the
 * AI lifecycle vocabulary, and EVIDENCE. Owns four tables in XORCISM: AIRISK (the register entry carrying
 * identify + assess + mitigate + monitor + ownership + residual-acceptance), AIRISKCONTROL (risk<->control
 * with design/operating effectiveness + evidence), AIRISKKRI (monitoring indicators with thresholds that
 * trigger action), AIRISKLOG (monitoring findings that feed back and close the loop). RBAC: XCOMPLIANCE.AUDIT.
 */
import { getDb } from "./db";
import { AI_LIFECYCLE, listAiSystems, aiControlLibrary } from "./aicontrol";

// ── Vocabularies (article-driven) ───────────────────────────────────────────────────────────
export const RISK_AREAS = [
  "Fairness & Non-Discrimination", "Privacy & Data Protection", "Security", "Reliability & Safety",
  "Explainability & Transparency", "Governance & Accountability", "Compliance & Legal",
] as const;
export const LOOP_STAGES = ["identify", "assess", "mitigate", "monitor"] as const;
export const RISK_STATUSES = ["open", "treated", "accepted", "closed"] as const;
export const TREATMENTS = ["avoid", "reduce", "transfer", "accept"] as const; // 4T
export const RISK_OWNERS = [
  "Business", "AI/Product", "Data", "Technology", "Information Security", "Privacy", "Legal",
  "Compliance", "Enterprise Risk",
] as const;
export const EFFECTIVENESS = ["untested", "ineffective", "partial", "effective"] as const;
export const KRI_DIRECTION = ["above", "below"] as const;
export const LOG_KINDS = [
  "new-risk", "changed-likelihood", "changed-impact", "control-failure", "incident", "new-threat",
  "regulatory-change", "reassess-triggered",
] as const;
export { AI_LIFECYCLE };

type Stage = (typeof LOOP_STAGES)[number];
const now = (): string => new Date().toISOString();
const clamp15 = (n: unknown): number => Math.max(1, Math.min(5, Math.round(Number(n) || 1)));
export const score = (l: number, i: number): number => clamp15(l) * clamp15(i);
export function band(s: number): "low" | "medium" | "high" | "critical" {
  return s >= 15 ? "critical" : s >= 10 ? "high" : s >= 5 ? "medium" : "low";
}
const j = (v: unknown): string => { try { return JSON.stringify(v ?? {}); } catch { return "{}"; } };
const pj = (s: unknown): Record<string, unknown> => { try { return s ? JSON.parse(String(s)) : {}; } catch { return {}; } };

export function ensureAiRiskTables(): void {
  const db = getDb("XORCISM");
  db.exec(`
    CREATE TABLE IF NOT EXISTS AIRISK (
      RiskID INTEGER PRIMARY KEY AUTOINCREMENT,
      AISystemID INTEGER, Title TEXT NOT NULL, RiskArea TEXT, Description TEXT,
      Context TEXT, LifecyclePhase TEXT, Owner TEXT,
      Stage TEXT DEFAULT 'identify', Status TEXT DEFAULT 'open',
      InherentLikelihood INTEGER, InherentImpact INTEGER,
      ResidualLikelihood INTEGER, ResidualImpact INTEGER,
      Factors TEXT, Treatment TEXT,
      AcceptanceBy TEXT, AcceptanceDate TEXT, AcceptanceRationale TEXT,
      LastReviewed TEXT, CreatedDate TEXT, UpdatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_airisk_tenant ON AIRISK(TenantID);
    CREATE INDEX IF NOT EXISTS ix_airisk_system ON AIRISK(AISystemID);

    CREATE TABLE IF NOT EXISTS AIRISKCONTROL (
      LinkID INTEGER PRIMARY KEY AUTOINCREMENT,
      RiskID INTEGER NOT NULL, ControlRef TEXT, ControlName TEXT, ControlOwner TEXT,
      DesignEffective TEXT DEFAULT 'untested', OperatingEffective TEXT DEFAULT 'untested',
      EvidenceRef TEXT, Notes TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_airiskctl_risk ON AIRISKCONTROL(RiskID);

    CREATE TABLE IF NOT EXISTS AIRISKKRI (
      KriID INTEGER PRIMARY KEY AUTOINCREMENT,
      RiskID INTEGER NOT NULL, Name TEXT, Metric TEXT, Threshold REAL, Direction TEXT DEFAULT 'above',
      CurrentValue REAL, Action TEXT, LastChecked TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_airiskkri_risk ON AIRISKKRI(RiskID);

    CREATE TABLE IF NOT EXISTS AIRISKLOG (
      LogID INTEGER PRIMARY KEY AUTOINCREMENT,
      RiskID INTEGER NOT NULL, Kind TEXT, Detail TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_airisklog_risk ON AIRISKLOG(RiskID);

    CREATE TABLE IF NOT EXISTS AIRISKEVIDENCE (
      EvID INTEGER PRIMARY KEY AUTOINCREMENT,
      RiskID INTEGER NOT NULL, LinkID INTEGER, Sha256 TEXT, Filename TEXT, Size INTEGER,
      ContentType TEXT, Title TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_airiskev_risk ON AIRISKEVIDENCE(RiskID);`);
}

const tclause = (t: number | null): string => (t != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "");
const tparams = (t: number | null): number[] => (t != null ? [t] : []);

export interface RiskControlRow { linkId: number; controlRef: string; controlName: string; controlOwner: string; designEffective: string; operatingEffective: string; evidenceRef: string | null; notes: string | null }
export interface KriRow { kriId: number; name: string; metric: string; threshold: number | null; direction: string; currentValue: number | null; action: string | null; lastChecked: string | null; breached: boolean }
export interface LogRow { logId: number; kind: string; detail: string; createdDate: string }
export interface EvidenceRow { evId: number; linkId: number | null; sha256: string; filename: string; size: number; contentType: string | null; title: string | null; createdDate: string }
export interface RiskFull {
  riskId: number; aiSystemId: number | null; systemName: string; title: string; riskArea: string; description: string;
  context: Record<string, unknown>; lifecyclePhase: string; owner: string; stage: Stage; status: string;
  inherentLikelihood: number | null; inherentImpact: number | null; inherentScore: number; inherentBand: string;
  residualLikelihood: number | null; residualImpact: number | null; residualScore: number; residualBand: string;
  factors: Record<string, unknown>; treatment: string;
  acceptanceBy: string | null; acceptanceDate: string | null; acceptanceRationale: string | null; lastReviewed: string | null;
  controls: RiskControlRow[]; kris: KriRow[]; log: LogRow[]; evidence: EvidenceRow[];
}

function kriBreached(k: { threshold: number | null; direction: string; currentValue: number | null }): boolean {
  if (k.currentValue == null || k.threshold == null) return false;
  return k.direction === "below" ? k.currentValue < k.threshold : k.currentValue > k.threshold;
}

function systemNames(tenant: number | null): Map<number, string> {
  const m = new Map<number, string>();
  for (const s of listAiSystems(tenant)) m.set(s.id, s.name);
  return m;
}

function hydrate(r: Record<string, unknown>, names: Map<number, string>, db: ReturnType<typeof getDb>): RiskFull {
  const riskId = Number(r.RiskID);
  const iL = r.InherentLikelihood != null ? Number(r.InherentLikelihood) : null;
  const iI = r.InherentImpact != null ? Number(r.InherentImpact) : null;
  const rL = r.ResidualLikelihood != null ? Number(r.ResidualLikelihood) : null;
  const rI = r.ResidualImpact != null ? Number(r.ResidualImpact) : null;
  const iScore = iL != null && iI != null ? score(iL, iI) : 0;
  const rScore = rL != null && rI != null ? score(rL, rI) : 0;
  const controls = (db.prepare("SELECT LinkID, ControlRef, ControlName, ControlOwner, DesignEffective, OperatingEffective, EvidenceRef, Notes FROM AIRISKCONTROL WHERE RiskID=? ORDER BY LinkID").all(riskId) as Record<string, unknown>[])
    .map((c) => ({ linkId: Number(c.LinkID), controlRef: String(c.ControlRef || ""), controlName: String(c.ControlName || ""), controlOwner: String(c.ControlOwner || ""), designEffective: String(c.DesignEffective || "untested"), operatingEffective: String(c.OperatingEffective || "untested"), evidenceRef: (c.EvidenceRef as string) || null, notes: (c.Notes as string) || null }));
  const kris = (db.prepare("SELECT KriID, Name, Metric, Threshold, Direction, CurrentValue, Action, LastChecked FROM AIRISKKRI WHERE RiskID=? ORDER BY KriID").all(riskId) as Record<string, unknown>[])
    .map((k) => { const row = { kriId: Number(k.KriID), name: String(k.Name || ""), metric: String(k.Metric || ""), threshold: k.Threshold != null ? Number(k.Threshold) : null, direction: String(k.Direction || "above"), currentValue: k.CurrentValue != null ? Number(k.CurrentValue) : null, action: (k.Action as string) || null, lastChecked: (k.LastChecked as string) || null }; return { ...row, breached: kriBreached(row) }; });
  const log = (db.prepare("SELECT LogID, Kind, Detail, CreatedDate FROM AIRISKLOG WHERE RiskID=? ORDER BY LogID DESC").all(riskId) as Record<string, unknown>[])
    .map((l) => ({ logId: Number(l.LogID), kind: String(l.Kind || ""), detail: String(l.Detail || ""), createdDate: String(l.CreatedDate || "") }));
  const evidence = (db.prepare("SELECT EvID, LinkID, Sha256, Filename, Size, ContentType, Title, CreatedDate FROM AIRISKEVIDENCE WHERE RiskID=? ORDER BY EvID DESC").all(riskId) as Record<string, unknown>[])
    .map((e) => ({ evId: Number(e.EvID), linkId: e.LinkID != null ? Number(e.LinkID) : null, sha256: String(e.Sha256 || ""), filename: String(e.Filename || ""), size: Number(e.Size || 0), contentType: (e.ContentType as string) || null, title: (e.Title as string) || null, createdDate: String(e.CreatedDate || "") }));
  const sid = r.AISystemID != null ? Number(r.AISystemID) : null;
  return {
    riskId, aiSystemId: sid, systemName: sid != null ? (names.get(sid) || `#${sid}`) : "(unassigned)",
    title: String(r.Title || ""), riskArea: String(r.RiskArea || ""), description: String(r.Description || ""),
    context: pj(r.Context), lifecyclePhase: String(r.LifecyclePhase || ""), owner: String(r.Owner || ""),
    stage: (String(r.Stage || "identify") as Stage), status: String(r.Status || "open"),
    inherentLikelihood: iL, inherentImpact: iI, inherentScore: iScore, inherentBand: iScore ? band(iScore) : "-",
    residualLikelihood: rL, residualImpact: rI, residualScore: rScore, residualBand: rScore ? band(rScore) : "-",
    factors: pj(r.Factors), treatment: String(r.Treatment || ""),
    acceptanceBy: (r.AcceptanceBy as string) || null, acceptanceDate: (r.AcceptanceDate as string) || null,
    acceptanceRationale: (r.AcceptanceRationale as string) || null, lastReviewed: (r.LastReviewed as string) || null,
    controls, kris, log, evidence,
  };
}

/** The full loop view: risks (hydrated with controls/KRIs/log), the system + control + vocab pickers, analytics. */
export function aiRiskLoop(tenant: number | null): {
  risks: RiskFull[]; systems: ReturnType<typeof listAiSystems>;
  controls: { ref: string; name: string; owner: string; evidence: string; riskDomains: string[] }[];
  vocab: { areas: readonly string[]; stages: readonly string[]; statuses: readonly string[]; treatments: readonly string[]; owners: readonly string[]; effectiveness: readonly string[]; lifecycle: readonly string[]; kriDirection: readonly string[]; logKinds: readonly string[] };
  summary: ReturnType<typeof loopSummary>;
} {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  const names = systemNames(tenant);
  const rows = db.prepare(`SELECT * FROM AIRISK ${tclause(tenant)} ORDER BY RiskID DESC`).all(...tparams(tenant)) as Record<string, unknown>[];
  const risks = rows.map((r) => hydrate(r, names, db));
  const lib = aiControlLibrary(tenant);
  const controls = lib.controls.map((c) => ({ ref: String(c.ref ?? ""), name: String(c.objective ?? ""), owner: String(c.owner ?? ""), evidence: String(c.evidence ?? ""), riskDomains: Array.isArray(c.riskDomains) ? c.riskDomains.map(String) : [] }));
  return {
    risks, systems: listAiSystems(tenant), controls,
    vocab: { areas: RISK_AREAS, stages: LOOP_STAGES, statuses: RISK_STATUSES, treatments: TREATMENTS, owners: RISK_OWNERS, effectiveness: EFFECTIVENESS, lifecycle: AI_LIFECYCLE, kriDirection: KRI_DIRECTION, logKinds: LOG_KINDS },
    summary: loopSummary(risks),
  };
}

/** Analytics + the article's common failure-pattern checks. */
export function loopSummary(risks: RiskFull[]) {
  const byArea: Record<string, number> = {}; const byStage: Record<string, number> = {}; const byTreatment: Record<string, number> = {};
  for (const s of LOOP_STAGES) byStage[s] = 0;
  let highCritResidual = 0, unowned = 0, controlsNoEvidence = 0, acceptedNoRationale = 0, kriBreaches = 0, overdueMonitor = 0, controlsUntested = 0, thirdPartyUnassessed = 0;
  const staleDays = 90; const nowMs = Date.now();
  for (const r of risks) {
    byArea[r.riskArea] = (byArea[r.riskArea] || 0) + 1;
    byStage[r.stage] = (byStage[r.stage] || 0) + 1;
    if (r.treatment) byTreatment[r.treatment] = (byTreatment[r.treatment] || 0) + 1;
    if (r.residualScore >= 10) highCritResidual++;
    if (!r.owner) unowned++;
    if ((r.status === "accepted" || r.treatment === "accept") && !r.acceptanceRationale) acceptedNoRationale++;
    for (const c of r.controls) { if (!c.evidenceRef) controlsNoEvidence++; if (c.operatingEffective === "untested") controlsUntested++; }
    for (const k of r.kris) if (k.breached) kriBreaches++;
    // overdue monitoring: a risk in monitor/treated with KRIs never (or long-ago) checked
    const anyChecked = r.kris.some((k) => k.lastChecked && (nowMs - Date.parse(k.lastChecked)) < staleDays * 864e5);
    if ((r.stage === "monitor" || r.status === "treated") && r.kris.length && !anyChecked) overdueMonitor++;
    if (String(r.factors.thirdParty || "").toLowerCase() === "yes" && !r.controls.length) thirdPartyUnassessed++;
  }
  // Common failure patterns (from the article) — each {id, label, count} where count>0 is a flag.
  const failurePatterns = [
    { id: "no-owner", label: "Risks without an accountable owner", count: unowned },
    { id: "control-no-evidence", label: "Controls with no operating evidence", count: controlsNoEvidence },
    { id: "control-untested", label: "Controls never tested for operation", count: controlsUntested },
    { id: "accepted-no-rationale", label: "Residual accepted without documented rationale", count: acceptedNoRationale },
    { id: "no-kri", label: "Treated/monitored risks with no KRI", count: risks.filter((r) => (r.stage === "monitor" || r.status === "treated") && !r.kris.length).length },
    { id: "overdue-monitor", label: "Monitored risks with stale/absent KRI checks", count: overdueMonitor },
    { id: "third-party", label: "Third-party-dependent risks with no control", count: thirdPartyUnassessed },
    { id: "no-assessment", label: "Risks past identify with no residual assessment", count: risks.filter((r) => r.stage !== "identify" && !r.residualScore).length },
  ].filter((p) => p.count > 0);
  return {
    total: risks.length, highCritResidual, unowned, controlsNoEvidence, kriBreaches, overdueMonitor,
    byArea, byStage, byTreatment,
    accepted: risks.filter((r) => r.status === "accepted").length,
    monitored: byStage["monitor"] || 0,
    avgResidual: risks.length ? Math.round((risks.reduce((n, r) => n + r.residualScore, 0) / risks.length) * 10) / 10 : 0,
    failurePatterns,
  };
}

export function getRisk(tenant: number | null, id: number): RiskFull | null {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  const r = db.prepare(`SELECT * FROM AIRISK WHERE RiskID=? ${tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : ""}`).get(...[id, ...(tenant != null ? [tenant] : [])]) as Record<string, unknown> | undefined;
  if (!r) return null;
  return hydrate(r, systemNames(tenant), db);
}

type RiskPatch = Partial<{ aiSystemId: number | null; title: string; riskArea: string; description: string; context: Record<string, unknown>; lifecyclePhase: string; owner: string; stage: string; status: string; inherentLikelihood: number; inherentImpact: number; residualLikelihood: number; residualImpact: number; factors: Record<string, unknown>; treatment: string; acceptanceBy: string; acceptanceDate: string; acceptanceRationale: string }>;

export function createRisk(tenant: number | null, p: RiskPatch): RiskFull {
  ensureAiRiskTables();
  if (!p.title) throw new Error("title required");
  const db = getDb("XORCISM");
  const ts = now();
  const info = db.prepare(`INSERT INTO AIRISK (AISystemID, Title, RiskArea, Description, Context, LifecyclePhase, Owner, Stage, Status, InherentLikelihood, InherentImpact, ResidualLikelihood, ResidualImpact, Factors, Treatment, CreatedDate, UpdatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    p.aiSystemId ?? null, p.title, p.riskArea ?? null, p.description ?? null, j(p.context), p.lifecyclePhase ?? null, p.owner ?? null,
    p.stage ?? "identify", p.status ?? "open",
    p.inherentLikelihood ?? null, p.inherentImpact ?? null, p.residualLikelihood ?? null, p.residualImpact ?? null,
    j(p.factors), p.treatment ?? null, ts, ts, tenant ?? null);
  const id = Number(info.lastInsertRowid);
  db.prepare("INSERT INTO AIRISKLOG (RiskID, Kind, Detail, CreatedDate) VALUES (?,?,?,?)").run(id, "new-risk", `Identified: ${p.title}`, ts);
  return getRisk(tenant, id)!;
}

export function updateRisk(tenant: number | null, id: number, p: RiskPatch): RiskFull {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  const cur = getRisk(tenant, id);
  if (!cur) throw new Error("unknown risk");
  const cols: Record<string, unknown> = {};
  const map: [keyof RiskPatch, string, (v: unknown) => unknown][] = [
    ["aiSystemId", "AISystemID", (v) => v], ["title", "Title", (v) => v], ["riskArea", "RiskArea", (v) => v],
    ["description", "Description", (v) => v], ["context", "Context", (v) => j(v)], ["lifecyclePhase", "LifecyclePhase", (v) => v],
    ["owner", "Owner", (v) => v], ["stage", "Stage", (v) => v], ["status", "Status", (v) => v],
    ["inherentLikelihood", "InherentLikelihood", (v) => v], ["inherentImpact", "InherentImpact", (v) => v],
    ["residualLikelihood", "ResidualLikelihood", (v) => v], ["residualImpact", "ResidualImpact", (v) => v],
    ["factors", "Factors", (v) => j(v)], ["treatment", "Treatment", (v) => v],
    ["acceptanceBy", "AcceptanceBy", (v) => v], ["acceptanceDate", "AcceptanceDate", (v) => v], ["acceptanceRationale", "AcceptanceRationale", (v) => v],
  ];
  for (const [k, col, fn] of map) if (p[k] !== undefined) cols[col] = fn(p[k]);
  // validate enums
  if (p.stage && !(LOOP_STAGES as readonly string[]).includes(p.stage)) throw new Error(`invalid stage ${p.stage}`);
  if (p.status && !(RISK_STATUSES as readonly string[]).includes(p.status)) throw new Error(`invalid status ${p.status}`);
  if (p.treatment && !(TREATMENTS as readonly string[]).includes(p.treatment)) throw new Error(`invalid treatment ${p.treatment}`);
  if (!Object.keys(cols).length) return cur;
  cols.UpdatedDate = now();
  const sets = Object.keys(cols).map((c) => `${c}=?`).join(", ");
  db.prepare(`UPDATE AIRISK SET ${sets} WHERE RiskID=?`).run(...Object.values(cols), id);
  return getRisk(tenant, id)!;
}

export function deleteRisk(tenant: number | null, id: number): void {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  if (!getRisk(tenant, id)) throw new Error("unknown risk");
  db.prepare("DELETE FROM AIRISKCONTROL WHERE RiskID=?").run(id);
  db.prepare("DELETE FROM AIRISKKRI WHERE RiskID=?").run(id);
  db.prepare("DELETE FROM AIRISKLOG WHERE RiskID=?").run(id);
  db.prepare("DELETE FROM AIRISK WHERE RiskID=?").run(id);
}

// ── MITIGATE: controls (design vs operating effectiveness + evidence) ─────────────────────────
export function linkControl(tenant: number | null, riskId: number, c: { controlRef?: string; controlName?: string; controlOwner?: string }): RiskFull {
  ensureAiRiskTables();
  if (!getRisk(tenant, riskId)) throw new Error("unknown risk");
  const db = getDb("XORCISM");
  db.prepare("INSERT INTO AIRISKCONTROL (RiskID, ControlRef, ControlName, ControlOwner, CreatedDate) VALUES (?,?,?,?,?)")
    .run(riskId, c.controlRef ?? null, c.controlName ?? null, c.controlOwner ?? null, now());
  return getRisk(tenant, riskId)!;
}
export function updateControlLink(tenant: number | null, linkId: number, p: { designEffective?: string; operatingEffective?: string; evidenceRef?: string; notes?: string }): void {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  for (const [k, v] of [["designEffective", p.designEffective], ["operatingEffective", p.operatingEffective]] as [string, string | undefined][])
    if (v && !(EFFECTIVENESS as readonly string[]).includes(v)) throw new Error(`invalid ${k} ${v}`);
  const cols: Record<string, unknown> = {};
  if (p.designEffective !== undefined) cols.DesignEffective = p.designEffective;
  if (p.operatingEffective !== undefined) cols.OperatingEffective = p.operatingEffective;
  if (p.evidenceRef !== undefined) cols.EvidenceRef = p.evidenceRef || null;
  if (p.notes !== undefined) cols.Notes = p.notes || null;
  if (!Object.keys(cols).length) return;
  const sets = Object.keys(cols).map((c) => `${c}=?`).join(", ");
  db.prepare(`UPDATE AIRISKCONTROL SET ${sets} WHERE LinkID=?`).run(...Object.values(cols), linkId);
}
export function unlinkControl(_tenant: number | null, linkId: number): void {
  ensureAiRiskTables(); getDb("XORCISM").prepare("DELETE FROM AIRISKCONTROL WHERE LinkID=?").run(linkId);
}

// ── MONITOR: KRIs (thresholds that trigger action) ───────────────────────────────────────────
export function addKri(tenant: number | null, riskId: number, k: { name?: string; metric?: string; threshold?: number; direction?: string; action?: string }): RiskFull {
  ensureAiRiskTables();
  if (!getRisk(tenant, riskId)) throw new Error("unknown risk");
  if (k.direction && !(KRI_DIRECTION as readonly string[]).includes(k.direction)) throw new Error(`invalid direction ${k.direction}`);
  const db = getDb("XORCISM");
  db.prepare("INSERT INTO AIRISKKRI (RiskID, Name, Metric, Threshold, Direction, Action, TenantID) VALUES (?,?,?,?,?,?,?)")
    .run(riskId, k.name ?? null, k.metric ?? null, k.threshold ?? null, k.direction ?? "above", k.action ?? null, tenant ?? null);
  return getRisk(tenant, riskId)!;
}
export function updateKri(tenant: number | null, kriId: number, p: { currentValue?: number | null; threshold?: number; direction?: string; action?: string; name?: string; metric?: string }): void {
  ensureAiRiskTables();
  if (p.direction && !(KRI_DIRECTION as readonly string[]).includes(p.direction)) throw new Error(`invalid direction ${p.direction}`);
  const db = getDb("XORCISM");
  const cols: Record<string, unknown> = {};
  if (p.name !== undefined) cols.Name = p.name;
  if (p.metric !== undefined) cols.Metric = p.metric;
  if (p.threshold !== undefined) cols.Threshold = p.threshold;
  if (p.direction !== undefined) cols.Direction = p.direction;
  if (p.action !== undefined) cols.Action = p.action || null;
  if (p.currentValue !== undefined) { cols.CurrentValue = p.currentValue; cols.LastChecked = now(); }
  if (!Object.keys(cols).length) return;
  const sets = Object.keys(cols).map((c) => `${c}=?`).join(", ");
  db.prepare(`UPDATE AIRISKKRI SET ${sets} WHERE KriID=?`).run(...Object.values(cols), kriId);
}
export function deleteKri(_tenant: number | null, kriId: number): void {
  ensureAiRiskTables(); getDb("XORCISM").prepare("DELETE FROM AIRISKKRI WHERE KriID=?").run(kriId);
}

/** Record a monitoring finding — closes the loop by feeding back to identify/assess. */
export function addLoopEvent(tenant: number | null, riskId: number, kind: string, detail: string, reopen = false): RiskFull {
  ensureAiRiskTables();
  if (!getRisk(tenant, riskId)) throw new Error("unknown risk");
  if (kind && !(LOG_KINDS as readonly string[]).includes(kind)) throw new Error(`invalid kind ${kind}`);
  const db = getDb("XORCISM");
  db.prepare("INSERT INTO AIRISKLOG (RiskID, Kind, Detail, CreatedDate) VALUES (?,?,?,?)").run(riskId, kind || "reassess-triggered", detail || "", now());
  // Findings that materially change exposure send the risk back to ASSESS (the loop closes).
  if (reopen || ["changed-likelihood", "changed-impact", "control-failure", "new-threat", "regulatory-change"].includes(kind)) {
    db.prepare("UPDATE AIRISK SET Stage='assess', Status=CASE WHEN Status='closed' THEN 'open' ELSE Status END, LastReviewed=?, UpdatedDate=? WHERE RiskID=?").run(now(), now(), riskId);
  }
  return getRisk(tenant, riskId)!;
}

// ── EVIDENCE: attach control/monitoring evidence files to the content-addressed store (CAS) ──────
export function attachEvidence(tenant: number | null, riskId: number, e: { sha256: string; filename: string; size: number; contentType?: string; title?: string; linkId?: number }): RiskFull {
  ensureAiRiskTables();
  if (!getRisk(tenant, riskId)) throw new Error("unknown risk");
  const db = getDb("XORCISM");
  db.prepare("INSERT INTO AIRISKEVIDENCE (RiskID, LinkID, Sha256, Filename, Size, ContentType, Title, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(riskId, e.linkId ?? null, e.sha256, e.filename, e.size, e.contentType ?? null, e.title ?? null, now(), tenant ?? null);
  return getRisk(tenant, riskId)!;
}
export function deleteEvidence(_tenant: number | null, evId: number): void {
  ensureAiRiskTables(); getDb("XORCISM").prepare("DELETE FROM AIRISKEVIDENCE WHERE EvID=?").run(evId);
}

/**
 * AI-risk exposure for the Enterprise Risk Score: a POSITIVE contribution (adds risk) for unmitigated
 * high/critical residual AI risks + KRI breaches + residual accepted without a documented rationale.
 * Capped so it shifts the score without dominating (like the maturity credit / weighted-controls driver).
 */
export function aiRiskExposure(tenant: number | null): { term: number; highCritUnmitigated: number; kriBreaches: number; acceptedNoRationale: number } {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  const rows = db.prepare(`SELECT RiskID, ResidualLikelihood, ResidualImpact, Status, Treatment, AcceptanceRationale FROM AIRISK ${tclause(tenant)}`).all(...tparams(tenant)) as Record<string, unknown>[];
  let pts = 0, hc = 0, br = 0, anr = 0;
  for (const r of rows) {
    const rL = r.ResidualLikelihood != null ? Number(r.ResidualLikelihood) : 0;
    const rI = r.ResidualImpact != null ? Number(r.ResidualImpact) : 0;
    const b = rL && rI ? band(score(rL, rI)) : "-";
    const breaches = (db.prepare("SELECT Threshold, Direction, CurrentValue FROM AIRISKKRI WHERE RiskID=?").all(Number(r.RiskID)) as Record<string, unknown>[])
      .filter((k) => kriBreached({ threshold: k.Threshold != null ? Number(k.Threshold) : null, direction: String(k.Direction || "above"), currentValue: k.CurrentValue != null ? Number(k.CurrentValue) : null })).length;
    const hasEffective = !!db.prepare("SELECT 1 FROM AIRISKCONTROL WHERE RiskID=? AND OperatingEffective='effective' LIMIT 1").get(Number(r.RiskID));
    const accepted = String(r.Status) === "accepted" || String(r.Treatment) === "accept";
    const acceptedOk = accepted && !!r.AcceptanceRationale;
    if ((b === "high" || b === "critical") && !hasEffective && !acceptedOk) { pts += b === "critical" ? 12 : 6; hc++; }
    br += breaches; pts += breaches * 4;
    if (accepted && !r.AcceptanceRationale) { anr++; pts += 5; }
  }
  return { term: Math.max(0, Math.min(60, Math.round(pts))), highCritUnmitigated: hc, kriBreaches: br, acceptedNoRationale: anr };
}

/** Markdown export: the traceability chain per risk (auditor / board handout). */
export function loopMarkdown(tenant: number | null): string {
  const d = aiRiskLoop(tenant);
  const L: string[] = ["# AI Risk Management Loop\n"];
  L.push(`Risks: **${d.summary.total}** · high/critical residual: ${d.summary.highCritResidual} · KRI breaches: ${d.summary.kriBreaches} · unowned: ${d.summary.unowned}\n`);
  L.push("Traceability: AI System -> Context -> Risk -> Assessment -> Control -> Owner -> Evidence -> Monitoring -> Decision\n");
  for (const r of d.risks) {
    L.push(`\n## ${r.title}  \n`);
    L.push(`- **System**: ${r.systemName} · **Area**: ${r.riskArea} · **Stage**: ${r.stage} · **Owner**: ${r.owner || "(none)"}`);
    L.push(`- **Inherent**: ${r.inherentScore || "-"} (${r.inherentBand}) → **Residual**: ${r.residualScore || "-"} (${r.residualBand}) · **Treatment**: ${r.treatment || "-"}`);
    L.push(`- **Controls**: ${r.controls.map((c) => `${c.controlRef || c.controlName} [design:${c.designEffective}/operating:${c.operatingEffective}${c.evidenceRef ? " ✓evidence" : ""}]`).join("; ") || "(none)"}`);
    L.push(`- **KRIs**: ${r.kris.map((k) => `${k.name} ${k.direction} ${k.threshold}${k.currentValue != null ? ` (now ${k.currentValue}${k.breached ? " ⚠BREACH" : ""})` : ""}`).join("; ") || "(none)"}`);
    if (r.status === "accepted" || r.treatment === "accept") L.push(`- **Decision**: residual accepted by ${r.acceptanceBy || "?"} on ${r.acceptanceDate || "?"} — ${r.acceptanceRationale || "(no rationale)"}`);
  }
  return L.join("\n");
}

/** Seed a demo AI risk (idempotent by title) so the cockpit is not empty. */
export function seedAiRiskDemo(tenant: number): void {
  ensureAiRiskTables();
  const db = getDb("XORCISM");
  const exists = db.prepare("SELECT RiskID FROM AIRISK WHERE Title=? AND TenantID=?").get("LLM support assistant may produce unsafe or biased answers", tenant) as { RiskID: number } | undefined;
  if (exists) return;
  const sys = listAiSystems(tenant)[0];
  const r = createRisk(tenant, {
    aiSystemId: sys?.id ?? null, title: "LLM support assistant may produce unsafe or biased answers", riskArea: "Reliability & Safety",
    description: "The customer-support LLM can hallucinate or produce biased/unsafe guidance that users act on.",
    context: { purpose: "Answer customer support questions", actors: "Product team (deploy), vendor (model)", affected: "Customers", data: "Support tickets, KB", decisions: "Suggests answers to agents", dependencies: "3rd-party LLM API", obligations: "EU AI Act transparency (Art.50), consumer law" },
    lifecyclePhase: "Deployment", owner: "AI/Product", stage: "monitor", status: "treated",
    inherentLikelihood: 4, inherentImpact: 4, residualLikelihood: 2, residualImpact: 3,
    factors: { severity: "medium", reversibility: "reversible", autonomy: "assistive", humanOversight: "human-in-the-loop", dataSensitivity: "medium", thirdParty: "yes", regulatory: "EU AI Act" },
    treatment: "reduce",
  });
  linkControl(tenant, r.riskId, { controlRef: "AI-HUM-01", controlName: "Human approval gate for high-impact decisions", controlOwner: "Business" });
  updateControlLink(tenant, r.controls.length ? r.controls[0].linkId : (getRisk(tenant, r.riskId)!.controls[0].linkId), { designEffective: "effective", operatingEffective: "partial", evidenceRef: "approval-logs Q3" });
  const withKri = addKri(tenant, r.riskId, { name: "Unsafe-answer rate", metric: "% flagged answers / week", threshold: 2, direction: "above", action: "Investigate + escalate to AI governance committee" });
  updateKri(tenant, withKri.kris[0].kriId, { currentValue: 1.1 });
}
