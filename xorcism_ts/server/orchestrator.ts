/**
 * orchestrator.ts — Agentic CROC orchestrator (/croc-orchestrator).
 *
 * The autonomous layer over the CROC loop: it watches the LOOPEVENT bus (croc.ts) for new
 * high/critical signals and, for each, selects the right analyst "copilot", produces a verdict +
 * recommended action + rationale, and queues it as a CROCACTION **for human approval**. Approving
 * records the decision (and notifies); dismissing closes it. Nothing side-effectful runs without a
 * human — the orchestrator triages and proposes at machine speed; the human stays in the loop.
 *
 * Deterministic + offline-safe (no model dependency); runs as an in-process poller (XOR_ORCHESTRATOR=0
 * to disable) and on demand. XORCISM.CROCACTION + ORCHCURSOR.
 */
import { randomUUID } from "crypto";
import { allocId, getDb, createNotification } from "./db";
import { emitLoopEvent } from "./croc";
import { recordAiActivity } from "./aiskills";
import { mobilizeToCtem, topOpenItemKeys } from "./threatdebt";
import { dispatchSoar, soarDashboard, runSoarPlaybook } from "./soar";

const now = (): string => new Date().toISOString();
const RANK: Record<string, number> = { info: 0, low: 1, medium: 2, notable: 2, high: 3, critical: 4 };
const rank = (s: string): number => RANK[(s || "").toLowerCase()] ?? 0;

export function ensureOrchestratorTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS CROCACTION (
      ActionID INTEGER PRIMARY KEY, ActionGUID TEXT, LoopEventID INTEGER, EventType TEXT, Severity TEXT,
      Title TEXT, Copilot TEXT, Verdict TEXT, RecommendedAction TEXT, Rationale TEXT, Confidence INTEGER,
      Status TEXT DEFAULT 'proposed', AssetID INTEGER, TenantID INTEGER, CreatedDate TEXT,
      DecidedBy INTEGER, DecidedDate TEXT, ExecutedOutcome TEXT);
    CREATE INDEX IF NOT EXISTS ix_crocaction_status ON CROCACTION(Status);
    CREATE INDEX IF NOT EXISTS ix_crocaction_tenant ON CROCACTION(TenantID);
    CREATE INDEX IF NOT EXISTS ix_crocaction_event ON CROCACTION(LoopEventID);
    CREATE TABLE IF NOT EXISTS ORCHCURSOR (Singleton INTEGER PRIMARY KEY CHECK (Singleton=1), LastLoopEventID INTEGER);
  `);
  // ExecutedOutcome added after the initial release — backfill on existing installs.
  try {
    const cols = new Set((getDb("XORCISM").prepare('PRAGMA table_info(CROCACTION)').all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("ExecutedOutcome")) getDb("XORCISM").exec("ALTER TABLE CROCACTION ADD COLUMN ExecutedOutcome TEXT");
  } catch { /* */ }
}

interface Proposal { copilot: string; verdict: string; action: string; rationale: string; confidence: number; title: string }

/** Pick the analyst copilot + craft a proposal from a loop event (deterministic playbook). */
function propose(ev: { EventType: string; Summary: string; Severity: string }): Proposal {
  const t = (ev.EventType || "").toLowerCase();
  const s = (ev.Summary || "").trim();
  const sev = (ev.Severity || "info").toLowerCase();
  const sevVerdict = sev === "critical" ? "Confirmed critical — act now" : sev === "high" ? "Likely true positive — prioritise" : "Notable — review";
  const mk = (copilot: string, action: string, rationale: string, confidence: number, title: string): Proposal => ({ copilot, verdict: sevVerdict, action, rationale, confidence, title });

  if (/identity|signin|kerbero|dcsync|account|mfa|cred/.test(t))
    return mk("itdr-investigate", "Investigate the identity; if confirmed, disable the account and reset credentials, then review blast radius in the knowledge graph.", "Identity threat detections precede account takeover and lateral movement; fast containment limits spread.", 80, s || "Identity threat detected");
  if (/exposure|kev|exploit|vuln|cve|surface|drift/.test(t))
    return mk("exposure-brief", "Prioritise remediation of the exposed asset (patch/mitigate); verify exploitability (KEV/EPSS) and the blast radius before scheduling the change.", "Exposure with exploitation signal is the highest-yield remediation; the prioritised worklist orders the work.", 78, s || "New exposure on an asset");
  if (/incident|alert|breach|ransom/.test(t))
    return mk("incident-copilot", "Triage and assign per the IR playbook; contain the impacted asset and start the timeline; escalate if scope grows.", "Open high/critical incidents need an owner and a contain→eradicate→recover path with SLA tracking.", 76, s || "Incident raised");
  if (/compliance|control|finding|audit|policy|obligation/.test(t))
    return mk("compliance-impl", "Open a remediation task for the failing control and assign an owner with a due date; attach evidence on closure.", "Failing controls and missed obligations are audit/regulatory risk; tracked remediation restores assurance.", 72, s || "Control / obligation gap");
  if (/anomaly|extraction|jailbreak|poison|prompt.?inject/.test(t))
    return mk("ai-incident-response", "Contain the AI system: throttle/enforce rate limits per user + API key, rotate any exposed keys, tighten input/output guardrails, and triage the AI runtime detections. If memorized/PII data was extracted, treat as a data breach (start the DPIA / 72h notification clock).", "AI runtime anomalies (training-data extraction, repeated jailbreak, poisoning drift) are an active attack on a model in production — fast containment limits exfiltration and abuse.", 80, s || "AI runtime anomaly");
  if (/ai|model|llm|prompt|guardrail/.test(t))
    return mk("ai-governance", "Review the AI system in the inventory; add the missing governing framework/guardrails and (if personal data) a DPIA.", "Ungoverned high-risk AI is EU-AI-Act and operational risk; the AI inventory tracks the gap.", 70, s || "AI governance signal");
  if (/threatdebt|adversary|opportunity|paydown/.test(t))
    return mk("threatdebt-paydown", s || "Pay down the highest-ROI adversary opportunity: harden the top choke point or close the highest-debt finding, then re-snapshot to confirm the AOI drop.", "Newly-accrued adversary opportunity compounds; retiring the highest-debt path/finding first removes the most attacker options per unit of effort (price-the-fix).", 75, s ? `Pay down: ${s.slice(0, 80)}` : "Adversary opportunity accrued");
  return mk("soc-triage", "Triage the signal, confirm true/false positive, and assign an owner if it warrants action.", "Every high/critical loop event deserves a verdict and, if real, an owner.", 60, s || `${ev.EventType} event`);
}

/** Generate proposals for new high/critical loop events since the watermark. Idempotent per event. */
export function runOrchestrator(): { scanned: number; proposed: number } {
  ensureOrchestratorTables();
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='LOOPEVENT'").get()) return { scanned: 0, proposed: 0 };
  const cursor = (db.prepare("SELECT LastLoopEventID FROM ORCHCURSOR WHERE Singleton=1").get() as { LastLoopEventID: number } | undefined)?.LastLoopEventID ?? 0;
  const events = db.prepare(
    `SELECT LoopEventID, EventType, Source, Summary, Severity, AssetID, TenantID FROM LOOPEVENT
     WHERE LoopEventID > ? AND LOWER(COALESCE(Severity,'')) IN ('high','critical') ORDER BY LoopEventID LIMIT 500`
  ).all(cursor) as any[];
  let proposed = 0, maxId = cursor;
  const recs: { tenant: number | null; copilot: string; title: string; eventType: string }[] = [];
  const ins = db.prepare(
    `INSERT INTO CROCACTION (ActionID, ActionGUID, LoopEventID, EventType, Severity, Title, Copilot, Verdict,
       RecommendedAction, Rationale, Confidence, Status, AssetID, TenantID, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,'proposed',?,?,?)`
  );
  const tx = db.transaction(() => {
    for (const ev of events) {
      maxId = Math.max(maxId, ev.LoopEventID);
      const dupe = db.prepare("SELECT 1 FROM CROCACTION WHERE LoopEventID=?").get(ev.LoopEventID);
      if (dupe) continue;
      const p = propose(ev);
      const id = allocId(db, "CROCACTION", "ActionID");
      ins.run(id, randomUUID(), ev.LoopEventID, ev.EventType, ev.Severity, p.title.slice(0, 300), p.copilot, p.verdict, p.action, p.rationale, p.confidence, ev.AssetID ?? null, ev.TenantID ?? null, now());
      recs.push({ tenant: ev.TenantID ?? null, copilot: p.copilot, title: p.title, eventType: ev.EventType });
      proposed++;
    }
    db.prepare("INSERT INTO ORCHCURSOR (Singleton, LastLoopEventID) VALUES (1, ?) ON CONFLICT(Singleton) DO UPDATE SET LastLoopEventID=excluded.LastLoopEventID").run(maxId);
  });
  tx();
  // AI provenance: log each proposal (delegate → copilot) to the AI activity log (best-effort).
  for (const r of recs) recordAiActivity(r.tenant, { actor: "croc-orchestrator", action: "orchestrator.propose", entityType: "LOOPEVENT", entityKey: r.eventType, summary: `Delegate → ${r.copilot}: ${r.title}`.slice(0, 580), outcome: "proposed" });
  return { scanned: events.length, proposed };
}

function rowToAction(r: any): any {
  return {
    id: r.ActionID, loopEventId: r.LoopEventID, eventType: r.EventType, severity: r.Severity, title: r.Title,
    copilot: r.Copilot, verdict: r.Verdict, recommendedAction: r.RecommendedAction, rationale: r.Rationale,
    confidence: r.Confidence, status: r.Status, assetId: r.AssetID, createdDate: r.CreatedDate, decidedDate: r.DecidedDate,
    executedOutcome: r.ExecutedOutcome || null,
  };
}

export function orchestratorDashboard(tenant: number | null): any {
  ensureOrchestratorTables();
  const db = getDb("XORCISM");
  const rows = (db.prepare(
    "SELECT * FROM CROCACTION WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY CASE Status WHEN 'proposed' THEN 0 ELSE 1 END, CASE LOWER(Severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, ActionID DESC LIMIT 400"
  ).all(tenant) as any[]).map(rowToAction);
  const by = (st: string) => rows.filter((r) => r.status === st);
  const summary = {
    proposed: by("proposed").length, approved: by("approved").length, dismissed: by("dismissed").length,
    critical: rows.filter((r) => (r.severity || "").toLowerCase() === "critical" && r.status === "proposed").length,
    total: rows.length,
  };
  return { summary, queue: by("proposed"), recent: rows.filter((r) => r.status !== "proposed").slice(0, 40), all: rows };
}

/**
 * Actuate an approved action — close the loop: (1) run a matching enabled SOAR playbook (simulate)
 * so the response workflow actually executes, (2) push to any external SOAR webhooks, (3) emit a
 * `croc.action_executed` loop event (info severity, so the orchestrator never re-proposes it — that
 * is the measurable "loop closed" signal). Best-effort and never throws. Returns a one-line outcome.
 */
function executeApprovedAction(a: any, tenant: number | null): string {
  const parts: string[] = [];
  try {
    const enabled = (soarDashboard(tenant).playbooks as any[]).filter((p) => p.enabled);
    const toks = String(a.EventType || "").toLowerCase().split(/[._]/).filter(Boolean);
    const match = enabled.find((p) => toks.some((tk: string) => { const tr = String(p.trigger).toLowerCase(); return tr.includes(tk) || tk.includes(tr); })) || enabled[0];
    if (match) { const run = runSoarPlaybook(match.id, tenant, { mode: "simulate", triggerRef: `crocaction:${a.ActionID}` }); if (run) parts.push(`ran SOAR playbook "${match.name}" (run #${run.runId}, ${run.status})`); }
    else parts.push("no enabled SOAR playbook — response logged");
  } catch { /* */ }
  try { void dispatchSoar(tenant, { action: "croc-approved", eventType: a.EventType, severity: a.Severity, summary: a.Title, refs: [`crocaction:${a.ActionID}`] }); } catch { /* */ }
  // "Pay down through CTEM": an approved AOI paydown becomes a tracked CTEM exposure (Prioritize stage).
  if (String(a.EventType || "").toLowerCase().startsWith("threatdebt")) {
    try { const ex = mobilizeToCtem(tenant, { title: String(a.Title || "AOI paydown"), severity: a.Severity, ledgerKeys: topOpenItemKeys(tenant, 5) }); if (ex) parts.push(`tracked in CTEM (exposure #${ex.id})`); } catch { /* */ }
  }
  try { emitLoopEvent({ type: "croc.action_executed", source: "orchestrator", summary: `Executed: ${String(a.RecommendedAction).slice(0, 180)}`, severity: "info", tenant, assetId: a.AssetID ?? undefined }); parts.push("loop closed"); } catch { /* */ }
  try { recordAiActivity(tenant, { actor: String(a.Copilot || "croc-orchestrator"), action: "orchestrator.execute", entityType: "CROCACTION", entityKey: String(a.ActionID), summary: `Executed approved action: ${String(a.Title || "").slice(0, 200)}`, outcome: "executed" }); } catch { /* */ }
  return parts.join("; ");
}

/** Approve (→ actuate the response) or dismiss a proposed action. */
export function decideAction(id: number, tenant: number | null, decision: "approved" | "dismissed", userId: number | null): boolean {
  ensureOrchestratorTables();
  const db = getDb("XORCISM");
  const r = db.prepare("SELECT * FROM CROCACTION WHERE ActionID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant) as any;
  if (!r || r.Status !== "proposed") return false;
  let outcome: string | null = null;
  if (decision === "approved") outcome = executeApprovedAction(r, tenant) || "response actuated";
  db.prepare("UPDATE CROCACTION SET Status=?, DecidedBy=?, DecidedDate=?, ExecutedOutcome=? WHERE ActionID=?").run(decision, userId ?? null, now(), outcome, id);
  if (decision === "approved" && userId) {
    try { createNotification({ userId, title: `CROC action approved: ${String(r.Title).slice(0, 80)}`, message: `${r.RecommendedAction}${outcome ? `\n↳ ${outcome}` : ""}`, level: (r.Severity || "").toLowerCase() === "critical" ? "warning" : "info", link: "/croc-orchestrator", source: "CROC orchestrator", tenantId: r.TenantID ?? null }); } catch { /* */ }
  }
  return true;
}

let timer: ReturnType<typeof setInterval> | null = null;
/** Background poller: propose actions for new high/critical loop events every ~2 min. */
export function startOrchestrator(): void {
  if (process.env.XOR_ORCHESTRATOR === "0") return;
  if (timer) return;
  const tick = () => { try { const r = runOrchestrator(); if (r.proposed) console.log(`[orchestrator] proposed ${r.proposed} action(s) from ${r.scanned} new event(s)`); } catch (e) { console.warn(`[orchestrator] ${(e as Error).message}`); } };
  setTimeout(tick, 8000); // initial pass shortly after boot
  timer = setInterval(tick, 120000);
}
