/**
 * croc.ts — Cyber Risk Operations Center: the Continuous Defense Loop engine (the ∞).
 *
 * The thesis (J. Castro, CROC / Continuous Defense Loop): most orgs have CROC *capabilities* but
 * no loop that *moves*. This module is XORCISM's movement layer — it wires the existing components
 * into a loop that is live (event-driven, not cron), bidirectional (CROC→SOC and SOC→CROC), and
 * measured (loop latency / machine-speed coverage), with decisions pre-authorized upstream.
 *
 *   • LOOPEVENT  — the change-feed / event bus. emitLoopEvent() is the heartbeat: any exposure- or
 *     incident-relevant change records an event (hooked into notifrules.dispatchEvent + cvematch).
 *   • LOOPPOLICY — pre-authorization ("decide before the race begins"): condition → pre-authorized
 *     action, evaluated the instant an event fires, at machine speed. Humans own the policy; the
 *     loop executes it.
 *   • Bidirectional flow — riskWeightedAlerts() (CROC→SOC: rank the SOC queue by live exposure ×
 *     criticality, not recency) and incidentExposureFeedback() (SOC→CROC: an incident reprioritizes
 *     matching exposures across the estate).
 *   • Cyber-risk hunting — topExposures() ("where could an adversary succeed?"), incl. over-scoped
 *     non-human identities (the over-scoped-agent-credential exposure).
 * Surfaced at /croc. Everything is best-effort + defensive (it must never break the notification path).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { topExposures } from "./fusion";
import { notifyTeams } from "./teams";
import { pushExternalTicket, externalTicketingConfigured, redactTargets, type OutboundTicket } from "./ticketing";
import { pushIamConstraint, externalIamConfigured, redactIamTargets, iamEnforceArmed, type IamConstraint } from "./iam";
import { dispatchSoar, externalSoarConfigured, redactSoar } from "./soar";
import { recomputeTenant, computeEnterpriseRiskScore } from "./riskscore";
import { attackPathGraph } from "./attackpath";
import * as xid from "./xid";

const now = (): string => new Date().toISOString();

/** topExposures() spans XVULNERABILITY + XORCISM; tolerate a sparse/missing exposure schema. */
function safeExposures(tenant: number | null, limit: number): { results: any[]; scanned: number } {
  try { return topExposures(tenant, limit); } catch { return { results: [], scanned: 0 }; }
}

// notification level / alert severity → a 0–4 rank (info … critical)
const SEV_RANK: Record<string, number> = {
  info: 0, success: 1, low: 1, warning: 2, medium: 2, high: 3, error: 3, critical: 4,
};
const rank = (s: string | null | undefined): number => SEV_RANK[String(s || "info").toLowerCase()] ?? 0;

export type LoopDirection = "croc->soc" | "soc->croc" | "internal";
/** Which way does an event flow? An incident/alert reshapes exposure (soc→croc); an exposure/drift
 *  change informs detection (croc→soc). */
function inferDirection(eventType: string): LoopDirection {
  const t = (eventType || "").toLowerCase();
  if (/incident|alert|malware|detect|soc|breach|sighting/.test(t)) return "soc->croc";
  if (/cve|vuln|exposure|drift|risk|control|asset|identity|compliance|patch/.test(t)) return "croc->soc";
  return "internal";
}

export function ensureCrocTables(): void {
  const db = getDb("XORCISM");
  db.exec(`
    CREATE TABLE IF NOT EXISTS LOOPEVENT (
      LoopEventID INTEGER PRIMARY KEY, LoopEventGUID TEXT, EventType TEXT, Source TEXT, Summary TEXT,
      Direction TEXT, Severity TEXT, AssetID INTEGER, AttackID TEXT, DecidedAction TEXT,
      LatencyMs INTEGER, Acknowledged INTEGER DEFAULT 0, CreatedDate TEXT, DecidedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_loopevent_created ON LOOPEVENT(CreatedDate);
    CREATE INDEX IF NOT EXISTS ix_loopevent_tenant ON LOOPEVENT(TenantID);
    CREATE TABLE IF NOT EXISTS LOOPPOLICY (
      PolicyID INTEGER PRIMARY KEY, PolicyGUID TEXT, Name TEXT, EventFilter TEXT, MinSeverity TEXT,
      Direction TEXT, Action TEXT, Enabled INTEGER DEFAULT 1, Description TEXT, CreatedDate TEXT, TenantID INTEGER);
  `);
}

interface PolicyRow { PolicyID: number; Name: string; EventFilter: string; MinSeverity: string; Direction: string; Action: string; Enabled: number; Description: string; TenantID: number | null }

function policiesFor(tenant: number | null): PolicyRow[] {
  try {
    return getDb("XORCISM").prepare(
      "SELECT * FROM LOOPPOLICY WHERE Enabled=1 AND (TenantID = ? OR TenantID IS NULL)"
    ).all(tenant) as PolicyRow[];
  } catch { return []; }
}

/** Evaluate the pre-authorization policies against an event → the actions that fire (machine-speed). */
function evaluatePolicies(ev: { type: string; direction: string; severity: string; tenant: number | null }): string[] {
  const out: string[] = [];
  for (const p of policiesFor(ev.tenant)) {
    if (p.MinSeverity && rank(ev.severity) < rank(p.MinSeverity)) continue;
    if (p.Direction && p.Direction !== "any" && p.Direction !== ev.direction) continue;
    const filt = (p.EventFilter || "*").trim();
    if (filt !== "*" && !filt.split(",").some((f) => ev.type.toLowerCase().includes(f.trim().toLowerCase()))) continue;
    if (!out.includes(p.Action)) out.push(p.Action);
  }
  return out;
}

/** Map a loop-event severity onto an XTICKET priority/severity bucket. */
function ticketSev(sev: string): "Critical" | "High" | "Medium" {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "error") return "Critical";
  if (s === "high" || s === "warning") return "High";
  return "Medium";
}

/**
 * ENFORCEMENT — "acts at machine speed". Turn the decided actions into real side effects:
 *   - `ticket` / `constrain` → open an XTICKET work item (one per event);
 *   - `escalate` / `notify` / `ticket` / `constrain` → push a Teams escalation card (fire-and-forget,
 *     a no-op when no webhook is configured).
 * Best-effort and bounded: it NEVER throws (it runs inside emitLoopEvent, which must never break its
 * caller) and it NEVER calls dispatchEvent (no recursion back into the loop). Returns a compact result
 * string (e.g. "ticket#42 · escalated") that is recorded on the event's DecidedAction — so the cockpit
 * shows what actually *fired*, not merely what was decided.
 */
function executeActions(
  ev: { type: string; summary: string; severity: string; tenant: number | null },
  actions: string[],
): { label: string; external: OutboundTicket | null; iam: IamConstraint | null } {
  const labels: string[] = [];
  const isConstrain = actions.includes("constrain");
  const wantTicket = actions.includes("ticket") || isConstrain;
  let external: OutboundTicket | null = null;
  // constrain → ask the IAM layer to enforce least-privilege on the named identity (dry-run by default).
  const iam: IamConstraint | null = isConstrain ? { identityName: ev.summary || ev.type, reason: ev.type } : null;
  // 1) Open a real ticket for ticket/constrain (at most one per event).
  if (wantTicket) {
    const sev = ticketSev(ev.severity);
    const subject = (isConstrain ? "Constrain: " : "CROC: ") + (ev.summary || ev.type).slice(0, 150);
    const desc = "Auto-opened by the CROC Continuous Defense Loop (a pre-authorized policy fired at machine speed).\n"
      + `Event type: ${ev.type}\nSeverity: ${ev.severity}\n${ev.summary || ""}`
      + (isConstrain ? "\n\nRecommended action: apply least-privilege / revoke standing privilege on the flagged identity." : "");
    try {
      const xt = getDb("XTICKET");
      const tid = allocId(xt, "TICKET", "TicketID");
      xt.prepare(
        `INSERT INTO TICKET (TicketID, TicketGUID, TicketNumber, Subject, Description, Status, Priority, Severity, TicketType, Tags, CreatedDate, UpdatedDate)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
      ).run(tid, randomUUID(), `CROC-${tid}`, subject, desc, "Open", sev, sev,
        isConstrain ? "Identity" : "Security", `croc,${ev.type}${isConstrain ? ",constrain" : ""}`, now(), now());
      labels.push(`ticket#${tid}`);
    } catch { /* internal ticketing unavailable — still try the external push */ }
    // Defer the external push (Jira/ServiceNow) to emitLoopEvent, which knows the LoopEventID to
    // back-fill with the external ref (jira:SEC-123 / snow:INC…) once the async POST resolves.
    external = { subject, body: desc, severity: ev.severity, eventType: ev.type };
  }
  // 2) Push a Teams escalation card (fire-and-forget; resolveTargets is a no-op when unconfigured).
  if (actions.some((a) => a === "escalate" || a === "notify" || a === "ticket" || a === "constrain")) {
    const isEscalate = actions.includes("escalate");
    try {
      void notifyTeams(`croc.${ev.type}`, {
        tenant: ev.tenant,
        title: `${isEscalate ? "\u{1F53A} CROC escalation" : "\u{1F501} CROC pre-authorized action"}: ${actions.join("/")}`,
        message: ev.summary || ev.type,
        level: ev.severity,
        source: "croc-loop",
        link: "/croc",
      }).catch(() => { /* outbound is best-effort */ });
    } catch { /* notifyTeams threw synchronously — ignore */ }
    labels.push(isEscalate ? "escalated" : "notified");
  }
  if (actions.includes("reprioritize")) labels.push("reprioritized");
  return { label: labels.join(" · "), external, iam };
}

/**
 * Fire the external ITSM ticket (Jira / ServiceNow) for a loop event, best-effort and asynchronously,
 * then back-fill the event's DecidedAction with the returned reference(s) once the POST(s) resolve.
 * No-op when no external destination is configured — the internal XTICKET still stands.
 */
function fireExternalTicket(eventId: number, tenant: number | null, t: OutboundTicket): void {
  try {
    if (!externalTicketingConfigured(tenant)) return;
    void pushExternalTicket(tenant, t).then((r) => {
      if (r && r.refs.length) backfill(eventId, r.refs);
    }).catch(() => { /* outbound is best-effort */ });
  } catch { /* never throw */ }
}

/** Append external reference(s) onto a loop event's DecidedAction once an async action resolves. */
function backfill(eventId: number, refs: string[]): void {
  try {
    getDb("XORCISM").prepare(
      "UPDATE LOOPEVENT SET DecidedAction = COALESCE(DecidedAction,'') || ? WHERE LoopEventID=?"
    ).run(" · " + refs.join(" · "), eventId);
  } catch { /* row gone — ignore */ }
}

/** constrain → enforce least-privilege in Entra (dry-run by default), back-filling the result ref. */
function fireIamConstraint(eventId: number, tenant: number | null, c: IamConstraint): void {
  try {
    if (!externalIamConfigured(tenant)) return;
    void pushIamConstraint(tenant, c).then((r) => {
      if (r && r.refs.length) backfill(eventId, r.refs);
    }).catch(() => { /* best-effort */ });
  } catch { /* never throw */ }
}

/** Fan the fired action(s) out to the SOAR/n8n automation webhooks (generic downstream glue). */
function fireSoar(tenant: number | null, ev: { type: string; summary: string; severity: string }, actions: string[], label: string): void {
  try {
    if (!externalSoarConfigured(tenant)) return;
    void dispatchSoar(tenant, { action: actions.join(","), eventType: ev.type, severity: ev.severity, summary: ev.summary, refs: label ? label.split(" · ") : [] }).catch(() => { /* best-effort */ });
  } catch { /* never throw */ }
}

/**
 * THE HEARTBEAT. Record a change on the loop and (synchronously, at machine speed) evaluate the
 * pre-authorization policies. Best-effort: never throws (it is called from dispatchEvent). The
 * `latencyMs` of an auto-decided event is ~0 — that is the point: a pre-decided action needs no
 * deliberation while the decision still matters.
 */
export function emitLoopEvent(e: {
  type: string; source?: string; summary?: string; severity?: string;
  direction?: LoopDirection; assetId?: number | null; attackId?: string | null; tenant?: number | null;
}): void {
  try {
    ensureCrocTables();
    const db = getDb("XORCISM");
    const direction = e.direction ?? inferDirection(e.type);
    const tenant = e.tenant ?? null;
    const t0 = Date.now();
    const actions = evaluatePolicies({ type: e.type, direction, severity: e.severity ?? "info", tenant });
    // ENFORCE: a pre-authorized action doesn't just get recorded — it FIRES (ticket / Teams escalation),
    // at machine speed, right here. executeActions never throws and never re-enters the loop.
    let decided: string | null = null;
    let external: OutboundTicket | null = null;
    let iam: IamConstraint | null = null;
    if (actions.length) {
      const fired = executeActions(
        { type: e.type, summary: e.summary || "", severity: e.severity ?? "info", tenant }, actions);
      decided = fired.label || actions.join(",");
      external = fired.external;
      iam = fired.iam;
    }
    const id = allocId(db, "LOOPEVENT", "LoopEventID");
    db.prepare(
      `INSERT INTO LOOPEVENT (LoopEventID, LoopEventGUID, EventType, Source, Summary, Direction, Severity,
         AssetID, AttackID, DecidedAction, LatencyMs, CreatedDate, DecidedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(id, randomUUID(), e.type.slice(0, 80), (e.source || "").slice(0, 80), (e.summary || "").slice(0, 400),
      direction, (e.severity || "info").toLowerCase(), e.assetId ?? null, e.attackId ?? null,
      decided, actions.length ? (Date.now() - t0) : null,
      now(), actions.length ? now() : null, tenant);
    // Outbound side effects happen after the event is recorded, keyed by its id so async results can be
    // back-filled onto DecidedAction. Each is a no-op when nothing is configured.
    if (external) fireExternalTicket(id, tenant, external);          // Jira / ServiceNow ticket
    if (iam) fireIamConstraint(id, tenant, iam);                     // Entra least-privilege enforcement
    if (actions.length) fireSoar(tenant, { type: e.type, summary: e.summary || "", severity: e.severity ?? "info" }, actions, decided || ""); // n8n / SOAR glue
    scheduleRecompute(tenant);                                       // continuous = live: refresh risk score reactively
  } catch { /* the loop must never break the caller */ }
}

// ── policy CRUD ──────────────────────────────────────────────────────────────────────
export function listPolicies(tenant: number | null): any[] {
  ensureCrocTables();
  return (getDb("XORCISM").prepare("SELECT * FROM LOOPPOLICY WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY PolicyID").all(tenant) as PolicyRow[])
    .map((p) => ({ id: p.PolicyID, name: p.Name, eventFilter: p.EventFilter, minSeverity: p.MinSeverity, direction: p.Direction, action: p.Action, enabled: !!p.Enabled, description: p.Description }));
}
export function addPolicy(tenant: number | null, p: { name: string; eventFilter?: string; minSeverity?: string; direction?: string; action: string; description?: string }): { id: number } {
  ensureCrocTables();
  const db = getDb("XORCISM");
  const id = allocId(db, "LOOPPOLICY", "PolicyID");
  db.prepare(
    "INSERT INTO LOOPPOLICY (PolicyID, PolicyGUID, Name, EventFilter, MinSeverity, Direction, Action, Enabled, Description, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,1,?,?,?)"
  ).run(id, randomUUID(), (p.name || "Policy").slice(0, 120), p.eventFilter || "*", p.minSeverity || "high",
    p.direction || "any", p.action || "escalate", (p.description || "").slice(0, 400), now(), tenant);
  return { id };
}
export function setPolicy(tenant: number | null, id: number, patch: { enabled?: boolean; minSeverity?: string; action?: string; eventFilter?: string }): boolean {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM LOOPPOLICY WHERE PolicyID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant)) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.enabled != null) { sets.push("Enabled=?"); vals.push(patch.enabled ? 1 : 0); }
  if (patch.minSeverity) { sets.push("MinSeverity=?"); vals.push(patch.minSeverity); }
  if (patch.action) { sets.push("Action=?"); vals.push(patch.action); }
  if (patch.eventFilter) { sets.push("EventFilter=?"); vals.push(patch.eventFilter); }
  if (sets.length) db.prepare(`UPDATE LOOPPOLICY SET ${sets.join(", ")} WHERE PolicyID=?`).run(...vals, id);
  return true;
}
export function deletePolicy(tenant: number | null, id: number): boolean {
  return getDb("XORCISM").prepare("DELETE FROM LOOPPOLICY WHERE PolicyID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant).changes > 0;
}

/** Seed sensible default pre-authorization policies (idempotent by name). */
export function seedCrocPolicies(tenant: number | null): void {
  ensureCrocTables();
  const db = getDb("XORCISM");
  const have = new Set((db.prepare("SELECT Name FROM LOOPPOLICY WHERE (TenantID = ? OR TenantID IS NULL)").all(tenant) as { Name: string }[]).map((r) => r.Name));
  const defaults = [
    { name: "Critical exposure → escalate", eventFilter: "cve,exposure,vuln,drift", minSeverity: "critical", direction: "croc->soc", action: "escalate", description: "A critical exposure change escalates into the SOC detection queue immediately." },
    { name: "Incident → reprioritize exposure", eventFilter: "incident,alert,malware", minSeverity: "high", direction: "soc->croc", action: "reprioritize", description: "A high+ incident reprioritizes matching exposures across the estate (SOC→CROC feedback)." },
    { name: "Detection drift → ticket", eventFilter: "drift", minSeverity: "high", direction: "any", action: "ticket", description: "A regressed detection (BAS re-validation) opens a remediation ticket." },
    { name: "Over-scoped agent identity → constrain", eventFilter: "identity", minSeverity: "high", direction: "any", action: "constrain", description: "A high-risk non-human/over-privileged identity drives a least-privilege constraint upstream." },
    { name: "Identity threat detected → escalate", eventFilter: "identity.threat", minSeverity: "high", direction: "any", action: "escalate", description: "A high/critical ITDR detection (brute force, spray, impossible travel, DCSync…) escalates into the SOC detection queue at machine speed." },
  ];
  for (const d of defaults) if (!have.has(d.name)) addPolicy(tenant, d);
}

// ── CROC→SOC: rank the SOC alert queue by live risk (exposure × criticality), not recency ──────
export function riskWeightedAlerts(tenant: number | null, limit = 20): any[] {
  let rows: any[] = [];
  try {
    const xi = getDb("XINCIDENT");
    rows = xi.prepare(
      `SELECT AlertID AS id, AlertName AS name, Severity AS severity, Category AS category,
              DetectionSource AS source, AttackTechniques AS attack, CreatedDate AS created
       FROM ALERT WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY CreatedDate DESC LIMIT 200`
    ).all(tenant) as any[];
  } catch { return []; }
  // criticality lookup: which assets are high-value (financial value) — best-effort, one query.
  let valued = new Set<string>();
  try {
    const xo = getDb("XORCISM");
    const vals = xo.prepare(
      `SELECT a.AssetName n FROM ASSET a JOIN ASSETFINANCIALVALUE f ON f.AssetID = a.AssetID
       WHERE f.FinancialValue > 0 GROUP BY a.AssetID`
    ).all() as { n: string }[];
    valued = new Set(vals.map((v) => String(v.n || "").toLowerCase()));
  } catch { /* no financial data */ }
  const ageDays = (d: string): number => { try { return (Date.now() - Date.parse(d)) / 86400000; } catch { return 99; } };
  const out = rows.map((r) => {
    let w = rank(r.severity) * 22;                          // severity is the floor
    const txt = `${r.name || ""} ${r.category || ""}`.toLowerCase();
    if (r.attack) w += 8;                                   // mapped to ATT&CK = known technique
    if ([...valued].some((v) => v && txt.includes(v))) w += 25; // touches a high-value asset
    if (/crown|prod|payment|domain controller|finance|critical/.test(txt)) w += 12;
    w = Math.max(0, Math.min(100, Math.round(w - Math.min(15, ageDays(r.created)))));
    return { ...r, riskWeight: w };
  });
  out.sort((a, b) => b.riskWeight - a.riskWeight);
  return out.slice(0, limit);
}

// ── SOC→CROC: an incident reprioritizes matching exposures across the estate ──────────────────
export function incidentExposureFeedback(tenant: number | null): any {
  // How many estate exposures match the techniques/CVEs seen in recent incidents/alerts?
  let techniques: string[] = [];
  try {
    const xi = getDb("XINCIDENT");
    const rows = xi.prepare("SELECT AttackTechniques a FROM ALERT WHERE AttackTechniques IS NOT NULL AND AttackTechniques != '' AND (TenantID = ? OR TenantID IS NULL) ORDER BY CreatedDate DESC LIMIT 50").all(tenant) as { a: string }[];
    techniques = [...new Set(rows.flatMap((r) => String(r.a).split(/[,\s]+/)).map((t) => t.trim().toUpperCase()).filter((t) => /^T\d{3,4}/.test(t)))];
  } catch { /* */ }
  const exp = safeExposures(tenant, 200);
  // exposures the SOC has now flagged as actively-attacked (technique seen in an incident) → hot
  const hot = exp.results.filter((e) => e.kev || e.itw || e.exploits > 0).length;
  return { techniquesSeen: techniques.slice(0, 12), matchingExposures: hot, totalExposures: exp.scanned };
}

// ── Cyber-risk hunting: over-scoped non-human identities (the over-scoped-agent-credential) ────
export function agenticExposures(tenant: number | null): any[] {
  try {
    const xo = getDb("XORCISM");
    const cols = new Set((xo.prepare("PRAGMA table_info(IDENTITY)").all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("IdentityName")) return [];
    const rows = xo.prepare(
      `SELECT IdentityName n, IdentityType t, IdentityClass c, PrivilegeLevel pl, RiskLevel rl,
              MFAEnabled mfa, Status st
       FROM IDENTITY WHERE (TenantID = ? OR TenantID IS NULL) LIMIT 1000`
    ).all(tenant) as any[];
    return rows
      .map((r) => {
        let risk = 0; const why: string[] = [];
        const nonHuman = /non.?human|service|machine|agent|nhi|bot/i.test(`${r.t} ${r.c}`);
        if (nonHuman) { risk += 1; why.push("non-human / agent"); }
        if (/admin|privileg|root|owner|global/i.test(`${r.pl || ""}`)) { risk += 2; why.push("privileged"); }
        if (String(r.mfa) === "0" || r.mfa === 0) { risk += 1; why.push("no MFA"); }
        if (/high|critical/i.test(`${r.rl || ""}`)) { risk += 1; why.push("flagged high-risk"); }
        if (/orphan|inactive|stale/i.test(`${r.st || ""}`)) { risk += 1; why.push("orphaned/stale"); }
        return { name: r.n, type: r.t, privilege: r.pl, risk, why };
      })
      .filter((r) => r.risk >= 3 && r.why.includes("non-human / agent"))
      .sort((a, b) => b.risk - a.risk).slice(0, 15);
  } catch { return []; }
}

export function crocDashboard(tenant: number | null): any {
  ensureCrocTables();
  const db = getDb("XORCISM");
  const since = new Date(Date.now() - 86400000).toISOString();
  let events: any[] = [];
  try {
    events = db.prepare("SELECT * FROM LOOPEVENT WHERE (TenantID = ? OR TenantID IS NULL) AND CreatedDate >= ? ORDER BY CreatedDate DESC LIMIT 400").all(tenant, since) as any[];
  } catch { /* */ }
  const byDir = { "croc->soc": 0, "soc->croc": 0, "internal": 0 } as Record<string, number>;
  let decided = 0, ticketsOpened = 0, externalTickets = 0, iamActions = 0; const latencies: number[] = [];
  for (const e of events) {
    byDir[e.Direction] = (byDir[e.Direction] || 0) + 1;
    if (e.DecidedAction) { decided++; if (e.LatencyMs != null) latencies.push(e.LatencyMs); }
    if (typeof e.DecidedAction === "string" && e.DecidedAction.includes("ticket#")) ticketsOpened++;
    if (typeof e.DecidedAction === "string" && /\b(jira|snow):/.test(e.DecidedAction)) externalTickets++;
    if (typeof e.DecidedAction === "string" && /\biam:/.test(e.DecidedAction)) iamActions++;
  }
  latencies.sort((a, b) => a - b);
  const lastHour = events.filter((e) => Date.parse(e.CreatedDate) > Date.now() - 3600000).length;
  // loop health: is it moving, and does intelligence cross in BOTH directions?
  const moving = lastHour > 0;
  const bidirectional = byDir["croc->soc"] > 0 && byDir["soc->croc"] > 0;
  const machineSpeedPct = events.length ? Math.round((decided / events.length) * 100) : 0;
  const exp = safeExposures(tenant, 25);
  return {
    summary: {
      eventsToday: events.length, lastHour,
      crocToSoc: byDir["croc->soc"], socToCroc: byDir["soc->croc"], internal: byDir["internal"],
      machineSpeedPct, autoDecided: decided, ticketsOpened, externalTickets, iamActions,
      medianLatencyMs: latencies.length ? latencies[Math.floor(latencies.length / 2)] : 0,
      p95LatencyMs: latencies.length ? latencies[Math.floor(latencies.length * 0.95)] : 0,
      moving, bidirectional,
      loopHealth: moving && bidirectional ? "moving" : moving ? "one-directional" : "still",
    },
    feed: events.slice(0, 30).map((e) => ({ id: e.LoopEventID, type: e.EventType, source: e.Source, summary: e.Summary, direction: e.Direction, severity: e.Severity, decided: e.DecidedAction, latencyMs: e.LatencyMs, at: e.CreatedDate })),
    riskWeightedAlerts: riskWeightedAlerts(tenant, 15),
    feedback: incidentExposureFeedback(tenant),
    hunting: exp.results.slice(0, 15),
    agentic: agenticExposures(tenant),
    policies: listPolicies(tenant),
    ticketing: { configured: safeBool(() => externalTicketingConfigured(tenant)), targets: safeArr(() => redactTargets(tenant)) },
    iam: { configured: safeBool(() => externalIamConfigured(tenant)), armed: safeBool(() => iamEnforceArmed()), targets: safeArr(() => redactIamTargets(tenant)) },
    soar: { configured: safeBool(() => externalSoarConfigured(tenant)), webhooks: safeArr(() => redactSoar(tenant)) },
    resilience: safeArr(() => resilienceTrend(tenant, 30)),
    resilienceSla: resilienceSla(),
  };
}

function safeBool(fn: () => boolean): boolean { try { return fn(); } catch { return false; } }
function safeArr(fn: () => any[]): any[] { try { return fn(); } catch { return []; } }

// ════════════════════════════════════════════════════════════════════════════════════════════
// REACTIVE RECOMPUTE — "continuous = live, not frequent". A material loop event recomputes the
// risk score within seconds (debounced) instead of waiting up to an hour for the cron. The hourly
// cron stays as a backstop; this makes the score *move* when the estate does.
// ════════════════════════════════════════════════════════════════════════════════════════════
const recomputeTimers = new Map<number, NodeJS.Timeout>();
const recomputeDebounceMs = (): number => { const n = Number(process.env.CROC_RECOMPUTE_DEBOUNCE_MS); return Number.isFinite(n) && n >= 0 ? n : 5000; };

/** Debounced reactive recompute for a tenant: refresh the EnterpriseRiskScore + accrue a resilience point. */
function scheduleRecompute(tenant: number | null): void {
  try {
    if (tenant == null) return; // global aggregate handled by the cron
    const prev = recomputeTimers.get(tenant);
    if (prev) clearTimeout(prev);
    const t = setTimeout(() => {
      recomputeTimers.delete(tenant);
      try { recomputeTenant(tenant); } catch { /* best-effort */ }   // full per-tenant recompute (assets + enterprise + org + VM)
      try { accrueLoopHealth(tenant); } catch { /* best-effort */ }  // resilience-over-time point
    }, recomputeDebounceMs());
    if (typeof t.unref === "function") t.unref();
    recomputeTimers.set(tenant, t);
  } catch { /* never throw — runs inside emitLoopEvent */ }
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// RESILIENCE OVER TIME — is the loop getting better? Daily snapshot of the loop's pulse so the
// trend (machine-speed, latency, exposure backlog, enforcement, risk score) is visible over weeks.
// ════════════════════════════════════════════════════════════════════════════════════════════
export function ensureLoopHealthTable(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS LOOPHEALTHSNAPSHOT (
      SnapshotID INTEGER PRIMARY KEY,
      SnapDate TEXT, MachineSpeedPct INTEGER, MedianLatencyMs INTEGER, Events INTEGER,
      TicketsOpened INTEGER, IamActions INTEGER, ExternalTickets INTEGER, ExposureBacklog INTEGER,
      LoopHealth TEXT, EnterpriseScore REAL, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_loophealth_tenant ON LOOPHEALTHSNAPSHOT(TenantID, SnapDate);
  `);
}

/** Compute the loop's current pulse for a tenant (last 24h of events + live exposure backlog). */
function loopMetrics(tenant: number | null): { machineSpeedPct: number; medianLatencyMs: number; events: number; ticketsOpened: number; iamActions: number; externalTickets: number; exposureBacklog: number; loopHealth: string; enterpriseScore: number } {
  let events: any[] = [];
  try {
    const since = new Date(Date.now() - 86400000).toISOString();
    events = getDb("XORCISM").prepare("SELECT Direction, DecidedAction, LatencyMs, CreatedDate FROM LOOPEVENT WHERE (TenantID = ? OR TenantID IS NULL) AND CreatedDate >= ? ORDER BY CreatedDate DESC LIMIT 400").all(tenant, since) as any[];
  } catch { /* */ }
  let decided = 0, ticketsOpened = 0, iamActions = 0, externalTickets = 0; const lat: number[] = [];
  const dir = { c2s: 0, s2c: 0 };
  for (const e of events) {
    if (e.Direction === "croc->soc") dir.c2s++; else if (e.Direction === "soc->croc") dir.s2c++;
    if (e.DecidedAction) { decided++; if (e.LatencyMs != null) lat.push(e.LatencyMs); }
    const da = typeof e.DecidedAction === "string" ? e.DecidedAction : "";
    if (da.includes("ticket#")) ticketsOpened++;
    if (/\b(jira|snow):/.test(da)) externalTickets++;
    if (/\biam:/.test(da)) iamActions++;
  }
  lat.sort((a, b) => a - b);
  const lastHour = events.filter((e) => Date.parse(e.CreatedDate) > Date.now() - 3600000).length;
  const exp = safeExposures(tenant, 200);
  const exposureBacklog = exp.results.filter((e: any) => e.kev || e.itw || (e.exploits || 0) > 0).length;
  let enterpriseScore = 0;
  if (tenant != null) { try { enterpriseScore = computeEnterpriseRiskScore(tenant); } catch { /* */ } }
  return {
    machineSpeedPct: events.length ? Math.round((decided / events.length) * 100) : 0,
    medianLatencyMs: lat.length ? lat[Math.floor(lat.length / 2)] : 0,
    events: events.length, ticketsOpened, iamActions, externalTickets, exposureBacklog,
    loopHealth: lastHour > 0 && dir.c2s > 0 && dir.s2c > 0 ? "moving" : lastHour > 0 ? "one-directional" : "still",
    enterpriseScore,
  };
}

/** Upsert today's resilience snapshot for a tenant (one row per tenant per day). */
export function accrueLoopHealth(tenant: number | null): void {
  try {
    ensureLoopHealthTable();
    const db = getDb("XORCISM");
    const m = loopMetrics(tenant);
    const day = new Date().toISOString().slice(0, 10);
    const existing = db.prepare("SELECT SnapshotID FROM LOOPHEALTHSNAPSHOT WHERE SnapDate=? AND (TenantID = ? OR (TenantID IS NULL AND ? IS NULL))").get(day, tenant, tenant) as { SnapshotID: number } | undefined;
    if (existing) {
      db.prepare("UPDATE LOOPHEALTHSNAPSHOT SET MachineSpeedPct=?, MedianLatencyMs=?, Events=?, TicketsOpened=?, IamActions=?, ExternalTickets=?, ExposureBacklog=?, LoopHealth=?, EnterpriseScore=? WHERE SnapshotID=?")
        .run(m.machineSpeedPct, m.medianLatencyMs, m.events, m.ticketsOpened, m.iamActions, m.externalTickets, m.exposureBacklog, m.loopHealth, m.enterpriseScore, existing.SnapshotID);
    } else {
      const id = allocId(db, "LOOPHEALTHSNAPSHOT", "SnapshotID");
      db.prepare("INSERT INTO LOOPHEALTHSNAPSHOT (SnapshotID, SnapDate, MachineSpeedPct, MedianLatencyMs, Events, TicketsOpened, IamActions, ExternalTickets, ExposureBacklog, LoopHealth, EnterpriseScore, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .run(id, day, m.machineSpeedPct, m.medianLatencyMs, m.events, m.ticketsOpened, m.iamActions, m.externalTickets, m.exposureBacklog, m.loopHealth, m.enterpriseScore, now(), tenant);
    }
  } catch { /* never throw */ }
}

/** Resilience trend (time series) for the cockpit chart. */
export function resilienceTrend(tenant: number | null, days = 30): any[] {
  try {
    ensureLoopHealthTable();
    const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
    return (getDb("XORCISM").prepare(
      "SELECT SnapDate AS date, MachineSpeedPct AS machineSpeedPct, MedianLatencyMs AS latencyMs, Events AS events, TicketsOpened AS tickets, IamActions AS iamActions, ExternalTickets AS externalTickets, ExposureBacklog AS backlog, LoopHealth AS loopHealth, EnterpriseScore AS score FROM LOOPHEALTHSNAPSHOT WHERE (TenantID = ? OR (TenantID IS NULL AND ? IS NULL)) AND SnapDate >= ? ORDER BY SnapDate"
    ).all(tenant, tenant, since) as any[]);
  } catch { return []; }
}

/**
 * RESILIENCE DEGRADATION ALERT — is the loop getting WORSE? Compares today's snapshot to the prior
 * baseline and, if it has materially regressed (machine-speed dropped, backlog ballooned, latency
 * spiked, or the loop went still), fires a one-per-day warning (Teams + loop feed). Called only from
 * the 6h accrual tick (NOT from accrueLoopHealth) so there is no recursion. Returns the reasons.
 */
/** The configurable resilience SLA targets (env-overridable) the loop is held to. */
export function resilienceSla(): { machineSpeedMin: number; latencyMaxMs: number; backlogMax: number } {
  const n = (v: string | undefined, d: number): number => { const x = Number(v); return Number.isFinite(x) && x >= 0 ? x : d; };
  return {
    machineSpeedMin: n(process.env.CROC_SLA_MACHINE_SPEED_MIN, 60), // % of events that must be auto-decided
    latencyMaxMs: n(process.env.CROC_SLA_LATENCY_MAX_MS, 1000),     // median decision latency ceiling
    backlogMax: n(process.env.CROC_SLA_BACKLOG_MAX, 25),           // actively-attacked exposure backlog ceiling
  };
}

export function checkResilienceDegradation(tenant: number | null): { degraded: boolean; reasons: string[] } {
  try {
    ensureLoopHealthTable();
    const db = getDb("XORCISM");
    const day = new Date().toISOString().slice(0, 10);
    const today = db.prepare("SELECT * FROM LOOPHEALTHSNAPSHOT WHERE SnapDate=? AND (TenantID = ? OR (TenantID IS NULL AND ? IS NULL))").get(day, tenant, tenant) as any;
    if (!today) return { degraded: false, reasons: [] };
    const reasons: string[] = [];

    // (1) Absolute SLA breaches — baseline-independent. Machine-speed/latency need enough signal (>=5 events).
    const sla = resilienceSla();
    if ((today.Events || 0) >= 5) {
      if (today.MachineSpeedPct < sla.machineSpeedMin) reasons.push(`machine-speed ${today.MachineSpeedPct}% below SLA ${sla.machineSpeedMin}%`);
      if (today.MedianLatencyMs > sla.latencyMaxMs) reasons.push(`decision latency ${today.MedianLatencyMs}ms over SLA ${sla.latencyMaxMs}ms`);
    }
    if (today.ExposureBacklog > sla.backlogMax) reasons.push(`actively-attacked backlog ${today.ExposureBacklog} over SLA ${sla.backlogMax}`);

    // (2) Relative regression vs the prior baseline (needs >=2 prior days).
    const prior = db.prepare("SELECT * FROM LOOPHEALTHSNAPSHOT WHERE SnapDate < ? AND (TenantID = ? OR (TenantID IS NULL AND ? IS NULL)) ORDER BY SnapDate DESC LIMIT 7").all(day, tenant, tenant) as any[];
    if (prior.length >= 2) {
      const avg = (k: string): number => prior.reduce((s, r) => s + (Number(r[k]) || 0), 0) / prior.length;
      const baseMs = avg("MachineSpeedPct");
      if (baseMs >= 40 && today.MachineSpeedPct < baseMs - 20) reasons.push(`machine-speed ${today.MachineSpeedPct}% (was ~${Math.round(baseMs)}%)`);
      const baseBack = avg("ExposureBacklog");
      if (today.ExposureBacklog > baseBack * 1.5 && today.ExposureBacklog > baseBack + 5) reasons.push(`actively-attacked backlog ${today.ExposureBacklog} (was ~${Math.round(baseBack)})`);
      const baseLat = avg("MedianLatencyMs");
      if (baseLat > 0 && today.MedianLatencyMs > baseLat * 3 && today.MedianLatencyMs > 50) reasons.push(`decision latency ${today.MedianLatencyMs}ms (was ~${Math.round(baseLat)}ms)`);
      const movingPrior = prior.filter((r) => r.LoopHealth === "moving").length;
      if (today.LoopHealth === "still" && movingPrior >= Math.ceil(prior.length / 2)) reasons.push("the loop went STILL (was moving)");
    }

    // de-duplicate reasons (an SLA breach and a regression may describe the same metric)
    const uniq = [...new Set(reasons)];
    if (uniq.length) {
      // one alert per tenant per day — dedupe on the loop event the alert is about to record.
      const already = db.prepare("SELECT 1 FROM LOOPEVENT WHERE EventType='croc.resilience_degraded' AND (TenantID = ? OR (TenantID IS NULL AND ? IS NULL)) AND substr(CreatedDate,1,10)=? LIMIT 1").get(tenant, tenant, day);
      if (!already) { alertDegradation(tenant, uniq); void loopDigest(tenant); } // alert + the AI's cross-loop read of WHY
    }
    return { degraded: uniq.length > 0, reasons: uniq };
  } catch { return { degraded: false, reasons: [] }; }
}

/** Fire the degradation warning via the notification engine (lazy require breaks the croc↔notifrules cycle). */
function alertDegradation(tenant: number | null, reasons: string[]): void {
  const title = "CROC resilience degraded";
  const message = "The continuous defense loop has regressed vs its baseline / SLA: " + reasons.join("; ") + ". Investigate why the loop slowed.";
  // Target the tenant's users in-app (each gets it only if their notification rule allows); Teams + loop
  // feed fire regardless. Global (null tenant) → Teams + loop only.
  let userIds: number[] = [];
  try { if (tenant != null) userIds = (xid.listUsers(tenant) as any[]).map((u) => Number(u.UserID)).filter((x) => Number.isInteger(x) && x > 0); } catch { /* */ }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nr = require("./notifrules") as typeof import("./notifrules");
    nr.dispatchEvent("croc.resilience_degraded", { tenant, userIds, title, message, level: "warning", link: "/croc" });
  } catch {
    try { emitLoopEvent({ type: "croc.resilience_degraded", source: "resilience", summary: title, severity: "warning", tenant }); } catch { /* */ }
  }
}

let accrualTimer: NodeJS.Timeout | null = null;
/** Boot: accrue a resilience point for every tenant now, then every 6h (so quiet days still get a point). */
export function startResilienceAccrual(): void {
  if (accrualTimer) return;
  const tick = () => {
    const tenants: (number | null)[] = [null];
    try { for (const t of xid.listTenants()) tenants.push(t.TenantID); } catch { /* */ }
    for (const t of tenants) {
      try { accrueLoopHealth(t); } catch { /* */ }
      try { checkResilienceDegradation(t); } catch { /* */ } // alert on regression vs baseline (one/day)
    }
  };
  try { tick(); } catch { /* */ }
  accrualTimer = setInterval(tick, 6 * 3600_000);
  if (typeof accrualTimer.unref === "function") accrualTimer.unref();
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// AUTOMATIC LOOP DIGEST — fire the local-AI cross-loop reasoning on a schedule (and on degradation),
// publishing it into the loop feed + notifications instead of waiting for someone to click "Reason".
// ════════════════════════════════════════════════════════════════════════════════════════════
function digestHeadline(md: string): { headline: string; nextMove: string } {
  const clean = (s: string): string => s.replace(/\*\*/g, "").replace(/[_`#]/g, "").trim();
  const one = md.match(/\*\*The one thing:\*\*\s*([^\n]+)/i);
  const nxt = md.match(/\*\*Next move:\*\*\s*([^\n]+)/i);
  const fallback = md.split("\n").find((l) => l.trim() && !l.startsWith("#") && !l.startsWith("_")) || "loop digest";
  return { headline: clean(one ? one[1] : fallback).slice(0, 200), nextMove: clean(nxt ? nxt[1] : "").slice(0, 200) };
}

/** Run the cross-loop reasoning and publish it as a digest (loop feed + Teams + opt-in in-app). Best-effort. */
export async function loopDigest(tenant: number | null): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const ai = require("./ai") as typeof import("./ai");
    const r = await ai.lifecycleReasoning(tenant);                       // Ollama or deterministic fallback
    const { headline, nextMove } = digestHeadline(r.reasoning || "");
    const title = ("CROC loop digest — " + (headline || "no signal")).slice(0, 160);
    const message = headline + (nextMove ? `\n\n→ Next move: ${nextMove}` : "") + (r.offline ? "\n\n(offline data-driven read — start Ollama for an LLM digest)" : "");
    let userIds: number[] = [];
    try { if (tenant != null) userIds = (xid.listUsers(tenant) as any[]).map((u) => Number(u.UserID)).filter((x) => Number.isInteger(x) && x > 0); } catch { /* */ }
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nr = require("./notifrules") as typeof import("./notifrules");
      nr.dispatchEvent("croc.loop_digest", { tenant, userIds, title, message, level: "info", link: "/croc" }); // → Teams + loop feed + opt-in in-app
    } catch {
      try { emitLoopEvent({ type: "croc.loop_digest", source: "ai-digest", summary: title, severity: "info", tenant }); } catch { /* */ }
    }
  } catch { /* never throw */ }
}

let digestTimer: NodeJS.Timeout | null = null;
/** Boot: schedule the daily AI loop digest (~5 min after start, then every CROC_DIGEST_INTERVAL_MS). XOR_CROC_DIGEST=0 to disable. */
export function startLoopDigest(): void {
  if (digestTimer) return;
  if (String(process.env.XOR_CROC_DIGEST ?? "1") === "0") return;
  const intervalMs = Number(process.env.CROC_DIGEST_INTERVAL_MS) || 24 * 3600_000;
  const run = async (): Promise<void> => {
    const tenants: (number | null)[] = [null];
    try { for (const t of xid.listTenants()) tenants.push(t.TenantID); } catch { /* */ }
    for (const t of tenants) { try { await loopDigest(t); } catch { /* */ } } // sequential — one LLM call at a time
  };
  const first = setTimeout(() => { void run(); }, Number(process.env.CROC_DIGEST_FIRST_DELAY_MS) || 300_000);
  if (typeof first.unref === "function") first.unref();
  digestTimer = setInterval(() => { void run(); }, intervalMs);
  if (typeof digestTimer.unref === "function") digestTimer.unref();
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// CYBER-RISK HUNTING — "where could an adversary succeed?" A dedicated worklist that fuses the
// prioritized exposures with the over-scoped non-human identities, each with a hunt hypothesis.
// ════════════════════════════════════════════════════════════════════════════════════════════
export function riskHunting(tenant: number | null): any {
  const exp = safeExposures(tenant, 60);
  // Build the attack-path graph once and index its nodes so every exposure can be annotated with the
  // reachability of the asset(s) it sits on (entry point / crown jewel / choke point / on-path).
  let nodeById = new Map<number, any>();
  let attackPaths: any[] = [], chokepoints: any[] = [], reachableJewels = 0;
  try {
    const g = attackPathGraph(tenant);
    nodeById = new Map((g.nodes || []).map((n: any) => [n.id, n]));
    attackPaths = (g.paths || []).slice(0, 10).map((p: any) => ({ entry: p.entryLabel, jewel: p.jewelLabel, hops: Math.max(0, (p.nodes || []).length - 1), cost: Math.round(p.cost || 0) }));
    chokepoints = (g.chokepoints || []).slice(0, 8).map((c: any) => ({ id: c.id, label: c.label, paths: c.paths }));
    reachableJewels = new Set((g.paths || []).map((p: any) => p.jewel)).size;
  } catch { /* sparse schema — no graph */ }

  /** Best reachability annotation across the asset(s) an exposure sits on. */
  const reachOf = (assetIds: number[]): { kind: string; label: string; choke: number } | null => {
    let best: { kind: string; label: string; choke: number } | null = null;
    const rankOf = (k: string): number => (k === "entry" ? 3 : k === "jewel" ? 2 : k === "choke" ? 1 : k === "onpath" ? 0 : -1);
    for (const id of assetIds) {
      const n = nodeById.get(id); if (!n) continue;
      const kind = n.role === "entry" ? "entry" : n.role === "jewel" ? "jewel" : (n.choke || 0) > 0 ? "choke" : n.onPath ? "onpath" : "none";
      if (kind === "none") continue;
      if (!best || rankOf(kind) > rankOf(best.kind) || (kind === best.kind && (n.choke || 0) > best.choke)) best = { kind, label: n.label, choke: n.choke || 0 };
    }
    return best;
  };

  const exposures = exp.results.map((e: any) => {
    const hot = !!(e.kev || e.itw || (e.exploits || 0) > 0);
    const reach = reachOf(e.assetIds || []);
    // Hypothesis sentences are built client-side (i18n) from these raw bits.
    return { ref: e.ref, vid: e.VulnerabilityID || null, priority: e.priority, cvss: e.cvss, kev: !!e.kev, itw: !!e.itw, exploits: e.exploits || 0, assets: e.assets || 0, maxValue: e.maxValue || 0, factors: (e.factors || []).slice(0, 4), hot, reach: reach ? reach.kind : null, reachLabel: reach ? reach.label : null, reachChoke: reach ? reach.choke : null };
  });
  const agentic = agenticExposures(tenant);
  return {
    summary: {
      scanned: exp.scanned, ranked: exposures.length,
      activelyAttacked: exposures.filter((e) => e.hot).length,
      crownReachable: exposures.filter((e) => (e.maxValue || 0) > 0).length,
      onAttackPath: exposures.filter((e) => e.reach).length,
      overScopedIdentities: agentic.length,
      reachableJewels, attackPaths: attackPaths.length,
    },
    exposures, agentic, attackPaths, chokepoints,
  };
}

/** Escalate a hunting finding back INTO the loop (so the pre-authorization policies fire on it). */
export function escalateHunt(tenant: number | null, kind: string, ref: string, priority: number): void {
  const sev = priority >= 70 ? "critical" : priority >= 40 ? "high" : "medium";
  if (kind === "identity") {
    emitLoopEvent({ type: "identity.overscoped", source: "risk-hunting", summary: ref, severity: "high", direction: "internal", tenant });
  } else {
    emitLoopEvent({ type: "exposure.hunt", source: "risk-hunting", summary: `Hunt escalation: ${ref}`, severity: sev, direction: "croc->soc", tenant });
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// DEMO SEED — populate a realistic, value-demonstrating CROC: a 24h bidirectional loop feed
// (CROC↔SOC at machine speed) + a 30-day improving resilience trend. Inserts LOOPEVENT rows
// DIRECTLY (never via emitLoopEvent) so NO real side effects fire (no tickets/Teams/SOAR).
// Idempotent (skips if demo events already exist for the tenant). Demo only (a single tenant).
// ════════════════════════════════════════════════════════════════════════════════════════════
type DemoEv = { type: string; source: string; dir: LoopDirection; sev: string; summary: string; decided?: string };
const CROC_DEMO_EVENTS: DemoEv[] = [
  // CROC → SOC : exposure changes flow into the detection queue at machine speed
  { type: "exposure.kev", source: "fusion", dir: "croc->soc", sev: "critical", summary: "KEV CVE-2024-3400 weaponized on web-prod-01 (internet-facing)", decided: "escalated" },
  { type: "exposure.new", source: "nvd-import", dir: "croc->soc", sev: "high", summary: "EPSS spike 71% — CVE-2024-21887 on api-gw-02" },
  { type: "drift.surface", source: "surface-drift", dir: "croc->soc", sev: "high", summary: "New internet-exposed service db-01:5432 (PostgreSQL)", decided: "escalated · ticket#" },
  { type: "exposure.chokepoint", source: "attack-path", dir: "croc->soc", sev: "high", summary: "Choke point dc-01 now sits on 4 attack paths to crown jewels" },
  { type: "exposure.kev", source: "fusion", dir: "croc->soc", sev: "critical", summary: "KEV CVE-2023-34362 (MOVEit) reachable on file-transfer-03", decided: "escalated" },
  { type: "cve.match", source: "cve-matcher", dir: "croc->soc", sev: "high", summary: "New CVE auto-linked to 6 assets by technology (Apache 2.4.x)" },
  { type: "exposure.relevant", source: "cti", dir: "croc->soc", sev: "high", summary: "CTI: actor APT29 actively exploiting an exposure on your estate" },
  // SOC → CROC : incidents reprioritize exposure across the estate (feedback)
  { type: "incident.created", source: "soc", dir: "soc->croc", sev: "critical", summary: "Ransomware precursor detected on finance-fs-01", decided: "reprioritized exposures" },
  { type: "alert.high", source: "rustinel-edr", dir: "soc->croc", sev: "high", summary: "Impossible-travel sign-in for svc-backup (NHI)" },
  { type: "malware.malicious", source: "malware-scan", dir: "soc->croc", sev: "high", summary: "Malicious hash (Cobalt Strike) on hr-laptop-12", decided: "reprioritized exposures" },
  { type: "incident.created", source: "soc", dir: "soc->croc", sev: "high", summary: "Phishing wave — 14 recipients, 2 clickers" },
  { type: "alert.high", source: "entra-id", dir: "soc->croc", sev: "high", summary: "Privilege escalation: svc-erp added to Global Admins" },
  // internal : the loop acts on itself (BAS re-validation, identity hygiene, control assurance)
  { type: "detection.drift", source: "purple-team", dir: "internal", sev: "high", summary: "BAS re-validation: T1059.001 detection regressed (false coverage)", decided: "ticket#" },
  { type: "identity.overscoped", source: "risk-hunting", dir: "internal", sev: "high", summary: "Over-privileged non-human identity svc-erp (standing Owner)", decided: "iam:dry-run constrain" },
  { type: "control.proven", source: "assurance", dir: "internal", sev: "info", summary: "Control NIST 800-53 AC-2 proven by live telemetry (continuous)" },
  { type: "patch.applied", source: "patch-mgmt", dir: "internal", sev: "info", summary: "KEV CVE-2024-3400 patched on web-prod-01 — backlog −1" },
  { type: "exposure.hunt", source: "risk-hunting", dir: "croc->soc", sev: "high", summary: "Hunt: reachable exposure on payment-api could chain to the cardholder DB", decided: "escalated · ticket#" },
];

/** Demo seed (single tenant): a 24h bidirectional loop feed + 30-day improving resilience trend. */
export function seedCrocDemo(tenant: number): { events: number; snapshots: number } {
  ensureCrocTables(); ensureLoopHealthTable();
  const db = getDb("XORCISM");
  // idempotent: skip if this tenant already has demo loop events
  if (Number((db.prepare("SELECT COUNT(*) n FROM LOOPEVENT WHERE TenantID = ? AND Source LIKE '%'").get(tenant) as { n: number }).n) > 0
      && Number((db.prepare("SELECT COUNT(*) n FROM LOOPEVENT WHERE TenantID = ? AND EventType IN ('exposure.kev','incident.created')").get(tenant) as { n: number }).n) > 0) {
    return { events: 0, snapshots: 0 };
  }
  seedCrocPolicies(tenant);

  // ── 24h loop feed: ~50 events spread across the last 24h, both directions, machine-speed decisions ──
  const tx = db.transaction(() => {
    let id = allocId(db, "LOOPEVENT", "LoopEventID");
    let ticketSeq = 41;
    const ins = db.prepare(
      `INSERT INTO LOOPEVENT (LoopEventID, LoopEventGUID, EventType, Source, Summary, Direction, Severity,
         AssetID, AttackID, DecidedAction, LatencyMs, Acknowledged, CreatedDate, DecidedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    const N = 52;
    for (let i = 0; i < N; i++) {
      const tmpl = CROC_DEMO_EVENTS[i % CROC_DEMO_EVENTS.length];
      // spread over 24h, denser in the last hour so the loop reads as "moving"
      const ageMs = i < 6 ? Math.round(Math.random() * 55 * 60000) : Math.round(Math.random() * 24 * 3600000);
      const created = new Date(Date.now() - ageMs).toISOString();
      let decided: string | null = tmpl.decided ?? null;
      if (decided && decided.endsWith("ticket#")) decided = decided + (ticketSeq++);
      const latency = decided ? 180 + Math.round(Math.random() * 1400) : null;
      ins.run(id++, randomUUID(), tmpl.type, tmpl.source, tmpl.summary, tmpl.dir, tmpl.sev,
        null, null, decided, latency, i % 5 === 0 ? 1 : 0, created, decided ? created : null, tenant);
    }
  });
  tx();
  const events = Number((db.prepare("SELECT COUNT(*) n FROM LOOPEVENT WHERE TenantID = ?").get(tenant) as { n: number }).n);

  // ── 30-day resilience trend: the loop measurably IMPROVING over time ──
  const snapTx = db.transaction(() => {
    let sid = allocId(db, "LOOPHEALTHSNAPSHOT", "SnapshotID");
    const ins = db.prepare(
      `INSERT INTO LOOPHEALTHSNAPSHOT (SnapshotID, SnapDate, MachineSpeedPct, MedianLatencyMs, Events, TicketsOpened,
         IamActions, ExternalTickets, ExposureBacklog, LoopHealth, EnterpriseScore, CreatedDate, TenantID)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    for (let d = 30; d >= 1; d--) {
      const day = new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
      const p = (30 - d) / 29; // 0 → 1 progress
      if (db.prepare("SELECT 1 FROM LOOPHEALTHSNAPSHOT WHERE SnapDate=? AND TenantID=?").get(day, tenant)) continue;
      const machine = Math.round(18 + p * 26 + (Math.random() * 4 - 2));        // 18% → ~44%
      const latency = Math.round(2200 - p * 1500 + (Math.random() * 120 - 60)); // 2200ms → ~700ms
      const backlog = Math.round(142 - p * 64 + (Math.random() * 8 - 4));       // 142 → ~78
      const score = Math.round(620 - p * 210 + (Math.random() * 20 - 10));      // EnterpriseRiskScore falling
      ins.run(sid++, day, Math.max(0, machine), Math.max(120, latency), 30 + Math.round(Math.random() * 30),
        2 + Math.round(Math.random() * 4), 1 + Math.round(Math.random() * 2), Math.round(Math.random() * 2),
        Math.max(0, backlog), "moving", Math.max(0, score), now(), tenant);
    }
  });
  snapTx();
  const snapshots = Number((db.prepare("SELECT COUNT(*) n FROM LOOPHEALTHSNAPSHOT WHERE TenantID = ?").get(tenant) as { n: number }).n);
  return { events, snapshots };
}
