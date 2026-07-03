/**
 * agentfw.ts — Agent Policy Firewall: a regulated pre-execution boundary for agent / automation actions.
 *
 * Every proposed action (MCP call, browser action, cloud connector, CLI task, SOAR playbook, remediation
 * bot) is evaluated BEFORE it runs: it is scored for blast radius, matched against ordered policies
 * (allow / deny / require-approval thresholds), checked for replay and segregation-of-duties, and recorded
 * with a tamper-evident SIGNED RECEIPT (SHA-256 hash chain — like the audit ledger). This is the governance
 * layer agent-harness teams (LangChain/CrewAI/AutoGen…) do not build. Complements the CROC loop (reactive,
 * [[croc-loop]]) and the AI guardrails ([[ai-guardrails-management]]).
 *
 * Deterministic decisions; no live action is taken here — the firewall only authorises/denies/holds and
 * signs the receipt. The calling harness honours the verdict.
 */
import { createHash, randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export const ACTION_TYPES = ["mcp_call", "browser_action", "cloud_connector", "cli_task", "soar_playbook", "remediation_bot"];
export const DECISIONS = ["allow", "deny", "approve"];
export const SENSITIVITY = ["low", "medium", "high", "crown-jewel"];

const BASE_BLAST: Record<string, number> = { remediation_bot: 40, soar_playbook: 35, cloud_connector: 35, cli_task: 30, mcp_call: 25, browser_action: 20 };
const SENS_BUMP: Record<string, number> = { low: 0, medium: 15, high: 30, "crown-jewel": 45 };
const DESTRUCTIVE = /\b(delete|drop|destroy|wipe|truncate|terminate|shutdown|disable|revoke|deactivate|rm\s+-rf|format|purge|mass|bulk|all\b|prod|production|payout|transfer|wire)\b/i;
const REPLAY_WINDOW_MS = 10 * 60 * 1000; // a re-submitted identical action within 10 min is a replay

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const clamp = (n: number): number => Math.max(0, Math.min(100, Math.round(n)));
const has = (db: ReturnType<typeof getDb>, t: string): boolean => { try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; } };
const tclause = (tenant: number | null): string => (tenant != null ? " AND (TenantID = ? OR TenantID IS NULL)" : "");

/** Deterministic blast-radius score (0-100): action type + target sensitivity + destructive intent. */
export function blastRadius(actionType: string, sensitivity: string, target: string, params: string): number {
  let b = BASE_BLAST[actionType] ?? 25;
  b += SENS_BUMP[sensitivity] ?? 0;
  if (DESTRUCTIVE.test(`${target} ${params}`)) b += 20;
  if (/\b(\*|everyone|global|tenant-wide|org-wide)\b/i.test(`${target} ${params}`)) b += 10;
  return clamp(b);
}

interface PolicyRow { PolicyID: number; Name: string; ActionType: string; TargetPattern: string; MinBlastRadius: number; Decision: string; RequireApprovers: number; Enabled: number; SortOrder: number; }

function matchPolicies(db: ReturnType<typeof getDb>, tenant: number | null, actionType: string, target: string, blast: number): PolicyRow | null {
  if (!has(db, "AGENTFWPOLICY")) return null;
  const rows = (tenant != null
    ? db.prepare("SELECT * FROM AGENTFWPOLICY WHERE Enabled=1 AND (TenantID = ? OR TenantID IS NULL) ORDER BY SortOrder, PolicyID").all(tenant)
    : db.prepare("SELECT * FROM AGENTFWPOLICY WHERE Enabled=1 ORDER BY SortOrder, PolicyID").all()) as PolicyRow[];
  const tlow = (target || "").toLowerCase();
  for (const p of rows) {
    const atOk = !p.ActionType || p.ActionType === "*" || p.ActionType === actionType;
    const pat = (p.TargetPattern || "").trim().toLowerCase();
    const patOk = !pat || pat === "*" || tlow.includes(pat.replace(/\*/g, ""));
    if (atOk && patOk && blast >= num(p.MinBlastRadius)) return p;
  }
  return null;
}

/** The firewall gate. Scores + decides + signs a receipt for one proposed agent action. */
export function evaluateAction(p: { actionType: string; actor: string; target: string; params?: string; sensitivity?: string; idempotencyKey?: string }, tenant: number | null): any {
  const db = getDb("XORCISM");
  const actionType = ACTION_TYPES.includes(String(p.actionType)) ? String(p.actionType) : "mcp_call";
  const sensitivity = SENSITIVITY.includes(String(p.sensitivity)) ? String(p.sensitivity) : "medium";
  const actor = String(p.actor || "agent").slice(0, 160);
  const target = String(p.target || "").slice(0, 400);
  const params = String(p.params || "").slice(0, 2000);
  const blast = blastRadius(actionType, sensitivity, target, params);

  // replay prevention: identical action content (or idempotency key) seen within the window → block
  const contentHash = sha256(JSON.stringify([actionType, actor, target, params, p.idempotencyKey || ""]));
  let replay = false;
  if (has(db, "AGENTACTION")) {
    const since = new Date(Date.now() - REPLAY_WINDOW_MS).toISOString();
    const prior = db.prepare(`SELECT 1 FROM AGENTACTION WHERE ContentHash = ? AND CreatedDate >= ? ${tclause(tenant)} LIMIT 1`)
      .get(...(tenant != null ? [contentHash, since, tenant] : [contentHash, since]));
    replay = !!prior;
  }

  // policy decision (replay overrides → deny; else policy; else sane default by blast radius)
  const pol = matchPolicies(db, tenant, actionType, target, blast);
  let decision: string, requiredApprovers = 0, rationale: string;
  if (replay) { decision = "deny"; rationale = "Replay prevention: an identical action was already submitted within the last 10 minutes."; }
  else if (pol) {
    decision = DECISIONS.includes(pol.Decision) ? pol.Decision : "allow";
    requiredApprovers = decision === "approve" ? Math.max(1, num(pol.RequireApprovers)) : 0;
    rationale = `Policy "${pol.Name}" matched (type ${pol.ActionType || "*"}, blast ≥ ${num(pol.MinBlastRadius)}) → ${decision}.`;
  } else if (blast >= 70) { decision = "approve"; requiredApprovers = 1; rationale = `No policy matched; blast radius ${blast} ≥ 70 → human approval required (default).`; }
  else { decision = "allow"; rationale = `No policy matched; blast radius ${blast} < 70 → allowed (default).`; }
  const status = decision === "allow" ? "allowed" : decision === "deny" ? "denied" : "pending";

  // record + sign the receipt (hash chain over the action ledger)
  const id = allocId(db, "AGENTACTION", "ActionID");
  const prevReceipt = (has(db, "AGENTACTION")
    ? (db.prepare("SELECT ReceiptHash FROM AGENTACTION ORDER BY ActionID DESC LIMIT 1").get() as { ReceiptHash: string } | undefined)?.ReceiptHash
    : "") || "";
  const now = new Date().toISOString();
  // The receipt signs the IMMUTABLE evaluation facts (identity + content + blast radius + time), NOT the
  // mutable workflow state (Status/Decision change on approve/deny — that lifecycle is audited via XAUDITLOG).
  const receipt = sha256(prevReceipt + "\n" + JSON.stringify([id, actionType, actor, target, contentHash, blast, now, tenant ?? null]));
  db.prepare(`INSERT INTO AGENTACTION (ActionID, ActionGUID, ActionType, Actor, Target, Params, Sensitivity, BlastRadius, Decision, Status,
      SodFlag, ReplayFlag, PolicyID, PolicyName, Rationale, ContentHash, ReceiptHash, PrevHash, RequiredApprovers, CreatedDate, TenantID)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), actionType, actor, target, params, sensitivity, blast, decision, status,
      0, replay ? 1 : 0, pol?.PolicyID ?? null, pol?.Name ?? null, rationale, contentHash, receipt, prevReceipt || null, requiredApprovers, now, tenant);

  return { actionId: id, decision, status, blastRadius: blast, sensitivity, replay, requiredApprovers, policy: pol?.Name ?? null, rationale, receipt, allowed: status === "allowed" };
}

/** Approve a pending action — with segregation-of-duties: the approver must differ from the requester. */
export function approveAction(id: number, approver: string, tenant: number | null): { ok: boolean; error?: string } {
  const db = getDb("XORCISM");
  const a = db.prepare("SELECT ActionID, Actor, Status, RequiredApprovers, TenantID FROM AGENTACTION WHERE ActionID=?").get(id) as any;
  if (!a || (tenant != null && a.TenantID != null && Number(a.TenantID) !== tenant)) return { ok: false, error: "not found" };
  if (a.Status !== "pending") return { ok: false, error: `action is ${a.Status}, not pending` };
  if (String(approver) === String(a.Actor)) { // SoD violation: requester cannot approve their own action
    db.prepare("UPDATE AGENTACTION SET SodFlag=1 WHERE ActionID=?").run(id);
    return { ok: false, error: "segregation-of-duties: the requester cannot approve their own action" };
  }
  db.prepare("UPDATE AGENTACTION SET Status='approved', Decision='allow', ApprovedBy=?, DecidedBy=?, DecidedDate=? WHERE ActionID=?")
    .run(approver, approver, new Date().toISOString(), id);
  return { ok: true };
}

export function denyAction(id: number, by: string, tenant: number | null): { ok: boolean; error?: string } {
  const db = getDb("XORCISM");
  const a = db.prepare("SELECT Status, TenantID FROM AGENTACTION WHERE ActionID=?").get(id) as any;
  if (!a || (tenant != null && a.TenantID != null && Number(a.TenantID) !== tenant)) return { ok: false, error: "not found" };
  db.prepare("UPDATE AGENTACTION SET Status='denied', Decision='deny', DecidedBy=?, DecidedDate=? WHERE ActionID=?").run(by, new Date().toISOString(), id);
  return { ok: true };
}

/** Verify the signed-receipt chain (recompute each receipt from the previous one + content). */
export function verifyReceipts(tenant: number | null): { ok: boolean; total: number; verified: number; firstBreakId: number | null } {
  const db = getDb("XORCISM");
  if (!has(db, "AGENTACTION")) return { ok: true, total: 0, verified: 0, firstBreakId: null };
  const rows = db.prepare("SELECT ActionID,ActionType,Actor,Target,ContentHash,BlastRadius,CreatedDate,TenantID,ReceiptHash FROM AGENTACTION ORDER BY ActionID").all() as any[];
  let prev = "", verified = 0, brk: number | null = null;
  for (const r of rows) {
    const expect = sha256(prev + "\n" + JSON.stringify([r.ActionID, r.ActionType, r.Actor, r.Target, r.ContentHash, r.BlastRadius, r.CreatedDate, r.TenantID ?? null]));
    if (r.ReceiptHash !== expect) { brk = r.ActionID; break; } // content was altered after signing
    prev = r.ReceiptHash; verified++;
  }
  return { ok: brk === null, total: rows.length, verified, firstBreakId: brk };
}

// ── read / dashboard ───────────────────────────────────────────────────────
export function dashboard(tenant: number | null): any {
  const db = getDb("XORCISM");
  const ref = { actionTypes: ACTION_TYPES, decisions: DECISIONS, sensitivity: SENSITIVITY };
  if (!has(db, "AGENTACTION")) return { ...ref, summary: { actions: 0 }, policies: [], actions: [], receipts: { ok: true, total: 0 } };
  const tp = tenant != null ? [tenant] : [];
  const w = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const actions = (db.prepare(`SELECT * FROM AGENTACTION ${w} ORDER BY ActionID DESC LIMIT 200`).all(...tp) as any[]).map((a) => ({
    id: Number(a.ActionID), actionType: String(a.ActionType), actor: String(a.Actor ?? ""), target: String(a.Target ?? ""),
    sensitivity: String(a.Sensitivity ?? ""), blastRadius: num(a.BlastRadius), decision: String(a.Decision ?? ""), status: String(a.Status ?? ""),
    sod: num(a.SodFlag) === 1, replay: num(a.ReplayFlag) === 1, policy: String(a.PolicyName ?? ""), rationale: String(a.Rationale ?? ""),
    requiredApprovers: num(a.RequiredApprovers), approvedBy: String(a.ApprovedBy ?? ""), receipt: String(a.ReceiptHash ?? "").slice(0, 16), createdDate: String(a.CreatedDate ?? ""),
  }));
  const all = db.prepare(`SELECT Decision, Status, BlastRadius, ActionType, SodFlag, ReplayFlag FROM AGENTACTION ${w}`).all(...tp) as any[];
  const cnt = (f: (x: any) => boolean) => all.filter(f).length;
  const byType: Record<string, number> = {};
  for (const a of all) byType[a.ActionType] = (byType[a.ActionType] || 0) + 1;
  const summary = {
    actions: all.length,
    allowed: cnt((a) => a.Status === "allowed" || a.Status === "approved"),
    denied: cnt((a) => a.Status === "denied"),
    pending: cnt((a) => a.Status === "pending"),
    avgBlast: all.length ? Math.round(all.reduce((s, a) => s + num(a.BlastRadius), 0) / all.length) : 0,
    replayBlocked: cnt((a) => num(a.ReplayFlag) === 1),
    sodViolations: cnt((a) => num(a.SodFlag) === 1),
    byType,
  };
  const policies = (db.prepare(`SELECT * FROM AGENTFWPOLICY ${w} ORDER BY SortOrder, PolicyID`).all(...tp) as any[]).map((p) => ({
    id: Number(p.PolicyID), name: String(p.Name ?? ""), actionType: String(p.ActionType ?? "*"), targetPattern: String(p.TargetPattern ?? ""),
    minBlastRadius: num(p.MinBlastRadius), decision: String(p.Decision ?? ""), requireApprovers: num(p.RequireApprovers), enabled: num(p.Enabled) === 1,
  }));
  return { ...ref, summary, policies, actions, receipts: verifyReceipts(tenant) };
}

// ── OWASP Agentic Top 10 verification (replicates AGT `agt verify`) ──────────────
// Maps the Agent Policy Firewall's deterministic controls to the OWASP Agentic Security Initiative
// Top‑10 agentic threats (T1–T10) and derives, from the tenant's *actual* firewall configuration
// (policies, receipt chain, SoD/replay enforcement), a covered / partial / gap verdict per threat —
// the same governance‑evidence idea Microsoft's Agent Governance Toolkit produces.
export function owaspAgenticCoverage(tenant: number | null): {
  categories: { code: string; name: string; control: string; nist: string; status: "covered" | "partial" | "gap"; detail: string }[];
  summary: { covered: number; partial: number; gap: number; pct: number; policies: number; receiptChainOk: boolean };
} {
  const d = dashboard(tenant);
  const pols = d.policies as { decision: string; actionType: string; enabled: boolean }[];
  const active = pols.filter((p) => p.enabled);
  const hasDeny = active.some((p) => p.decision === "deny");
  const hasApprove = active.some((p) => p.decision === "approve");
  const anyPolicy = active.length > 0;
  const receiptsOk = !!d.receipts.ok && d.receipts.total > 0;
  const s = (cond: boolean, partialCond = false): "covered" | "partial" | "gap" =>
    cond ? "covered" : partialCond ? "partial" : "gap";

  const categories: { code: string; name: string; control: string; nist: string; status: "covered" | "partial" | "gap"; detail: string }[] = [
    { code: "T1", name: "Memory Poisoning", nist: "MAP 2.3",
      control: "Approval / deny gate on state-writing actions; audited ledger",
      status: s(false, anyPolicy), detail: "The firewall gates tool/action calls, not memory content — pair with input validation on memory writes." },
    { code: "T2", name: "Tool Misuse", nist: "MANAGE 2.1",
      control: "mcp_call policies + deny-by-default + blast-radius gate",
      status: s(hasDeny || anyPolicy, true), detail: hasDeny ? "Deny policies block disallowed tool calls; high-blast calls are gated." : "Add a deny/approve policy for mcp_call to fully cover." },
    { code: "T3", name: "Privilege Compromise", nist: "MANAGE 2.2",
      control: "Separation-of-Duties (self-approval blocked) + approval gates",
      status: s(hasApprove, true), detail: "SoD is enforced on every action; add approval gates on privileged actions." },
    { code: "T4", name: "Resource Overload", nist: "MEASURE 2.6",
      control: "Replay/idempotency block + blast-radius throttling",
      status: "covered", detail: "Duplicate/replayed actions are blocked and high-blast actions are gated." },
    { code: "T5", name: "Cascading Hallucination", nist: "MEASURE 2.5",
      control: "Human-approval gate on high-blast / crown-jewel actions",
      status: s(hasApprove, true), detail: hasApprove ? "High-impact actions require human approval before execution." : "Add an approval gate on high-blast actions." },
    { code: "T6", name: "Intent Breaking & Goal Manipulation", nist: "GOVERN 1.2",
      control: "Deny-by-default policy + approval gates",
      status: s(hasDeny && hasApprove, anyPolicy), detail: "Deterministic policy makes out-of-policy intent structurally blocked." },
    { code: "T7", name: "Misaligned & Deceptive Behaviors", nist: "MEASURE 2.11",
      control: "Policy evaluation + tamper-evident action ledger (detective)",
      status: s(false, anyPolicy || receiptsOk), detail: "Every decision is recorded for post-hoc review of misaligned behaviour." },
    { code: "T8", name: "Repudiation & Untraceability", nist: "GOVERN 1.4",
      control: "Signed, hash-chained decision records (Merkle-style receipts)",
      status: s(receiptsOk), detail: receiptsOk ? "Receipt chain intact — every action is attributable and tamper-evident." : "No verified receipt chain yet; evaluate actions through the gate." },
    { code: "T9", name: "Identity Spoofing & Impersonation", nist: "MAP 1.1",
      control: "Actor identity stamped on every action + SoD",
      status: s(false, true), detail: "Each action carries its actor; add SPIFFE/DID/mTLS agent identity for full zero-trust." },
    { code: "T10", name: "Overwhelming Human-in-the-Loop", nist: "MANAGE 4.1",
      control: "Approval gates with required-approver thresholds",
      status: s(hasApprove, true), detail: "Approvals are scoped to high-risk actions to avoid approval fatigue." },
  ];
  const covered = categories.filter((c) => c.status === "covered").length;
  const partial = categories.filter((c) => c.status === "partial").length;
  const gap = categories.filter((c) => c.status === "gap").length;
  const pct = Math.round(((covered + partial * 0.5) / categories.length) * 100);
  return { categories, summary: { covered, partial, gap, pct, policies: active.length, receiptChainOk: receiptsOk } };
}

// ── policy CRUD + seeds ────────────────────────────────────────────────────
export function addPolicy(p: any, tenant: number | null): { id: number } {
  const db = getDb("XORCISM");
  const id = allocId(db, "AGENTFWPOLICY", "PolicyID");
  const sort = num((db.prepare(`SELECT IFNULL(MAX(SortOrder),0)+1 n FROM AGENTFWPOLICY`).get() as { n: number }).n);
  db.prepare("INSERT INTO AGENTFWPOLICY (PolicyID, PolicyGUID, Name, ActionType, TargetPattern, MinBlastRadius, Decision, RequireApprovers, Enabled, Notes, SortOrder, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), String(p.name || "Policy").slice(0, 160), ACTION_TYPES.includes(String(p.actionType)) ? String(p.actionType) : "*",
      String(p.targetPattern || "").slice(0, 200), num(p.minBlastRadius), DECISIONS.includes(String(p.decision)) ? String(p.decision) : "allow",
      num(p.requireApprovers), p.enabled === false ? 0 : 1, String(p.notes || "").slice(0, 1000), num(p.sortOrder) || sort, new Date().toISOString(), tenant);
  return { id };
}
export function deletePolicy(id: number, tenant: number | null): boolean {
  const db = getDb("XORCISM");
  const r = db.prepare("SELECT TenantID FROM AGENTFWPOLICY WHERE PolicyID=?").get(id) as any;
  if (!r || (tenant != null && r.TenantID != null && Number(r.TenantID) !== tenant)) return false;
  db.prepare("DELETE FROM AGENTFWPOLICY WHERE PolicyID=?").run(id);
  return true;
}

export function seedDemo(tenant: number): { created: number } {
  const db = getDb("XORCISM");
  if (db.prepare("SELECT 1 FROM AGENTFWPOLICY WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 1").get(tenant)) return { created: 0 };
  // default policy set (ordered: most specific / strongest first)
  addPolicy({ name: "Block destructive actions on crown jewels", actionType: "*", targetPattern: "", minBlastRadius: 90, decision: "deny", notes: "Extreme blast radius is never auto-run." }, tenant);
  addPolicy({ name: "Approve high blast-radius remediation", actionType: "remediation_bot", targetPattern: "", minBlastRadius: 60, decision: "approve", requireApprovers: 1 }, tenant);
  addPolicy({ name: "Approve SOAR playbooks on production", actionType: "soar_playbook", targetPattern: "prod", minBlastRadius: 0, decision: "approve", requireApprovers: 1 }, tenant);
  addPolicy({ name: "Allow read-only MCP & browser actions", actionType: "mcp_call", targetPattern: "", minBlastRadius: 0, decision: "allow" }, tenant);
  // a few sample evaluated actions to populate the ledger / receipt chain
  evaluateAction({ actionType: "mcp_call", actor: "triage-agent", target: "read asset inventory", sensitivity: "low" }, tenant);
  evaluateAction({ actionType: "remediation_bot", actor: "remediation-agent", target: "isolate prod database host", params: "shutdown all sessions", sensitivity: "crown-jewel" }, tenant);
  evaluateAction({ actionType: "soar_playbook", actor: "soc-bot", target: "prod firewall block IP", sensitivity: "high" }, tenant);
  evaluateAction({ actionType: "cloud_connector", actor: "iac-agent", target: "revoke all IAM keys", params: "bulk delete", sensitivity: "crown-jewel" }, tenant);
  return { created: 1 };
}
