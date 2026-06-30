/**
 * remediation.ts — Autonomous Exposure Remediation (AER): the CTEM "Mobilization" layer.
 *
 * Gartner's CTEM cycle is Scoping → Discovery → Prioritization → Validation → **Mobilization**, and
 * most programs stall at mobilization because acting on findings needs cross-team coordination,
 * approvals and follow-through. XORCISM already does the first four stages (asset/exposure discovery,
 * the [[exposure-fusion]] prioritization score, [[ctem-org]], BAS validation) and already owns the
 * *actuators* (ITSM ticketing, IAM constraint, Teams/SOAR via [[croc-loop]]) and the *guardrails*
 * (the Agent Policy Firewall, [[agent-policy-firewall]]) — but had no remediation **lifecycle** that
 * ties them into a closed loop. This module is that loop:
 *
 *     PLAN ──▶ GATE (autonomy ladder + Agent Policy Firewall) ──▶ EXECUTE (actuators / dry-run)
 *       ▲                                                                        │
 *       └────────────── REOPEN ◀── VERIFY (re-check live exposure state) ◀───────┘ ──▶ CLOSE
 *
 * Design principles drawn from the state of the art (2025/2026 autonomous SecOps):
 *   • Autonomy ladder with human-in-the-loop — manual / assisted / supervised / autonomous. Only low
 *     blast-radius, reversible actions auto-execute; everything else escalates to approval. The decision
 *     is made by the Agent Policy Firewall (blast radius + ordered policies + SoD + replay), not here.
 *   • Closed-loop verification — "patched in ticket XYZ" is not closure; AER re-checks the live
 *     ASSETVULNERABILITY state (the platform's continuous re-scan) and reopens if the exposure persists.
 *   • Non-patchable reality — action types include compensating-control / isolate / WAF / mitigate /
 *     risk-accept, not just patch (Gartner: non-patchable surface is growing past half the estate).
 *   • Owner routing + SLA — each plan is routed to an accountable owner and bound to a severity SLA
 *     (reusing the VOC SLA policy when present), so due dates are meaningful and MTTR is measurable.
 *   • Tamper-evident — every autonomous/approved execution is signed into a SHA-256 receipt chain.
 *
 * Deterministic + offline-safe: planning/decisions are pure functions of data XORCISM holds; execution
 * actuators are best-effort and dry-run by default (no live offensive action; no network required).
 */
import { createHash, randomUUID } from "crypto";
import { allocId, getDb } from "./db";
import { topExposures, fusionForVuln, assetsForVuln, type FusionScore } from "./fusion";
import { evaluateAction, approveAction } from "./agentfw";

export const ACTION_TYPES = ["patch", "config", "compensating-control", "isolate", "iam-constrain", "waf", "mitigate", "risk-accept"] as const;
export const AUTONOMY = ["manual", "assisted", "supervised", "autonomous"] as const;
export const STATUSES = ["proposed", "awaiting-approval", "queued", "in-progress", "awaiting-verification", "verified", "closed", "reopened", "blocked", "failed", "risk-accepted"] as const;
const OPEN_STATUSES = ["proposed", "awaiting-approval", "queued", "in-progress", "awaiting-verification", "reopened"];
const RESOLVED_PATCH = new Set(["patched", "remediated", "fixed", "mitigated", "closed", "resolved", "done"]);

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const nowIso = (): string => new Date().toISOString();
const CVE_RX = /CVE-\d{4}-\d{3,7}/i;
const cveOf = (ref: string): string | null => { const m = (ref || "").match(CVE_RX); return m ? m[0].toUpperCase() : null; };
const has = (db: ReturnType<typeof getDb>, t: string): boolean => { try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; } };
function colset(db: ReturnType<typeof getDb>, table: string): Set<string> { try { return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); } }
function xv() { return getDb("XVULNERABILITY"); }

// ── policy: autonomy default + SLA hours by severity (env-overridable; SLA reuses VOC tiers if present) ──
export function defaultAutonomy(): string {
  const a = String(process.env.AER_AUTONOMY || "supervised").toLowerCase();
  return (AUTONOMY as readonly string[]).includes(a) ? a : "supervised";
}
const SLA_FALLBACK: Record<string, number> = { critical: 24, high: 72, medium: 168, low: 720 }; // hours
/** SLA hours per severity — from VOC SLA tiers (days→hours) when configured, else sane defaults. */
export function slaHoursBySeverity(tenant: number | null): Record<string, number> {
  const out = { ...SLA_FALLBACK };
  try {
    const db = xv();
    if (has(db, "VOCSLATIER")) {
      const rows = db.prepare(`SELECT Tier, RemediationDays FROM VOCSLATIER ${tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : ""}`).all(...(tenant != null ? [tenant] : [])) as { Tier: string; RemediationDays: number }[];
      for (const r of rows) { const t = String(r.Tier || "").toLowerCase(); if (out[t] != null && num(r.RemediationDays) > 0) out[t] = num(r.RemediationDays) * 24; }
    }
  } catch { /* best-effort */ }
  for (const k of Object.keys(out)) { const e = process.env[`AER_SLA_${k.toUpperCase()}_HOURS`]; if (e && num(e) > 0) out[k] = num(e); }
  return out;
}

// ── derivations (pure) ───────────────────────────────────────────────────────
function severityOf(fs: FusionScore): string {
  if (fs.kev || (fs.cvss ?? 0) >= 9) return "critical";
  if ((fs.cvss ?? 0) >= 7 || fs.priority >= 70) return "high";
  if ((fs.cvss ?? 0) >= 4 || fs.priority >= 40) return "medium";
  return "low";
}
/** Choose the remediation action type for an exposure (patch isn't always possible — pick the fastest safe lever). */
export function inferAction(fs: FusionScore): { action: string; reason: string } {
  const hot = !!(fs.kev || fs.itw || fs.exploits > 0);
  if (fs.publicFacing && fs.window === "hours") return { action: "isolate", reason: "Internet-facing with an active-exploitation window (hours): contain/segment first, then patch." };
  if (fs.publicFacing && hot) return { action: "waf", reason: "Internet-facing + demonstrated exploitability: deploy a virtual-patch / WAF rule as a compensating control, then patch." };
  if (cveOf(fs.ref)) return { action: "patch", reason: hot ? "Known-exploited / exploitable CVE: apply the vendor patch on the affected assets." : "Apply the vendor patch for this CVE on the affected assets." };
  return { action: "mitigate", reason: "No direct patch reference: apply a configuration/mitigation or compensating control." };
}
/** Map an exposure to a firewall sensitivity tier (drives blast radius in the Agent Policy Firewall). */
function sensitivityOf(fs: FusionScore, action: string): string {
  if ((action === "isolate" || action === "iam-constrain") && fs.publicFacing && fs.priority >= 80) return "crown-jewel";
  if (fs.priority >= 75 || fs.kev) return "high";
  if (fs.priority >= 45) return "medium";
  return "low";
}
function defaultSteps(action: string, ref: string, assets: number): { title: string; kind: string }[] {
  const a = `${assets} affected asset${assets === 1 ? "" : "s"}`;
  const common = (fix: string[]): { title: string; kind: string }[] => [
    { title: `Snapshot / capture rollback point on ${a}`, kind: "prepare" },
    ...fix.map((t) => ({ title: t, kind: "action" })),
    { title: `Re-scan ${a} to confirm ${ref} is no longer detected (closed-loop verification)`, kind: "check" },
    { title: "If still present, reopen and escalate to the owner", kind: "check" },
  ];
  switch (action) {
    case "patch": return common([`Stage and deploy the vendor patch for ${ref}`, "Restart/reload affected services and validate functionality"]);
    case "config": return common([`Apply the secure configuration / hardening change addressing ${ref}`]);
    case "isolate": return common(["Segment / isolate the asset (EDR isolate, firewall/SG quarantine, or take offline)", "Plan the permanent patch under change control while contained"]);
    case "waf": return common([`Deploy a virtual-patch / WAF rule blocking exploitation of ${ref}`, "Schedule the underlying patch behind the compensating control"]);
    case "iam-constrain": return common(["Right-size or revoke the over-scoped identity's privileges (least privilege)", "Rotate affected credentials / sessions"]);
    case "mitigate":
    case "compensating-control": return common([`Apply the documented compensating control / mitigation for ${ref}`, "Record the residual risk and review date"]);
    case "risk-accept": return [{ title: `Document risk acceptance for ${ref} (justification, approver, expiry)`, kind: "action" }, { title: "Set a review date to re-evaluate", kind: "check" }];
    default: return common([`Remediate ${ref}`]);
  }
}

// ── owner routing ──────────────────────────────────────────────────────────
function resolveOwner(vid: number, assetIds: number[]): number | null {
  try {
    const xo = getDb("XORCISM");
    const av = colset(xo, "ASSETVULNERABILITY");
    if (av.has("RemediationOwnerPersonID") && av.has("VulnerabilityID")) {
      const r = xo.prepare(`SELECT RemediationOwnerPersonID o FROM ASSETVULNERABILITY WHERE VulnerabilityID=? AND RemediationOwnerPersonID IS NOT NULL LIMIT 1`).get(vid) as { o: number } | undefined;
      if (r?.o) return num(r.o);
    }
    const a = colset(xo, "ASSET");
    if (a.has("OwnerPersonID") && assetIds.length) {
      const ph = assetIds.slice(0, 50).map(() => "?").join(",");
      const r = xo.prepare(`SELECT OwnerPersonID o FROM ASSET WHERE AssetID IN (${ph}) AND OwnerPersonID IS NOT NULL LIMIT 1`).get(...assetIds.slice(0, 50)) as { o: number } | undefined;
      if (r?.o) return num(r.o);
    }
  } catch { /* best-effort */ }
  return null;
}

// ── event log ──────────────────────────────────────────────────────────────
function logEvent(planId: number, event: string, actor: string, detail: string, tenant: number | null): void {
  try {
    const db = xv();
    const id = allocId(db, "REMEDIATIONEVENT", "EventID");
    db.prepare("INSERT INTO REMEDIATIONEVENT (EventID, PlanID, At, Event, Actor, Detail, TenantID) VALUES (?,?,?,?,?,?,?)")
      .run(id, planId, nowIso(), String(event).slice(0, 80), String(actor || "system").slice(0, 120), String(detail || "").slice(0, 1000), tenant);
  } catch { /* best-effort */ }
}

function rowToPlan(p: any): any {
  return {
    id: num(p.PlanID), guid: String(p.PlanGUID || ""), title: String(p.Title || ""), exposureRef: String(p.ExposureRef || ""),
    vulnerabilityId: p.VulnerabilityID != null ? num(p.VulnerabilityID) : null, cve: String(p.CveId || ""),
    actionType: String(p.ActionType || ""), severity: String(p.Severity || ""), priority: num(p.Priority), score: num(p.Score),
    assetCount: num(p.AssetCount), assetIds: String(p.AssetIds || "").split(",").map(Number).filter(Boolean),
    publicFacing: num(p.PublicFacing) === 1, window: String(p.Window || ""), autonomy: String(p.Autonomy || ""), status: String(p.Status || ""),
    ownerPersonId: p.OwnerPersonID != null ? num(p.OwnerPersonID) : null, slaHours: num(p.SlaHours), dueDate: String(p.DueDate || ""),
    firewallActionId: p.FirewallActionID != null ? num(p.FirewallActionID) : null, executionMode: String(p.ExecutionMode || ""),
    executionRef: String(p.ExecutionRef || ""), receipt: String(p.ReceiptHash || "").slice(0, 16), reopenCount: num(p.ReopenCount),
    createdDate: String(p.CreatedDate || ""), approvedDate: String(p.ApprovedDate || ""), executedDate: String(p.ExecutedDate || ""),
    verifiedDate: String(p.VerifiedDate || ""), closedDate: String(p.ClosedDate || ""), source: String(p.Source || ""),
    plan: (() => { try { return JSON.parse(p.PlanJson || "{}"); } catch { return {}; } })(),
  };
}
function getPlanRow(planId: number, tenant: number | null): any {
  const db = xv();
  const p = db.prepare("SELECT * FROM REMEDIATIONPLAN WHERE PlanID=?").get(planId) as any;
  if (!p || (tenant != null && p.TenantID != null && num(p.TenantID) !== tenant)) return null;
  return p;
}

// ── PLAN ─────────────────────────────────────────────────────────────────────
/** Create (or return the existing open) remediation plan for one prioritized exposure (by VulnerabilityID). */
export function planRemediation(tenant: number, opts: { vid: number; autonomy?: string; actionType?: string; ownerPersonId?: number | null; source?: string }): { plan: any; created: boolean } {
  const db = xv();
  const vid = num(opts.vid);
  // idempotent: one open plan per (vuln, tenant)
  const existing = db.prepare(`SELECT * FROM REMEDIATIONPLAN WHERE VulnerabilityID=? AND (TenantID=? OR TenantID IS NULL) AND Status NOT IN ('closed','verified','risk-accepted') ORDER BY PlanID DESC LIMIT 1`).get(vid, tenant) as any;
  if (existing) return { plan: rowToPlan(existing), created: false };

  const fs = fusionForVuln(vid);
  if (!fs) throw new Error("exposure not found");
  if (!fs.assetIds || !fs.assetIds.length) fs.assetIds = assetsForVuln(vid, tenant).map((a) => a.id);
  const severity = severityOf(fs);
  const inf = inferAction(fs);
  const action = opts.actionType && (ACTION_TYPES as readonly string[]).includes(opts.actionType) ? opts.actionType : inf.action;
  const autonomy = opts.autonomy && (AUTONOMY as readonly string[]).includes(opts.autonomy) ? opts.autonomy : defaultAutonomy();
  const slaH = slaHoursBySeverity(tenant)[severity] ?? SLA_FALLBACK[severity];
  const due = new Date(Date.now() + slaH * 3600 * 1000).toISOString();
  const owner = opts.ownerPersonId != null ? num(opts.ownerPersonId) : resolveOwner(vid, fs.assetIds);
  const cve = cveOf(fs.ref) || "";
  const title = `${action === "patch" ? "Patch" : action === "isolate" ? "Isolate" : action === "waf" ? "Virtual-patch" : action === "iam-constrain" ? "Constrain identity for" : "Remediate"} ${fs.ref}`;
  const planJson = JSON.stringify({ reason: inf.reason, factors: fs.factors, window: fs.window, steps: defaultSteps(action, fs.ref, fs.assetIds.length) });

  const id = allocId(db, "REMEDIATIONPLAN", "PlanID");
  db.prepare(`INSERT INTO REMEDIATIONPLAN (PlanID, PlanGUID, Title, ExposureRef, VulnerabilityID, CveId, ActionType, Severity, Priority, Score,
      AssetCount, AssetIds, PublicFacing, Window, Autonomy, Status, OwnerPersonID, SlaHours, DueDate, PlanJson, Source, ReopenCount, CreatedDate, TenantID)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), title.slice(0, 200), fs.ref.slice(0, 200), vid, cve, action, severity, fs.priority, fs.score,
      fs.assetIds.length, fs.assetIds.slice(0, 50).join(","), fs.publicFacing ? 1 : 0, fs.window || "", autonomy, "proposed",
      owner, slaH, due, planJson, opts.source || "manual", 0, nowIso(), tenant);
  logEvent(id, "planned", "system", `${action} · severity ${severity} · priority ${fs.priority} · SLA ${slaH}h · ${inf.reason}`, tenant);
  return { plan: rowToPlan(getPlanRow(id, tenant)), created: true };
}

/** Mobilization automation: turn the top prioritized exposures into remediation plans (idempotent). */
export function autoPlanFromExposures(tenant: number, limit = 15, autonomy?: string): { created: number; skipped: number; total: number; plans: any[] } {
  const { results } = topExposures(tenant, Math.min(Math.max(1, limit), 100));
  let created = 0, skipped = 0; const plans: any[] = [];
  for (const fs of results) {
    try {
      const r = planRemediation(tenant, { vid: fs.VulnerabilityID, autonomy, source: "auto-plan" });
      if (r.created) created++; else skipped++;
      plans.push(r.plan);
    } catch { /* skip unresolvable */ }
  }
  return { created, skipped, total: results.length, plans };
}

// ── GATE + EXECUTE ───────────────────────────────────────────────────────────
const DESTRUCTIVE_ACTIONS = new Set(["isolate", "iam-constrain"]);
function firewallTarget(p: any): { target: string; params: string; sensitivity: string } {
  const assets = num(p.AssetCount);
  const target = `${p.ActionType} ${p.ExposureRef} on ${assets} asset${assets === 1 ? "" : "s"}${num(p.PublicFacing) === 1 ? " (internet-facing)" : ""}`;
  const params = DESTRUCTIVE_ACTIONS.has(String(p.ActionType)) ? "isolate/disable/revoke" : `severity=${p.Severity} priority=${p.Priority}`;
  const fs = { kev: 0, itw: false, exploits: 0, priority: num(p.Priority), publicFacing: num(p.PublicFacing) === 1 } as any;
  return { target: target.slice(0, 380), params, sensitivity: sensitivityOf({ ...fs } as FusionScore, String(p.ActionType)) };
}

async function fireActuators(p: any): Promise<{ refs: string[]; mode: string }> {
  const tenant = p.TenantID != null ? num(p.TenantID) : null;
  const refs: string[] = [];
  const subject = `[XORCISM AER] ${p.Title}`.slice(0, 240);
  const body = `Autonomous Exposure Remediation plan #${p.PlanID}\nExposure: ${p.ExposureRef}\nAction: ${p.ActionType} · severity ${p.Severity} · priority ${p.Priority}\nAssets: ${p.AssetCount}\nSLA due: ${p.DueDate}`;
  try {
    if (String(p.ActionType) === "iam-constrain") {
      const iam = require("./iam");
      const r = await iam.pushIamConstraint(tenant, { name: String(p.ExposureRef).slice(0, 120), mode: "recommend", reason: `AER plan #${p.PlanID}` });
      if (r?.refs?.length) refs.push(...r.refs);
    } else {
      const tk = require("./ticketing");
      if (tk.externalTicketingConfigured(tenant)) {
        const r = await tk.pushExternalTicket(tenant, { subject, body, severity: String(p.Severity), eventType: "remediation" });
        if (r?.refs?.length) refs.push(...r.refs);
      }
    }
  } catch { /* actuator best-effort */ }
  try { const teams = require("./teams"); await teams.notifyTeams(`remediation.${p.ActionType}`, { tenant, title: subject, text: body, link: "/exposure-remediation" }); } catch { /* */ }
  return { refs: refs.length ? refs : [`internal:plan-${p.PlanID}`], mode: "actuator" };
}

/** Sign an execution into the tamper-evident receipt chain (immutable execution facts only). */
function signExecution(db: ReturnType<typeof getDb>, p: any, executionRef: string, executedDate: string, mode: string): { receipt: string; prev: string } {
  const prev = (db.prepare("SELECT ReceiptHash FROM REMEDIATIONPLAN WHERE ReceiptHash IS NOT NULL AND ReceiptHash<>'' ORDER BY ExecutedDate DESC, PlanID DESC LIMIT 1").get() as { ReceiptHash: string } | undefined)?.ReceiptHash || "";
  const receipt = sha256(prev + "\n" + JSON.stringify([p.PlanGUID, p.VulnerabilityID ?? null, p.ActionType, executionRef, executedDate, mode, p.TenantID ?? null]));
  return { receipt, prev };
}

async function doExecute(p: any, mode: string, actor: string): Promise<void> {
  const db = xv();
  const tenant = p.TenantID != null ? num(p.TenantID) : null;
  const fired = await fireActuators(p);
  const executedDate = nowIso();
  const ref = fired.refs.join(",").slice(0, 300);
  const { receipt, prev } = signExecution(db, p, ref, executedDate, mode);
  db.prepare("UPDATE REMEDIATIONPLAN SET Status='awaiting-verification', ExecutionMode=?, ExecutionRef=?, ExecutedDate=?, ReceiptHash=?, PrevHash=? WHERE PlanID=?")
    .run(mode, ref, executedDate, receipt, prev || null, p.PlanID);
  logEvent(num(p.PlanID), "executed", actor, `${mode} execution → ${ref} (receipt ${receipt.slice(0, 12)}…); awaiting verification`, tenant);
}

/**
 * GATE: run the plan through the autonomy ladder + Agent Policy Firewall.
 *   autonomous + firewall "allow" → execute now.
 *   anything else (supervised/assisted/manual, or firewall "approve") → awaiting-approval.
 *   firewall "deny" → blocked.
 */
export async function executePlan(planId: number, actor: string, tenant: number | null): Promise<{ ok: boolean; status?: string; decision?: string; error?: string; plan?: any }> {
  const db = xv();
  const p = getPlanRow(planId, tenant);
  if (!p) return { ok: false, error: "not found" };
  if (!["proposed", "queued", "reopened"].includes(String(p.Status))) return { ok: false, error: `plan is ${p.Status}, not actionable` };
  if (String(p.ActionType) === "risk-accept") return { ok: false, error: "use risk-accept, not execute" };

  const ft = firewallTarget(p);
  const verdict = evaluateAction({ actionType: "remediation_bot", actor: actor || "aer-agent", target: ft.target, params: ft.params, sensitivity: ft.sensitivity }, tenant);
  db.prepare("UPDATE REMEDIATIONPLAN SET FirewallActionID=? WHERE PlanID=?").run(num(verdict.actionId), p.PlanID);

  if (verdict.decision === "deny") {
    db.prepare("UPDATE REMEDIATIONPLAN SET Status='blocked' WHERE PlanID=?").run(p.PlanID);
    logEvent(planId, "blocked", actor, `Agent Policy Firewall denied (blast ${verdict.blastRadius}): ${verdict.rationale}`, tenant);
    return { ok: true, status: "blocked", decision: "deny", plan: rowToPlan(getPlanRow(planId, tenant)) };
  }
  const canAuto = String(p.Autonomy) === "autonomous" && verdict.decision === "allow";
  if (!canAuto) {
    db.prepare("UPDATE REMEDIATIONPLAN SET Status='awaiting-approval' WHERE PlanID=?").run(p.PlanID);
    const why = verdict.decision === "approve" ? `firewall requires approval (blast ${verdict.blastRadius})` : `autonomy '${p.Autonomy}' requires human approval`;
    logEvent(planId, "gated", actor, `${why}: ${verdict.rationale}`, tenant);
    return { ok: true, status: "awaiting-approval", decision: verdict.decision, plan: rowToPlan(getPlanRow(planId, tenant)) };
  }
  await doExecute(p, "autonomous", actor || "aer-agent");
  return { ok: true, status: "awaiting-verification", decision: "allow", plan: rowToPlan(getPlanRow(planId, tenant)) };
}

/** Approve a gated plan (segregation-of-duties enforced via the firewall) and execute it. */
export async function approvePlan(planId: number, approver: string, tenant: number | null): Promise<{ ok: boolean; error?: string; plan?: any }> {
  const p = getPlanRow(planId, tenant);
  if (!p) return { ok: false, error: "not found" };
  if (String(p.Status) !== "awaiting-approval") return { ok: false, error: `plan is ${p.Status}, not awaiting approval` };
  if (p.FirewallActionID) {
    const r = approveAction(num(p.FirewallActionID), approver || "approver", tenant);
    if (!r.ok) { logEvent(planId, "approve-rejected", approver, r.error || "rejected", tenant); return { ok: false, error: r.error }; }
  }
  xv().prepare("UPDATE REMEDIATIONPLAN SET ApprovedDate=? WHERE PlanID=?").run(nowIso(), planId);
  logEvent(planId, "approved", approver, "approved by human (SoD enforced) → executing", tenant);
  await doExecute(p, "approved", approver || "approver");
  return { ok: true, plan: rowToPlan(getPlanRow(planId, tenant)) };
}

// ── VERIFY (closed loop) ───────────────────────────────────────────────────
/** Count the still-open exposure rows for a plan's vuln across its assets (the live "re-scan"). */
function openExposureCount(vid: number, assetIds: number[]): { open: number; checked: number } {
  try {
    const xo = getDb("XORCISM");
    const av = colset(xo, "ASSETVULNERABILITY");
    if (!av.has("VulnerabilityID")) return { open: 0, checked: 0 };
    const fp = av.has("FalsePositive") ? "AND COALESCE(FalsePositive,0)=0" : "";
    const idClause = assetIds.length ? `AND AssetID IN (${assetIds.slice(0, 50).map(() => "?").join(",")})` : "";
    const args = assetIds.length ? [vid, ...assetIds.slice(0, 50)] : [vid];
    const rows = xo.prepare(`SELECT AssetID, ${av.has("PatchStatus") ? "PatchStatus" : "NULL PatchStatus"} ps FROM ASSETVULNERABILITY WHERE VulnerabilityID=? ${fp} ${idClause}`).all(...args) as { AssetID: number; ps: string | null }[];
    const open = rows.filter((r) => !RESOLVED_PATCH.has(String(r.ps || "").toLowerCase())).length;
    return { open, checked: rows.length };
  } catch { return { open: 0, checked: 0 }; }
}

/** Verify closure: if the exposure is gone → verified+closed; if still present past due → reopened. */
export function verifyPlan(planId: number, tenant: number | null, actor = "system"): { ok: boolean; error?: string; result?: string; openAssets?: number; plan?: any } {
  const db = xv();
  const p = getPlanRow(planId, tenant);
  if (!p) return { ok: false, error: "not found" };
  if (!["awaiting-verification", "in-progress", "reopened"].includes(String(p.Status))) return { ok: false, error: `plan is ${p.Status}, not verifiable` };
  const assetIds = String(p.AssetIds || "").split(",").map(Number).filter(Boolean);
  const { open, checked } = openExposureCount(num(p.VulnerabilityID), assetIds);
  const t = tenant != null ? tenant : (p.TenantID != null ? num(p.TenantID) : null);
  if (open === 0) {
    const now = nowIso();
    db.prepare("UPDATE REMEDIATIONPLAN SET Status='verified', VerifiedDate=?, ClosedDate=? WHERE PlanID=?").run(now, now, planId);
    logEvent(planId, "verified", actor, `Closed-loop verification passed: exposure no longer detected on ${checked || assetIds.length} asset(s). Plan closed.`, t);
    return { ok: true, result: "verified", openAssets: 0, plan: rowToPlan(getPlanRow(planId, t)) };
  }
  const overdue = p.DueDate && new Date(p.DueDate).getTime() < Date.now();
  if (overdue) {
    db.prepare("UPDATE REMEDIATIONPLAN SET Status='reopened', ReopenCount=COALESCE(ReopenCount,0)+1 WHERE PlanID=?").run(planId);
    logEvent(planId, "reopened", actor, `Verification FAILED past SLA: exposure still present on ${open} asset(s) — reopened/escalated.`, t);
    return { ok: true, result: "reopened", openAssets: open, plan: rowToPlan(getPlanRow(planId, t)) };
  }
  logEvent(planId, "verify-pending", actor, `Still present on ${open} asset(s); within SLA window — awaiting fix.`, t);
  return { ok: true, result: "pending", openAssets: open, plan: rowToPlan(getPlanRow(planId, t)) };
}

/** Verify every plan currently awaiting verification (the periodic re-scan sweep). */
export function runVerificationSweep(tenant: number | null): { checked: number; verified: number; reopened: number; pending: number } {
  const db = xv();
  const rows = db.prepare(`SELECT PlanID FROM REMEDIATIONPLAN WHERE Status='awaiting-verification' ${tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : ""}`).all(...(tenant != null ? [tenant] : [])) as { PlanID: number }[];
  let verified = 0, reopened = 0, pending = 0;
  for (const r of rows) {
    const v = verifyPlan(num(r.PlanID), tenant, "sweep");
    if (v.result === "verified") verified++; else if (v.result === "reopened") reopened++; else pending++;
  }
  return { checked: rows.length, verified, reopened, pending };
}

// ── manual lifecycle ─────────────────────────────────────────────────────────
export function setPlanStatus(planId: number, status: string, tenant: number | null, by: string, note?: string): { ok: boolean; error?: string; plan?: any } {
  const db = xv();
  const p = getPlanRow(planId, tenant);
  if (!p) return { ok: false, error: "not found" };
  if (!(STATUSES as readonly string[]).includes(status)) return { ok: false, error: "invalid status" };
  const sets: string[] = ["Status=?"]; const args: any[] = [status];
  if (status === "risk-accepted" || status === "closed") { sets.push("ClosedDate=?"); args.push(nowIso()); }
  if (status === "reopened") sets.push("ReopenCount=COALESCE(ReopenCount,0)+1");
  args.push(planId);
  db.prepare(`UPDATE REMEDIATIONPLAN SET ${sets.join(", ")} WHERE PlanID=?`).run(...args);
  logEvent(planId, status === "risk-accepted" ? "risk-accepted" : "status", by, note || `status → ${status}`, tenant);
  return { ok: true, plan: rowToPlan(getPlanRow(planId, tenant)) };
}
export function assignPlan(planId: number, personId: number | null, tenant: number | null, by: string): { ok: boolean; error?: string } {
  const p = getPlanRow(planId, tenant);
  if (!p) return { ok: false, error: "not found" };
  xv().prepare("UPDATE REMEDIATIONPLAN SET OwnerPersonID=? WHERE PlanID=?").run(personId, planId);
  logEvent(planId, "assigned", by, personId ? `owner → person #${personId}` : "owner cleared", tenant);
  return { ok: true };
}

// ── receipt chain verification ──────────────────────────────────────────────
/** Re-sign the whole execution receipt chain in canonical (ExecutedDate, PlanID) order. Used after demo
 *  seeding (backdated executions insert into the middle of the chain); deterministic + idempotent. */
function rebuildReceiptChain(): void {
  const db = xv();
  const rows = db.prepare("SELECT PlanID, PlanGUID, VulnerabilityID, ActionType, ExecutionRef, ExecutedDate, ExecutionMode, TenantID FROM REMEDIATIONPLAN WHERE ExecutedDate IS NOT NULL AND ExecutedDate<>'' ORDER BY ExecutedDate, PlanID").all() as any[];
  const upd = db.prepare("UPDATE REMEDIATIONPLAN SET ReceiptHash=?, PrevHash=? WHERE PlanID=?");
  let prev = "";
  for (const r of rows) {
    const receipt = sha256(prev + "\n" + JSON.stringify([r.PlanGUID, r.VulnerabilityID ?? null, r.ActionType, String(r.ExecutionRef || ""), r.ExecutedDate, r.ExecutionMode, r.TenantID ?? null]));
    upd.run(receipt, prev || null, r.PlanID);
    prev = receipt;
  }
}

export function verifyReceipts(tenant: number | null): { ok: boolean; total: number; verified: number; firstBreakId: number | null } {
  const db = xv();
  if (!has(db, "REMEDIATIONPLAN")) return { ok: true, total: 0, verified: 0, firstBreakId: null };
  const rows = db.prepare("SELECT PlanID, PlanGUID, VulnerabilityID, ActionType, ExecutionRef, ExecutedDate, ExecutionMode, TenantID, ReceiptHash FROM REMEDIATIONPLAN WHERE ReceiptHash IS NOT NULL AND ReceiptHash<>'' ORDER BY ExecutedDate, PlanID").all() as any[];
  let prev = "", verified = 0, brk: number | null = null;
  for (const r of rows) {
    const expect = sha256(prev + "\n" + JSON.stringify([r.PlanGUID, r.VulnerabilityID ?? null, r.ActionType, String(r.ExecutionRef || ""), r.ExecutedDate, r.ExecutionMode, r.TenantID ?? null]));
    if (r.ReceiptHash !== expect) { brk = num(r.PlanID); break; }
    prev = r.ReceiptHash; verified++;
  }
  return { ok: brk === null, total: rows.length, verified, firstBreakId: brk };
}

// ── dashboard ────────────────────────────────────────────────────────────────
export function planDetail(planId: number, tenant: number | null): any {
  const p = getPlanRow(planId, tenant);
  if (!p) return null;
  const events = (xv().prepare("SELECT At, Event, Actor, Detail FROM REMEDIATIONEVENT WHERE PlanID=? ORDER BY EventID").all(planId) as any[])
    .map((e) => ({ at: String(e.At || ""), event: String(e.Event || ""), actor: String(e.Actor || ""), detail: String(e.Detail || "") }));
  return { ...rowToPlan(p), events };
}

export function remediationDashboard(tenant: number | null): any {
  const ref = { actionTypes: ACTION_TYPES, autonomy: AUTONOMY, statuses: STATUSES };
  const db = xv();
  if (!has(db, "REMEDIATIONPLAN")) return { ...ref, summary: { total: 0 }, policy: { autonomy: defaultAutonomy(), sla: slaHoursBySeverity(tenant) }, worklist: [], plans: [], receipts: { ok: true, total: 0 } };
  const tp = tenant != null ? [tenant] : [];
  const w = tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  const all = db.prepare(`SELECT * FROM REMEDIATIONPLAN ${w}`).all(...tp) as any[];
  const plans = all.map(rowToPlan);
  const cnt = (f: (x: any) => boolean) => plans.filter(f).length;
  const byStatus: Record<string, number> = {}, byAction: Record<string, number> = {}, byAutonomy: Record<string, number> = {};
  for (const p of plans) { byStatus[p.status] = (byStatus[p.status] || 0) + 1; byAction[p.actionType] = (byAction[p.actionType] || 0) + 1; byAutonomy[p.autonomy] = (byAutonomy[p.autonomy] || 0) + 1; }
  const open = plans.filter((p) => OPEN_STATUSES.includes(p.status));
  const closedSet = plans.filter((p) => p.status === "verified" || p.status === "closed");
  // SLA compliance: of closed/verified, % closed on/before due date
  const withDue = closedSet.filter((p) => p.dueDate && p.closedDate);
  const onTime = withDue.filter((p) => new Date(p.closedDate).getTime() <= new Date(p.dueDate).getTime()).length;
  const slaCompliance = withDue.length ? Math.round((onTime / withDue.length) * 100) : null;
  // MTTR (hours) over closed/verified
  const mttrs = closedSet.filter((p) => p.createdDate && p.closedDate).map((p) => (new Date(p.closedDate).getTime() - new Date(p.createdDate).getTime()) / 3600000);
  const mttrHours = mttrs.length ? Math.round(mttrs.reduce((s, n) => s + n, 0) / mttrs.length) : null;
  // autonomous %: of executed plans, share executed autonomously
  const executed = plans.filter((p) => p.executedDate);
  const autoExec = executed.filter((p) => p.executionMode === "autonomous").length;
  const autonomousPct = executed.length ? Math.round((autoExec / executed.length) * 100) : null;
  const now = Date.now();
  const overdue = open.filter((p) => p.dueDate && new Date(p.dueDate).getTime() < now);

  const worklist = open.map((p) => ({ ...p, overdue: !!(p.dueDate && new Date(p.dueDate).getTime() < now) }))
    .sort((a, b) => (Number(b.overdue) - Number(a.overdue)) || (b.priority - a.priority)).slice(0, 100);

  const summary = {
    total: plans.length, open: open.length, proposed: byStatus["proposed"] || 0,
    awaitingApproval: byStatus["awaiting-approval"] || 0, awaitingVerification: byStatus["awaiting-verification"] || 0,
    verified: (byStatus["verified"] || 0) + (byStatus["closed"] || 0), reopened: byStatus["reopened"] || 0,
    blocked: byStatus["blocked"] || 0, riskAccepted: byStatus["risk-accepted"] || 0,
    overdue: overdue.length, slaCompliance, mttrHours, autonomousPct,
    executed: executed.length, autoExecuted: autoExec, byStatus, byAction, byAutonomy,
  };
  // mobilization pipeline (CTEM closed loop counts)
  const pipeline = {
    plan: open.filter((p) => p.status === "proposed" || p.status === "queued").length,
    gate: byStatus["awaiting-approval"] || 0,
    execute: byStatus["awaiting-verification"] || 0,
    verify: cnt((p) => p.status === "reopened"),
    close: summary.verified,
  };
  return {
    ...ref, summary, pipeline,
    policy: { autonomy: defaultAutonomy(), sla: slaHoursBySeverity(tenant) },
    worklist,
    plans: plans.sort((a, b) => b.id - a.id).slice(0, 200),
    receipts: verifyReceipts(tenant),
  };
}

// ── demo seed ────────────────────────────────────────────────────────────────
export function seedDemo(tenant: number): { created: number } {
  const db = xv();
  if (db.prepare("SELECT 1 FROM REMEDIATIONPLAN WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 1").get(tenant)) return { created: 0 };
  // First try to mobilize real seeded exposures.
  let created = 0;
  try { created = autoPlanFromExposures(tenant, 8, "supervised").created; } catch { /* */ }
  // Then craft a few plans in varied lifecycle states so the cockpit KPIs (MTTR, SLA%, autonomous%) populate.
  const H = 3600 * 1000;
  const demos: { ref: string; action: string; sev: string; prio: number; assets: number; pub: number; window: string; autonomy: string; status: string; ageH: number; closeH?: number; mode?: string }[] = [
    { ref: "CVE-2024-3094", action: "isolate", sev: "critical", prio: 92, assets: 3, pub: 1, window: "hours", autonomy: "supervised", status: "awaiting-approval", ageH: 4 },
    { ref: "CVE-2023-44487", action: "waf", sev: "high", prio: 81, assets: 6, pub: 1, window: "hours", autonomy: "autonomous", status: "awaiting-verification", ageH: 10, mode: "autonomous" },
    { ref: "CVE-2021-44228", action: "patch", sev: "critical", prio: 95, assets: 4, pub: 1, window: "hours", autonomy: "autonomous", status: "verified", ageH: 60, closeH: 18, mode: "autonomous" },
    { ref: "CVE-2022-22965", action: "patch", sev: "high", prio: 74, assets: 2, pub: 0, window: "days", autonomy: "supervised", status: "verified", ageH: 120, closeH: 70, mode: "approved" },
    { ref: "CVE-2023-23397", action: "patch", sev: "high", prio: 70, assets: 5, pub: 0, window: "days", autonomy: "supervised", status: "reopened", ageH: 96 },
    { ref: "CVE-2020-1472", action: "patch", sev: "critical", prio: 90, assets: 1, pub: 0, window: "hours", autonomy: "supervised", status: "proposed", ageH: 2 },
    { ref: "Weak TLS configuration (legacy ciphers)", action: "config", sev: "medium", prio: 38, assets: 7, pub: 1, window: "weeks", autonomy: "assisted", status: "risk-accepted", ageH: 200, closeH: 30 },
  ];
  const insert = db.prepare(`INSERT INTO REMEDIATIONPLAN (PlanID, PlanGUID, Title, ExposureRef, VulnerabilityID, CveId, ActionType, Severity, Priority, Score,
      AssetCount, AssetIds, PublicFacing, Window, Autonomy, Status, OwnerPersonID, SlaHours, DueDate, ExecutionMode, ExecutionRef, ReceiptHash, PrevHash, PlanJson, Source, ReopenCount, CreatedDate, ApprovedDate, ExecutedDate, VerifiedDate, ClosedDate, TenantID)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  for (const d of demos) {
    const id = allocId(db, "REMEDIATIONPLAN", "PlanID");
    const slaH = SLA_FALLBACK[d.sev];
    const createdDate = new Date(Date.now() - d.ageH * H).toISOString();
    const dueDate = new Date(new Date(createdDate).getTime() + slaH * H).toISOString();
    const cve = cveOf(d.ref) || "";
    const planJson = JSON.stringify({ reason: inferAction({ ref: d.ref, kev: 0, itw: false, exploits: 0, publicFacing: !!d.pub, window: d.window } as any).reason, steps: defaultSteps(d.action, d.ref, d.assets) });
    let executedDate: string | null = null, approvedDate: string | null = null, verifiedDate: string | null = null, closedDate: string | null = null, execRef: string | null = null;
    if (["awaiting-verification", "verified", "reopened"].includes(d.status)) {
      executedDate = new Date(new Date(createdDate).getTime() + Math.min(d.closeH ?? d.ageH, d.ageH) * 0.5 * H).toISOString();
      if (d.mode === "approved") approvedDate = executedDate;
      execRef = `internal:plan-${id}`;
    }
    if (d.status === "verified" || (d.status === "risk-accepted")) { closedDate = new Date(new Date(createdDate).getTime() + (d.closeH ?? 24) * H).toISOString(); if (d.status === "verified") verifiedDate = closedDate; }
    insert.run(id, `demo-${id}`, `${d.action === "patch" ? "Patch" : d.action === "isolate" ? "Isolate" : d.action === "waf" ? "Virtual-patch" : "Remediate"} ${d.ref}`.slice(0, 200),
      d.ref, null, cve, d.action, d.sev, d.prio, Math.min(100, d.prio + 5), d.assets, "", d.pub, d.window, d.autonomy, d.status, null, slaH, dueDate,
      d.mode || null, execRef, null, null, planJson, "demo", d.status === "reopened" ? 1 : 0, createdDate, approvedDate, executedDate, verifiedDate, closedDate, tenant);
    logEvent(id, "planned", "system", `demo · ${d.action} · ${d.sev}`, tenant);
    if (executedDate) logEvent(id, "executed", "system", `${d.mode || "autonomous"} execution → ${execRef}`, tenant);
    if (verifiedDate) logEvent(id, "verified", "system", "closed-loop verification passed", tenant);
    if (d.status === "reopened") logEvent(id, "reopened", "system", "verification failed past SLA — reopened", tenant);
    created++;
  }
  rebuildReceiptChain(); // sign the demo executions into a consistent (ExecutedDate-ordered) receipt chain
  return { created };
}
