/**
 * secplans.ts — System Plans per NIST SP 800-18r2
 * ("Developing Security, Privacy, and Cybersecurity Supply Chain Risk Management Plans for Systems").
 *
 * A SYSTEMPLAN is a living plan for one system (linked ASSET) of a chosen type:
 *   security (System Security Plan) · privacy (System Privacy Plan) · cscrm (C-SCRM Plan) · consolidated.
 * Each plan is seeded with the 21 System Plan Elements of SP 800-18r2 Table 1, each carrying its
 * source RMF step + RMF task(s) (the authoritative SP 800-18r2 → RMF mapping) — see NIST_ELEMENTS.
 * The 7 RMF steps (Prepare→Categorize→Select→Implement→Assess→Authorize→Monitor) form the
 * development journey; per-step and overall completeness are derived from element status.
 *
 * Exports: JSON (plan + elements + journey), an OSCAL 1.1.2 System-Security-Plan and a Markdown
 * artifact, plus an AI draft (local Ollama, offline heuristic fallback) per element.
 */
import { randomUUID } from "crypto";
import { getDb, ensureSystemPlanTables } from "./db";
import { ollamaStatus, ollamaChat } from "./ai";

const now = (): string => new Date().toISOString();
const num = (v: unknown): number => (typeof v === "number" ? v : parseInt(String(v ?? 0), 10) || 0);

// ── The 7 RMF steps (SP 800-37) — the plan-development journey ───────────────────
export interface RmfStep { key: string; order: number; label: string; desc: string; }
export const RMF_STEPS: RmfStep[] = [
  { key: "prepare", order: 1, label: "Prepare", desc: "Collect the system context — mission/business focus, stakeholders, information types, information life cycle and the authorization boundary; assign the system identifier; designate roles." },
  { key: "categorize", order: 2, label: "Categorize", desc: "FIPS-199 security categorization of each information type for confidentiality, integrity and availability; the system category is the high-water mark." },
  { key: "select", order: 3, label: "Select", desc: "Select, tailor and allocate controls (baseline or organization-generated, optional CSF/overlay profiles); document planned control implementations; obtain plan approval." },
  { key: "implement", order: 4, label: "Implement", desc: "Implement the allocated controls and record their implementation status and the information exchanges with systems outside the boundary." },
  { key: "assess", order: 5, label: "Assess", desc: "Assess control effectiveness; record assessment status and the remediation actions / plan of action & milestones (POA&M)." },
  { key: "authorize", order: 6, label: "Authorize", desc: "Produce the authorization package, the risk determination and the authorization decision (and, where applicable, a Digital Identity Acceptance Statement)." },
  { key: "monitor", order: 7, label: "Monitor", desc: "Continuously monitor the system; keep the operational status, plan review records and plan change records current across the life cycle." },
];
const STEP_ORDER: Record<string, number> = Object.fromEntries(RMF_STEPS.map((s) => [s.key, s.order]));

// ── The 21 System Plan Elements (SP 800-18r2 Table 1) with their RMF task mapping ─
export interface NistElement { key: string; step: string; tasks: string; title: string; overview: string; optional?: boolean; control?: boolean; }
export const NIST_ELEMENTS: NistElement[] = [
  { key: "system-name", step: "prepare", tasks: "P-18", title: "System Name and Identifier", overview: "Identify the system name and unique system identifier." },
  { key: "system-type", step: "prepare", tasks: "P-8, C-1", title: "System Type", overview: "Identify the type of system." },
  { key: "system-overview", step: "prepare", tasks: "P-8, C-1, M-1", title: "System Overview", overview: "Identify the mission processes and business functions that the system is intended to support." },
  { key: "roles", step: "prepare", tasks: "P-9", title: "Role Identification and Responsible Personnel", overview: "Identify the individuals who serve as authorizing officials and system owners as well as other key roles with system responsibilities." },
  { key: "info-types", step: "prepare", tasks: "P-12, P-13", title: "System Information Types", overview: "Identify the information types that are processed, stored, or transmitted by the system." },
  { key: "laws", step: "prepare", tasks: "P-15, P-17", title: "Laws, Regulations, and Policies Affecting the System Requirements", overview: "Identify current laws, regulations, and policies that influence organizational policies and system requirements." },
  { key: "auth-boundary", step: "prepare", tasks: "P-10, P-11, P-13, P-16, M-1", title: "Authorization Boundary Description", overview: "Define the scope of the system protections that encompass the authorization boundary, including all components and subsystems to be authorized for operation." },
  { key: "component-inventory", step: "prepare", tasks: "P-10, M-7", title: "System Component Inventory", overview: "Identify the inventory of components being used within the authorization boundary." },
  { key: "env-diagrams", step: "prepare", tasks: "P-10, P-11, P-13, P-16, M-1", title: "Environment of Operation Diagrams", overview: "Include system diagrams that clearly depict the components of the system architecture within the authorization boundary." },
  { key: "categorization", step: "categorize", tasks: "C-2, C-3", title: "System Categorization", overview: "Categorize information types by their impact level for each security objective (confidentiality, integrity, availability). The system security category reflects the high-water mark of all designated subsystems." },
  { key: "control-impl-details", step: "select", tasks: "P-4, P-5, S-1, S-2, S-3, S-4, S-5, I-1, I-2, A-5, R-3, M-1, M-3", title: "Control Implementation Details", overview: "Provide implementation details for all controls allocated to the system. Identify the location of artifacts referenced in the control implementation details.", control: true },
  { key: "plan-approval", step: "select", tasks: "S-6", title: "System Plan Approval", overview: "Indicate whether the plan has been approved by the authorizing official." },
  { key: "control-impl-status", step: "implement", tasks: "S-4, I-2", title: "Control Implementation Status", overview: "Indicate the implementation status of the control." },
  { key: "info-exchanges", step: "implement", tasks: "P-13, I-1, I-2, R-3, M-1, M-3", title: "Information Exchanges Summary", overview: "Summarize the flow of information exchanged with other systems outside the authorization boundary." },
  { key: "control-assess-status", step: "assess", tasks: "A-5, A-6, M-2", title: "Control Assessment Status", overview: "Indicate the assessment status of each allocated control resulting from the assessment process." },
  { key: "remediation-actions", step: "assess", tasks: "I-2, A-5, A-6, R-1, R-3, M-3, M-4", title: "Remediation Actions", overview: "Identify controls that require remediation action resulting from assessment results and the associated plan of action and milestones (POA&M)." },
  { key: "dias", step: "authorize", tasks: "R-1, M-4", title: "Digital Identity Acceptance Statement", overview: "Provide a Digital Identity Acceptance Statement (DIAS), as described in SP 800-63-4.", optional: true },
  { key: "auth-decision", step: "authorize", tasks: "A-5, R-2, R-4, M-4, M-6", title: "System Authorization Decision", overview: "Identify the authorization decision and the effective date and duration of the authorization provided by the authorizing official." },
  { key: "operational-status", step: "monitor", tasks: "C-1, M-1, M-7", title: "System Operational Status", overview: "Indicate the operational status of the system and subsystems." },
  { key: "review-records", step: "monitor", tasks: "M-4", title: "System Plan Review Records", overview: "Provide a method for recording system plan reviews over the course of the system life cycle." },
  { key: "change-records", step: "monitor", tasks: "I-2, A-5, A-6, R-3, M-1, M-3, M-4, M-7", title: "System Plan Change Records", overview: "Provide a method for recording system plan changes over the course of the system life cycle." },
];

export const PLAN_TYPES = [
  { key: "security", label: "System Security Plan", pub: "NIST SP 800-18r2 / SP 800-37" },
  { key: "privacy", label: "System Privacy Plan", pub: "NIST SP 800-18r2 / SP 800-53B privacy baseline" },
  { key: "cscrm", label: "Cybersecurity Supply Chain Risk Management Plan", pub: "NIST SP 800-18r2 / SP 800-161" },
  { key: "consolidated", label: "Consolidated System Plan", pub: "NIST SP 800-18r2 (security + privacy + C-SCRM)" },
];
export const IMPACT_LEVELS = ["low", "moderate", "high"];
export const OPERATIONAL_STATUS = ["under-development", "operational", "under-major-modification", "disposition"];

// ── Row types ────────────────────────────────────────────────────────────────
export interface PlanRow { PlanID: number; [k: string]: unknown; }
const T = (tenant: number | null): string => (tenant == null ? "" : " AND (TenantID = @t OR TenantID IS NULL)");

// ── Create ───────────────────────────────────────────────────────────────────
export function createPlan(tenant: number | null, opts: {
  name: string; systemIdentifier?: string; planType?: string; assetId?: number | null;
  systemType?: string; systemOverview?: string; authorizingOfficial?: string; systemOwner?: string;
  confImpact?: string; integImpact?: string; availImpact?: string; createdBy?: string;
}): { planId: number } {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  const planType = PLAN_TYPES.some((p) => p.key === opts.planType) ? opts.planType! : "security";
  const overall = highWater(opts.confImpact, opts.integImpact, opts.availImpact);
  const info = db.prepare(`INSERT INTO SYSTEMPLAN
      (PlanGUID, Name, SystemIdentifier, PlanType, AssetID, SystemType, SystemOverview,
       AuthorizingOfficial, SystemOwner, ConfImpact, IntegImpact, AvailImpact, OverallCategorization,
       OperationalStatus, CurrentRmfStep, Status, TenantID, CreatedBy, CreatedDate, UpdatedDate)
      VALUES (@guid,@name,@sid,@pt,@aid,@stype,@sov,@ao,@so,@ci,@ii,@ai,@oc,'under-development','prepare','draft',@t,@cb,@now,@now)`)
    .run({
      guid: randomUUID(), name: opts.name, sid: opts.systemIdentifier || autoId(opts.name),
      pt: planType, aid: opts.assetId ?? null, stype: opts.systemType || "", sov: opts.systemOverview || "",
      ao: opts.authorizingOfficial || "", so: opts.systemOwner || "",
      ci: opts.confImpact || "", ii: opts.integImpact || "", ai: opts.availImpact || "", oc: overall,
      t: tenant, cb: opts.createdBy || "system", now: now(),
    });
  const planId = num(info.lastInsertRowid);
  const ins = db.prepare(`INSERT INTO SYSTEMPLANELEMENT
      (PlanID, ElementKey, RmfStep, RmfStepOrder, RmfTasks, Title, Overview, Content, Status, Optional, ControlRefs, ElementOrder, UpdatedDate, TenantID)
      VALUES (@pid,@k,@step,@so,@tasks,@title,@ov,'', 'todo',@opt,'',@ord,@now,@t)`);
  NIST_ELEMENTS.forEach((e, i) => ins.run({
    pid: planId, k: e.key, step: e.step, so: STEP_ORDER[e.step] || 99, tasks: e.tasks,
    title: e.title, ov: e.overview, opt: e.optional ? 1 : 0, ord: i, now: now(), t: tenant,
  }));
  return { planId };
}

const autoId = (name: string): string =>
  "SYS-" + (name || "system").toUpperCase().replace(/[^A-Z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 20) + "-" + Math.random().toString(36).slice(2, 6).toUpperCase();

const RANK: Record<string, number> = { low: 1, moderate: 2, high: 3 };
function highWater(...impacts: (string | undefined)[]): string {
  let best = ""; let r = 0;
  for (const i of impacts) { const v = (i || "").toLowerCase(); if (RANK[v] && RANK[v] > r) { r = RANK[v]; best = v; } }
  return best;
}

// ── Read ─────────────────────────────────────────────────────────────────────
export function listPlans(tenant: number | null): Record<string, unknown>[] {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  const rows = db.prepare(`SELECT p.*, (SELECT COUNT(*) FROM SYSTEMPLANELEMENT e WHERE e.PlanID=p.PlanID) elemTotal,
      (SELECT COUNT(*) FROM SYSTEMPLANELEMENT e WHERE e.PlanID=p.PlanID AND e.Status IN ('complete','na')) elemDone
      FROM SYSTEMPLAN p WHERE 1=1${T(tenant)} ORDER BY p.UpdatedDate DESC, p.PlanID DESC`).all({ t: tenant }) as Record<string, unknown>[];
  return rows.map((p) => ({ ...p, completeness: p.elemTotal ? Math.round((num(p.elemDone) / num(p.elemTotal)) * 100) : 0 }));
}

export function getPlan(tenant: number | null, id: number): { plan: Record<string, unknown>; elements: Record<string, unknown>[]; journey: unknown[]; completeness: number } | null {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  const plan = db.prepare(`SELECT * FROM SYSTEMPLAN WHERE PlanID=@id${T(tenant)}`).get({ id, t: tenant }) as Record<string, unknown> | undefined;
  if (!plan) return null;
  if (plan.AssetID != null) {
    try { const a = getDb("XORCISM").prepare("SELECT Name FROM ASSET WHERE AssetID=?").get(plan.AssetID) as { Name?: string } | undefined; if (a) plan.AssetName = a.Name; } catch { /* ignore */ }
  }
  const elements = db.prepare(`SELECT * FROM SYSTEMPLANELEMENT WHERE PlanID=@id ORDER BY ElementOrder`).all({ id }) as Record<string, unknown>[];
  const journey = RMF_STEPS.map((s) => {
    const els = elements.filter((e) => e.RmfStep === s.key);
    const done = els.filter((e) => e.Status === "complete" || e.Status === "na").length;
    return { ...s, total: els.length, done, pct: els.length ? Math.round((done / els.length) * 100) : 0, active: plan.CurrentRmfStep === s.key };
  });
  const total = elements.length, done = elements.filter((e) => e.Status === "complete" || e.Status === "na").length;
  return { plan, elements, journey, completeness: total ? Math.round((done / total) * 100) : 0 };
}

// ── Update ───────────────────────────────────────────────────────────────────
const PLAN_FIELDS: Record<string, string> = {
  name: "Name", systemIdentifier: "SystemIdentifier", planType: "PlanType", assetId: "AssetID",
  systemType: "SystemType", systemOverview: "SystemOverview", authorizingOfficial: "AuthorizingOfficial",
  systemOwner: "SystemOwner", confImpact: "ConfImpact", integImpact: "IntegImpact", availImpact: "AvailImpact",
  operationalStatus: "OperationalStatus", authorizationDecision: "AuthorizationDecision",
  authorizationDate: "AuthorizationDate", authorizationExpiry: "AuthorizationExpiry",
  currentRmfStep: "CurrentRmfStep", status: "Status",
};
export function updatePlan(tenant: number | null, id: number, patch: Record<string, unknown>): boolean {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  const sets: string[] = []; const args: Record<string, unknown> = { id, t: tenant, now: now() };
  for (const [k, col] of Object.entries(PLAN_FIELDS)) {
    if (k in patch) { sets.push(`${col}=@${k}`); args[k] = patch[k]; }
  }
  if (["confImpact", "integImpact", "availImpact"].some((k) => k in patch)) {
    const cur = db.prepare(`SELECT ConfImpact,IntegImpact,AvailImpact FROM SYSTEMPLAN WHERE PlanID=?`).get(id) as Record<string, string> | undefined;
    const oc = highWater(patch.confImpact as string ?? cur?.ConfImpact, patch.integImpact as string ?? cur?.IntegImpact, patch.availImpact as string ?? cur?.AvailImpact);
    sets.push("OverallCategorization=@oc"); args.oc = oc;
  }
  if (!sets.length) return false;
  db.prepare(`UPDATE SYSTEMPLAN SET ${sets.join(", ")}, UpdatedDate=@now WHERE PlanID=@id${T(tenant)}`).run(args);
  return true;
}

export function updateElement(tenant: number | null, planId: number, elementId: number, patch: { content?: string; status?: string; artifactRef?: string; controlRefs?: string }): boolean {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  const sets: string[] = []; const args: Record<string, unknown> = { eid: elementId, pid: planId, now: now() };
  if (patch.content !== undefined) { sets.push("Content=@c"); args.c = patch.content; }
  if (patch.status !== undefined) { sets.push("Status=@s"); args.s = patch.status; }
  if (patch.artifactRef !== undefined) { sets.push("ArtifactRef=@a"); args.a = patch.artifactRef; }
  if (patch.controlRefs !== undefined) { sets.push("ControlRefs=@r"); args.r = patch.controlRefs; }
  if (!sets.length) return false;
  db.prepare(`UPDATE SYSTEMPLANELEMENT SET ${sets.join(", ")}, UpdatedDate=@now WHERE ElementID=@eid AND PlanID=@pid`).run(args);
  db.prepare(`UPDATE SYSTEMPLAN SET UpdatedDate=@now WHERE PlanID=@pid`).run({ now: now(), pid: planId });
  return true;
}

export function deletePlan(tenant: number | null, id: number): boolean {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare(`DELETE FROM SYSTEMPLANELEMENT WHERE PlanID=@id`).run({ id });
  db.prepare(`DELETE FROM SYSTEMPLAN WHERE PlanID=@id${T(tenant)}`).run({ id, t: tenant });
  return true;
}

// ── Markdown artifact ────────────────────────────────────────────────────────
export function planMarkdown(tenant: number | null, id: number): string | null {
  const d = getPlan(tenant, id); if (!d) return null;
  const p = d.plan;
  const typeLabel = PLAN_TYPES.find((x) => x.key === p.PlanType)?.label || "System Plan";
  const cat = (p.OverallCategorization as string) || "—";
  const L: string[] = [];
  L.push(`# ${typeLabel} — ${p.Name}`);
  L.push(`_NIST SP 800-18r2 · system \`${p.SystemIdentifier}\` · categorization **${cat.toUpperCase()}** (C:${(p.ConfImpact as string || "—")} / I:${(p.IntegImpact as string || "—")} / A:${(p.AvailImpact as string || "—")}) · status ${p.OperationalStatus} · completeness ${d.completeness}%_\n`);
  L.push(`| Field | Value |`); L.push(`|---|---|`);
  L.push(`| System type | ${p.SystemType || "—"} |`);
  L.push(`| Authorizing official | ${p.AuthorizingOfficial || "—"} |`);
  L.push(`| System owner | ${p.SystemOwner || "—"} |`);
  L.push(`| Authorization decision | ${p.AuthorizationDecision || "—"} |`);
  L.push(`| Current RMF step | ${p.CurrentRmfStep} |\n`);
  for (const s of RMF_STEPS) {
    const els = d.elements.filter((e) => e.RmfStep === s.key); if (!els.length) continue;
    L.push(`## ${s.order}. ${s.label} (RMF)`);
    L.push(`_${s.desc}_\n`);
    for (const e of els) {
      L.push(`### ${e.Title}  \n\`RMF: ${e.RmfTasks}\` · status: **${e.Status}**${e.Optional ? " · _optional_" : ""}`);
      L.push(`> ${e.Overview}`);
      if (e.Content) L.push(`\n${e.Content}`);
      if (e.ControlRefs) L.push(`\n_Controls: ${e.ControlRefs}_`);
      if (e.ArtifactRef) L.push(`\n_Artifact: ${e.ArtifactRef}_`);
      L.push("");
    }
  }
  return L.join("\n");
}

// ── OSCAL 1.1.2 System-Security-Plan ─────────────────────────────────────────
export function planOscal(tenant: number | null, id: number): Record<string, unknown> | null {
  const d = getPlan(tenant, id); if (!d) return null;
  const p = d.plan;
  const sens = ((p.OverallCategorization as string) || "low").toLowerCase();
  const oscalSens = IMPACT_LEVELS.includes(sens) ? sens : "low";
  const ctlEl = d.elements.find((e) => e.ElementKey === "control-impl-details");
  const ctlRefs = String(ctlEl?.ControlRefs || "").split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  const impl = ctlRefs.map((cid) => ({
    uuid: randomUUID(), "control-id": cid.toLowerCase(),
    props: [{ name: "implementation-status", value: statusToOscal(String(ctlEl?.Status || "todo")) }],
    statements: [{ "statement-id": `${cid}_stmt`, uuid: randomUUID(),
      "by-components": [{ "component-uuid": randomUUID(), uuid: randomUUID(), description: String(ctlEl?.Content || "Planned control implementation.") }] }],
  }));
  const typeLabel = PLAN_TYPES.find((x) => x.key === p.PlanType)?.label || "System Plan";
  return { "system-security-plan": {
    uuid: randomUUID(),
    metadata: { title: `${typeLabel} — ${p.Name}`, "last-modified": now(), version: "1.0", "oscal-version": "1.1.2",
      props: [{ name: "plan-type", value: String(p.PlanType), ns: "https://xorcism.ai/ns/nist-800-18r2" }] },
    "import-profile": { href: "#" },
    "system-characteristics": {
      "system-ids": [{ "identifier-type": "https://xorcism.ai/ns/system", id: String(p.SystemIdentifier) }],
      "system-name": String(p.Name),
      description: String(p.SystemOverview || `${typeLabel} developed per NIST SP 800-18r2.`),
      "security-sensitivity-level": oscalSens,
      "system-information": { "information-types": [{ uuid: randomUUID(), title: "System information types",
        description: String(d.elements.find((e) => e.ElementKey === "info-types")?.Content || "See System Information Types element."),
        "confidentiality-impact": { base: oscalImpact(p.ConfImpact) }, "integrity-impact": { base: oscalImpact(p.IntegImpact) }, "availability-impact": { base: oscalImpact(p.AvailImpact) } }] },
      "security-impact-level": { "security-objective-confidentiality": oscalImpact(p.ConfImpact), "security-objective-integrity": oscalImpact(p.IntegImpact), "security-objective-availability": oscalImpact(p.AvailImpact) },
      status: { state: mapOpStatus(String(p.OperationalStatus)) },
      "authorization-boundary": { description: String(d.elements.find((e) => e.ElementKey === "auth-boundary")?.Content || "See Authorization Boundary Description element.") },
    },
    "system-implementation": {
      users: [{ uuid: randomUUID(), title: String(p.SystemOwner || "System owner"), "role-ids": ["system-owner"] },
              { uuid: randomUUID(), title: String(p.AuthorizingOfficial || "Authorizing official"), "role-ids": ["authorizing-official"] }],
      components: [{ uuid: randomUUID(), type: "system", title: String(p.AssetName || p.Name), description: String(p.SystemType || "Assessed system"), status: { state: mapOpStatus(String(p.OperationalStatus)) } }],
    },
    "control-implementation": {
      description: "Planned/implemented controls allocated to the system (SP 800-18r2 Control Implementation Details element).",
      "implemented-requirements": impl.length ? impl : [{ uuid: randomUUID(), "control-id": "pl-2", props: [{ name: "implementation-status", value: "planned" }],
        statements: [{ "statement-id": "pl-2_stmt", uuid: randomUUID(), "by-components": [{ "component-uuid": randomUUID(), uuid: randomUUID(), description: "System plan maintained per NIST SP 800-18r2." }] }] }],
    },
    // Each SP 800-18r2 element surfaced as a back-matter resource with its RMF mapping.
    "back-matter": { resources: d.elements.map((e) => ({ uuid: randomUUID(), title: String(e.Title),
      description: `${e.Overview}${e.Content ? `\n\n${e.Content}` : ""}`,
      props: [{ name: "rmf-step", value: String(e.RmfStep) }, { name: "rmf-tasks", value: String(e.RmfTasks) }, { name: "status", value: String(e.Status) }] })) },
  } };
}
const oscalImpact = (v: unknown): string => { const s = String(v || "").toLowerCase(); return IMPACT_LEVELS.includes(s) ? s : "low"; };
const statusToOscal = (s: string): string => s === "complete" ? "implemented" : s === "in-progress" ? "partial" : s === "na" ? "not-applicable" : "planned";
const mapOpStatus = (s: string): string => s === "operational" ? "operational" : s === "disposition" ? "disposition" : "under-development";

// ── AI draft (Ollama, offline heuristic fallback) ────────────────────────────
export async function draftElement(tenant: number | null, planId: number, elementId: number): Promise<{ draft: string; model: string; offline: boolean }> {
  const d = getPlan(tenant, planId);
  const el = d?.elements.find((e) => num(e.ElementID) === elementId);
  if (!d || !el) return { draft: "", model: "", offline: true };
  const p = d.plan;
  const ctx = `${PLAN_TYPES.find((x) => x.key === p.PlanType)?.label || "System Plan"} for system "${p.Name}" (id ${p.SystemIdentifier}, categorization ${(p.OverallCategorization as string) || "—"}). System type: ${p.SystemType || "n/a"}. Overview: ${p.SystemOverview || "n/a"}.`;
  const st = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  if (st.reachable) {
    try {
      const answer = await ollamaChat([
        { role: "system", content: "You are a FISMA/RMF documentation assistant. Draft a concise, professional NIST SP 800-18r2 system-plan element. Output only the element body (no headings). 4–8 sentences, specific and audit-ready." },
        { role: "user", content: `${ctx}\n\nPlan element: "${el.Title}"\nRMF mapping: ${el.RmfTasks}\nObjective: ${el.Overview}\n\nDraft the content for this element.` },
      ], 0.3);
      if (answer && answer.trim()) return { draft: answer.trim(), model: st.model, offline: false };
    } catch { /* fall through to offline */ }
  }
  return { draft: offlineDraft(p, el), model: "offline", offline: true };
}

function offlineDraft(p: Record<string, unknown>, el: Record<string, unknown>): string {
  const sys = `${p.Name} (${p.SystemIdentifier})`;
  const cat = (p.OverallCategorization as string) || "to be determined";
  const map: Record<string, string> = {
    "system-name": `The system is named **${p.Name}** and is uniquely identified as \`${p.SystemIdentifier}\`. This identifier associates the component inventory, audit records and all system artifacts throughout the life cycle.`,
    "system-type": `${sys} is a ${p.SystemType || "[general support system / major application / minor application]"}. [Describe deployment model — on-premises, cloud (IaaS/PaaS/SaaS), hybrid — and whether it is a general support system, major application or subsystem.]`,
    "system-overview": p.SystemOverview ? String(p.SystemOverview) : `${sys} supports the following mission processes and business functions: [list the missions/business functions the system enables and the organizational outcomes it delivers].`,
    "roles": `Authorizing Official: ${p.AuthorizingOfficial || "[name/title]"}. System Owner: ${p.SystemOwner || "[name/title]"}. Additional key roles (ISSO, ISSM, system administrator, privacy officer, C-SCRM lead) and their responsibilities are defined per SP 800-37 Appendix D.`,
    "info-types": `The system processes, stores and transmits the following information types (per NIST SP 800-60): [enumerate information types with their provisional confidentiality/integrity/availability impacts].`,
    "laws": `Applicable laws, regulations and policies influencing this system's requirements include: FISMA, OMB Circular A-130, [sector/data-specific — e.g. Privacy Act, HIPAA, PCI-DSS, GDPR], and organizational policies [reference].`,
    "auth-boundary": `The authorization boundary encompasses all components and subsystems of ${sys} authorized for operation: [list in-boundary components, interconnections and any subsystems]. Components outside the boundary from which controls are inherited are identified as common control providers.`,
    "component-inventory": `The component inventory within the authorization boundary comprises: [hardware, software, firmware and services with make/model/version and criticality]. It is kept current and reconciled with the automated asset inventory.`,
    "env-diagrams": `Refer to the attached architecture/data-flow diagrams depicting the components within the authorization boundary, network zones, trust boundaries and external interconnections. [Attach diagram artifact.]`,
    "categorization": `Per FIPS-199, the security categorization is Confidentiality **${p.ConfImpact || "—"}**, Integrity **${p.IntegImpact || "—"}**, Availability **${p.AvailImpact || "—"}**; the overall system category (high-water mark) is **${cat}**. Rationale: [justify each objective, including privacy and C-SCRM impacts per SP 800-60v2].`,
    "control-impl-details": `Controls are selected from the ${cat} baseline (SP 800-53B) and tailored to the system. For each allocated control, implementation details, responsible role, inheritance (common/hybrid/system-specific) and the location of supporting artifacts are recorded. Referenced controls: [add control ids].`,
    "plan-approval": `This ${PLAN_TYPES.find((x) => x.key === p.PlanType)?.label || "plan"} [has been / has not yet been] approved by the Authorizing Official ${p.AuthorizingOfficial || "[name]"} on [date].`,
    "control-impl-status": `Implementation status per control: [implemented / partially implemented / planned / alternative implementation / not applicable], with target dates for controls not yet fully implemented.`,
    "info-exchanges": `Information exchanged with systems outside the authorization boundary: [for each interconnection list the peer system, data exchanged, direction, protection (e.g. encryption) and the governing agreement (ISA/MOU per SP 800-47)].`,
    "control-assess-status": `Assessment status of each allocated control from the most recent assessment: [satisfied / other-than-satisfied], including the assessor, method and date.`,
    "remediation-actions": `Controls requiring remediation and their POA&M entries: [for each finding, the weakness, risk, remediation, resources, milestones and completion date].`,
    "dias": `Digital Identity Acceptance Statement (per SP 800-63-4): the selected IAL/AAL/FAL and the risk-acceptance rationale for the system's digital identity approach. [Optional — include where applicable.]`,
    "auth-decision": `Authorization decision: ${p.AuthorizationDecision || "[Authorization to Operate / ATO with conditions / Denial]"}, effective ${p.AuthorizationDate || "[date]"} through ${p.AuthorizationExpiry || "[date]"}, granted by ${p.AuthorizingOfficial || "[AO]"}.`,
    "operational-status": `Operational status of the system and subsystems: **${p.OperationalStatus}**. [Note any subsystems with a differing status.]`,
    "review-records": `System plan reviews are recorded here over the life cycle: [date · reviewer · outcome]. Reviews occur at least annually and upon significant change.`,
    "change-records": `System plan changes are recorded here over the life cycle: [date · change · driver (assessment, POA&M, environment change) · approver].`,
  };
  return map[String(el.ElementKey)] || `${el.Overview}\n\n[Provide the content for this element. RMF mapping: ${el.RmfTasks}.]`;
}

// ── Demo seed ────────────────────────────────────────────────────────────────
export function seedSystemPlanDemo(tenant: number): { created: number } {
  ensureSystemPlanTables();
  const db = getDb("XCOMPLIANCE");
  const existing = db.prepare(`SELECT COUNT(*) c FROM SYSTEMPLAN WHERE TenantID=?`).get(tenant) as { c: number };
  if (existing.c > 0) return { created: 0 };
  const { planId } = createPlan(tenant, {
    name: "Customer Portal", systemIdentifier: "SYS-CUSTPORTAL-DEMO", planType: "consolidated",
    systemType: "Major application (public-facing web application, cloud PaaS)",
    systemOverview: "Public customer self-service portal supporting account management, billing and support ticketing for the retail line of business.",
    authorizingOfficial: "Dana Reyes, CISO (AO)", systemOwner: "Sam Okafor, Product Owner",
    confImpact: "moderate", integImpact: "moderate", availImpact: "high", createdBy: "seed",
  });
  // Pre-fill a few elements + set the plan to the Select step, so the journey shows progress.
  const els = db.prepare(`SELECT ElementID, ElementKey FROM SYSTEMPLANELEMENT WHERE PlanID=?`).all(planId) as { ElementID: number; ElementKey: string }[];
  const byKey = Object.fromEntries(els.map((e) => [e.ElementKey, e.ElementID]));
  const fill = (key: string, content: string, status = "complete", controlRefs = "") => {
    if (byKey[key]) updateElement(tenant, planId, byKey[key], { content, status, controlRefs });
  };
  fill("system-name", "The system is named Customer Portal and is uniquely identified as SYS-CUSTPORTAL-DEMO.");
  fill("system-type", "Major application: a public-facing web application hosted on a cloud PaaS with an isolated production account.");
  fill("system-overview", "Supports account self-service, billing and support ticketing for the retail line of business (~40k active customers).");
  fill("roles", "AO: Dana Reyes (CISO). System Owner: Sam Okafor. ISSO: J. Park. Privacy Officer: L. Chen. C-SCRM lead: R. Díaz.");
  fill("info-types", "PII (contact + billing), payment tokens (no PAN stored), support content. Provisional impacts per SP 800-60.");
  fill("categorization", "FIPS-199: C=moderate, I=moderate, A=high → overall HIGH (availability high-water mark).");
  fill("control-impl-details", "Controls tailored from the SP 800-53B moderate baseline plus availability enhancements; details recorded per control.", "in-progress", "AC-2, AC-6, AU-2, CP-9, IA-2, SC-7, SC-13, SI-4, SR-3");
  fill("auth-boundary", "Web tier, API tier, managed database and object storage in the prod cloud account; CDN and IdP are inherited common controls.");
  db.prepare(`UPDATE SYSTEMPLAN SET CurrentRmfStep='select', Status='in-progress', UpdatedDate=? WHERE PlanID=?`).run(now(), planId);
  return { created: 1 };
}
