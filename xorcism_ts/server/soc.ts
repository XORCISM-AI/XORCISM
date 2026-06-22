/**
 * soc.ts — SOC Operations cockpit (XINCIDENT backend).
 *
 * Ties the SOC together on top of the existing INCIDENT/ALERT model:
 *   - Analyst rota & on-call (SOCSHIFT) — who is covering each tier right now.
 *   - Detection/response KPIs — MTTD (start→detect), MTTA (detect→acknowledge), MTTR (detect→resolve),
 *     computed from the INCIDENT timestamps and surfaced on the dashboard.
 *   - Escalation procedure — an ordered ESCALATIONPOLICY/ESCALATIONTIER (ack/resolve timeouts per tier)
 *     and a per-incident escalation log (INCIDENTESCALATION); the queue flags incidents past their
 *     tier ack-SLA so they get escalated.
 *   - IR playbooks — a PLAYBOOK/PLAYBOOKSTEP library (NIST SP 800-61 phases) attachable to an incident
 *     (materialized as INCIDENTPLAYBOOKSTEP) with per-step completion tracking.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const PHASES = ["Detection & Analysis", "Containment", "Eradication", "Recovery", "Post-Incident"] as const;

// ── default escalation tiers (NIST 800-61 / SOC tiering) ───────────────────────
export const DEFAULT_TIERS = [
  { level: 1, name: "L1", role: "SOC Analyst — Triage", ack: 15, resolve: 240 },
  { level: 2, name: "L2", role: "SOC Analyst — Investigation", ack: 30, resolve: 480 },
  { level: 3, name: "L3", role: "Incident Responder / Detection Eng.", ack: 60, resolve: 1440 },
  { level: 4, name: "Manager", role: "SOC Manager — escalation & crisis", ack: 120, resolve: 2880 },
];
const TIER_ORDER = DEFAULT_TIERS.map((t) => t.name);

// ── IR playbook library (NIST SP 800-61 phased) ────────────────────────────────
type PStep = { phase: string; title: string; desc: string; role?: string };
type PB = { category: string; name: string; severity: string; steps: PStep[] };
const s = (phase: string, title: string, desc: string, role?: string): PStep => ({ phase, title, desc, role });

export const PLAYBOOKS: PB[] = [
  { category: "Phishing", name: "Phishing / credential-harvesting response", severity: "Medium", steps: [
    s("Detection & Analysis", "Confirm and scope the campaign", "Verify the reported email is malicious; search the mail gateway for other recipients and similar messages."),
    s("Detection & Analysis", "Extract IOCs", "Pull sender, URLs, attachment hashes; scan them (multi-engine) and check CTI."),
    s("Containment", "Quarantine and block", "Quarantine the message tenant-wide, block sender/domain/URL at the gateway and proxy."),
    s("Containment", "Handle clickers", "Identify who clicked/submitted; force password reset and revoke sessions for submitters."),
    s("Eradication", "Remove artifacts", "Purge delivered copies, remove any dropped payloads, revoke malicious OAuth grants."),
    s("Recovery", "Restore and monitor", "Re-enable accounts after reset; watch for follow-on logins from the harvested credentials."),
    s("Post-Incident", "Awareness & lessons learned", "Brief the affected users, feed a phishing-simulation, document the timeline."),
  ]},
  { category: "Malware", name: "Endpoint malware infection response", severity: "High", steps: [
    s("Detection & Analysis", "Triage the EDR alert", "Confirm the detection, identify the host, user, process tree and file hashes."),
    s("Detection & Analysis", "Determine blast radius", "Check the hash/IOCs across the fleet for other infected hosts."),
    s("Containment", "Isolate the host", "Network-isolate the endpoint via EDR; preserve volatile evidence first if feasible."),
    s("Eradication", "Remove the malware", "Kill/quarantine the malicious process and persistence, remove dropped files and scheduled tasks."),
    s("Recovery", "Rebuild or clean", "Re-image if integrity is uncertain; restore from known-good backup; rotate credentials used on the host."),
    s("Post-Incident", "Tune detections", "Add IOCs to blocklists, create/refine the detection rule, record lessons learned."),
  ]},
  { category: "Ransomware", name: "Ransomware outbreak response", severity: "Critical", steps: [
    s("Detection & Analysis", "Confirm encryption activity", "Validate mass file-rename / ransom notes; identify patient zero and the strain."),
    s("Containment", "Contain spread fast", "Isolate affected segments, disable the compromised accounts, block C2, suspend backups jobs from being encrypted."),
    s("Containment", "Activate crisis process", "Notify the crisis lead; assess the regulator/notification clock; engage legal & comms."),
    s("Eradication", "Remove footholds", "Eliminate the actor's access, persistence and tooling across all touched hosts."),
    s("Recovery", "Restore from clean backups", "Validate backup integrity, restore by priority (RTO/RPO), rebuild domain trust if needed."),
    s("Post-Incident", "After-action review", "Document the decision log (incl. payment stance), report, and harden the entry vector."),
  ]},
  { category: "Business Email Compromise", name: "BEC / invoice-fraud response", severity: "High", steps: [
    s("Detection & Analysis", "Verify the fraud", "Confirm the suspicious payment/redirect request and the look-alike domain or compromised mailbox."),
    s("Containment", "Stop the money & access", "Initiate bank recall if a payment went out; reset the mailbox, revoke sessions, remove inbox rules."),
    s("Eradication", "Clear persistence", "Remove forwarding/transport rules and OAuth grants; hunt for other affected mailboxes."),
    s("Recovery", "Re-secure finance flow", "Re-enable accounts with MFA; reinforce out-of-band payment verification."),
    s("Post-Incident", "Report & train", "File with law enforcement, brief finance/leadership, update the verification control."),
  ]},
  { category: "Account Compromise", name: "Cloud/identity account takeover response", severity: "High", steps: [
    s("Detection & Analysis", "Confirm the takeover", "Validate impossible-travel/anomalous sign-in; identify the account and its privileges."),
    s("Containment", "Revoke access", "Force sign-out, reset password, require MFA re-registration; revoke tokens and app grants."),
    s("Eradication", "Remove persistence", "Delete attacker-created OAuth apps, inbox rules, MFA methods and any new admin roles."),
    s("Recovery", "Assess blast radius", "Review federated SaaS access and data touched; reset affected sessions, notify app owners."),
    s("Post-Incident", "Strengthen identity", "Tighten conditional access, review privileged roles, record lessons learned."),
  ]},
  { category: "Data Exfiltration", name: "Data exfiltration response", severity: "High", steps: [
    s("Detection & Analysis", "Confirm and scope exfil", "Validate the DLP/anomalous-egress alert; identify the data, volume, channel and account."),
    s("Containment", "Cut the channel", "Block the destination/cloud app, disable the account/path, preserve logs and evidence."),
    s("Eradication", "Close the gap", "Remove the access path used; revoke credentials and any exfil tooling."),
    s("Recovery", "Assess impact", "Scope which records/fields left; engage legal/DPO on notification obligations."),
    s("Post-Incident", "Notify & remediate", "Customer/regulator notification as required; tune DLP and access controls."),
  ]},
];

// ── helpers ────────────────────────────────────────────────────────────────────
function cols(table: string): Set<string> {
  try { return new Set((getDb("XINCIDENT").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(table: string): boolean { try { return !!getDb("XINCIDENT").prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; } }
const ms = (v: unknown): number | null => { if (v == null || v === "") return null; const t = Date.parse(String(v).replace(" ", "T")); return Number.isFinite(t) ? t : null; };
const tw = (tenant: number | null, col = "TenantID"): string => (tenant != null ? `WHERE (${col} = ${tenant} OR ${col} IS NULL)` : "");
const OPEN = /new|open|active|inprogress|in progress|triage|investigat|contain/i;
const DONE = /resolv|closed|done|recover|eradicat/i;

function personMap(): Map<number, string> {
  const m = new Map<number, string>();
  try { for (const p of getDb("XORCISM").prepare("SELECT PersonID, FullName FROM PERSON").all() as { PersonID: number; FullName: string }[]) m.set(Number(p.PersonID), p.FullName || `#${p.PersonID}`); } catch { /* */ }
  return m;
}

/** The active escalation policy's tiers (ack/resolve minutes), falling back to DEFAULT_TIERS. */
function tierConfig(tenant: number | null): { name: string; role: string; level: number; ack: number; resolve: number }[] {
  if (has("ESCALATIONTIER")) {
    try {
      const pol = getDb("XINCIDENT").prepare(`SELECT PolicyID FROM ESCALATIONPOLICY ${tw(tenant)} ORDER BY IsDefault DESC, PolicyID ASC LIMIT 1`).get() as { PolicyID: number } | undefined;
      if (pol) {
        const rows = getDb("XINCIDENT").prepare("SELECT Level, Name, TargetRole, AckMinutes, ResolveMinutes FROM ESCALATIONTIER WHERE PolicyID = ? ORDER BY Level").all(pol.PolicyID) as any[];
        if (rows.length) return rows.map((r) => ({ name: String(r.Name), role: String(r.TargetRole ?? ""), level: Number(r.Level), ack: Number(r.AckMinutes ?? 30), resolve: Number(r.ResolveMinutes ?? 480) }));
      }
    } catch { /* */ }
  }
  return DEFAULT_TIERS.map((t) => ({ name: t.name, role: t.role, level: t.level, ack: t.ack, resolve: t.resolve }));
}

function avg(xs: number[]): number | null { return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null; }

// ── dashboard ────────────────────────────────────────────────────────────────────
export function socDashboard(tenant: number | null): any {
  const db = getDb("XINCIDENT");
  if (!has("INCIDENT")) return { metrics: {}, onCall: [], shifts: [], queue: [], escalation: { tiers: [] }, playbooks: [], worklist: [], summary: {} };
  const persons = personMap();
  const tiers = tierConfig(tenant);
  const ackByTier = new Map(tiers.map((t) => [t.name, t.ack]));
  const now = Date.now();

  const ic = cols("INCIDENT");
  const sel = (c: string) => (ic.has(c) ? `"${c}"` : `NULL AS "${c}"`);
  const incs = db.prepare(`SELECT IncidentID, ${sel("IncidentName")}, ${sel("Severity")}, ${sel("status")},
      ${sel("start_datetime")}, ${sel("detect_datetime")}, ${sel("acknowledge_datetime")}, ${sel("end_datetime")},
      ${sel("Duration")}, ${sel("AssignedTo")}, ${sel("AssignedPersonID")}, ${sel("EscalationTier")}, ${sel("PlaybookID")}
      FROM INCIDENT ${tw(tenant)} ORDER BY IncidentID DESC`).all() as Record<string, any>[];

  // metrics (MTTD/MTTA/MTTR)
  const mttd: number[] = [], mtta: number[] = [], mttr: number[] = [];
  for (const i of incs) {
    const st = ms(i.start_datetime), dt = ms(i.detect_datetime), ak = ms(i.acknowledge_datetime), en = ms(i.end_datetime);
    if (st != null && dt != null && dt >= st) mttd.push((dt - st) / 60000);
    if (dt != null && ak != null && ak >= dt) mtta.push((ak - dt) / 60000);
    if (dt != null && en != null && en >= dt) mttr.push((en - dt) / 3600000);
    else if (i.Duration != null && DONE.test(String(i.status ?? ""))) mttr.push(Number(i.Duration));
  }
  const r1 = (x: number | null) => (x == null ? null : Math.round(x * 10) / 10);

  // playbook progress per incident
  const pbProgress = new Map<number, { done: number; total: number }>();
  if (has("INCIDENTPLAYBOOKSTEP")) {
    for (const r of db.prepare("SELECT IncidentID, Status FROM INCIDENTPLAYBOOKSTEP").all() as { IncidentID: number; Status: string }[]) {
      const p = pbProgress.get(Number(r.IncidentID)) || { done: 0, total: 0 };
      p.total++; if (String(r.Status) === "done") p.done++; pbProgress.set(Number(r.IncidentID), p);
    }
  }
  const escCount = new Map<number, number>();
  if (has("INCIDENTESCALATION")) for (const r of db.prepare("SELECT IncidentID FROM INCIDENTESCALATION").all() as { IncidentID: number }[]) escCount.set(Number(r.IncidentID), (escCount.get(Number(r.IncidentID)) || 0) + 1);
  const pbName = new Map<number, string>();
  if (has("PLAYBOOK")) for (const r of db.prepare("SELECT PlaybookID, Name FROM PLAYBOOK").all() as { PlaybookID: number; Name: string }[]) pbName.set(Number(r.PlaybookID), r.Name);

  // open-incident queue
  const queue: any[] = [];
  for (const i of incs) {
    const open = OPEN.test(String(i.status ?? "")) && !DONE.test(String(i.status ?? ""));
    if (!open) continue;
    const dt = ms(i.detect_datetime) ?? ms(i.start_datetime);
    const ageMin = dt != null ? Math.round((now - dt) / 60000) : null;
    const tier = String(i.EscalationTier || "L1");
    const ackSla = ackByTier.get(tier) ?? 30;
    const acknowledged = ms(i.acknowledge_datetime) != null;
    const ackBreached = !acknowledged && ageMin != null && ageMin > ackSla;
    const sev = String(i.Severity || "");
    const pb = pbProgress.get(Number(i.IncidentID));
    const owner = i.AssignedPersonID != null ? (persons.get(Number(i.AssignedPersonID)) || String(i.AssignedTo ?? "")) : String(i.AssignedTo ?? "");
    queue.push({
      id: Number(i.IncidentID), name: String(i.IncidentName ?? `Incident #${i.IncidentID}`), severity: sev, status: String(i.status ?? ""),
      tier, owner, detectedAt: i.detect_datetime ? String(i.detect_datetime).slice(0, 16).replace("T", " ") : null,
      ageMinutes: ageMin, acknowledged, ackBreached, ackSlaMin: ackSla,
      playbookId: i.PlaybookID != null ? Number(i.PlaybookID) : null, playbookName: i.PlaybookID != null ? (pbName.get(Number(i.PlaybookID)) || null) : null,
      playbookDone: pb?.done ?? 0, playbookTotal: pb?.total ?? 0, escalations: escCount.get(Number(i.IncidentID)) || 0,
    });
  }
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  queue.sort((a, b) => (sevRank[a.severity] ?? 4) - (sevRank[b.severity] ?? 4) || (b.ageMinutes ?? 0) - (a.ageMinutes ?? 0));

  // worklist: what needs SOC action now
  const worklist: any[] = [];
  for (const q of queue) {
    if (q.ackBreached) worklist.push({ id: q.id, name: q.name, severity: "High", reason: `Unacknowledged ${q.ageMinutes}m — past ${q.tier} ack SLA (${q.ackSlaMin}m), escalate` });
    else if (!q.acknowledged && (q.severity === "Critical" || q.severity === "High")) worklist.push({ id: q.id, name: q.name, severity: q.severity, reason: `${q.severity} incident not yet acknowledged` });
    if ((q.severity === "Critical" || q.severity === "High") && !q.playbookId) worklist.push({ id: q.id, name: q.name, severity: "Medium", reason: "No IR playbook attached" });
  }
  const sr: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  worklist.sort((a, b) => (sr[a.severity] ?? 4) - (sr[b.severity] ?? 4));

  // on-call / shifts
  let onCall: any[] = [], shifts: any[] = [], coverageNow: string[] = [];
  if (has("SOCSHIFT")) {
    const all = db.prepare(`SELECT * FROM SOCSHIFT ${tw(tenant)} ORDER BY StartTime`).all() as Record<string, any>[];
    for (const sh of all) {
      const st = ms(sh.StartTime), en = ms(sh.EndTime);
      const active = st != null && en != null && now >= st && now <= en;
      const row = { id: Number(sh.ShiftID), person: String(sh.PersonName || persons.get(Number(sh.PersonID)) || `#${sh.PersonID}`), tier: String(sh.Tier || ""), onCall: !!sh.OnCall,
        start: sh.StartTime ? String(sh.StartTime).slice(0, 16).replace("T", " ") : "", end: sh.EndTime ? String(sh.EndTime).slice(0, 16).replace("T", " ") : "", active };
      shifts.push(row);
      if (active) { onCall.push(row); if (row.tier && !coverageNow.includes(row.tier)) coverageNow.push(row.tier); }
    }
    shifts = shifts.filter((r) => { const en = ms(r.end.replace(" ", "T")); return en == null || en >= now - 6 * 3600000; }).slice(0, 40);
  }
  const coverageGaps = tiers.filter((t) => t.level <= 3 && !coverageNow.includes(t.name)).map((t) => t.name);

  // playbook catalogue summary
  let playbooks: any[] = [];
  if (has("PLAYBOOK")) {
    playbooks = (db.prepare(`SELECT PlaybookID, Name, Category, Severity, StepCount FROM PLAYBOOK ${tw(tenant)} ORDER BY Category`).all() as any[])
      .map((p) => ({ id: Number(p.PlaybookID), name: String(p.Name), category: String(p.Category ?? ""), severity: String(p.Severity ?? ""), steps: Number(p.StepCount ?? 0) }));
  }

  const openCount = queue.length;
  const escalationsToday = has("INCIDENTESCALATION") ? Number((db.prepare(`SELECT COUNT(*) n FROM INCIDENTESCALATION WHERE substr(EscalatedAt,1,10)=? ${tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : ""}`).get(...(tenant != null ? [new Date().toISOString().slice(0, 10), tenant] : [new Date().toISOString().slice(0, 10)])) as { n: number }).n) : 0;
  const adherence = (() => { let d = 0, t = 0; for (const p of pbProgress.values()) { d += p.done; t += p.total; } return t ? Math.round((d / t) * 100) : null; })();

  return {
    metrics: {
      mttdMinutes: r1(avg(mttd)), mttaMinutes: r1(avg(mtta)), mttrHours: r1(avg(mttr)),
      detectedCount: mttd.length, ackCount: mtta.length, resolvedCount: mttr.length,
    },
    onCall, shifts, coverageNow, coverageGaps,
    queue, worklist: worklist.slice(0, 40),
    escalation: { tiers },
    playbooks,
    summary: {
      openIncidents: openCount, unacknowledged: queue.filter((q) => !q.acknowledged).length, ackBreached: queue.filter((q) => q.ackBreached).length,
      criticalOpen: queue.filter((q) => q.severity === "Critical").length, onCallNow: onCall.length, coverageGaps: coverageGaps.length,
      escalationsToday, playbookAdherence: adherence, withPlaybook: queue.filter((q) => q.playbookId).length,
    },
  };
}

// ── mutations ────────────────────────────────────────────────────────────────────
function nextId(table: string, pk: string): number { return (getDb("XINCIDENT").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n; }

export function createShift(p: { personId?: number; personName?: string; tier?: string; start: string; end: string; onCall?: boolean }, tenant: number | null): { id: number } {
  const db = getDb("XINCIDENT"); const id = nextId("SOCSHIFT", "ShiftID"); const now = new Date().toISOString();
  let name = p.personName || "";
  if (!name && p.personId != null) name = personMap().get(Number(p.personId)) || `#${p.personId}`;
  db.prepare("INSERT INTO SOCSHIFT (ShiftID, ShiftGUID, PersonID, PersonName, Tier, ShiftDate, StartTime, EndTime, OnCall, Status, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), p.personId ?? null, name, p.tier ?? "L1", String(p.start).slice(0, 10), p.start, p.end, p.onCall ? 1 : 0, "Scheduled", tenant, now);
  return { id };
}

function incidentTenant(incidentId: number): boolean { return !!getDb("XINCIDENT").prepare("SELECT 1 FROM INCIDENT WHERE IncidentID = ?").get(incidentId); }

export function acknowledgeIncident(incidentId: number, by: string, personId: number | null): boolean {
  if (!incidentTenant(incidentId)) return false;
  const db = getDb("XINCIDENT"); const ic = cols("INCIDENT"); const now = new Date().toISOString();
  const sets: string[] = []; const vals: unknown[] = [];
  if (ic.has("acknowledge_datetime")) { sets.push('"acknowledge_datetime" = ?'); vals.push(now); }
  if (ic.has("AssignedPersonID") && personId != null) { sets.push('"AssignedPersonID" = ?'); vals.push(personId); }
  if (ic.has("AssignedTo") && by) { sets.push('"AssignedTo" = ?'); vals.push(by); }
  if (ic.has("status")) { sets.push('"status" = ?'); vals.push("InProgress"); }
  if (!sets.length) return true;
  vals.push(incidentId);
  db.prepare(`UPDATE INCIDENT SET ${sets.join(", ")} WHERE IncidentID = ?`).run(...vals);
  return true;
}

export function escalateIncident(incidentId: number, p: { toTier?: string; reason?: string; byPerson?: string; toPerson?: string }, tenant: number | null): { tier: string } | null {
  if (!incidentTenant(incidentId)) return null;
  const db = getDb("XINCIDENT"); const ic = cols("INCIDENT");
  const cur = String((db.prepare(`SELECT ${ic.has("EscalationTier") ? "EscalationTier" : "NULL AS EscalationTier"} FROM INCIDENT WHERE IncidentID = ?`).get(incidentId) as any)?.EscalationTier || "L1");
  const idx = TIER_ORDER.indexOf(cur);
  const to = p.toTier && TIER_ORDER.includes(p.toTier) ? p.toTier : TIER_ORDER[Math.min(idx + 1, TIER_ORDER.length - 1)];
  db.prepare("INSERT INTO INCIDENTESCALATION (EscalationID, IncidentID, FromTier, ToTier, Reason, ByPerson, ToPerson, EscalatedAt, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(nextId("INCIDENTESCALATION", "EscalationID"), incidentId, cur, to, (p.reason || "").slice(0, 500), p.byPerson ?? null, p.toPerson ?? null, new Date().toISOString(), tenant);
  if (ic.has("EscalationTier")) db.prepare("UPDATE INCIDENT SET EscalationTier = ? WHERE IncidentID = ?").run(to, incidentId);
  return { tier: to };
}

export function attachPlaybook(incidentId: number, playbookId: number, tenant: number | null): { steps: number } | null {
  if (!incidentTenant(incidentId)) return null;
  const db = getDb("XINCIDENT");
  const steps = db.prepare("SELECT Phase, StepOrder, Title, Description FROM PLAYBOOKSTEP WHERE PlaybookID = ? ORDER BY StepOrder").all(playbookId) as any[];
  if (!steps.length) return null;
  db.prepare("DELETE FROM INCIDENTPLAYBOOKSTEP WHERE IncidentID = ?").run(incidentId);
  let id = nextId("INCIDENTPLAYBOOKSTEP", "RunStepID");
  const ins = db.prepare("INSERT INTO INCIDENTPLAYBOOKSTEP (RunStepID, IncidentID, PlaybookID, Phase, StepOrder, Title, Description, Status, TenantID) VALUES (?,?,?,?,?,?,?,?,?)");
  for (const st of steps) ins.run(id++, incidentId, playbookId, st.Phase, st.StepOrder, st.Title, st.Description, "todo", tenant);
  if (cols("INCIDENT").has("PlaybookID")) db.prepare("UPDATE INCIDENT SET PlaybookID = ? WHERE IncidentID = ?").run(playbookId, incidentId);
  return { steps: steps.length };
}

export function completePlaybookStep(runStepId: number, status: string, by: string): boolean {
  const db = getDb("XINCIDENT");
  const ok = db.prepare("SELECT 1 FROM INCIDENTPLAYBOOKSTEP WHERE RunStepID = ?").get(runStepId);
  if (!ok) return false;
  const st = ["todo", "in_progress", "done", "na"].includes(status) ? status : "done";
  db.prepare("UPDATE INCIDENTPLAYBOOKSTEP SET Status = ?, CompletedBy = ?, CompletedAt = ? WHERE RunStepID = ?")
    .run(st, st === "done" ? by : null, st === "done" ? new Date().toISOString() : null, runStepId);
  return true;
}

export function incidentPlaybook(incidentId: number): { phases: any[]; progress: { done: number; total: number; pct: number } } {
  const db = getDb("XINCIDENT");
  if (!has("INCIDENTPLAYBOOKSTEP")) return { phases: [], progress: { done: 0, total: 0, pct: 0 } };
  const rows = db.prepare("SELECT RunStepID, Phase, StepOrder, Title, Description, Status FROM INCIDENTPLAYBOOKSTEP WHERE IncidentID = ? ORDER BY StepOrder").all(incidentId) as any[];
  const byPhase = new Map<string, any>();
  let done = 0;
  for (const r of rows) {
    if (String(r.Status) === "done") done++;
    let ph = byPhase.get(String(r.Phase)); if (!ph) { ph = { name: String(r.Phase), steps: [] }; byPhase.set(String(r.Phase), ph); }
    ph.steps.push({ id: Number(r.RunStepID), title: String(r.Title), description: String(r.Description ?? ""), status: String(r.Status ?? "todo") });
  }
  const order = (n: string) => { const i = (PHASES as readonly string[]).indexOf(n); return i < 0 ? 99 : i; };
  const phases = [...byPhase.values()].sort((a, b) => order(a.name) - order(b.name));
  return { phases, progress: { done, total: rows.length, pct: rows.length ? Math.round((done / rows.length) * 100) : 0 } };
}

// ── seed ──────────────────────────────────────────────────────────────────────
/** Seed default escalation policy + IR playbooks + SOC shifts, and backfill demo incidents. */
export function seedSocDefaults(tenant: number): { policy: number; playbooks: number; shifts: number; backfilled: number } {
  const db = getDb("XINCIDENT"); const now = new Date().toISOString();
  let policyN = 0, pbN = 0, shiftN = 0, backfilled = 0;

  // escalation policy (idempotent by name+tenant)
  let policyId = (db.prepare("SELECT PolicyID FROM ESCALATIONPOLICY WHERE Name = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get("Default SOC escalation", tenant) as { PolicyID: number } | undefined)?.PolicyID;
  if (!policyId) {
    policyId = nextId("ESCALATIONPOLICY", "PolicyID");
    db.prepare("INSERT INTO ESCALATIONPOLICY (PolicyID, PolicyGUID, Name, Description, IsDefault, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?)")
      .run(policyId, randomUUID(), "Default SOC escalation", "L1 → L2 → L3 → SOC Manager with ack/resolve timeouts.", 1, tenant, now);
    let tid = nextId("ESCALATIONTIER", "TierID");
    const ins = db.prepare("INSERT INTO ESCALATIONTIER (TierID, PolicyID, Level, Name, TargetRole, AckMinutes, ResolveMinutes, TenantID) VALUES (?,?,?,?,?,?,?,?)");
    for (const t of DEFAULT_TIERS) ins.run(tid++, policyId, t.level, t.name, t.role, t.ack, t.resolve, tenant);
    policyN = 1;
  }

  // playbooks (idempotent by name+tenant)
  for (const pb of PLAYBOOKS) {
    let pid = (db.prepare("SELECT PlaybookID FROM PLAYBOOK WHERE Name = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(pb.name, tenant) as { PlaybookID: number } | undefined)?.PlaybookID;
    if (pid) continue;
    pid = nextId("PLAYBOOK", "PlaybookID");
    db.prepare("INSERT INTO PLAYBOOK (PlaybookID, PlaybookGUID, Name, Category, Description, Severity, StepCount, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(pid, randomUUID(), pb.name, pb.category, `NIST SP 800-61 response playbook for ${pb.category.toLowerCase()} incidents.`, pb.severity, pb.steps.length, tenant, now);
    let sid = nextId("PLAYBOOKSTEP", "StepID");
    const ins = db.prepare("INSERT INTO PLAYBOOKSTEP (StepID, PlaybookID, Phase, StepOrder, Title, Description, Role, TenantID) VALUES (?,?,?,?,?,?,?,?)");
    pb.steps.forEach((st, i) => ins.run(sid++, pid, st.phase, i + 1, st.title, st.desc, st.role ?? null, tenant));
    pbN++;
  }

  // shifts for the security team (idempotent: skip if shifts already exist for the tenant today)
  const today = new Date();
  const existingToday = Number((db.prepare("SELECT COUNT(*) n FROM SOCSHIFT WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) AND ShiftDate=?").get(tenant, today.toISOString().slice(0, 10)) as { n: number }).n);
  if (!existingToday) {
    const team = (getDb("XORCISM").prepare("SELECT PersonID, FullName, IFNULL(JobTitle,'') jt FROM PERSON WHERE IFNULL(Department,'')='Security' ORDER BY PersonID").all() as { PersonID: number; FullName: string; jt: string }[]);
    // map by role → tier
    const tierOf = (jt: string): string => /manager/i.test(jt) ? "Manager" : /detection|responder|lead/i.test(jt) ? "L3" : /grc|compliance/i.test(jt) ? "L2" : "L1";
    const dayStart = new Date(today); dayStart.setHours(8, 0, 0, 0);
    const dayEnd = new Date(today); dayEnd.setHours(20, 0, 0, 0);
    const nightStart = new Date(dayEnd); const nightEnd = new Date(today); nightEnd.setDate(nightEnd.getDate() + 1); nightEnd.setHours(8, 0, 0, 0);
    team.forEach((p, idx) => {
      const tier = tierOf(p.jt);
      // most on the current day shift; one on-call for the night
      const day = idx % 3 !== 2;
      const start = day ? dayStart : nightStart, end = day ? dayEnd : nightEnd;
      createShift({ personId: p.PersonID, personName: p.FullName, tier, start: start.toISOString(), end: end.toISOString(), onCall: tier === "L3" || tier === "Manager" || !day }, tenant);
      shiftN++;
    });
  }

  // backfill open demo incidents: set EscalationTier + acknowledge_datetime (1h after detect) for some
  const ic = cols("INCIDENT");
  if (ic.has("EscalationTier")) {
    const incs = db.prepare(`SELECT IncidentID, Severity, status, detect_datetime, acknowledge_datetime, EscalationTier FROM INCIDENT ${tw(tenant)} ORDER BY IncidentID`).all() as Record<string, any>[];
    for (const i of incs) {
      const sets: string[] = []; const vals: unknown[] = [];
      if (!i.EscalationTier) { const sev = String(i.Severity || ""); sets.push("EscalationTier = ?"); vals.push(sev === "Critical" ? "L3" : sev === "High" ? "L2" : "L1"); }
      // acknowledge resolved/in-progress incidents 30-90 min after detection (leave New/Active unacked → drives the queue)
      if (ic.has("acknowledge_datetime") && !i.acknowledge_datetime && /resolv|closed|inprogress|in progress/i.test(String(i.status ?? "")) && i.detect_datetime) {
        const ack = new Date((ms(i.detect_datetime) ?? Date.now()) + (30 + (Number(i.IncidentID) * 13) % 60) * 60000).toISOString();
        sets.push("acknowledge_datetime = ?"); vals.push(ack);
      }
      if (sets.length) { vals.push(i.IncidentID); db.prepare(`UPDATE INCIDENT SET ${sets.join(", ")} WHERE IncidentID = ?`).run(...vals); backfilled++; }
    }
  }
  return { policy: policyN, playbooks: pbN, shifts: shiftN, backfilled };
}
