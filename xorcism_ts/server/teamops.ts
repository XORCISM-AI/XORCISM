/**
 * teamops.ts — Purple / Red / Blue Team Operations (VECTR-style, MITRE ATT&CK aligned).
 *
 * A purple-team exercise (TEAMEXERCISE) is a campaign of test cases (EXERCISETESTCASE), one per
 * ATT&CK technique: the RED offensive action vs the BLUE outcome (prevented / detected / logged /
 * missed) with a detection time and source. From the outcomes we measure efficiency — prevention
 * rate, detection rate, visibility, MTTD — and per-tactic ATT&CK coverage, and we surface the
 * "missed" techniques as a detection-engineering worklist. TEAMCAPABILITY tracks red/blue/purple
 * capability maturity & capacity. Reuses the n8n-CyberSecurity-Workflows ideas as automation
 * playbook templates (offensive + defensive).
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export const TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"];
export const OUTCOMES = ["prevented", "detected", "logged", "missed"];

// Automation playbook templates (reused from JoasASantos/n8n-CyberSecurity-Workflows; runnable via the n8n connector).
export const AUTOMATIONS = [
  { team: "Blue", name: "IOC enrichment microservice", desc: "Score IPs/URLs/hashes across VirusTotal, AbuseIPDB, urlscan, OTX in parallel.", tools: "VirusTotal, AbuseIPDB, urlscan, OTX" },
  { team: "Blue", name: "Phishing auto-triage with URL detonation", desc: "Parse reported email, detonate URLs, verdict + notify, open a case.", tools: "urlscan, VirusTotal, Slack/Jira" },
  { team: "Blue", name: "Alert triage & routing pipeline", desc: "Dedupe, enrich and route SIEM alerts to the right tier with context.", tools: "SIEM, Slack, ServiceNow" },
  { team: "Blue", name: "Impossible-travel / anomalous login", desc: "Detect impossible-travel sign-ins and trigger session revocation.", tools: "IdP logs, GeoIP" },
  { team: "Blue", name: "Ransomware canary & beaconing monitor", desc: "Watch canary files and beacon patterns; isolate on hit.", tools: "EDR, canaries" },
  { team: "Red", name: "Subdomain enum & asset-change detection", desc: "Continuously enumerate subdomains and diff for new exposed assets.", tools: "amass, subfinder, httpx" },
  { team: "Red", name: "Cloud bucket misconfiguration discovery", desc: "Hunt public/world-readable buckets across providers.", tools: "AWS/GCP/Azure APIs" },
  { team: "Red", name: "Phishing campaign orchestration", desc: "Spin up and track a phishing campaign + payload callbacks.", tools: "gophish, mailer" },
  { team: "Purple", name: "Vulnerability prioritization (EPSS×exposure)", desc: "Score findings by EPSS/KEV and asset exposure, feed the worklist.", tools: "EPSS, KEV, asset graph" },
  { team: "Purple", name: "Threat-intel normalization", desc: "Aggregate multiple feeds into a standardized CTI format.", tools: "MISP, OTX, feeds" },
  { team: "AppSec", name: "Secrets detection & rotation", desc: "Monitor repos for leaked secrets and trigger rotation.", tools: "trufflehog, vault" },
  { team: "AppSec", name: "IaC misconfiguration scan", desc: "Scan Terraform/K8s for misconfig on every change.", tools: "trivy, checkov, semgrep" },
];

function db() { return getDb("XTHREAT"); }
function nextId(table: string, pk: string): number { return (db().prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n; }
function tw(tenant: number | null): string { return tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : ""; }
const pct = (a: number, b: number): number => (b ? Math.round((a / b) * 100) : 0);

export function teamOpsDashboard(tenant: number | null): any {
  const args = tenant != null ? [tenant] : [];
  const exercises = db().prepare(`SELECT * FROM TEAMEXERCISE ${tw(tenant)} ORDER BY ExerciseID DESC`).all(...args) as any[];
  const cases = db().prepare("SELECT * FROM EXERCISETESTCASE").all() as any[];
  const byEx = new Map<number, any[]>();
  for (const c of cases) { const a = byEx.get(Number(c.ExerciseID)) || []; a.push(c); byEx.set(Number(c.ExerciseID), a); }

  const exRows = exercises.map((e) => {
    const cs = byEx.get(Number(e.ExerciseID)) || [];
    const total = cs.length;
    const prevented = cs.filter((c) => c.Prevented).length;
    const detected = cs.filter((c) => c.Detected).length;
    const logged = cs.filter((c) => c.Logged && !c.Detected && !c.Prevented).length;
    const missed = cs.filter((c) => !c.Prevented && !c.Detected && !c.Logged).length;
    return { id: Number(e.ExerciseID), name: String(e.Name ?? ""), type: String(e.ExerciseType ?? "Purple"), actor: String(e.ThreatActor ?? ""),
      status: String(e.Status ?? "Planned"), start: e.StartDate ? String(e.StartDate).slice(0, 10) : "", total,
      preventionRate: pct(prevented, total), detectionRate: pct(prevented + detected, total), visibility: pct(prevented + detected + logged, total), missed };
  });

  // overall efficiency across all in-scope test cases
  const inScope = cases.filter((c) => exercises.some((e) => Number(e.ExerciseID) === Number(c.ExerciseID)));
  const total = inScope.length;
  const prevented = inScope.filter((c) => c.Prevented).length;
  const detected = inScope.filter((c) => c.Detected).length;
  const logged = inScope.filter((c) => c.Logged && !c.Detected && !c.Prevented).length;
  const missed = inScope.filter((c) => !c.Prevented && !c.Detected && !c.Logged).length;
  const detTimes = inScope.filter((c) => c.Detected && c.DetectionTimeMin != null).map((c) => Number(c.DetectionTimeMin));
  const mttd = detTimes.length ? Math.round(detTimes.reduce((a, b) => a + b, 0) / detTimes.length) : null;

  // per-tactic coverage
  const byTactic = TACTICS.map((tac) => {
    const cs = inScope.filter((c) => String(c.Tactic) === tac);
    return { tactic: tac, tested: cs.length, detected: cs.filter((c) => c.Prevented || c.Detected).length, rate: pct(cs.filter((c) => c.Prevented || c.Detected).length, cs.length) };
  }).filter((t) => t.tested > 0);

  // detection-engineering worklist (missed / logged-only)
  const worklist = inScope.filter((c) => (!c.Prevented && !c.Detected)).map((c) => ({
    id: Number(c.TestCaseID), attackId: String(c.AttackID ?? ""), technique: String(c.Technique ?? ""), tactic: String(c.Tactic ?? ""),
    outcome: c.Logged ? "logged-only" : "missed", offensive: String(c.OffensiveAction ?? ""), severity: c.Logged ? "Medium" : "High",
  })).sort((a, b) => (a.severity === "High" ? -1 : 1) - (b.severity === "High" ? -1 : 1)).slice(0, 40);

  const caps = (db().prepare(`SELECT * FROM TEAMCAPABILITY ${tw(tenant)} ORDER BY Team, CapabilityID`).all(...args) as any[]).map((c) => ({
    id: Number(c.CapabilityID), team: String(c.Team ?? ""), name: String(c.Name ?? ""), category: String(c.Category ?? ""),
    maturity: c.Maturity != null ? Number(c.Maturity) : null, capacity: String(c.Capacity ?? ""), tooling: String(c.Tooling ?? "") }));
  const capByTeam = ["Red", "Blue", "Purple"].map((tm) => { const list = caps.filter((c) => c.team === tm); const scored = list.filter((c) => c.maturity != null); return { team: tm, count: list.length, maturity: scored.length ? Math.round((scored.reduce((s, c) => s + (c.maturity || 0), 0) / scored.length) * 10) / 10 : null }; });

  return {
    exercises: exRows, byTactic, worklist, capabilities: caps, capByTeam, automations: AUTOMATIONS, tactics: TACTICS,
    summary: {
      exercises: exRows.length, testCases: total, preventionRate: pct(prevented, total), detectionRate: pct(prevented + detected, total),
      visibility: pct(prevented + detected + logged, total), missed, mttdMinutes: mttd,
      tacticsCovered: byTactic.length, capabilities: caps.length, redMaturity: capByTeam[0].maturity, blueMaturity: capByTeam[1].maturity, purpleMaturity: capByTeam[2].maturity,
    },
  };
}

export function exerciseDetail(id: number, tenant: number | null): any | null {
  const e = db().prepare(`SELECT * FROM TEAMEXERCISE WHERE ExerciseID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`).get(...(tenant != null ? [id, tenant] : [id])) as any;
  if (!e) return null;
  const cases = (db().prepare("SELECT * FROM EXERCISETESTCASE WHERE ExerciseID = ? ORDER BY TestCaseID").all(id) as any[]).map((c) => ({
    id: Number(c.TestCaseID), attackId: String(c.AttackID ?? ""), technique: String(c.Technique ?? ""), tactic: String(c.Tactic ?? ""),
    offensive: String(c.OffensiveAction ?? ""), tool: String(c.OffensiveTool ?? ""), expectedDefense: String(c.ExpectedDefense ?? ""),
    outcome: c.Prevented ? "prevented" : c.Detected ? "detected" : c.Logged ? "logged" : "missed",
    prevented: !!c.Prevented, detected: !!c.Detected, logged: !!c.Logged, detectionTimeMin: c.DetectionTimeMin != null ? Number(c.DetectionTimeMin) : null,
    detectionSource: String(c.DetectionSource ?? ""), responseAction: String(c.ResponseAction ?? ""), notes: String(c.Notes ?? ""),
  }));
  return { exercise: { id: Number(e.ExerciseID), name: String(e.Name ?? ""), type: String(e.ExerciseType ?? ""), objective: String(e.Objective ?? ""), actor: String(e.ThreatActor ?? ""), status: String(e.Status ?? ""), start: e.StartDate ? String(e.StartDate).slice(0, 10) : "" }, cases };
}

export function createExercise(p: { name: string; type?: string; objective?: string; actor?: string; startDate?: string }, tenant: number | null): { id: number } {
  const id = nextId("TEAMEXERCISE", "ExerciseID"); const now = new Date().toISOString();
  db().prepare("INSERT INTO TEAMEXERCISE (ExerciseID, ExerciseGUID, Name, ExerciseType, Objective, ThreatActor, Status, StartDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), p.name.slice(0, 300), p.type ?? "Purple", (p.objective || "").slice(0, 2000), p.actor ?? null, "Planned", p.startDate || now.slice(0, 10), tenant, now);
  return { id };
}

export function addTestCase(exerciseId: number, p: { attackId?: string; technique: string; tactic?: string; offensiveAction?: string; offensiveTool?: string; expectedDefense?: string }, tenant: number | null): { id: number } | null {
  if (!db().prepare("SELECT 1 FROM TEAMEXERCISE WHERE ExerciseID = ?").get(exerciseId)) return null;
  const id = nextId("EXERCISETESTCASE", "TestCaseID");
  db().prepare("INSERT INTO EXERCISETESTCASE (TestCaseID, ExerciseID, AttackID, Technique, Tactic, OffensiveAction, OffensiveTool, ExpectedDefense, Outcome, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, exerciseId, (p.attackId || "").toUpperCase().slice(0, 12) || null, p.technique.slice(0, 200), p.tactic ?? null, (p.offensiveAction || "").slice(0, 1000), p.offensiveTool ?? null, (p.expectedDefense || "").slice(0, 1000), "missed", tenant, new Date().toISOString());
  return { id };
}

export function setOutcome(testCaseId: number, p: { outcome?: string; detectionTimeMin?: number; detectionSource?: string; responseAction?: string; notes?: string }): boolean {
  const c = db().prepare("SELECT TestCaseID FROM EXERCISETESTCASE WHERE TestCaseID = ?").get(testCaseId);
  if (!c) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (p.outcome && OUTCOMES.includes(p.outcome)) {
    sets.push("Outcome = ?", "Prevented = ?", "Detected = ?", "Logged = ?");
    vals.push(p.outcome, p.outcome === "prevented" ? 1 : 0, p.outcome === "detected" ? 1 : 0, (p.outcome === "logged" || p.outcome === "detected" || p.outcome === "prevented") ? 1 : 0);
  }
  if (p.detectionTimeMin != null) { sets.push("DetectionTimeMin = ?"); vals.push(Math.max(0, Math.round(p.detectionTimeMin))); }
  if (p.detectionSource != null) { sets.push("DetectionSource = ?"); vals.push(String(p.detectionSource).slice(0, 200)); }
  if (p.responseAction != null) { sets.push("ResponseAction = ?"); vals.push(String(p.responseAction).slice(0, 1000)); }
  if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 1000)); }
  if (!sets.length) return true;
  vals.push(testCaseId);
  db().prepare(`UPDATE EXERCISETESTCASE SET ${sets.join(", ")} WHERE TestCaseID = ?`).run(...vals);
  return true;
}

export function createCapability(p: { team: string; name: string; category?: string; maturity?: number; capacity?: string; tooling?: string }, tenant: number | null): { id: number } {
  const id = nextId("TEAMCAPABILITY", "CapabilityID");
  db().prepare("INSERT INTO TEAMCAPABILITY (CapabilityID, Team, Name, Category, Maturity, Capacity, Tooling, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(id, p.team ?? "Purple", p.name.slice(0, 200), p.category ?? null, p.maturity != null ? Math.max(0, Math.min(5, Math.round(p.maturity))) : null, p.capacity ?? null, p.tooling ?? null, tenant, new Date().toISOString());
  return { id };
}

// ── seed ──────────────────────────────────────────────────────────────────────
const SEED_CASES: [string, string, string, string, string, string][] = [
  // attackId, technique, tactic, offensive action, tool, outcome
  ["T1566", "Phishing", "Initial Access", "Send spear-phishing with a malicious link to finance", "gophish", "detected"],
  ["T1059.001", "PowerShell", "Execution", "Run an encoded PowerShell downloader", "Atomic Red Team", "detected"],
  ["T1055", "Process Injection", "Defense Evasion", "Inject shellcode into a benign process", "Cobalt Strike", "missed"],
  ["T1003.001", "LSASS Memory", "Credential Access", "Dump LSASS to harvest credentials", "Mimikatz", "prevented"],
  ["T1021.001", "Remote Desktop Protocol", "Lateral Movement", "Move laterally via RDP with stolen creds", "xfreerdp", "logged"],
  ["T1486", "Data Encrypted for Impact", "Impact", "Encrypt files on a test host", "custom", "detected"],
  ["T1071.001", "Web Protocols", "Command and Control", "Beacon over HTTPS to C2", "Cobalt Strike", "missed"],
  ["T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "Exfiltrate data over DNS", "dnscat2", "logged"],
  ["T1078", "Valid Accounts", "Persistence", "Use a valid service account for persistence", "manual", "detected"],
  ["T1547.001", "Registry Run Keys", "Persistence", "Add a Run key for persistence", "Atomic Red Team", "prevented"],
];

export function seedTeamOps(tenant: number): { exercises: number; cases: number; capabilities: number } {
  if ((db().prepare("SELECT COUNT(*) n FROM TEAMEXERCISE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { exercises: 0, cases: 0, capabilities: 0 };
  const ex = createExercise({ name: "Q2 Purple-Team Exercise — Ransomware kill chain", type: "Purple", actor: "Big-game ransomware affiliate (LockBit-style)", objective: "Measure prevention/detection coverage across the ransomware kill chain and close detection gaps." }, tenant);
  db().prepare("UPDATE TEAMEXERCISE SET Status='Completed' WHERE ExerciseID=?").run(ex.id);
  let nc = 0;
  for (const [aid, tech, tac, act, tool, outcome] of SEED_CASES) {
    const tc = addTestCase(ex.id, { attackId: aid, technique: tech, tactic: tac, offensiveAction: act, offensiveTool: tool, expectedDefense: "EDR/SIEM detection or prevention" }, tenant);
    if (tc) {
      setOutcome(tc.id, { outcome, detectionTimeMin: outcome === "detected" ? 5 + (tc.id * 7) % 50 : undefined, detectionSource: outcome === "missed" ? "" : "EDR/SIEM", responseAction: outcome === "prevented" ? "Blocked by control" : outcome === "detected" ? "Alert triaged + isolated" : "" });
      nc++;
    }
  }
  const caps: [string, string, string, number, string, string][] = [
    ["Red", "Adversary emulation", "Offensive", 3, "1 FTE", "Atomic Red Team, Caldera, Cobalt Strike"],
    ["Red", "External pentest", "Offensive", 4, "2 FTE", "nmap, nuclei, Burp/burpwn"],
    ["Red", "Phishing simulation", "Offensive", 3, "shared", "gophish, KnowBe4"],
    ["Blue", "Detection engineering", "Defensive", 3, "1 FTE", "Sigma, SIEM, EDR"],
    ["Blue", "Incident response", "Defensive", 4, "3 FTE", "SOAR, EDR, playbooks"],
    ["Blue", "Threat hunting", "Defensive", 2, "0.5 FTE", "EDR, KQL, hypotheses"],
    ["Purple", "Exercise facilitation", "Coordination", 3, "shared", "VECTR-style tracking"],
    ["Purple", "ATT&CK coverage management", "Coordination", 3, "shared", "ATT&CK Navigator, Sigma"],
  ];
  let ncap = 0;
  for (const [team, name, cat, mat, cap, tool] of caps) { createCapability({ team, name, category: cat, maturity: mat, capacity: cap, tooling: tool }, tenant); ncap++; }
  return { exercises: 1, cases: nc, capabilities: ncap };
}
