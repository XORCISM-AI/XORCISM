/**
 * workforce.ts — cybersecurity workforce framework around PERSON.
 *
 * A catalogue of work roles from NIST NICE (SP 800-181) and the European ENISA ECSF (12 role
 * profiles), assignable to people (PERSONWORKROLE). Surfaces who covers which role, role-coverage
 * gaps, and per-person role profiles — so staffing maps to a recognized competency framework.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

type Role = { framework: "NICE" | "ECSF"; code: string; name: string; category: string; desc: string; skills: string };
const r = (framework: "NICE" | "ECSF", code: string, name: string, category: string, desc: string, skills: string): Role => ({ framework, code, name, category, desc, skills });

export const WORKROLES: Role[] = [
  // ── ENISA ECSF (European Cybersecurity Skills Framework) — 12 role profiles ──
  r("ECSF", "ECSF-CISO", "Chief Information Security Officer (CISO)", "Govern", "Manages an organisation's cybersecurity strategy and its implementation.", "Strategy, governance, risk, leadership, compliance"),
  r("ECSF", "ECSF-RISK", "Cybersecurity Risk Manager", "Govern", "Continuously manages cybersecurity risk and treatment to acceptable levels.", "Risk assessment, treatment, FAIR, controls, reporting"),
  r("ECSF", "ECSF-ARCH", "Cybersecurity Architect", "Design", "Plans and designs security architecture for systems and infrastructures.", "Security architecture, zero-trust, design, standards"),
  r("ECSF", "ECSF-IMPL", "Cybersecurity Implementer", "Implement", "Develops, deploys and operates cybersecurity solutions.", "Hardening, deployment, secure engineering, tooling"),
  r("ECSF", "ECSF-IR", "Cyber Incident Responder", "Operate", "Monitors and handles incidents to restore secure operations.", "Incident handling, triage, containment, SOC, DFIR"),
  r("ECSF", "ECSF-DFIR", "Digital Forensics Investigator", "Operate", "Collects, analyses and reports digital evidence from cyber incidents.", "Forensics, chain of custody, evidence, malware analysis"),
  r("ECSF", "ECSF-PENTEST", "Penetration Tester", "Assess", "Assesses security by simulating attacks and exploiting weaknesses.", "Pentesting, exploitation, red team, reporting"),
  r("ECSF", "ECSF-CTI", "Cyber Threat Intelligence Specialist", "Operate", "Collects, analyses and reports on cyber threats and adversaries.", "CTI, STIX/TAXII, ATT&CK, analysis, hunting"),
  r("ECSF", "ECSF-AUDIT", "Cybersecurity Auditor", "Assess", "Performs independent reviews to assess control effectiveness and compliance.", "Auditing, ISO 27001, evidence, controls testing"),
  r("ECSF", "ECSF-LEGAL", "Cyber Legal, Policy & Compliance Officer", "Govern", "Manages compliance with legal, regulatory and policy requirements.", "GDPR, NIS2, DORA, policy, compliance"),
  r("ECSF", "ECSF-EDU", "Cybersecurity Educator", "Govern", "Improves cybersecurity knowledge and awareness across the organisation.", "Awareness, training, phishing simulation, education"),
  r("ECSF", "ECSF-RES", "Cybersecurity Researcher", "Design", "Researches the cybersecurity domain and produces new solutions.", "Research, analysis, emerging threats, innovation"),
  // ── NIST NICE (SP 800-181) — representative work roles ──
  r("NICE", "OG-WRL-007", "Security Control Assessor", "Oversight & Governance", "Conducts independent assessments of security/privacy controls.", "Controls assessment, RMF, NIST 800-53A"),
  r("NICE", "OG-WRL-009", "Cybersecurity Policy & Planning", "Oversight & Governance", "Develops cybersecurity policy, plans and strategy.", "Policy, planning, governance, strategy"),
  r("NICE", "DD-WRL-005", "Secure Software Developer", "Design & Development", "Develops, creates and writes secure software.", "Secure coding, SDLC, SAST, code review"),
  r("NICE", "DD-WRL-008", "Systems Security Architect", "Design & Development", "Designs the security architecture for systems and networks.", "Architecture, design, requirements"),
  r("NICE", "IO-WRL-002", "Network Operations Specialist", "Implementation & Operation", "Plans, implements and operates network services/systems.", "Networking, operations, monitoring"),
  r("NICE", "PD-WRL-001", "Cyber Defense Analyst", "Protection & Defense", "Uses defensive measures and information to analyze and respond to events.", "SOC, SIEM, detection, triage, analysis"),
  r("NICE", "PD-WRL-004", "Incident Responder", "Protection & Defense", "Investigates, analyzes and responds to cyber incidents.", "Incident response, containment, recovery"),
  r("NICE", "PD-WRL-002", "Cyber Defense Infrastructure Support", "Protection & Defense", "Tests, implements and maintains defensive tools.", "EDR, IDS/IPS, tooling, maintenance"),
  r("NICE", "IN-WRL-001", "Digital Forensics Analyst", "Investigation", "Collects, processes and analyzes digital evidence.", "Forensics, evidence, chain of custody"),
  r("NICE", "CI-WRL-001", "Threat/Warning Analyst", "Cyberspace Intelligence", "Develops cyber indications and warnings; assesses threats.", "CTI, threat analysis, warning"),
];

const FRAMEWORKS = ["ECSF", "NICE"];

function persons(): Map<number, string> { const m = new Map<number, string>(); try { for (const p of getDb("XORCISM").prepare("SELECT PersonID, FullName FROM PERSON").all() as any[]) m.set(Number(p.PersonID), String(p.FullName || `#${p.PersonID}`)); } catch { /* */ } return m; }

export function workforceInventory(tenant: number | null): any {
  const db = getDb("XORCISM");
  const roles = db.prepare("SELECT WorkRoleID, Framework, Code, Name, Category, Description, Skills FROM WORKROLE ORDER BY Framework, Code").all() as any[];
  const assigns = (tenant != null ? db.prepare("SELECT * FROM PERSONWORKROLE WHERE (TenantID = ? OR TenantID IS NULL)").all(tenant) : db.prepare("SELECT * FROM PERSONWORKROLE").all()) as any[];
  const pmap = persons();
  const byRole = new Map<number, any[]>();
  const byPerson = new Map<number, any[]>();
  for (const a of assigns) {
    const role = roles.find((x) => Number(x.WorkRoleID) === Number(a.WorkRoleID));
    const ra = byRole.get(Number(a.WorkRoleID)) || []; ra.push({ personId: Number(a.PersonID), person: pmap.get(Number(a.PersonID)) || `#${a.PersonID}`, proficiency: String(a.Proficiency ?? ""), primary: !!a.Primary_ }); byRole.set(Number(a.WorkRoleID), ra);
    if (role) { const pa = byPerson.get(Number(a.PersonID)) || []; pa.push({ id: Number(a.PersonWorkRoleID), workRoleId: Number(a.WorkRoleID), code: String(role.Code), name: String(role.Name), framework: String(role.Framework), proficiency: String(a.Proficiency ?? ""), primary: !!a.Primary_ }); byPerson.set(Number(a.PersonID), pa); }
  }
  const roleRows = roles.map((x) => ({ id: Number(x.WorkRoleID), framework: String(x.Framework), code: String(x.Code), name: String(x.Name), category: String(x.Category ?? ""), description: String(x.Description ?? ""), skills: String(x.Skills ?? ""), holders: byRole.get(Number(x.WorkRoleID)) || [] }));
  const people = [...byPerson.entries()].map(([id, rolesP]) => ({ id, name: pmap.get(id) || `#${id}`, roles: rolesP })).sort((a, b) => a.name.localeCompare(b.name));
  const byFw = FRAMEWORKS.map((f) => { const list = roleRows.filter((r) => r.framework === f); return { framework: f, roles: list.length, covered: list.filter((r) => r.holders.length).length }; });
  const gaps = roleRows.filter((r) => !r.holders.length).map((r) => ({ id: r.id, framework: r.framework, code: r.code, name: r.name, category: r.category }));
  return {
    roles: roleRows, people, byFramework: byFw, gaps: gaps.slice(0, 40), shapes: {},
    summary: { roles: roleRows.length, ecsf: roleRows.filter((r) => r.framework === "ECSF").length, nice: roleRows.filter((r) => r.framework === "NICE").length, assigned: people.length, covered: roleRows.filter((r) => r.holders.length).length, gaps: gaps.length, coverage: roleRows.length ? Math.round((roleRows.filter((r) => r.holders.length).length / roleRows.length) * 100) : 0 },
  };
}

export function assignRole(personId: number, workRoleId: number, p: { proficiency?: string; primary?: boolean }, tenant: number | null): { id: number } | null {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM WORKROLE WHERE WorkRoleID = ?").get(workRoleId)) return null;
  if (!db.prepare("SELECT 1 FROM PERSON WHERE PersonID = ?").get(personId)) return null;
  const ex = db.prepare("SELECT PersonWorkRoleID FROM PERSONWORKROLE WHERE PersonID = ? AND WorkRoleID = ?").get(personId, workRoleId) as { PersonWorkRoleID: number } | undefined;
  if (ex) { db.prepare("UPDATE PERSONWORKROLE SET Proficiency = ?, Primary_ = ? WHERE PersonWorkRoleID = ?").run(p.proficiency ?? "Proficient", p.primary ? 1 : 0, ex.PersonWorkRoleID); return { id: ex.PersonWorkRoleID }; }
  const id = (db.prepare("SELECT COALESCE(MAX(PersonWorkRoleID),0)+1 n FROM PERSONWORKROLE").get() as { n: number }).n;
  db.prepare("INSERT INTO PERSONWORKROLE (PersonWorkRoleID, PersonID, WorkRoleID, Proficiency, Primary_, AssignedDate, TenantID) VALUES (?,?,?,?,?,?,?)")
    .run(id, personId, workRoleId, p.proficiency ?? "Proficient", p.primary ? 1 : 0, new Date().toISOString(), tenant);
  return { id };
}

export function unassignRole(personWorkRoleId: number): boolean {
  getDb("XORCISM").prepare("DELETE FROM PERSONWORKROLE WHERE PersonWorkRoleID = ?").run(personWorkRoleId);
  return true;
}

export function seedWorkforce(tenant: number): { roles: number; assignments: number } {
  const db = getDb("XORCISM");
  let n = 0;
  if (!(db.prepare("SELECT COUNT(*) n FROM WORKROLE").get() as { n: number }).n) {
    let id = 1; const now = new Date().toISOString();
    const ins = db.prepare("INSERT INTO WORKROLE (WorkRoleID, WorkRoleGUID, Framework, Code, Name, Category, Description, Skills, URL, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)");
    for (const role of WORKROLES) ins.run(id++, randomUUID(), role.framework, role.code, role.name, role.category, role.desc, role.skills,
      role.framework === "ECSF" ? "https://www.enisa.europa.eu/topics/skills-and-competences/skills-development/european-cybersecurity-skills-framework-ecsf" : "https://niccs.cisa.gov/workforce-development/nice-framework", now);
    n = WORKROLES.length;
  }
  // assign ECSF profiles to the security team
  let a = 0;
  if (!(db.prepare("SELECT COUNT(*) n FROM PERSONWORKROLE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) {
    const role = (code: string) => (db.prepare("SELECT WorkRoleID FROM WORKROLE WHERE Code = ?").get(code) as { WorkRoleID: number } | undefined)?.WorkRoleID;
    const pid = (like: string) => (db.prepare("SELECT PersonID FROM PERSON WHERE FullName LIKE ? LIMIT 1").get(`%${like}%`) as { PersonID: number } | undefined)?.PersonID;
    const plan: [string, string, string][] = [
      ["Dana", "ECSF-CISO", "Expert"], ["Sara", "ECSF-RISK", "Expert"], ["Sara", "ECSF-AUDIT", "Proficient"],
      ["Omar", "ECSF-IR", "Expert"], ["Omar", "ECSF-CISO", "Proficient"], ["Tom", "ECSF-IR", "Proficient"],
      ["Lena", "PD-WRL-001", "Proficient"], ["Ravi", "ECSF-DFIR", "Expert"], ["Ravi", "ECSF-CTI", "Proficient"],
      ["Nadia", "ECSF-LEGAL", "Proficient"], ["Maya", "ECSF-ARCH", "Expert"],
    ];
    for (const [who, code, prof] of plan) { const p = pid(who), w = role(code); if (p && w) { assignRole(p, w, { proficiency: prof, primary: prof === "Expert" }, tenant); a++; } }
  }
  return { roles: n, assignments: a };
}
