/**
 * certops.ts — CERT / CSIRT operations: DFIR case management with a tamper-evident chain of custody.
 *
 * Forensic cases (FORENSICCASE) hold evidence exhibits (FORENSICEVIDENCE, with acquisition hashes)
 * and an append-only chain-of-custody log (CUSTODYEVENT: who handled what, when, why, hash-verified).
 * CERT activities (CERTACTIVITY) track the broader CSIRT service portfolio. State-of-the-art
 * references (NIST SP 800-86, ISO/IEC 27037/27041/27042/27043, RFC 3227, ENISA CSIRT) are surfaced
 * so handling follows recognized standards.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export const SOTA_REFERENCES = [
  { ref: "NIST SP 800-86", title: "Guide to Integrating Forensic Techniques into Incident Response" },
  { ref: "ISO/IEC 27037", title: "Identification, collection, acquisition and preservation of digital evidence" },
  { ref: "ISO/IEC 27041", title: "Assurance for digital-evidence investigation methods" },
  { ref: "ISO/IEC 27042", title: "Analysis and interpretation of digital evidence" },
  { ref: "ISO/IEC 27043", title: "Incident investigation principles and processes" },
  { ref: "RFC 3227", title: "Guidelines for Evidence Collection and Archiving (order of volatility)" },
  { ref: "ENISA CSIRT", title: "Good practice guide for CSIRTs / incident handling" },
];
export const CERT_SERVICES = ["Incident handling", "Forensics & analysis", "Vulnerability management", "Situational awareness", "Threat intelligence", "Knowledge transfer", "Coordination & disclosure"];

const now = () => new Date().toISOString();
function nextId(db: any, table: string, pk: string): number { return (db.prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n; }
function tw(tenant: number | null): string { return tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : ""; }

export function certInventory(tenant: number | null): any {
  const db = getDb("XINCIDENT");
  const args = tenant != null ? [tenant] : [];
  const cases = db.prepare(`SELECT * FROM FORENSICCASE ${tw(tenant)} ORDER BY CaseID DESC`).all(...args) as any[];
  const evCount = new Map<number, number>();
  for (const r of db.prepare("SELECT CaseID, COUNT(*) n FROM FORENSICEVIDENCE GROUP BY CaseID").all() as any[]) evCount.set(Number(r.CaseID), Number(r.n));
  const custCount = new Map<number, number>();
  for (const r of db.prepare("SELECT CaseID, COUNT(*) n FROM CUSTODYEVENT GROUP BY CaseID").all() as any[]) custCount.set(Number(r.CaseID), Number(r.n));
  const rows = cases.map((c) => ({
    id: Number(c.CaseID), number: String(c.CaseNumber ?? `CASE-${c.CaseID}`), title: String(c.Title ?? ""), status: String(c.Status ?? "Open"),
    severity: String(c.Severity ?? ""), examiner: String(c.Examiner ?? ""), incidentId: c.IncidentID != null ? Number(c.IncidentID) : null,
    methodology: String(c.Methodology ?? ""), opened: c.OpenedDate ? String(c.OpenedDate).slice(0, 10) : "", closed: c.ClosedDate ? String(c.ClosedDate).slice(0, 10) : "",
    evidence: evCount.get(Number(c.CaseID)) || 0, custody: custCount.get(Number(c.CaseID)) || 0,
  }));
  const activities = (db.prepare(`SELECT * FROM CERTACTIVITY ${tw(tenant)} ORDER BY ActivityID DESC`).all(...args) as any[]).map((a) => ({
    id: Number(a.ActivityID), title: String(a.Title ?? ""), type: String(a.ActivityType ?? ""), service: String(a.Service ?? ""),
    status: String(a.Status ?? "Open"), priority: String(a.Priority ?? ""), assignedTo: String(a.AssignedTo ?? ""), dueDate: a.DueDate ? String(a.DueDate).slice(0, 10) : "",
  }));
  const open = rows.filter((r) => !/closed/i.test(r.status));
  return {
    cases: rows, activities, references: SOTA_REFERENCES, services: CERT_SERVICES,
    summary: {
      cases: rows.length, openCases: open.length, evidenceItems: [...evCount.values()].reduce((a, b) => a + b, 0),
      custodyEvents: [...custCount.values()].reduce((a, b) => a + b, 0),
      activities: activities.length, openActivities: activities.filter((a) => !/closed|done/i.test(a.status)).length,
      brokenCustody: rows.filter((r) => r.evidence > 0 && r.custody === 0).length,
    },
  };
}

export function caseDetail(caseId: number, tenant: number | null): any | null {
  const db = getDb("XINCIDENT");
  const c = db.prepare(`SELECT * FROM FORENSICCASE WHERE CaseID = ? ${tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : ""}`).get(...(tenant != null ? [caseId, tenant] : [caseId])) as any;
  if (!c) return null;
  const custodyByEv = new Map<number, any[]>();
  for (const e of db.prepare("SELECT * FROM CUSTODYEVENT WHERE CaseID = ? ORDER BY CustodyID").all(caseId) as any[]) {
    const a = custodyByEv.get(Number(e.EvidenceID)) || []; a.push({ id: Number(e.CustodyID), action: String(e.Action ?? ""), from: String(e.FromParty ?? ""), to: String(e.ToParty ?? ""), purpose: String(e.Purpose ?? ""), hash: String(e.Hash ?? ""), verified: !!e.HashVerified, at: e.At ? String(e.At).slice(0, 16).replace("T", " ") : "" }); custodyByEv.set(Number(e.EvidenceID), a);
  }
  const evidence = (db.prepare("SELECT * FROM FORENSICEVIDENCE WHERE CaseID = ? ORDER BY EvidenceID").all(caseId) as any[]).map((e) => ({
    id: Number(e.EvidenceID), exhibit: String(e.ExhibitNumber ?? ""), description: String(e.Description ?? ""), type: String(e.EvidenceType ?? ""),
    source: String(e.Source ?? ""), tool: String(e.AcquisitionTool ?? ""), sha256: String(e.Sha256 ?? ""), size: String(e.Size ?? ""),
    status: String(e.Status ?? ""), collectedBy: String(e.CollectedBy ?? ""), collectedAt: e.CollectedAt ? String(e.CollectedAt).slice(0, 16).replace("T", " ") : "",
    storage: String(e.StorageLocation ?? ""), custody: custodyByEv.get(Number(e.EvidenceID)) || [],
  }));
  return {
    case: { id: Number(c.CaseID), number: String(c.CaseNumber ?? ""), title: String(c.Title ?? ""), status: String(c.Status ?? ""), severity: String(c.Severity ?? ""),
      examiner: String(c.Examiner ?? ""), incidentId: c.IncidentID != null ? Number(c.IncidentID) : null, description: String(c.Description ?? ""), methodology: String(c.Methodology ?? ""),
      opened: c.OpenedDate ? String(c.OpenedDate).slice(0, 16).replace("T", " ") : "", closed: c.ClosedDate ? String(c.ClosedDate).slice(0, 10) : "" },
    evidence,
  };
}

export function createCase(p: { title: string; incidentId?: number; severity?: string; examiner?: string; description?: string; methodology?: string }, tenant: number | null): { id: number } {
  const db = getDb("XINCIDENT"); const id = nextId(db, "FORENSICCASE", "CaseID");
  db.prepare(`INSERT INTO FORENSICCASE (CaseID, CaseGUID, CaseNumber, Title, IncidentID, Status, Severity, Examiner, Description, Methodology, OpenedDate, TenantID, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), `CASE-${String(id).padStart(4, "0")}`, p.title.slice(0, 300), p.incidentId ?? null, "Open", p.severity ?? "Medium",
      p.examiner ?? null, (p.description || "").slice(0, 4000), p.methodology ?? "NIST SP 800-86", now(), tenant, now());
  return { id };
}

export function addEvidence(caseId: number, p: { description: string; type?: string; source?: string; tool?: string; sha256?: string; size?: string; collectedBy?: string; storage?: string }, tenant: number | null): { id: number } | null {
  const db = getDb("XINCIDENT");
  if (!db.prepare("SELECT 1 FROM FORENSICCASE WHERE CaseID = ?").get(caseId)) return null;
  const id = nextId(db, "FORENSICEVIDENCE", "EvidenceID");
  const exhibit = `E${(db.prepare("SELECT COUNT(*) n FROM FORENSICEVIDENCE WHERE CaseID = ?").get(caseId) as { n: number }).n + 1}`;
  db.prepare(`INSERT INTO FORENSICEVIDENCE (EvidenceID, EvidenceGUID, CaseID, ExhibitNumber, Description, EvidenceType, Source, AcquisitionTool, Sha256, Size, Status, CollectedBy, CollectedAt, StorageLocation, TenantID, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), caseId, exhibit, p.description.slice(0, 1000), p.type ?? "disk-image", p.source ?? null, p.tool ?? null, (p.sha256 || "").toLowerCase().slice(0, 64) || null,
      p.size ?? null, "Acquired", p.collectedBy ?? null, now(), p.storage ?? "Evidence vault", tenant, now());
  // seed the chain of custody with the acquisition event
  addCustody(id, { action: "Acquired", from: p.source ?? "Source system", to: p.collectedBy ?? "Examiner", purpose: "Initial acquisition", hash: p.sha256, verified: true }, tenant);
  return { id };
}

export function addCustody(evidenceId: number, p: { action: string; from?: string; to?: string; purpose?: string; hash?: string; verified?: boolean }, tenant: number | null): { id: number } | null {
  const db = getDb("XINCIDENT");
  const ev = db.prepare("SELECT CaseID, Sha256 FROM FORENSICEVIDENCE WHERE EvidenceID = ?").get(evidenceId) as { CaseID: number; Sha256: string } | undefined;
  if (!ev) return null;
  const id = nextId(db, "CUSTODYEVENT", "CustodyID");
  const hash = (p.hash || ev.Sha256 || "").toLowerCase().slice(0, 64) || null;
  const verified = p.verified != null ? !!p.verified : (hash != null && ev.Sha256 != null && hash === String(ev.Sha256).toLowerCase());
  db.prepare("INSERT INTO CUSTODYEVENT (CustodyID, EvidenceID, CaseID, Action, FromParty, ToParty, Purpose, Hash, HashVerified, At, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, evidenceId, ev.CaseID, p.action.slice(0, 80), p.from ?? null, p.to ?? null, (p.purpose || "").slice(0, 500), hash, verified ? 1 : 0, now(), tenant);
  return { id };
}

export function createActivity(p: { title: string; type?: string; service?: string; priority?: string; assignedTo?: string; incidentId?: number; description?: string; dueDate?: string }, tenant: number | null): { id: number } {
  const db = getDb("XINCIDENT"); const id = nextId(db, "CERTACTIVITY", "ActivityID");
  db.prepare(`INSERT INTO CERTACTIVITY (ActivityID, ActivityGUID, Title, ActivityType, Service, Status, Priority, IncidentID, AssignedTo, Description, DueDate, TenantID, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.title.slice(0, 300), p.type ?? "Task", p.service ?? "Incident handling", "Open", p.priority ?? "Medium",
      p.incidentId ?? null, p.assignedTo ?? null, (p.description || "").slice(0, 2000), p.dueDate ?? null, tenant, now());
  return { id };
}

export function seedCertOps(tenant: number): { cases: number; activities: number } {
  const db = getDb("XINCIDENT");
  if ((db.prepare("SELECT COUNT(*) n FROM FORENSICCASE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { cases: 0, activities: 0 };
  // a forensic case for the ransomware incident, with evidence + chain of custody
  const inc = db.prepare("SELECT IncidentID FROM INCIDENT WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) AND IncidentName LIKE '%ansomware%' LIMIT 1").get(tenant) as { IncidentID: number } | undefined;
  const c = createCase({ title: "Ransomware — endpoint forensic acquisition", incidentId: inc?.IncidentID, severity: "High", examiner: "Ravi Patel", description: "Forensic acquisition and analysis of the ransomware-infected endpoint.", methodology: "NIST SP 800-86 / ISO 27037" }, tenant);
  const e1 = addEvidence(c.id, { description: "Full disk image of WKS-FIN-07", type: "disk-image", source: "WKS-FIN-07", tool: "FTK Imager", sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", size: "476 GB", collectedBy: "Ravi Patel", storage: "Evidence vault A-12" }, tenant);
  const e2 = addEvidence(c.id, { description: "Memory capture (RAM)", type: "memory", source: "WKS-FIN-07", tool: "WinPmem", sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", size: "16 GB", collectedBy: "Ravi Patel", storage: "Evidence vault A-12" }, tenant);
  if (e1) addCustody(e1.id, { action: "Transferred", from: "Ravi Patel", to: "Lena Roth", purpose: "Malware analysis", verified: true }, tenant);
  if (e2) addCustody(e2.id, { action: "Analyzed", from: "Evidence vault A-12", to: "Lena Roth", purpose: "Volatility analysis", verified: true }, tenant);
  const acts = [
    { title: "Coordinate disclosure with affected vendor", type: "Coordination", service: "Coordination & disclosure", priority: "High" },
    { title: "Produce IOC package for constituency", type: "Dissemination", service: "Threat intelligence", priority: "Medium" },
    { title: "After-action report — ransomware case", type: "Report", service: "Knowledge transfer", priority: "Medium" },
  ];
  for (const a of acts) createActivity({ ...a, assignedTo: "Omar Haddad", incidentId: inc?.IncidentID }, tenant);
  return { cases: 1, activities: acts.length };
}
