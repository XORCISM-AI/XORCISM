/**
 * governance.ts — the "G" in GRC / NIST CSF 2.0 Govern (GV) function.
 *
 * A register of the GV subcategories across its six categories (Organizational Context, Risk
 * Management Strategy, Roles/Responsibilities/Authorities, Policy, Oversight, Supply-Chain Risk
 * Management) with a per-tenant status + maturity, rolled up to a governance posture. Cross-links
 * to live evidence already in the platform (policies, the risk register, defined roles).
 */
import { allocId, getDb } from "./db";

type GItem = { category: string; code: string; sub: string; title: string; desc: string };
const g = (category: string, code: string, sub: string, title: string, desc: string): GItem => ({ category, code, sub, title, desc });

export const GV_ITEMS: GItem[] = [
  g("Organizational Context", "GV.OC", "GV.OC-01", "Mission & objectives understood", "The organizational mission is understood and informs cybersecurity risk management."),
  g("Organizational Context", "GV.OC", "GV.OC-02", "Stakeholder expectations", "Internal and external stakeholders are understood and their expectations considered."),
  g("Organizational Context", "GV.OC", "GV.OC-03", "Legal & regulatory requirements", "Legal, regulatory and contractual requirements are understood and managed."),
  g("Organizational Context", "GV.OC", "GV.OC-04", "Critical objectives & services", "Critical objectives, capabilities and services that stakeholders depend on are understood."),
  g("Organizational Context", "GV.OC", "GV.OC-05", "Outcomes & dependencies", "Outcomes, capabilities and services the organization depends on are understood."),
  g("Risk Management Strategy", "GV.RM", "GV.RM-01", "Risk objectives agreed", "Risk-management objectives are established and agreed by stakeholders."),
  g("Risk Management Strategy", "GV.RM", "GV.RM-02", "Risk appetite & tolerance", "Risk appetite and risk tolerance statements are established and communicated."),
  g("Risk Management Strategy", "GV.RM", "GV.RM-03", "Risk in ERM", "Cybersecurity risk is included in enterprise risk-management."),
  g("Risk Management Strategy", "GV.RM", "GV.RM-04", "Strategic direction & response", "Strategic direction describing appropriate risk-response options is established."),
  g("Risk Management Strategy", "GV.RM", "GV.RM-05", "Risk communication lines", "Lines of communication for cybersecurity risk are established."),
  g("Risk Management Strategy", "GV.RM", "GV.RM-06", "Risk methodology standardized", "A standardized method for calculating and prioritizing risk is established."),
  g("Roles, Responsibilities & Authorities", "GV.RR", "GV.RR-01", "Leadership accountability", "Leadership is accountable for cybersecurity risk and fosters a risk-aware culture."),
  g("Roles, Responsibilities & Authorities", "GV.RR", "GV.RR-02", "Roles & responsibilities", "Roles, responsibilities and authorities are established, communicated and enforced."),
  g("Roles, Responsibilities & Authorities", "GV.RR", "GV.RR-03", "Adequate resources", "Adequate resources are allocated commensurate with the risk strategy."),
  g("Roles, Responsibilities & Authorities", "GV.RR", "GV.RR-04", "HR / cybersecurity integration", "Cybersecurity is included in human-resources practices."),
  g("Policy", "GV.PO", "GV.PO-01", "Policy established", "Policy for managing cybersecurity risk is established and communicated."),
  g("Policy", "GV.PO", "GV.PO-02", "Policy reviewed & enforced", "Policy is reviewed, updated, communicated and enforced over time."),
  g("Oversight", "GV.OV", "GV.OV-01", "Strategy outcomes reviewed", "Risk-management strategy outcomes are reviewed to inform and adjust direction."),
  g("Oversight", "GV.OV", "GV.OV-02", "Strategy reviewed & adjusted", "The strategy is reviewed and adjusted to ensure coverage of requirements and risks."),
  g("Oversight", "GV.OV", "GV.OV-03", "Performance evaluated", "Cybersecurity risk-management performance is evaluated and reviewed for adjustments."),
  g("Supply-Chain Risk Management", "GV.SC", "GV.SC-01", "SCRM program established", "A cyber supply-chain risk-management program is established and agreed."),
  g("Supply-Chain Risk Management", "GV.SC", "GV.SC-02", "Supplier roles defined", "Roles and responsibilities for suppliers and partners are established."),
  g("Supply-Chain Risk Management", "GV.SC", "GV.SC-04", "Suppliers prioritized", "Suppliers are known and prioritized by criticality."),
  g("Supply-Chain Risk Management", "GV.SC", "GV.SC-05", "Requirements in contracts", "Requirements to address cybersecurity risks are included in supplier contracts."),
  g("Supply-Chain Risk Management", "GV.SC", "GV.SC-07", "Supplier risk monitored", "Risks posed by suppliers and their products/services are understood and monitored."),
  g("Supply-Chain Risk Management", "GV.SC", "GV.SC-10", "Incident & end-of-life planning", "Supply-chain plans include provisions for incidents and end-of-service."),
];
const CATEGORIES = ["Organizational Context", "Risk Management Strategy", "Roles, Responsibilities & Authorities", "Policy", "Oversight", "Supply-Chain Risk Management"];
const STATUS_RANK: Record<string, number> = { Implemented: 4, "Partially implemented": 3, Planned: 2, "Not implemented": 1, "Not applicable": 0 };

function liveSignals(tenant: number | null): { policies: number; approvedPolicies: number; risks: number; rolesDefined: number } {
  const count = (db: string, sql: string, args: unknown[]): number => { try { return Number((getDb(db).prepare(sql).get(...args) as { n: number }).n); } catch { return 0; } };
  const tt = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const a = tenant != null ? [tenant] : [];
  return {
    // Policies live in XORCISM.POLICY (the controlled-document estate, see policies.ts), not XCOMPLIANCE.
    policies: count("XORCISM", `SELECT COUNT(*) n FROM POLICY ${tt}`, a),
    approvedPolicies: count("XORCISM", `SELECT COUNT(*) n FROM POLICY ${tt ? tt + " AND" : "WHERE"} (WorkflowStatus IN ('Approved','Published','Active','Effective') OR Status IN ('Approved','Published','Active','Effective'))`, a),
    risks: count("XCOMPLIANCE", `SELECT COUNT(*) n FROM RISKREGISTERENTRY ${tt}`, a),
    rolesDefined: count("XORCISM", "SELECT COUNT(*) n FROM PERSON WHERE ManagerPersonID IS NOT NULL", []),
  };
}

export function governanceInventory(tenant: number | null): any {
  const db = getDb("XCOMPLIANCE");
  const items = db.prepare("SELECT ItemID, Category, CategoryCode, SubCode, Title, Description FROM GOVERNANCEITEM ORDER BY SortOrder").all() as any[];
  const status = new Map<number, any>();
  for (const s of (tenant != null ? db.prepare("SELECT * FROM GOVERNANCESTATUS WHERE (TenantID = ? OR TenantID IS NULL)").all(tenant) : db.prepare("SELECT * FROM GOVERNANCESTATUS").all()) as any[]) status.set(Number(s.ItemID), s);
  const rows = items.map((it) => {
    const s = status.get(Number(it.ItemID));
    return { id: Number(it.ItemID), category: String(it.Category), code: String(it.CategoryCode), sub: String(it.SubCode), title: String(it.Title), description: String(it.Description ?? ""),
      status: s ? String(s.Status ?? "Not implemented") : "Not implemented", maturity: s && s.Maturity != null ? Number(s.Maturity) : null, owner: s && s.OwnerPersonID != null ? Number(s.OwnerPersonID) : null, notes: s ? String(s.Notes ?? "") : "" };
  });
  const byCat = CATEGORIES.map((cat) => {
    const list = rows.filter((r) => r.category === cat);
    const impl = list.filter((r) => r.status === "Implemented").length;
    const partial = list.filter((r) => r.status === "Partially implemented").length;
    return { category: cat, code: list[0]?.code ?? "", items: list.length, implemented: impl, partial, pct: list.length ? Math.round(((impl + partial * 0.5) / list.length) * 100) : 0 };
  });
  const implemented = rows.filter((r) => r.status === "Implemented").length;
  const partial = rows.filter((r) => r.status === "Partially implemented").length;
  const score = rows.length ? Math.round(((implemented + partial * 0.5) / rows.length) * 100) : 0;
  const worklist = rows.filter((r) => r.status === "Not implemented" || r.status === "Planned").map((r) => ({ id: r.id, sub: r.sub, title: r.title, category: r.category, status: r.status, severity: r.category.includes("Risk") || r.category === "Policy" ? "High" : "Medium" }))
    .sort((a, b) => (a.severity === "High" ? -1 : 1) - (b.severity === "High" ? -1 : 1)).slice(0, 30);
  return { byCategory: byCat, rows, signals: liveSignals(tenant), worklist, summary: { items: rows.length, implemented, partial, notImplemented: rows.filter((r) => r.status === "Not implemented").length, score, noOwner: rows.filter((r) => r.status !== "Not implemented" && !r.owner).length } };
}

export function saveGovernanceStatus(itemId: number, p: { status?: string; maturity?: number; ownerPersonId?: number; evidence?: string; notes?: string }, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  if (!db.prepare("SELECT 1 FROM GOVERNANCEITEM WHERE ItemID = ?").get(itemId)) return false;
  const now = new Date().toISOString();
  const ex = db.prepare("SELECT StatusID FROM GOVERNANCESTATUS WHERE ItemID = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(itemId, tenant) as { StatusID: number } | undefined;
  const st = p.status && STATUS_RANK[p.status] != null ? p.status : undefined;
  if (ex) {
    const sets: string[] = ["UpdatedDate = ?"]; const vals: unknown[] = [now];
    if (st) { sets.push("Status = ?"); vals.push(st); }
    if (p.maturity != null) { sets.push("Maturity = ?"); vals.push(Math.max(0, Math.min(5, Math.round(p.maturity)))); }
    if (p.ownerPersonId != null) { sets.push("OwnerPersonID = ?"); vals.push(p.ownerPersonId); }
    if (p.evidence != null) { sets.push("Evidence = ?"); vals.push(String(p.evidence).slice(0, 1000)); }
    if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 1000)); }
    vals.push(ex.StatusID);
    db.prepare(`UPDATE GOVERNANCESTATUS SET ${sets.join(", ")} WHERE StatusID = ?`).run(...vals);
  } else {
    const id = allocId(db, "GOVERNANCESTATUS", "StatusID");
    db.prepare("INSERT INTO GOVERNANCESTATUS (StatusID, ItemID, Status, Maturity, OwnerPersonID, Evidence, Notes, TenantID, UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(id, itemId, st ?? "Not implemented", p.maturity != null ? Math.max(0, Math.min(5, Math.round(p.maturity))) : null, p.ownerPersonId ?? null, String(p.evidence ?? "").slice(0, 1000), String(p.notes ?? "").slice(0, 1000), tenant, now);
  }
  return true;
}

export function seedGovernance(tenant: number): { items: number; statuses: number } {
  const db = getDb("XCOMPLIANCE");
  let n = 0;
  if (!(db.prepare("SELECT COUNT(*) n FROM GOVERNANCEITEM").get() as { n: number }).n) {
    let id = 1;
    const ins = db.prepare("INSERT INTO GOVERNANCEITEM (ItemID, Category, CategoryCode, SubCode, Title, Description, SortOrder) VALUES (?,?,?,?,?,?,?)");
    GV_ITEMS.forEach((it, i) => { ins.run(id++, it.category, it.code, it.sub, it.title, it.desc, i); n++; });
  }
  let sc = 0;
  if (!(db.prepare("SELECT COUNT(*) n FROM GOVERNANCESTATUS WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) {
    const items = db.prepare("SELECT ItemID, Category FROM GOVERNANCEITEM ORDER BY SortOrder").all() as any[];
    const owner = (getDb("XORCISM").prepare("SELECT PersonID FROM PERSON WHERE FullName LIKE '%Sara%' LIMIT 1").get() as { PersonID: number } | undefined)?.PersonID ?? null;
    items.forEach((it, i) => {
      // demo: most policy/RR implemented, supply-chain lagging
      const s = it.Category.includes("Supply") ? (i % 3 === 0 ? "Partially implemented" : "Not implemented")
        : it.Category === "Policy" || it.Category.includes("Roles") ? "Implemented"
        : i % 4 === 0 ? "Partially implemented" : i % 5 === 0 ? "Planned" : "Implemented";
      saveGovernanceStatus(it.ItemID, { status: s, maturity: s === "Implemented" ? 4 : s === "Partially implemented" ? 2 : 1, ownerPersonId: owner ?? undefined }, tenant); sc++;
    });
  }
  return { items: n, statuses: sc };
}
