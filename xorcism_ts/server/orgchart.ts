/**
 * orgchart.ts — organisation chart over XORCISM.PERSON.
 *
 * Builds the management hierarchy from PERSON.ManagerPersonID (the self-referential edge added
 * by ensurePersonOrgChartColumns, aligned with Microsoft Entra ID `manager` / AD `manager`), with
 * the directory attributes an Entra/AD import populates (JobTitle, Department, UPN, EmployeeID,
 * AccountEnabled…). Returns a forest (people + roots) + a department/headcount summary.
 */
import { getDb } from "./db";

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

export interface OrgPerson {
  id: number; name: string; title: string; department: string; email: string; upn: string;
  managerId: number | null; enabled: boolean; reports: number; entra: boolean;
}
export interface OrgChart {
  people: OrgPerson[]; roots: number[];
  summary: { total: number; managers: number; withManager: number; orphans: number; departments: number;
    disabled: number; fromEntra: number; maxDepth: number; byDepartment: Record<string, number> };
}

export function orgChart(): OrgChart {
  const db = getDb("XORCISM");
  const empty: OrgChart = { people: [], roots: [], summary: { total: 0, managers: 0, withManager: 0, orphans: 0, departments: 0, disabled: 0, fromEntra: 0, maxDepth: 0, byDepartment: {} } };
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='PERSON'").get()) return empty;
  const pc = cols("PERSON");
  const sel = (c: string): string => (pc.has(c) ? c : `NULL AS ${c}`);
  const rows = db.prepare(
    `SELECT PersonID, ${sel("FullName")}, ${sel("FirstName")}, ${sel("LastName")}, ${sel("JobTitle")},
            ${sel("Department")}, ${sel("email")}, ${sel("UserPrincipalName")}, ${sel("ManagerPersonID")},
            ${sel("AccountEnabled")}, ${sel("EntraObjectID")}, ${sel("PersonFunction")}
     FROM PERSON`
  ).all() as Record<string, any>[];
  if (!rows.length) return empty;

  const present = new Set(rows.map((r) => Number(r.PersonID)));
  const reportsOf = new Map<number, number>();
  for (const r of rows) {
    const m = r.ManagerPersonID != null ? Number(r.ManagerPersonID) : null;
    if (m != null && present.has(m)) reportsOf.set(m, (reportsOf.get(m) || 0) + 1);
  }
  const people: OrgPerson[] = rows.map((r) => {
    const id = Number(r.PersonID);
    const name = String(r.FullName ?? "").trim()
      || [r.FirstName, r.LastName].map((x) => String(x ?? "").trim()).filter(Boolean).join(" ")
      || `Person #${id}`;
    const m = r.ManagerPersonID != null ? Number(r.ManagerPersonID) : null;
    return {
      id, name, title: String(r.JobTitle ?? r.PersonFunction ?? "").trim(), department: String(r.Department ?? "").trim(),
      email: String(r.email ?? "").trim(), upn: String(r.UserPrincipalName ?? "").trim(),
      managerId: m != null && present.has(m) ? m : null,
      enabled: r.AccountEnabled == null ? true : (Number(r.AccountEnabled) === 1 || String(r.AccountEnabled).toLowerCase() === "true"),
      reports: reportsOf.get(id) || 0, entra: !!String(r.EntraObjectID ?? "").trim(),
    };
  });

  const roots = people.filter((p) => p.managerId == null).map((p) => p.id);
  // depth (cycle-guarded)
  const byId = new Map(people.map((p) => [p.id, p]));
  const depthOf = (id: number, seen = new Set<number>()): number => {
    if (seen.has(id)) return 0; seen.add(id);
    const p = byId.get(id); if (!p || p.managerId == null) return 0;
    return 1 + depthOf(p.managerId, seen);
  };
  const maxDepth = people.reduce((mx, p) => Math.max(mx, depthOf(p.id)), 0);
  const byDepartment: Record<string, number> = {};
  for (const p of people) { const d = p.department || "—"; byDepartment[d] = (byDepartment[d] || 0) + 1; }

  return {
    people, roots,
    summary: {
      total: people.length,
      managers: people.filter((p) => p.reports > 0).length,
      withManager: people.filter((p) => p.managerId != null).length,
      orphans: people.filter((p) => p.managerId == null && p.reports === 0).length,
      departments: Object.keys(byDepartment).filter((d) => d !== "—").length,
      disabled: people.filter((p) => !p.enabled).length,
      fromEntra: people.filter((p) => p.entra).length,
      maxDepth, byDepartment,
    },
  };
}
