/**
 * pir.ts — Priority Intelligence Requirements (PIR) coverage register.
 *
 * PIRs are the standing questions that drive a CTI program's collection. This
 * module measures, for each requirement, how much collected reporting actually
 * addresses it — by matching the PIR's keywords against THREATREPORT text — so
 * analysts see which requirements are *covered* and which are *collection gaps*.
 * Read-only; PIR CRUD is the schema-driven explorer (XTHREAT.PIR).
 */
import { getDb } from "./db";

export interface PirRow {
  pirId: number;
  name: string;
  description: string;
  priority: string;
  status: string;
  keywords: string[];
  owner: string | null;
  measurable: boolean;                 // has keywords → coverage can be computed
  matches: number;                     // reports addressing this PIR
  recent: { id: number; name: string; date: string }[];
  gap: boolean;                        // active + measurable + zero matching reporting
}

export interface PirRegister {
  rows: PirRow[];
  summary: { total: number; active: number; covered: number; gaps: number; unmeasured: number; byPriority: Record<string, number> };
}

const ACTIVE = new Set(["active", "on hold", "draft", ""]); // statuses still seeking intel
const EMPTY: PirRegister = { rows: [], summary: { total: 0, active: 0, covered: 0, gaps: 0, unmeasured: 0, byPriority: {} } };

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

/** Each PIR with its coverage from collected threat reporting + collection-gap flags. */
export function pirRegister(tenant: number | null): PirRegister {
  const xt = getDb("XTHREAT");
  if (!xt.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='PIR'").get()) return EMPTY;

  const pc = cols("XTHREAT", "PIR");
  const ptw = tenant != null && pc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const pirs = xt.prepare(
    `SELECT PIRID, PIRName, PIRDescription, Priority, Status, Keywords, PersonID FROM PIR ${ptw}
     ORDER BY CASE lower(COALESCE(Priority,'')) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, PIRID`
  ).all() as Record<string, unknown>[];
  if (!pirs.length) return { ...EMPTY };

  // Collected reporting (concatenated searchable text + a date), tenant-scoped if possible.
  const rc = cols("XTHREAT", "THREATREPORT");
  const f = (c: string): string => (rc.has(c) ? `COALESCE("${c}",'')` : "''");
  const rtw = tenant != null && rc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const dateExpr = rc.has("ValidFrom") ? "ValidFrom" : rc.has("CreatedDate") ? "CreatedDate" : "''";
  let reports: { id: number; name: string; hay: string; date: string }[] = [];
  if (rc.size) {
    reports = (xt.prepare(
      `SELECT ThreatReportID AS id, ${f("ThreatReportName")} AS name,
              lower(${f("ThreatReportName")}||' '||${f("ThreatReportDescription")}||' '||${f("AiSummary")}||' '||${f("CveTags")}) AS hay,
              ${dateExpr} AS date FROM THREATREPORT ${rtw}`
    ).all() as { id: number; name: string; hay: string; date: string }[]);
  }

  // Owner display names (PERSON lives in XORCISM).
  const owners = new Map<number, string>();
  try {
    const xo = getDb("XORCISM");
    if (cols("XORCISM", "PERSON").has("FullName")) {
      for (const p of xo.prepare(`SELECT PersonID, FullName FROM PERSON`).all() as { PersonID: number; FullName: string }[]) {
        owners.set(Number(p.PersonID), p.FullName);
      }
    }
  } catch { /* PERSON unavailable */ }

  const rows: PirRow[] = pirs.map((p) => {
    const kws = String(p.Keywords ?? "").split(",").map((k) => k.trim().toLowerCase()).filter(Boolean);
    const matched = kws.length ? reports.filter((r) => kws.some((k) => r.hay.includes(k))) : [];
    const recent = matched
      .slice().sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, 5)
      .map((r) => ({ id: r.id, name: r.name, date: r.date ? String(r.date).slice(0, 10) : "" }));
    const status = String(p.Status ?? "").trim() || "Active";
    const active = ACTIVE.has(status.toLowerCase());
    return {
      pirId: Number(p.PIRID),
      name: (p.PIRName as string) || `PIR #${p.PIRID}`,
      description: (p.PIRDescription as string) || "",
      priority: (p.Priority as string) || "Medium",
      status,
      keywords: kws,
      owner: p.PersonID != null ? owners.get(Number(p.PersonID)) || `#${p.PersonID}` : null,
      measurable: kws.length > 0,
      matches: matched.length,
      recent,
      gap: active && kws.length > 0 && matched.length === 0,
    };
  });

  const byPriority: Record<string, number> = {};
  for (const r of rows) byPriority[r.priority] = (byPriority[r.priority] || 0) + 1;
  return {
    rows,
    summary: {
      total: rows.length,
      active: rows.filter((r) => ACTIVE.has(r.status.toLowerCase())).length,
      covered: rows.filter((r) => r.matches > 0).length,
      gaps: rows.filter((r) => r.gap).length,
      unmeasured: rows.filter((r) => ACTIVE.has(r.status.toLowerCase()) && !r.measurable).length,
      byPriority,
    },
  };
}
