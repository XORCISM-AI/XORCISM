/**
 * accessgov.ts — Access Governance (Saviynt-style) over the IDENTITY estate.
 *
 * XORCISM already had identity inventory (/identities) and access certification (/identity-governance);
 * this adds the Saviynt-distinctive layer those lacked — the entitlement fabric and the controls that
 * operate on it:
 *
 *   • Entitlement catalogue (ENTITLEMENT) + assignments (IDENTITYENTITLEMENT) — who holds what access,
 *     direct / via role / time-bound JIT.
 *   • Segregation of Duties (SoD) — a toxic-combination ruleset (SODRULE) detected across the estate
 *     (SODVIOLATION). Saviynt's flagship: catch "create-vendor + pay-invoice"-style conflicts the
 *     role-level review misses, at the function level.
 *   • Access requests + JIT (ACCESSREQUEST) — request → approve → provision → auto-expire, with a
 *     PREVENTIVE SoD pre-check at request time (block toxic grants before they happen, not just after).
 *   • Identity intelligence — peer-group outliers (access rare among same-type peers).
 *
 * Deterministic, tenant-scoped, idempotent. No external calls.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const RISK_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const now = (): string => new Date().toISOString();
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const has = (db: ReturnType<typeof getDb>, t: string): boolean => { try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; } };
function xo() { return getDb("XORCISM"); }
const tclause = (tenant: number | null): string => (tenant != null ? " AND (TenantID = ? OR TenantID IS NULL)" : "");
const targ = (tenant: number | null, ...rest: any[]): any[] => (tenant != null ? [...rest, tenant] : rest);

// An entitlement "is" function F if its Function/Name/Type CSV-matches any token of the rule side.
function entMatches(ent: { function?: string; name?: string; type?: string }, csv: string): boolean {
  const hay = `${ent.function || ""} ${ent.name || ""} ${ent.type || ""}`.toLowerCase();
  return String(csv || "").split(/[,;]/).map((s) => s.trim().toLowerCase()).filter(Boolean).some((tok) => hay.includes(tok));
}

interface EntRow { id: number; name: string; app: string; type: string; risk: string; priv: number; fn: string }
interface HeldRow { identityId: number; identityName: string; entId: number; name: string; fn: string; type: string; grantType: string; expires: string | null }

function entitlements(tenant: number | null): EntRow[] {
  const db = xo();
  if (!has(db, "ENTITLEMENT")) return [];
  return (db.prepare(`SELECT EntitlementID id, COALESCE(Name,'') name, COALESCE(Application,'') app, COALESCE(EntitlementType,'') type, COALESCE(Risk,'medium') risk, COALESCE(Privileged,0) priv, COALESCE(Function,'') fn FROM ENTITLEMENT WHERE 1=1${tclause(tenant)}`).all(...targ(tenant)) as any[])
    .map((r) => ({ id: num(r.id), name: String(r.name), app: String(r.app), type: String(r.type), risk: String(r.risk), priv: num(r.priv), fn: String(r.fn) }));
}

/** All (identity → entitlement) holdings, with the entitlement's function + the identity's name/type. */
function holdings(tenant: number | null): HeldRow[] {
  const db = xo();
  if (!has(db, "IDENTITYENTITLEMENT") || !has(db, "ENTITLEMENT")) return [];
  const idName = has(db, "IDENTITY");
  const join = idName ? "LEFT JOIN IDENTITY i ON i.IdentityID=ie.IdentityID" : "";
  const sel = idName ? "COALESCE(i.IdentityName,'Identity '||ie.IdentityID) iname, COALESCE(i.IdentityType,'') itype" : "'Identity '||ie.IdentityID iname, '' itype";
  return (db.prepare(
    `SELECT ie.IdentityID iid, ${sel}, ie.EntitlementID eid, COALESCE(e.Name,'') ename, COALESCE(e.Function,'') efn, COALESCE(ie.GrantType,'direct') gt, ie.ExpiresDate exp
     FROM IDENTITYENTITLEMENT ie JOIN ENTITLEMENT e ON e.EntitlementID=ie.EntitlementID ${join}
     WHERE 1=1 ${tenant != null ? "AND (ie.TenantID = ? OR ie.TenantID IS NULL)" : ""}`).all(...targ(tenant)) as any[])
    .map((r) => ({ identityId: num(r.iid), identityName: String(r.iname), entId: num(r.eid), name: String(r.ename), fn: String(r.efn), type: String(r.itype), grantType: String(r.gt), expires: r.exp ? String(r.exp) : null }));
}

interface SodRule { id: number; name: string; fnA: string; fnB: string; risk: string; mitigation: string }
function sodRules(tenant: number | null, enabledOnly = true): SodRule[] {
  const db = xo();
  if (!has(db, "SODRULE")) return [];
  return (db.prepare(`SELECT SodRuleID id, COALESCE(Name,'') name, COALESCE(FunctionA,'') fnA, COALESCE(FunctionB,'') fnB, COALESCE(Risk,'high') risk, COALESCE(MitigatingControl,'') mit FROM SODRULE WHERE ${enabledOnly ? "COALESCE(Enabled,1)=1" : "1=1"}${tclause(tenant)}`).all(...targ(tenant)) as any[])
    .map((r) => ({ id: num(r.id), name: String(r.name), fnA: String(r.fnA), fnB: String(r.fnB), risk: String(r.risk), mitigation: String(r.mit) }));
}

// ── SoD detection (detective control) ─────────────────────────────────────────
/** Recompute SoD violations across the estate. Idempotent; auto-resolves cleared 'open' rows; preserves
 *  manually mitigated/accepted ones. Returns the count of currently-open violations. */
export function detectSod(tenant: number | null): { rules: number; violations: number; created: number; resolved: number } {
  const db = xo();
  if (!has(db, "SODVIOLATION")) return { rules: 0, violations: 0, created: 0, resolved: 0 };
  const rules = sodRules(tenant);
  const held = holdings(tenant);
  const byId = new Map<number, HeldRow[]>();
  for (const h of held) { const a = byId.get(h.identityId) || []; a.push(h); byId.set(h.identityId, a); }

  // current violation set: (ruleId, identityId) → {left, right, risk, name}
  const current = new Map<string, { ruleId: number; ruleName: string; identityId: number; identityName: string; left: string; right: string; risk: string }>();
  for (const [iid, ents] of byId) {
    const iname = ents[0]?.identityName || `Identity ${iid}`;
    for (const r of rules) {
      const left = ents.find((e) => entMatches({ function: e.fn, name: e.name }, r.fnA));
      const right = ents.find((e) => entMatches({ function: e.fn, name: e.name }, r.fnB));
      if (left && right && left.entId !== right.entId) {
        current.set(`${r.id}:${iid}`, { ruleId: r.id, ruleName: r.name, identityId: iid, identityName: iname, left: left.name, right: right.name, risk: r.risk });
      }
    }
  }

  const existing = (db.prepare(`SELECT SodViolationID id, SodRuleID rid, IdentityID iid, Status status FROM SODVIOLATION WHERE 1=1${tclause(tenant)}`).all(...targ(tenant)) as any[])
    .map((r) => ({ id: num(r.id), key: `${num(r.rid)}:${num(r.iid)}`, status: String(r.status) }));
  const existKeys = new Map(existing.map((e) => [e.key, e]));

  let created = 0, resolved = 0;
  const ts = now();
  const ins = db.prepare("INSERT INTO SODVIOLATION (SodViolationID, SodRuleID, RuleName, IdentityID, IdentityName, LeftEntitlement, RightEntitlement, Risk, Status, DetectedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
  const tx = db.transaction(() => {
    for (const [key, v] of current) {
      if (!existKeys.has(key)) {
        ins.run(allocId(db, "SODVIOLATION", "SodViolationID"), v.ruleId, v.ruleName, v.identityId, v.identityName, v.left, v.right, v.risk, "open", ts, tenant);
        created++;
      } else {
        // refresh sample entitlements on the existing row (keep status)
        db.prepare("UPDATE SODVIOLATION SET LeftEntitlement=?, RightEntitlement=?, RuleName=?, Risk=? WHERE SodViolationID=?").run(v.left, v.right, v.ruleName, v.risk, existKeys.get(key)!.id);
      }
    }
    // auto-resolve 'open' rows whose combination no longer holds (preserve mitigated/accepted)
    for (const e of existing) {
      if (!current.has(e.key) && e.status === "open") { db.prepare("DELETE FROM SODVIOLATION WHERE SodViolationID=?").run(e.id); resolved++; }
    }
  });
  tx();
  const open = num((db.prepare(`SELECT COUNT(*) n FROM SODVIOLATION WHERE Status='open'${tclause(tenant)}`).get(...targ(tenant)) as { n: number }).n);
  return { rules: rules.length, violations: open, created, resolved };
}

/** Would granting `entId` to `identityId` create a NEW SoD violation? (preventive check at request time) */
export function sodPreCheck(tenant: number | null, identityId: number, entId: number): { conflict: boolean; detail: string } {
  const ents = entitlements(tenant);
  const target = ents.find((e) => e.id === entId);
  if (!target) return { conflict: false, detail: "" };
  const held = holdings(tenant).filter((h) => h.identityId === identityId);
  const rules = sodRules(tenant);
  const hits: string[] = [];
  for (const r of rules) {
    const tA = entMatches({ function: target.fn, name: target.name }, r.fnA);
    const tB = entMatches({ function: target.fn, name: target.name }, r.fnB);
    if (!tA && !tB) continue;
    const otherSide = tA ? r.fnB : r.fnA;
    const held2 = held.find((h) => h.entId !== entId && entMatches({ function: h.fn, name: h.name }, otherSide));
    if (held2) hits.push(`${r.name}: "${target.name}" + already-held "${held2.name}" (${r.risk})`);
  }
  return { conflict: hits.length > 0, detail: hits.join(" · ") };
}

// ── access requests + JIT ─────────────────────────────────────────────────────
export function requestAccess(tenant: number, p: { identityId: number; entitlementId: number; justification?: string; jitHours?: number }, by: string): { id: number; sodConflict: boolean; sodDetail: string } {
  const db = xo();
  const ent = entitlements(tenant).find((e) => e.id === num(p.entitlementId));
  const iname = (has(db, "IDENTITY") ? (db.prepare("SELECT IdentityName n FROM IDENTITY WHERE IdentityID=?").get(num(p.identityId)) as { n: string } | undefined)?.n : null) || `Identity ${num(p.identityId)}`;
  const chk = sodPreCheck(tenant, num(p.identityId), num(p.entitlementId));
  const id = allocId(db, "ACCESSREQUEST", "RequestID");
  db.prepare(`INSERT INTO ACCESSREQUEST (RequestID, RequestGUID, IdentityID, IdentityName, EntitlementID, EntitlementName, Justification, JitHours, Status, SodConflict, SodDetail, RequestedBy, CreatedDate, TenantID)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), num(p.identityId), iname, num(p.entitlementId), ent?.name || `Entitlement ${num(p.entitlementId)}`, String(p.justification || "").slice(0, 1000), num(p.jitHours), "pending", chk.conflict ? 1 : 0, chk.detail, String(by).slice(0, 120), now(), tenant);
  return { id, sodConflict: chk.conflict, sodDetail: chk.detail };
}

/** Approve/deny a request. Approve provisions the entitlement (JIT-expiring if JitHours>0). SoD-conflicting
 *  grants are BLOCKED unless overrideSod (then a violation is recorded — risk accepted with audit). */
export function decideRequest(tenant: number | null, id: number, decision: "approve" | "deny", by: string, overrideSod = false): { ok: boolean; status?: string; error?: string; needsOverride?: boolean } {
  const db = xo();
  const r = db.prepare(`SELECT * FROM ACCESSREQUEST WHERE RequestID=?`).get(id) as any;
  if (!r || (tenant != null && r.TenantID != null && num(r.TenantID) !== tenant)) return { ok: false, error: "not found" };
  if (String(r.Status) !== "pending") return { ok: false, error: `request is ${r.Status}` };
  if (decision === "deny") {
    db.prepare("UPDATE ACCESSREQUEST SET Status='denied', DecidedBy=?, DecidedDate=? WHERE RequestID=?").run(String(by), now(), id);
    return { ok: true, status: "denied" };
  }
  if (num(r.SodConflict) === 1 && !overrideSod) return { ok: false, needsOverride: true, error: "SoD conflict — approval requires explicit override (risk acceptance)" };
  const jit = num(r.JitHours);
  const exp = jit > 0 ? new Date(Date.now() + jit * 3600 * 1000).toISOString() : null;
  // provision the holding (idempotent on the unique (IdentityID, EntitlementID) index)
  const existing = db.prepare("SELECT IdentityEntitlementID id FROM IDENTITYENTITLEMENT WHERE IdentityID=? AND EntitlementID=?").get(num(r.IdentityID), num(r.EntitlementID)) as { id: number } | undefined;
  if (existing) db.prepare("UPDATE IDENTITYENTITLEMENT SET GrantType=?, ExpiresDate=?, AssignedDate=? WHERE IdentityEntitlementID=?").run(jit > 0 ? "jit" : "direct", exp, now(), existing.id);
  else db.prepare("INSERT INTO IDENTITYENTITLEMENT (IdentityEntitlementID, IdentityID, EntitlementID, GrantType, AssignedDate, ExpiresDate, Source, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(allocId(db, "IDENTITYENTITLEMENT", "IdentityEntitlementID"), num(r.IdentityID), num(r.EntitlementID), jit > 0 ? "jit" : "direct", now(), exp, "access-request", now(), r.TenantID ?? tenant);
  db.prepare("UPDATE ACCESSREQUEST SET Status='provisioned', DecidedBy=?, DecidedDate=?, ProvisionedDate=?, ExpiresDate=? WHERE RequestID=?").run(String(by), now(), now(), exp, id);
  detectSod(tenant); // surface any resulting violation (esp. an overridden one)
  return { ok: true, status: "provisioned" };
}

/** Expire time-bound (JIT) grants whose window has passed, and the requests behind them. */
export function jitSweep(tenant: number | null): { revoked: number; expired: number } {
  const db = xo();
  if (!has(db, "IDENTITYENTITLEMENT")) return { revoked: 0, expired: 0 };
  const nowIso = now();
  const stale = db.prepare(`SELECT IdentityEntitlementID id FROM IDENTITYENTITLEMENT WHERE GrantType='jit' AND ExpiresDate IS NOT NULL AND ExpiresDate < ?${tclause(tenant)}`).all(...targ(tenant, nowIso)) as { id: number }[];
  const tx = db.transaction(() => { for (const s of stale) db.prepare("DELETE FROM IDENTITYENTITLEMENT WHERE IdentityEntitlementID=?").run(s.id); });
  tx();
  const exp = db.prepare(`UPDATE ACCESSREQUEST SET Status='expired' WHERE Status='provisioned' AND ExpiresDate IS NOT NULL AND ExpiresDate < ?${tclause(tenant)}`).run(...targ(tenant, nowIso));
  if (stale.length) detectSod(tenant);
  return { revoked: stale.length, expired: num((exp as any).changes) };
}

export function setViolationStatus(tenant: number | null, id: number, status: string, note: string, by: string): { ok: boolean; error?: string } {
  const db = xo();
  const v = db.prepare("SELECT TenantID FROM SODVIOLATION WHERE SodViolationID=?").get(id) as any;
  if (!v || (tenant != null && v.TenantID != null && num(v.TenantID) !== tenant)) return { ok: false, error: "not found" };
  if (!["open", "mitigated", "accepted", "resolved"].includes(status)) return { ok: false, error: "invalid status" };
  db.prepare("UPDATE SODVIOLATION SET Status=?, Notes=?, DecidedBy=?, DecidedDate=? WHERE SodViolationID=?").run(status, String(note || "").slice(0, 1000), String(by), now(), id);
  return { ok: true };
}

export function addSodRule(tenant: number, p: { name: string; description?: string; functionA: string; functionB: string; risk?: string; mitigation?: string }): { id: number } {
  const db = xo();
  const id = allocId(db, "SODRULE", "SodRuleID");
  db.prepare("INSERT INTO SODRULE (SodRuleID, SodRuleGUID, Name, Description, FunctionA, FunctionB, Risk, MitigatingControl, Enabled, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,1,?,?)")
    .run(id, randomUUID(), String(p.name).slice(0, 200), String(p.description || "").slice(0, 1000), String(p.functionA || ""), String(p.functionB || ""), RISK_RANK[String(p.risk)] ? String(p.risk) : "high", String(p.mitigation || ""), now(), tenant);
  return { id };
}

/** Identity intelligence: holders of a high-risk/privileged entitlement who are the sole holder among ≥3 same-type peers. */
export function peerOutliers(tenant: number | null): { identityId: number; identityName: string; entitlement: string; risk: string; reason: string }[] {
  const ents = new Map(entitlements(tenant).map((e) => [e.id, e]));
  const held = holdings(tenant);
  if (!held.length) return [];
  const byType = new Map<string, Set<number>>();
  for (const h of held) { const k = h.type || "unknown"; const s = byType.get(k) || new Set<number>(); s.add(h.identityId); byType.set(k, s); }
  const holdersOf = new Map<number, { iid: number; type: string }[]>();
  for (const h of held) { const a = holdersOf.get(h.entId) || []; a.push({ iid: h.identityId, type: h.type || "unknown" }); holdersOf.set(h.entId, a); }
  const out: { identityId: number; identityName: string; entitlement: string; risk: string; reason: string }[] = [];
  const seen = new Set<string>();
  for (const h of held) {
    const e = ents.get(h.entId); if (!e) continue;
    if (!(e.priv || RISK_RANK[e.risk] >= 3)) continue;
    const peers = byType.get(h.type || "unknown")?.size || 1;
    const sameTypeHolders = (holdersOf.get(h.entId) || []).filter((x) => x.type === (h.type || "unknown")).length;
    if (peers >= 3 && sameTypeHolders === 1) {
      const key = `${h.identityId}:${h.entId}`; if (seen.has(key)) continue; seen.add(key);
      out.push({ identityId: h.identityId, identityName: h.identityName, entitlement: e.name, risk: e.risk, reason: `sole ${h.type || "identity"} holding "${e.name}" (of ${peers} peers)` });
    }
  }
  return out.slice(0, 50);
}

// ── dashboard ────────────────────────────────────────────────────────────────
export function accessGovDashboard(tenant: number | null): any {
  const db = xo();
  if (!has(db, "ENTITLEMENT")) return { summary: { entitlements: 0 }, sodViolations: [], pendingRequests: [], jitActive: [], topEntitlements: [], sodRules: [], outliers: [] };
  const ents = entitlements(tenant);
  const held = holdings(tenant);
  const holdersByEnt = new Map<number, Set<number>>();
  for (const h of held) { const s = holdersByEnt.get(h.entId) || new Set<number>(); s.add(h.identityId); holdersByEnt.set(h.entId, s); }
  const viol = (db.prepare(`SELECT SodViolationID id, SodRuleID ruleId, RuleName ruleName, IdentityID identityId, IdentityName identityName, LeftEntitlement leftEnt, RightEntitlement rightEnt, Risk risk, Status status, Notes notes, DetectedDate detectedDate FROM SODVIOLATION WHERE 1=1${tclause(tenant)} ORDER BY (Status='open') DESC, CASE Risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, SodViolationID DESC`).all(...targ(tenant)) as any[])
    .map((r) => ({ id: num(r.id), ruleId: num(r.ruleId), ruleName: String(r.ruleName || ""), identityId: num(r.identityId), identityName: String(r.identityName || ""), left: String(r.leftEnt || ""), right: String(r.rightEnt || ""), risk: String(r.risk || ""), status: String(r.status || ""), notes: String(r.notes || ""), detectedDate: String(r.detectedDate || "") }));
  const reqs = (db.prepare(`SELECT RequestID id, IdentityName identityName, EntitlementName entitlementName, Justification justification, JitHours jitHours, Status status, SodConflict sodConflict, SodDetail sodDetail, RequestedBy requestedBy, CreatedDate createdDate, ExpiresDate expiresDate, DecidedBy decidedBy FROM ACCESSREQUEST WHERE 1=1${tclause(tenant)} ORDER BY RequestID DESC LIMIT 200`).all(...targ(tenant)) as any[])
    .map((r) => ({ id: num(r.id), identityName: String(r.identityName || ""), entitlementName: String(r.entitlementName || ""), justification: String(r.justification || ""), jitHours: num(r.jitHours), status: String(r.status || ""), sodConflict: num(r.sodConflict) === 1, sodDetail: String(r.sodDetail || ""), requestedBy: String(r.requestedBy || ""), createdDate: String(r.createdDate || ""), expiresDate: String(r.expiresDate || ""), decidedBy: String(r.decidedBy || "") }));
  const nowMs = Date.now();
  const jitActive = held.filter((h) => h.grantType === "jit" && h.expires && new Date(h.expires).getTime() > nowMs)
    .map((h) => ({ identityName: h.identityName, entitlement: h.name, expiresDate: h.expires, hoursLeft: Math.max(0, Math.round((new Date(h.expires!).getTime() - nowMs) / 3600000)) }))
    .sort((a, b) => a.hoursLeft - b.hoursLeft).slice(0, 50);
  const topEntitlements = ents.map((e) => ({ id: e.id, name: e.name, app: e.app, risk: e.risk, privileged: !!e.priv, holders: holdersByEnt.get(e.id)?.size || 0 }))
    .sort((a, b) => (RISK_RANK[b.risk] - RISK_RANK[a.risk]) || (b.holders - a.holders)).slice(0, 50);
  const ruleRows = sodRules(tenant, false).map((r) => ({ id: r.id, name: r.name, functionA: r.fnA, functionB: r.fnB, risk: r.risk, mitigation: r.mitigation }));
  const outliers = peerOutliers(tenant);

  const openViol = viol.filter((v) => v.status === "open");
  const summary = {
    entitlements: ents.length,
    highRiskEnt: ents.filter((e) => RISK_RANK[e.risk] >= 3).length,
    privilegedEnt: ents.filter((e) => e.priv).length,
    assignments: held.length,
    identitiesWithAccess: new Set(held.map((h) => h.identityId)).size,
    sodRules: ruleRows.filter(() => true).length,
    sodViolations: openViol.length,
    sodCritical: openViol.filter((v) => RISK_RANK[v.risk] >= 3).length,
    sodMitigated: viol.filter((v) => v.status === "mitigated" || v.status === "accepted").length,
    pendingRequests: reqs.filter((r) => r.status === "pending").length,
    sodBlockedPending: reqs.filter((r) => r.status === "pending" && r.sodConflict).length,
    jitActive: jitActive.length,
    outliers: outliers.length,
  };
  return { summary, sodViolations: viol.slice(0, 200), pendingRequests: reqs.filter((r) => r.status === "pending"), requests: reqs.slice(0, 100), jitActive, topEntitlements, sodRules: ruleRows, outliers };
}

// ── demo seed ────────────────────────────────────────────────────────────────
export function seedAccessGovDemo(tenant: number): { created: number } {
  const db = xo();
  if (!has(db, "ENTITLEMENT")) return { created: 0 };
  if (db.prepare("SELECT 1 FROM ENTITLEMENT WHERE Source='demo' AND IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 1").get(tenant)) return { created: 0 };

  // entitlements (with SoD function codes)
  const ENTS: [string, string, string, string, number, string][] = [
    // name, app, type, risk, privileged, function
    ["AP Vendor Maintenance", "ERP-Finance", "transaction", "high", 0, "AP_VENDOR_MAINT"],
    ["AP Invoice Entry", "ERP-Finance", "transaction", "medium", 0, "AP_INVOICE"],
    ["AP Payment Run", "ERP-Finance", "transaction", "high", 0, "AP_PAYMENT"],
    ["GL Journal Post", "ERP-Finance", "transaction", "high", 0, "GL_POST"],
    ["PO Create", "ERP-Procure", "transaction", "medium", 0, "PO_CREATE"],
    ["PO Approve", "ERP-Procure", "transaction", "high", 0, "PO_APPROVE"],
    ["Domain Admins", "ActiveDirectory", "group", "critical", 1, "USER_ADMIN"],
    ["Security Audit Reader", "SIEM", "role", "medium", 0, "SEC_AUDIT"],
    ["Prod DB Owner", "Database", "role", "critical", 1, "DB_ADMIN"],
  ];
  const entId = new Map<string, number>();
  const insE = db.prepare("INSERT INTO ENTITLEMENT (EntitlementID, EntitlementGUID, Name, Application, EntitlementType, Description, Risk, Privileged, Function, Source, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
  for (const [name, app, type, risk, priv, fn] of ENTS) { const id = allocId(db, "ENTITLEMENT", "EntitlementID"); insE.run(id, randomUUID(), name, app, type, "", risk, priv, fn, "demo", now(), tenant); entId.set(fn, id); }

  // identities to assign to — reuse existing, else synthesize a few demo IDENTITY rows
  let ids = has(db, "IDENTITY") ? (db.prepare(`SELECT IdentityID id, IdentityName n, IdentityType t FROM IDENTITY WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 6`).all(tenant) as any[]).map((r) => ({ id: num(r.id), n: String(r.n), t: String(r.t || "user") })) : [];
  if (ids.length < 4 && has(db, "IDENTITY")) {
    const ic = new Set((db.prepare(`PRAGMA table_info("IDENTITY")`).all() as { name: string }[]).map((c) => c.name));
    for (const nm of ["alice.finance", "bob.procurement", "carol.dba", "dave.contractor"]) {
      const id = allocId(db, "IDENTITY", "IdentityID");
      const cols: string[] = ["IdentityID", "IdentityName"]; const vals: any[] = [id, nm];
      const add = (c: string, v: any): void => { if (ic.has(c)) { cols.push(c); vals.push(v); } };
      add("IdentityGUID", randomUUID()); add("IdentityType", "user"); add("IdentityClass", "Human");
      add("Status", "active"); add("PrivilegeLevel", "standard"); add("Provider", "demo"); add("CreatedDate", now()); add("TenantID", tenant);
      db.prepare(`INSERT INTO IDENTITY (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")})`).run(...vals);
      ids.push({ id, n: nm, t: "user" });
    }
  }
  if (!ids.length) return { created: 0 };

  const assign = (iid: number, fn: string, grant = "direct", expHrs = 0): void => {
    const eid = entId.get(fn); if (!eid) return;
    const exp = expHrs > 0 ? new Date(Date.now() + expHrs * 3600 * 1000).toISOString() : null;
    try { db.prepare("INSERT INTO IDENTITYENTITLEMENT (IdentityEntitlementID, IdentityID, EntitlementID, GrantType, AssignedDate, ExpiresDate, Source, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)").run(allocId(db, "IDENTITYENTITLEMENT", "IdentityEntitlementID"), iid, eid, grant, now(), exp, "demo", now(), tenant); } catch { /* unique */ }
  };
  // alice: vendor maint + payment = SoD violation; bob: PO create + approve = SoD; carol: DB admin (privileged outlier); broad audit access
  const a = ids[0].id, b = ids[1]?.id ?? ids[0].id, c = ids[2]?.id ?? ids[0].id, d = ids[3]?.id ?? ids[0].id;
  assign(a, "AP_VENDOR_MAINT"); assign(a, "AP_PAYMENT"); assign(a, "AP_INVOICE");
  assign(b, "PO_CREATE"); assign(b, "PO_APPROVE");
  assign(c, "DB_ADMIN"); assign(c, "GL_POST");
  assign(d, "USER_ADMIN", "jit", 8); // active JIT grant
  for (const x of ids) assign(x.id, "SEC_AUDIT");

  // SoD rules (classic toxic combinations)
  addSodRule(tenant, { name: "Create Vendor + Pay Invoice", description: "A user who can both maintain vendors and run payments can pay a fake vendor.", functionA: "AP_VENDOR_MAINT", functionB: "AP_PAYMENT", risk: "critical", mitigation: "Dual control on payment run" });
  addSodRule(tenant, { name: "Create PO + Approve PO", description: "Self-approval of purchase orders.", functionA: "PO_CREATE", functionB: "PO_APPROVE", risk: "high", mitigation: "Approval threshold + manager review" });
  addSodRule(tenant, { name: "Privileged Admin + Security Audit", description: "An admin who is also the auditor can hide their own actions.", functionA: "USER_ADMIN", functionB: "SEC_AUDIT", risk: "high", mitigation: "Independent SOC review of admin actions" });

  detectSod(tenant);

  // a couple of access requests (one SoD-conflicting → pending blocked; one clean)
  try { requestAccess(tenant, { identityId: b, entitlementId: entId.get("AP_PAYMENT")!, justification: "Cover for AP team during close", jitHours: 24 }, "demo"); } catch { /* */ }
  try { requestAccess(tenant, { identityId: d, entitlementId: entId.get("SEC_AUDIT")!, justification: "Quarterly access review", jitHours: 0 }, "demo"); } catch { /* */ }

  return { created: 1 };
}
