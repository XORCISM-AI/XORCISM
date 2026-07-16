/**
 * cc.ts — Common Criteria (ISO/IEC 15408) Security Target / TOE cockpit.
 *
 * Turns the imported CC catalogue (VOCABULARY "Common Criteria (ISO/IEC 15408)", populated by
 * xorcism_python/importers/import_cc.py from the official CC:2022 R1 parts) into a working
 * Security Target:
 *   • a TOE + Security Target (CCTARGET) with its conformance claim, scheme and target EAL;
 *   • the Security Functional Requirements the ST claims (CCSFR), picked from CC Part 2;
 *   • the Security Assurance Requirements it must meet (CCSAR) — **auto-seeded from the chosen
 *     EAL package** (CC Part 5 defines exactly which components each EAL comprises), each tracked
 *     met / partial / gap / n-a with its evidence.
 *
 * EUCC / CRA: under Commission Implementing Regulation (EU) 2024/482 (EUCC) the **AVA_VAN level —
 * not the EAL — is the classifier**: AVA_VAN.1-2 => assurance level 'substantial', AVA_VAN.3-5 =>
 * 'high'. CRA Article 27 gives a presumption of conformity to products certified under a
 * recognised European scheme at level 'substantial' or above, limited to the Annex I requirements
 * the certificate actually covers. euccLevel()/craPresumption() implement exactly that, linking
 * this cockpit to /cra-compliance (cra.ts).
 *
 * Tables live in XCOMPLIANCE (RBAC XCOMPLIANCE.AUDIT, like cra.ts / ess8.ts).
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();
export const CC_VOCAB = "Common Criteria (ISO/IEC 15408)";
export const CC_STATUS = ["draft", "in-evaluation", "certified", "archived"] as const;
export const SAR_STATUS = ["met", "partial", "gap", "na"] as const;
/** EUCC assurance levels are decided by the AVA_VAN component covered (Reg. (EU) 2024/482). */
export const EUCC_RULE: Record<string, string[]> = {
  substantial: ["AVA_VAN.1", "AVA_VAN.2"],
  high: ["AVA_VAN.3", "AVA_VAN.4", "AVA_VAN.5"],
};

export interface CcItem { cis: string; name: string; kind: string; level: string; cls: string; family: string | null }
export interface CcEal { id: string; name: string; components: string[] }
export interface CcCatalogue { sfr: CcItem[]; sar: CcItem[]; classes: CcItem[]; eals: CcEal[]; imported: boolean }

export function ensureCcTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS CCTARGET(
      TargetID INTEGER PRIMARY KEY, TargetGUID TEXT, TenantID INTEGER, Name TEXT, ToeName TEXT,
      ToeVersion TEXT, Developer TEXT, Scheme TEXT, CertId TEXT, EalTarget TEXT, PpClaim TEXT,
      ConformanceClaim TEXT, Status TEXT, Notes TEXT, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CCSFR(
      SfrID INTEGER PRIMARY KEY, TargetID INTEGER, Cis TEXT, Name TEXT, Cls TEXT,
      Rationale TEXT, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS CCSAR(
      SarID INTEGER PRIMARY KEY, TargetID INTEGER, Cis TEXT, Name TEXT, Cls TEXT,
      Status TEXT, Evidence TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_cctarget_tenant ON CCTARGET(TenantID);
    CREATE INDEX IF NOT EXISTS ix_ccsfr_target ON CCSFR(TargetID);
    CREATE INDEX IF NOT EXISTS ix_ccsar_target ON CCSAR(TargetID);
  `);
}

const tw = (tenant: number | null): string => (tenant == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");

// ── the imported CC catalogue (XORCISM.CONTROL under the CC vocabulary) ──
let CACHE: CcCatalogue | null = null;
export function ccCatalogue(): CcCatalogue {
  if (CACHE) return CACHE;
  const empty: CcCatalogue = { sfr: [], sar: [], classes: [], eals: [], imported: false };
  let db;
  try { db = getDb("XORCISM"); } catch { return empty; }
  const v = db.prepare("SELECT VocabularyID AS id FROM VOCABULARY WHERE VocabularyName = ?").get(CC_VOCAB) as { id: number } | undefined;
  if (!v) return empty;
  const rows = db.prepare("SELECT CIS AS cis, Statement AS name, ControlDescription AS d FROM CONTROL WHERE VocabularyID = ?")
    .all(v.id) as { cis: string; name: string; d: string }[];
  const sfr: CcItem[] = [], sar: CcItem[] = [], classes: CcItem[] = [], eals: CcEal[] = [];
  for (const r of rows) {
    const d = r.d || "";
    if (/^EAL\d$/.test(r.cis)) {
      const comps = (d.match(/[A-Z]{3}_[A-Z]{3}\.\d+/g) || []);
      eals.push({ id: r.cis, name: (r.name || "").replace(/^EAL\d\s*[-–]\s*/, ""), components: comps });
      continue;
    }
    const kind = /\bSAR\b/.test(d) ? "SAR" : "SFR";
    const level = /\bclass\b\s*$/.test(d) || / (SFR|SAR) class /.test(d) ? "class" : / (SFR|SAR) family /.test(d) ? "family" : "component";
    const cm = /class ([A-Z]{3})/.exec(d);
    const fm = /family ([A-Z]{3}_[A-Z]{3})/.exec(d);
    const item: CcItem = { cis: r.cis, name: r.name, kind, level, cls: cm ? cm[1] : r.cis.slice(0, 3), family: fm ? fm[1] : (level === "family" ? r.cis : null) };
    if (level === "class") classes.push(item);
    else if (level === "component") (kind === "SAR" ? sar : sfr).push(item);
  }
  const byCis = (a: { cis: string }, b: { cis: string }) => a.cis.localeCompare(b.cis);
  CACHE = {
    sfr: sfr.sort(byCis), sar: sar.sort(byCis), classes: classes.sort(byCis),
    eals: eals.sort((a, b) => a.id.localeCompare(b.id)), imported: rows.length > 0,
  };
  return CACHE;
}

// ── EUCC / CRA ──────────────────────────────────────────────────────────────
/** EUCC assurance level from the AVA_VAN component(s) covered (Reg. (EU) 2024/482, Art. 3). */
export function euccLevel(components: string[]): { level: "high" | "substantial" | "none"; van: string | null } {
  const vans = components.filter((c) => c.startsWith("AVA_VAN.")).sort();
  const top = vans.length ? vans[vans.length - 1] : null;
  if (!top) return { level: "none", van: null };
  if (EUCC_RULE.high.includes(top)) return { level: "high", van: top };
  if (EUCC_RULE.substantial.includes(top)) return { level: "substantial", van: top };
  return { level: "none", van: top };
}

/** CRA Art. 27 presumption of conformity from an EUCC assurance level. */
export function craPresumption(level: string): { eligible: boolean; note: string } {
  if (level === "high" || level === "substantial")
    return {
      eligible: true,
      note: `An EUCC certificate at assurance level '${level}' gives a presumption of conformity with the CRA essential requirements (Art. 27) — but only to the extent the certificate actually covers them. Map the covered Annex I requirements in /cra-compliance.`,
    };
  return { eligible: false, note: "No AVA_VAN component is claimed, so the ST is not yet EUCC-classifiable (EUCC needs AVA_VAN.1+ for 'substantial'). No CRA Art. 27 presumption." };
}

// ── targets ─────────────────────────────────────────────────────────────────
export interface CcTargetRow {
  id: number; name: string; toeName: string; toeVersion: string; developer: string; scheme: string;
  certId: string; eal: string; ppClaim: string; conformanceClaim: string; status: string; notes: string;
  sfrs: number; sars: number; met: number; conformance: number; eucc: string; van: string | null; craEligible: boolean;
}

function rowToTarget(db: ReturnType<typeof getDb>, r: any): CcTargetRow {
  const sfrs = (db.prepare("SELECT COUNT(*) n FROM CCSFR WHERE TargetID=?").get(r.TargetID) as { n: number }).n;
  const sars = db.prepare("SELECT Cis, Status FROM CCSAR WHERE TargetID=?").all(r.TargetID) as { Cis: string; Status: string }[];
  const met = sars.filter((s) => s.Status === "met").length;
  const scored = sars.filter((s) => s.Status !== "na").length;
  const e = euccLevel(sars.map((s) => s.Cis));
  return {
    id: r.TargetID, name: r.Name || "", toeName: r.ToeName || "", toeVersion: r.ToeVersion || "",
    developer: r.Developer || "", scheme: r.Scheme || "", certId: r.CertId || "", eal: r.EalTarget || "",
    ppClaim: r.PpClaim || "", conformanceClaim: r.ConformanceClaim || "", status: r.Status || "draft",
    notes: r.Notes || "", sfrs, sars: sars.length, met,
    conformance: scored ? Math.round((met / scored) * 100) : 0,
    eucc: e.level, van: e.van, craEligible: craPresumption(e.level).eligible,
  };
}

export function ccDashboard(tenant: number | null): {
  targets: CcTargetRow[];
  summary: { targets: number; certified: number; avgConformance: number; euccHigh: number; euccSubstantial: number; craEligible: number };
  catalogue: { imported: boolean; sfr: number; sar: number; eals: CcEal[] };
} {
  ensureCcTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM CCTARGET WHERE ${tw(tenant)} ORDER BY TargetID DESC`).all(...args) as any[];
  const targets = rows.map((r) => rowToTarget(db, r));
  const cat = ccCatalogue();
  const avg = targets.length ? Math.round(targets.reduce((n, t) => n + t.conformance, 0) / targets.length) : 0;
  return {
    targets,
    summary: {
      targets: targets.length,
      certified: targets.filter((t) => t.status === "certified").length,
      avgConformance: avg,
      euccHigh: targets.filter((t) => t.eucc === "high").length,
      euccSubstantial: targets.filter((t) => t.eucc === "substantial").length,
      craEligible: targets.filter((t) => t.craEligible).length,
    },
    catalogue: { imported: cat.imported, sfr: cat.sfr.length, sar: cat.sar.length, eals: cat.eals },
  };
}

export function ccTargetDetail(id: number, tenant: number | null): {
  target: CcTargetRow; sfrs: any[]; sars: any[]; eucc: { level: string; van: string | null; note: string };
} | null {
  ensureCcTables();
  const db = getDb("XCOMPLIANCE");
  const args = tenant == null ? [id] : [id, tenant];
  const r = db.prepare(`SELECT * FROM CCTARGET WHERE TargetID=? AND ${tw(tenant)}`).get(...args) as any;
  if (!r) return null;
  const target = rowToTarget(db, r);
  const sfrs = db.prepare("SELECT SfrID AS id, Cis AS cis, Name AS name, Cls AS cls, Rationale AS rationale FROM CCSFR WHERE TargetID=? ORDER BY Cis").all(id);
  const sars = db.prepare("SELECT SarID AS id, Cis AS cis, Name AS name, Cls AS cls, Status AS status, Evidence AS evidence FROM CCSAR WHERE TargetID=? ORDER BY Cis").all(id);
  const p = craPresumption(target.eucc);
  return { target, sfrs, sars, eucc: { level: target.eucc, van: target.van, note: p.note } };
}

export function createTarget(tenant: number | null, b: Record<string, unknown>): { id: number } {
  ensureCcTables();
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "CCTARGET", "TargetID");
  const s = (k: string, max = 200): string => String(b[k] ?? "").slice(0, max);
  db.prepare(
    `INSERT INTO CCTARGET (TargetID, TargetGUID, TenantID, Name, ToeName, ToeVersion, Developer, Scheme,
       CertId, EalTarget, PpClaim, ConformanceClaim, Status, Notes, CreatedDate)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, randomUUID(), tenant, s("name", 300) || "Untitled Security Target", s("toeName"), s("toeVersion", 60),
    s("developer"), s("scheme", 80), s("certId", 80), s("eal", 8), s("ppClaim", 200),
    s("conformanceClaim", 200) || "CC:2022 Part 2 conformant, Part 3 conformant",
    (CC_STATUS as readonly string[]).includes(s("status")) ? s("status") : "draft", s("notes", 2000), now());
  if (s("eal")) setEal(id, s("eal"));
  return { id };
}

export function deleteTarget(id: number): { ok: boolean } {
  ensureCcTables();
  const db = getDb("XCOMPLIANCE");
  db.prepare("DELETE FROM CCSFR WHERE TargetID=?").run(id);
  db.prepare("DELETE FROM CCSAR WHERE TargetID=?").run(id);
  db.prepare("DELETE FROM CCTARGET WHERE TargetID=?").run(id);
  return { ok: true };
}

/** Set the target EAL and (re)seed the assurance worklist from the EAL package's component set. */
export function setEal(targetId: number, eal: string): { ok: boolean; seeded: number } {
  ensureCcTables();
  const db = getDb("XCOMPLIANCE");
  const pkg = ccCatalogue().eals.find((e) => e.id === eal.toUpperCase());
  db.prepare("UPDATE CCTARGET SET EalTarget=? WHERE TargetID=?").run(pkg ? pkg.id : "", targetId);
  if (!pkg) return { ok: true, seeded: 0 };
  const byCis = new Map(ccCatalogue().sar.map((s) => [s.cis, s] as const));
  const prev = new Map((db.prepare("SELECT Cis, Status, Evidence FROM CCSAR WHERE TargetID=?").all(targetId) as any[])
    .map((r) => [r.Cis, r] as const));
  db.prepare("DELETE FROM CCSAR WHERE TargetID=?").run(targetId);
  const ins = db.prepare("INSERT INTO CCSAR (SarID, TargetID, Cis, Name, Cls, Status, Evidence, CreatedDate) VALUES (?,?,?,?,?,?,?,?)");
  let id = allocId(db, "CCSAR", "SarID");
  const tx = db.transaction(() => {
    for (const cis of pkg.components) {
      const meta = byCis.get(cis);
      const old = prev.get(cis);                    // keep an existing assessment when the EAL changes
      ins.run(id++, targetId, cis, meta?.name || cis, cis.slice(0, 3), old?.Status || "gap", old?.Evidence || "", now());
    }
  });
  tx();
  return { ok: true, seeded: pkg.components.length };
}

export function selectSfr(targetId: number, cis: string, rationale?: string): { ok: boolean; error?: string } {
  ensureCcTables();
  const meta = ccCatalogue().sfr.find((s) => s.cis === cis.toUpperCase());
  if (!meta) return { ok: false, error: "unknown SFR component" };
  const db = getDb("XCOMPLIANCE");
  if (db.prepare("SELECT 1 FROM CCSFR WHERE TargetID=? AND Cis=?").get(targetId, meta.cis)) return { ok: true };
  db.prepare("INSERT INTO CCSFR (SfrID, TargetID, Cis, Name, Cls, Rationale, CreatedDate) VALUES (?,?,?,?,?,?,?)")
    .run(allocId(db, "CCSFR", "SfrID"), targetId, meta.cis, meta.name, meta.cls, (rationale || "").slice(0, 1000), now());
  return { ok: true };
}

export function removeSfr(id: number): { ok: boolean } {
  ensureCcTables();
  getDb("XCOMPLIANCE").prepare("DELETE FROM CCSFR WHERE SfrID=?").run(id);
  return { ok: true };
}

export function assessSar(id: number, status: string, evidence?: string): { ok: boolean; error?: string } {
  ensureCcTables();
  if (!(SAR_STATUS as readonly string[]).includes(status)) return { ok: false, error: "invalid status" };
  getDb("XCOMPLIANCE").prepare("UPDATE CCSAR SET Status=?, Evidence=? WHERE SarID=?")
    .run(status, (evidence || "").slice(0, 2000), id);
  return { ok: true };
}

/** Demo seed (tenant only) — an EAL4 Security Target part-way through evaluation. */
export function seedCcDemo(tenant: number): { targets: number } {
  ensureCcTables();
  const db = getDb("XCOMPLIANCE");
  if (Number((db.prepare("SELECT COUNT(*) n FROM CCTARGET WHERE TenantID=?").get(tenant) as { n: number }).n)) return { targets: 0 };
  if (!ccCatalogue().imported) return { targets: 0 };
  const { id } = createTarget(tenant, {
    name: "XORCISM Gateway Security Target", toeName: "XORCISM Secure Gateway", toeVersion: "2.4",
    developer: "XORCISM", scheme: "EUCC", eal: "EAL4", status: "in-evaluation",
    conformanceClaim: "CC:2022 Part 2 conformant, Part 3 conformant, EAL4",
    notes: "Demo Security Target seeded by XORCISM.",
  });
  for (const cis of ["FAU_GEN.1", "FCS_COP.1", "FDP_ACC.1", "FIA_UAU.2", "FIA_UID.2", "FMT_SMR.1", "FPT_STM.1", "FTP_TRP.1"])
    selectSfr(id, cis, "Claimed by the demo ST.");
  const sars = db.prepare("SELECT SarID, Cis FROM CCSAR WHERE TargetID=?").all(id) as { SarID: number; Cis: string }[];
  for (const s of sars) {
    if (/^(ASE_|AGD_|ALC_CMC|ALC_CMS|ALC_DEL)/.test(s.Cis)) assessSar(s.SarID, "met", "Evidence delivered to the ITSEF.");
    else if (/^(ADV_FSP|ADV_TDS|ATE_)/.test(s.Cis)) assessSar(s.SarID, "partial", "Draft under review by the evaluator.");
  }
  return { targets: 1 };
}
