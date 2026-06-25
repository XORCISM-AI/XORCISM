/**
 * osv.ts — OSV.dev integration (https://google.github.io/osv.dev/api/).
 *
 * Two uses:
 *   • Enrich the VULNERABILITY form from an identifier (CVE, GHSA…)
 *     without writing to the database — normalizeOsv() returns the XVULNERABILITY fields.
 *   • Import a new VULNERABILITY (or update the existing one) into
 *     XVULNERABILITY.db — importOsv().
 *
 * Import conventions aligned with the NVD import (see project memory):
 *   VULGUID = VULReferential = VULReferentialID = VULName = VULShortName = id;
 *   bulk UPDATEs target VULReferentialID (the only indexed column).
 *   VulnerabilityID is NOT auto-incremented → allocated via MAX(VulnerabilityID)+1.
 */
import { allocId, getDb } from "./db";

const OSV_API = (process.env.OSV_API_URL || "https://api.osv.dev").replace(/\/$/, "");
const OSV_ID_RE = /^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9.\-_]+$/; // CVE-…, GHSA-…, PYSEC-…, etc.

/** Plausible OSV identifier format (prefix-… : CVE, GHSA, PYSEC, OSV, …). */
export function isValidOsvId(id: string): boolean {
  return OSV_ID_RE.test(id);
}

export interface OsvNormalized {
  referential: string;
  fields: Record<string, string | number>; // XVULNERABILITY columns → value
  summary: string; // short label for the UI
  cvssVector: string | null;
}

/** Fetches an OSV record by identifier (GET /v1/vulns/{id}). */
export async function fetchOsv(id: string): Promise<Record<string, any>> {
  if (!OSV_ID_RE.test(id)) throw new Error("Identifiant OSV invalide");
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const r = await fetch(`${OSV_API}/v1/vulns/${encodeURIComponent(id)}`, {
      headers: { Accept: "application/json" },
      signal: ctrl.signal,
    });
    if (r.status === 404) throw new Error(`Introuvable dans OSV : ${id}`);
    if (!r.ok) throw new Error(`OSV ${r.status}`);
    return (await r.json()) as Record<string, any>;
  } finally {
    clearTimeout(timer);
  }
}

// ── CVSS v3.x: vector → NVD metrics + base score computation ────────────

const AV_WORD: Record<string, string> = { N: "NETWORK", A: "ADJACENT_NETWORK", L: "LOCAL", P: "PHYSICAL" };
const LHN_WORD: Record<string, string> = { H: "HIGH", L: "LOW", N: "NONE" };
const AC_WORD: Record<string, string> = { L: "LOW", H: "HIGH" };

/** Parses a "CVSS:3.x/AV:…/…" vector into a dictionary of metrics. */
function parseCvssVector(vector: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (k && v && k !== "CVSS") out[k] = v;
  }
  return out;
}

/** CVSS v3.1 "roundup" rounding (spec: via integers, robust against float noise). */
function cvssRoundup(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.x base score from the vector; null if metrics are incomplete. */
function cvss3BaseScore(m: Record<string, string>): number | null {
  const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number> = { L: 0.77, H: 0.44 };
  const UI: Record<string, number> = { N: 0.85, R: 0.62 };
  const IMP: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const changed = m.S === "C";
  const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.C || !m.I || !m.A) return null;
  if (!(m.AV in AV) || !(m.AC in AC) || !(m.UI in UI)) return null;

  const iss = 1 - (1 - IMP[m.C]) * (1 - IMP[m.I]) * (1 - IMP[m.A]);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const prTab = changed ? PR_C : PR_U;
  const expl = 8.22 * AV[m.AV] * AC[m.AC] * prTab[m.PR] * UI[m.UI];
  const base = changed
    ? Math.min(1.08 * (impact + expl), 10)
    : Math.min(impact + expl, 10);
  return cvssRoundup(base);
}

/** Picks the best severity entry (preference v3.1 > v3.0). */
function pickCvssVector(osv: Record<string, any>): string | null {
  const sev: any[] = Array.isArray(osv.severity) ? osv.severity : [];
  const v3 = sev.find((s) => s?.type === "CVSS_V3" && typeof s.score === "string");
  if (v3) return v3.score;
  const any = sev.find((s) => typeof s?.score === "string" && s.score.startsWith("CVSS:"));
  return any ? any.score : null;
}

/** Normalizes an OSV record into the XVULNERABILITY.VULNERABILITY columns. */
export function normalizeOsv(osv: Record<string, any>): OsvNormalized {
  const id = String(osv.id || "");
  const fields: Record<string, string | number> = {};

  // Identity (import convention) — the user can override in the form.
  for (const col of ["VULReferential", "VULReferentialID", "VULGUID", "VULName", "VULShortName"]) {
    fields[col] = id;
  }

  const desc = String(osv.details || osv.summary || "").trim();
  if (desc) fields.VULDescription = desc;
  if (osv.published) {
    fields.VULPublishedDate = String(osv.published);
    fields.ValidFromDate = String(osv.published);
  }
  if (osv.modified) fields.VULModifiedDate = String(osv.modified);
  fields.VULType = "OSV";

  const vector = pickCvssVector(osv);
  if (vector) {
    const m = parseCvssVector(vector);
    if (m.AV && AV_WORD[m.AV]) fields.CVSSMetricAccessVector = AV_WORD[m.AV];
    if (m.AC && AC_WORD[m.AC]) fields.CVSSMetricAccessComplexity = AC_WORD[m.AC];
    if (m.PR && LHN_WORD[m.PR]) fields.CVSSMetricAuthentication = LHN_WORD[m.PR]; // PR (v3) → Authentication
    if (m.C && LHN_WORD[m.C]) fields.CVSSMetricConfImpact = LHN_WORD[m.C];
    if (m.I && LHN_WORD[m.I]) fields.CVSSMetricIntegImpact = LHN_WORD[m.I];
    if (m.A && LHN_WORD[m.A]) fields.CVSSMetricAvailImpact = LHN_WORD[m.A];
    const score = cvss3BaseScore(m);
    if (score != null) fields.CVSSBaseScore = score;
  }

  // First relevant reference (advisory first) → VULURL.
  const refs: any[] = Array.isArray(osv.references) ? osv.references : [];
  const advisory = refs.find((r) => r?.type === "ADVISORY" && r.url) || refs.find((r) => r?.url);
  if (advisory?.url) fields.VULURL = String(advisory.url);

  // Details: aliases + up to 10 references (traceability).
  const aliases: string[] = Array.isArray(osv.aliases) ? osv.aliases : [];
  const detail: string[] = [];
  if (aliases.length) detail.push("Aliases: " + aliases.join(", "));
  if (refs.length) {
    detail.push("References:");
    for (const r of refs.slice(0, 10)) if (r?.url) detail.push(`- ${r.url}`);
  }
  if (detail.length) fields.VULDetailedInformation = detail.join("\n");

  const summary = String(osv.summary || (desc ? desc.slice(0, 120) : id));
  return { referential: id, fields, summary, cvssVector: vector };
}

/** Fetches + normalizes (without writing) — to enrich the form. */
export async function lookupOsv(id: string): Promise<OsvNormalized> {
  return normalizeOsv(await fetchOsv(id));
}

export interface OsvImportResult {
  action: "inserted" | "updated";
  vulnerabilityId: number;
  referential: string;
}

/**
 * Generic upsert of a VULNERABILITY into XVULNERABILITY (shared OSV/CIRCL).
 * Matches by VULReferentialID (indexed); only writes real columns;
 * allocates VulnerabilityID = MAX+1 on insert (table without autoincrement).
 */
export function upsertVulnerability(
  referential: string,
  fields: Record<string, string | number>
): OsvImportResult {
  const db = getDb("XVULNERABILITY");
  const nowIso = new Date().toISOString();

  const existing = db
    .prepare(`SELECT VulnerabilityID FROM "VULNERABILITY" WHERE VULReferentialID = ? LIMIT 1`)
    .get(referential) as { VulnerabilityID: number } | undefined;

  const cols = new Set(
    (db.prepare(`PRAGMA table_info("VULNERABILITY")`).all() as { name: string }[]).map((c) => c.name)
  );
  const data: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(fields)) if (cols.has(k)) data[k] = v;

  if (existing) {
    data.VULModifiedDate = data.VULModifiedDate || nowIso;
    const set = Object.keys(data).map((c) => `"${c}" = @${c}`).join(", ");
    db.prepare(`UPDATE "VULNERABILITY" SET ${set} WHERE VULReferentialID = @ref`).run({ ...data, ref: referential });
    return { action: "updated", vulnerabilityId: existing.VulnerabilityID, referential };
  }

  const next = allocId(db, "VULNERABILITY", "VulnerabilityID");
  data.VulnerabilityID = next;
  if (cols.has("CreatedDate")) data.CreatedDate = nowIso;
  if (cols.has("isEncrypted")) data.isEncrypted = 0;
  const keys = Object.keys(data);
  db.prepare(
    `INSERT INTO "VULNERABILITY" (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map((k) => `@${k}`).join(", ")})`
  ).run(data);
  return { action: "inserted", vulnerabilityId: next, referential };
}

/**
 * Imports (or updates) a VULNERABILITY from OSV into XVULNERABILITY.
 */
export async function importOsv(id: string): Promise<OsvImportResult> {
  const norm = await lookupOsv(id);
  return upsertVulnerability(norm.referential, norm.fields);
}
