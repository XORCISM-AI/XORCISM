/**
 * frameworks.ts — Frameworks management (Compliance).
 *
 * A governance pane over XORCISM.FRAMEWORK: the catalogue of compliance/security frameworks
 * (ISO 27001, NIST 800-53, PCI DSS, …), each of which can be **mapped to a VOCABULARY** — the
 * controlled vocabulary that holds its controls catalogue (VOCABULARY ⋈ CONTROL.VocabularyID).
 * Mapping a framework to a vocabulary is what lets the rest of the platform resolve "this
 * framework's controls" (control-management, journeys, audits) from one place.
 *
 * FRAMEWORK is a global reference table (no TenantID — like VOCABULARY / TOOL); it already
 * carries a VocabularyID column, so this module manages the rows + the mapping, no schema churn.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
const nowIso = (): string => new Date().toISOString();

/** Defensive: make sure FRAMEWORK can hold the vocabulary mapping (legacy DBs already have it). */
export function ensureFrameworkVocabulary(): void {
  try {
    const db = getDb("XORCISM");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='FRAMEWORK'").get()) return;
    if (!cols("FRAMEWORK").has("VocabularyID")) db.exec(`ALTER TABLE "FRAMEWORK" ADD COLUMN "VocabularyID" INTEGER`);
  } catch { /* best-effort */ }
}

// Curated framework catalogue → mapped to a VOCABULARY by name when one exists in the DB.
const FRAMEWORK_SEED: { name: string; version: string; vocab: string | null; desc: string }[] = [
  { name: "ISO/IEC 27001:2022", version: "2022", vocab: "ISO27001", desc: "Information security management system (ISMS) requirements." },
  { name: "ISO/IEC 27002:2022", version: "2022", vocab: "ISO 27002", desc: "Information security controls (code of practice)." },
  { name: "NIST SP 800-53 Rev 5", version: "Rev 5", vocab: "NIST 800-53", desc: "Security & privacy controls for information systems and organizations." },
  { name: "NIST SP 800-30 Rev 1", version: "Rev 1", vocab: "NIST-800-30", desc: "Guide for conducting risk assessments." },
  { name: "CIS Critical Security Controls v8", version: "v8", vocab: "CIS", desc: "Prioritized set of safeguards to mitigate the most common attacks." },
  { name: "ISO/IEC 42001:2023", version: "2023", vocab: "ISO42001", desc: "Artificial intelligence management system (AIMS) requirements." },
  { name: "ISO/IEC 27031:2011", version: "2011", vocab: "ISO/IEC 27031", desc: "ICT readiness for business continuity (IRBC)." },
  { name: "CSA Cloud Controls Matrix v4", version: "v4", vocab: "CSA CCM", desc: "Cloud-specific security controls framework." },
  { name: "Secure Controls Framework (SCF)", version: "2024", vocab: "SCF", desc: "Metaframework of cybersecurity & data-privacy controls." },
  { name: "OWASP ASVS 4.0.3", version: "4.0.3", vocab: "OWASP ASVS 4.0.3", desc: "Application Security Verification Standard." },
  { name: "PCI DSS v4.0", version: "4.0", vocab: "PCI DSS v4.0", desc: "Payment Card Industry Data Security Standard." },
  { name: "ITMG IRCF v1.0", version: "1.0", vocab: "ITMG IRCF v1.0", desc: "Insider Risk Capability Framework." },
  { name: "NIS2 Directive", version: "EU 2022/2555", vocab: "NIS2", desc: "EU network & information security directive (NIS2)." },
  { name: "DORA", version: "EU 2022/2554", vocab: "DORA", desc: "Digital Operational Resilience Act." },
  // No matching VOCABULARY yet — seeded unmapped so they can be mapped from the UI.
  { name: "NIST CSF 2.0", version: "2.0", vocab: null, desc: "Cybersecurity Framework — Govern/Identify/Protect/Detect/Respond/Recover." },
  { name: "SOC 2", version: "2017 TSC", vocab: null, desc: "AICPA Trust Services Criteria." },
  { name: "GDPR", version: "EU 2016/679", vocab: null, desc: "General Data Protection Regulation." },
  { name: "EU AI Act", version: "2024/1689", vocab: null, desc: "EU Artificial Intelligence Act." },
];

/** Idempotent seed (by FrameworkName) so the management page is populated + pre-mapped. */
export function seedFrameworks(): void {
  try {
    const db = getDb("XORCISM");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='FRAMEWORK'").get()) return;
    ensureFrameworkVocabulary();
    const fc = cols("FRAMEWORK");
    if (!fc.has("FrameworkName")) return;
    const vocabId = new Map<string, number>();
    for (const v of db.prepare("SELECT VocabularyID, VocabularyName FROM VOCABULARY").all() as { VocabularyID: number; VocabularyName: string }[])
      vocabId.set(String(v.VocabularyName).trim().toLowerCase(), Number(v.VocabularyID));
    const existing = new Set((db.prepare("SELECT FrameworkName FROM FRAMEWORK").all() as { FrameworkName: string }[]).map((r) => String(r.FrameworkName)));
    const toAdd = FRAMEWORK_SEED.filter((f) => !existing.has(f.name));
    if (!toAdd.length) return;
    let id = allocId(db, "FRAMEWORK", "FrameworkID");
    const tx = db.transaction(() => {
      for (const f of toAdd) {
        const rec: Record<string, unknown> = {
          FrameworkID: id++, FrameworkName: f.name, FrameworkVersion: f.version,
          FrameworkDescription: f.desc, VocabularyID: f.vocab ? (vocabId.get(f.vocab.toLowerCase()) ?? null) : null,
          CreatedDate: nowIso(), ValidFromDate: nowIso(), isEncrypted: 0,
        };
        if (fc.has("FrameworkGUID")) rec.FrameworkGUID = randomUUID();
        const keys = Object.keys(rec).filter((k) => fc.has(k));
        db.prepare(`INSERT INTO "FRAMEWORK" (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
      }
    });
    tx();
    console.log(`[seed] XORCISM.FRAMEWORK ← +${toAdd.length} frameworks`);
  } catch (e) { console.warn(`[seed] FRAMEWORK: ${(e as Error).message}`); }
}

export interface VocabRef { id: number; name: string; version: string | null; reference: string | null; controls: number }
export interface FrameworkRow {
  id: number; name: string; version: string | null; description: string | null;
  vocabularyId: number | null; vocabularyName: string | null; controls: number; mapped: boolean;
}
export interface FrameworksInventory {
  rows: FrameworkRow[];
  vocabularies: VocabRef[];
  summary: { total: number; mapped: number; unmapped: number; controlsCovered: number; vocabularies: number };
}

/** Control counts per VocabularyID (CONTROL.VocabularyID), computed once. */
function controlCounts(): Map<number, number> {
  const m = new Map<number, number>();
  try {
    const db = getDb("XORCISM");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROL'").get()) return m;
    if (!cols("CONTROL").has("VocabularyID")) return m;
    for (const r of db.prepare("SELECT VocabularyID, COUNT(*) n FROM CONTROL WHERE VocabularyID IS NOT NULL GROUP BY VocabularyID").all() as { VocabularyID: number; n: number }[])
      m.set(Number(r.VocabularyID), Number(r.n));
  } catch { /* */ }
  return m;
}

export function listVocabularies(): VocabRef[] {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='VOCABULARY'").get()) return [];
  const vc = cols("VOCABULARY");
  const counts = controlCounts();
  const verCol = vc.has("VocabularyVersion") ? "VocabularyVersion" : "NULL AS VocabularyVersion";
  const refCol = vc.has("VocabularyReference") ? "VocabularyReference" : "NULL AS VocabularyReference";
  return (db.prepare(`SELECT VocabularyID, VocabularyName, ${verCol}, ${refCol} FROM VOCABULARY ORDER BY VocabularyName COLLATE NOCASE`).all() as Record<string, unknown>[])
    .map((v) => ({ id: Number(v.VocabularyID), name: String(v.VocabularyName ?? "").trim(), version: v.VocabularyVersion ? String(v.VocabularyVersion) : null, reference: v.VocabularyReference ? String(v.VocabularyReference) : null, controls: counts.get(Number(v.VocabularyID)) ?? 0 }));
}

export function frameworksInventory(): FrameworksInventory {
  const empty: FrameworksInventory = { rows: [], vocabularies: [], summary: { total: 0, mapped: 0, unmapped: 0, controlsCovered: 0, vocabularies: 0 } };
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='FRAMEWORK'").get()) return empty;
  ensureFrameworkVocabulary();
  const fc = cols("FRAMEWORK");
  if (!fc.has("FrameworkName")) return empty;
  const counts = controlCounts();
  const vocabName = new Map<number, string>();
  for (const v of db.prepare("SELECT VocabularyID, VocabularyName FROM VOCABULARY").all() as { VocabularyID: number; VocabularyName: string }[])
    vocabName.set(Number(v.VocabularyID), String(v.VocabularyName).trim());
  const verCol = fc.has("FrameworkVersion") ? "FrameworkVersion" : "NULL AS FrameworkVersion";
  const descCol = fc.has("FrameworkDescription") ? "FrameworkDescription" : "NULL AS FrameworkDescription";
  const vocCol = fc.has("VocabularyID") ? "VocabularyID" : "NULL AS VocabularyID";
  const rows: FrameworkRow[] = (db.prepare(`SELECT FrameworkID, FrameworkName, ${verCol}, ${descCol}, ${vocCol} FROM FRAMEWORK ORDER BY FrameworkName COLLATE NOCASE`).all() as Record<string, unknown>[])
    .map((f) => {
      const vid = f.VocabularyID != null ? Number(f.VocabularyID) : null;
      return {
        id: Number(f.FrameworkID), name: String(f.FrameworkName ?? "").trim() || `Framework #${f.FrameworkID}`,
        version: f.FrameworkVersion ? String(f.FrameworkVersion) : null, description: f.FrameworkDescription ? String(f.FrameworkDescription) : null,
        vocabularyId: vid, vocabularyName: vid != null ? (vocabName.get(vid) ?? `#${vid}`) : null,
        controls: vid != null ? (counts.get(vid) ?? 0) : 0, mapped: vid != null,
      };
    });
  const mapped = rows.filter((r) => r.mapped).length;
  return {
    rows, vocabularies: listVocabularies(),
    summary: { total: rows.length, mapped, unmapped: rows.length - mapped, controlsCovered: rows.reduce((s, r) => s + r.controls, 0), vocabularies: vocabName.size },
  };
}

/** Create a framework (optionally pre-mapped to a vocabulary). Returns the new FrameworkID. */
export function createFramework(p: { name: string; version?: string; description?: string; vocabularyId?: number | null }): { id: number } {
  const db = getDb("XORCISM");
  ensureFrameworkVocabulary();
  const fc = cols("FRAMEWORK");
  const name = p.name.trim();
  if (!name) throw new Error("name required");
  if (db.prepare("SELECT 1 FROM FRAMEWORK WHERE FrameworkName = ?").get(name)) throw new Error("a framework with this name already exists");
  const id = allocId(db, "FRAMEWORK", "FrameworkID");
  const rec: Record<string, unknown> = {
    FrameworkID: id, FrameworkName: name.slice(0, 200), FrameworkVersion: (p.version || "").slice(0, 60) || null,
    FrameworkDescription: (p.description || "").slice(0, 1000) || null,
    VocabularyID: p.vocabularyId != null ? Number(p.vocabularyId) : null, CreatedDate: nowIso(), ValidFromDate: nowIso(), isEncrypted: 0,
  };
  if (fc.has("FrameworkGUID")) rec.FrameworkGUID = randomUUID();
  const keys = Object.keys(rec).filter((k) => fc.has(k));
  db.prepare(`INSERT INTO "FRAMEWORK" (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  return { id };
}

/** Map (or unmap, with null) a framework to a VOCABULARY. */
export function setFrameworkVocabulary(frameworkId: number, vocabularyId: number | null): { ok: boolean; controls: number } {
  const db = getDb("XORCISM");
  ensureFrameworkVocabulary();
  if (vocabularyId != null && !db.prepare("SELECT 1 FROM VOCABULARY WHERE VocabularyID = ?").get(vocabularyId))
    throw new Error("unknown vocabulary");
  const r = db.prepare("UPDATE FRAMEWORK SET VocabularyID = ? WHERE FrameworkID = ?").run(vocabularyId, frameworkId);
  if (!r.changes) throw new Error("framework not found");
  return { ok: true, controls: vocabularyId != null ? (controlCounts().get(vocabularyId) ?? 0) : 0 };
}
