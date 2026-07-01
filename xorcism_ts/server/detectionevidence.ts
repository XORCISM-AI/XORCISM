/**
 * detectionevidence.ts — the PROOF behind a detection.
 *
 * A detection rule (Sigma / YARA) can carry the evidence that shows it does what it claims:
 *   • intel      — the CTI report / threat intel it was derived from
 *   • poc        — the proof-of-concept exploit / attack code it detects
 *   • log        — the log sample it was tested against (matched)
 *   • pcap       — the packet capture it was tested against
 *   • prompt     — the AI prompt that generated the rule
 *   • reference  — a link/citation that backs the claim
 *   • test-result — a recorded match/no-match outcome (matched / not-matched / partial)
 *
 * Text/URL evidence is inline (Content/Url); files (PCAP, logs, PoC) go to the content-addressed
 * blob store ([[blob-store]]). A per-detection "provenance" summary reports which proof classes are
 * present and a completeness score, so a reviewer can trust a rule, not just run it.
 */
import { randomUUID } from "crypto";
import { getDb, allocId } from "./db";
import { putBlob, readBlob } from "./blobstore";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const s = (v: unknown): string => (v == null ? "" : String(v));
const MAX_EVIDENCE_BYTES = 15 * 1024 * 1024; // 15 MB/file (base64 ~20 MB, under the 25 MB JSON body limit)

export const EVIDENCE_TYPES = ["intel", "poc", "log", "pcap", "prompt", "reference", "test-result"] as const;
/** The proof classes that make a detection "trustworthy" (for the completeness score). */
const PROVENANCE_CLASSES = ["intel", "poc", "log", "prompt", "reference", "test-result"];
export const VERDICTS = ["matched", "not-matched", "partial"];
const DETECTIONS: Record<string, { db: string; table: string; idCol: string; nameCol: string }> = {
  sigma: { db: "XTHREAT", table: "SIGMARULE", idCol: "SigmaRuleID", nameCol: "SigmaRuleName" },
  yara: { db: "XTHREAT", table: "YARARULE", idCol: "YaraRuleID", nameCol: "YaraRuleName" },
};

const tw = (tenant: number | null): string => (tenant != null ? "(TenantID = ? OR TenantID IS NULL)" : "1=1");
const ta = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

function detectionName(type: string, id: number): string {
  const d = DETECTIONS[type];
  if (!d) return "";
  const db = getDb(d.db);
  if (!has(db, d.table)) return "";
  try { const r = db.prepare(`SELECT ${d.nameCol} n FROM ${d.table} WHERE ${d.idCol}=?`).get(id) as { n?: string } | undefined; return s(r?.n); } catch { return ""; }
}

const evidenceRow = (r: any): any => ({
  id: r.EvidenceID, detectionType: r.DetectionType, detectionId: r.DetectionID, detectionName: r.DetectionName,
  evidenceType: r.EvidenceType, title: r.Title, content: r.Content, url: r.Url, source: r.Source, verdict: r.Verdict,
  fileName: r.FileName, contentType: r.ContentType, sha256: r.Sha256, size: r.Size,
  hasFile: !!r.Sha256, addedBy: r.AddedByName, createdDate: r.CreatedDate,
});

/** All evidence for a detection + a provenance summary (which proof classes present, completeness). */
export function listEvidence(type: string, id: number, tenant: number | null): any {
  const db = getDb("XTHREAT");
  if (!has(db, "DETECTIONEVIDENCE")) return { items: [], summary: emptySummary() };
  const rows = db.prepare(`SELECT * FROM DETECTIONEVIDENCE WHERE DetectionType=? AND DetectionID=? AND ${tw(tenant)} ORDER BY EvidenceID DESC`).all(type, id, ...ta(tenant)) as any[];
  const items = rows.map(evidenceRow);
  const present = new Set(items.map((i) => i.evidenceType));
  const covered = PROVENANCE_CLASSES.filter((c) => present.has(c));
  return {
    items,
    summary: {
      total: items.length,
      byType: EVIDENCE_TYPES.reduce((m: any, t) => { m[t] = items.filter((i) => i.evidenceType === t).length; return m; }, {}),
      provenanceClasses: PROVENANCE_CLASSES.map((c) => ({ type: c, present: present.has(c) })),
      completeness: Math.round((covered.length / PROVENANCE_CLASSES.length) * 100),
      validated: items.some((i) => i.evidenceType === "test-result" && i.verdict === "matched"),
      files: items.filter((i) => i.hasFile).length,
    },
  };
}
const emptySummary = () => ({ total: 0, byType: {}, provenanceClasses: PROVENANCE_CLASSES.map((c) => ({ type: c, present: false })), completeness: 0, validated: false, files: 0 });

/** Add text / URL evidence (intel summary, PoC snippet, prompt text, reference link, test result). */
export function addEvidence(type: string, id: number, tenant: number | null, b: any, user: { id?: number | null; name?: string }): { id: number } | { error: string } {
  if (!DETECTIONS[type]) return { error: "unknown detection type" };
  const et = s(b.evidenceType);
  if (!(EVIDENCE_TYPES as readonly string[]).includes(et)) return { error: "invalid evidence type" };
  const db = getDb("XTHREAT");
  if (!has(db, "DETECTIONEVIDENCE")) return { error: "not available" };
  const eid = allocId(db, "DETECTIONEVIDENCE", "EvidenceID");
  db.prepare(`INSERT INTO DETECTIONEVIDENCE (EvidenceID, EvidenceGUID, DetectionType, DetectionID, DetectionName, EvidenceType, Title, Content, Url, Source, Verdict, AddedByUserID, AddedByName, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    eid, randomUUID(), type, id, detectionName(type, id).slice(0, 300), et, s(b.title).slice(0, 300),
    s(b.content).slice(0, 20000), s(b.url).slice(0, 1000), s(b.source).slice(0, 300),
    et === "test-result" ? (VERDICTS.includes(s(b.verdict)) ? s(b.verdict) : "matched") : null,
    user.id ?? null, s(user.name).slice(0, 120), new Date().toISOString(), tenant);
  return { id: eid };
}

/** Attach a file (base64) as evidence — PCAP, log sample, PoC file — stored in the CAS. */
export function addFileEvidence(type: string, id: number, tenant: number | null, b: any, user: { id?: number | null; name?: string }): { id: number; sha256: string; size: number } | { error: string } {
  if (!DETECTIONS[type]) return { error: "unknown detection type" };
  const et = s(b.evidenceType) || "pcap";
  if (!(EVIDENCE_TYPES as readonly string[]).includes(et)) return { error: "invalid evidence type" };
  const raw = s(b.dataBase64).replace(/^data:[^;]+;base64,/, "");
  if (!raw) return { error: "no file data" };
  let buf: Buffer;
  try { buf = Buffer.from(raw, "base64"); } catch { return { error: "invalid base64" }; }
  if (!buf.length) return { error: "empty file" };
  if (buf.length > MAX_EVIDENCE_BYTES) return { error: `file too large (max ${MAX_EVIDENCE_BYTES / 1024 / 1024} MB)` };
  const name = s(b.fileName || "evidence").slice(0, 260);
  const ct = s(b.contentType || "application/octet-stream").slice(0, 120);
  const put = putBlob(buf, { name, contentType: ct, pin: true }); // pin: evidence is retained, not GC'd
  const db = getDb("XTHREAT");
  if (!has(db, "DETECTIONEVIDENCE")) return { error: "not available" };
  const eid = allocId(db, "DETECTIONEVIDENCE", "EvidenceID");
  db.prepare(`INSERT INTO DETECTIONEVIDENCE (EvidenceID, EvidenceGUID, DetectionType, DetectionID, DetectionName, EvidenceType, Title, Source, FileName, ContentType, Sha256, Size, AddedByUserID, AddedByName, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    eid, randomUUID(), type, id, detectionName(type, id).slice(0, 300), et, s(b.title || name).slice(0, 300),
    s(b.source).slice(0, 300), name, ct, put.sha256, put.size, user.id ?? null, s(user.name).slice(0, 120), new Date().toISOString(), tenant);
  return { id: eid, sha256: put.sha256, size: put.size };
}

/** Fetch the bytes of a file evidence item (for download) — scoped to the tenant. */
export function readEvidenceFile(eid: number, tenant: number | null): { buf: Buffer; name: string; ct: string } | null {
  const db = getDb("XTHREAT");
  if (!has(db, "DETECTIONEVIDENCE")) return null;
  const r = db.prepare(`SELECT Sha256, FileName, ContentType FROM DETECTIONEVIDENCE WHERE EvidenceID=? AND ${tw(tenant)}`).get(eid, ...ta(tenant)) as any;
  if (!r || !r.Sha256) return null;
  const buf = readBlob(s(r.Sha256));
  if (!buf) return null;
  return { buf, name: s(r.FileName) || "evidence", ct: s(r.ContentType) || "application/octet-stream" };
}

export function removeEvidence(eid: number, tenant: number | null): { ok: boolean } {
  const db = getDb("XTHREAT");
  if (!has(db, "DETECTIONEVIDENCE")) return { ok: false };
  const r = db.prepare(`DELETE FROM DETECTIONEVIDENCE WHERE EvidenceID=? AND ${tw(tenant)}`).run(eid, ...ta(tenant));
  return { ok: r.changes > 0 };
}

/** Detections available to attach evidence to (Sigma + YARA), with their current evidence count + completeness. */
export function detectionPickList(tenant: number | null): any {
  const db = getDb("XTHREAT");
  const out: any[] = [];
  const counts = new Map<string, { n: number; classes: Set<string> }>();
  if (has(db, "DETECTIONEVIDENCE")) {
    for (const r of db.prepare(`SELECT DetectionType, DetectionID, EvidenceType FROM DETECTIONEVIDENCE WHERE ${tw(tenant)}`).all(...ta(tenant)) as any[]) {
      const k = `${r.DetectionType}:${r.DetectionID}`;
      const c = counts.get(k) || { n: 0, classes: new Set<string>() };
      c.n++; c.classes.add(r.EvidenceType); counts.set(k, c);
    }
  }
  for (const [type, d] of Object.entries(DETECTIONS)) {
    if (!has(db, d.table)) continue;
    try {
      for (const r of db.prepare(`SELECT ${d.idCol} id, ${d.nameCol} name FROM ${d.table} WHERE ${d.nameCol} IS NOT NULL ORDER BY ${d.idCol} DESC LIMIT 500`).all() as any[]) {
        const c = counts.get(`${type}:${r.id}`);
        const cov = c ? PROVENANCE_CLASSES.filter((x) => c.classes.has(x)).length : 0;
        out.push({ type, id: r.id, name: s(r.name), evidence: c?.n || 0, completeness: Math.round((cov / PROVENANCE_CLASSES.length) * 100) });
      }
    } catch { /* tolerate */ }
  }
  const withProof = out.filter((d) => d.evidence > 0).length;
  return { detections: out, summary: { total: out.length, withProof, fullyProven: out.filter((d) => d.completeness === 100).length, evidenceTypes: EVIDENCE_TYPES, verdicts: VERDICTS } };
}
