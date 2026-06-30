/**
 * ave.ts — AVE (Agentic Vulnerability Enumeration, bawbel/ave, Apache-2.0).
 *
 * A behavioral-classification standard for agentic-AI components (AI agents, skill files, MCP
 * servers, system prompts). Unlike CVE/OSV — which need a package version — AVE scores *behavioral*
 * classes (prompt injection, tool-allowlist breach, metamorphic supply-chain payloads, …) with
 * AIVSS (OWASP AIVSS: a CVSS base × an agentic amplification of autonomy / tool-use / self-modification
 * / etc.), and maps each to the OWASP Agentic Top 10, OWASP MCP Top 10, MITRE ATLAS and NIST AI RMF.
 *
 * XORCISM stores the AVE catalogue as reference records (XVULNERABILITY.AVERECORD), surfaced at /ave
 * and available to map AI-agent findings (AI Guardrails / AWARE / LLM-pentest) onto a stable taxonomy.
 */
import fs from "fs";
import path from "path";
import { getDb } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const s = (v: unknown): string => (v == null ? "" : Array.isArray(v) ? v.join(", ") : String(v));
const num = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) ? n : null; };
export const aveSeverity = (score: number | null): string =>
  score == null ? "" : score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";

/** Normalize one AVE record (its JSON schema) into an AVERECORD row. */
function normalizeAve(r: any): Record<string, any> | null {
  const id = s(r.ave_id || r.id).trim();
  if (!/^AVE-/i.test(id)) return null;
  const aivss = r.aivss || {};
  const score = num(r.aivss_score) ?? num(aivss.aivss_score);
  return {
    AveId: id, Title: s(r.title).slice(0, 300), AttackClass: s(r.attack_class).slice(0, 200),
    ComponentType: s(r.component_type).slice(0, 60), Description: s(r.description).slice(0, 4000),
    Severity: s(r.severity || aivss.aivss_severity) || aveSeverity(score), AivssScore: score,
    CvssBase: num(aivss.cvss_base), CvssVector: s(r.cvss_base_vector).slice(0, 120),
    OwaspAgentic: s(r.owasp_mapping), OwaspMcp: s(r.owasp_mcp || aivss.owasp_mcp_mapping),
    NistAiRmf: s(r.nist_ai_rmf_mapping), MitreAtlas: s(r.mitre_atlas_mapping),
    BehavioralVector: s(r.behavioral_vector), BehavioralFingerprint: s(r.behavioral_fingerprint).slice(0, 500),
    MutationCount: num(r.mutation_count), DetectionMethodology: s(r.detection_methodology).slice(0, 2000),
    Iocs: s(r.indicators_of_compromise).slice(0, 2000), Remediation: s(r.remediation).slice(0, 2000),
    AffectedPlatforms: s(r.affected_platforms), Status: s(r.status).slice(0, 30),
    Researcher: s(r.researcher).slice(0, 120), Published: s(r.published).slice(0, 40),
    LastUpdated: s(r.last_updated).slice(0, 40), SpecVersion: s(aivss.spec_version || r.schema_version).slice(0, 20),
  };
}

/** Upsert a batch of AVE records (idempotent by AveId). Returns counts. */
export function importAve(records: any[], source = "AVE"): { imported: number; updated: number } {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "AVERECORD")) return { imported: 0, updated: 0 };
  const now = new Date().toISOString();
  let imp = 0, upd = 0;
  const tx = db.transaction(() => {
    for (const raw of records) {
      const r = normalizeAve(raw);
      if (!r) continue;
      const exists = db.prepare("SELECT 1 FROM AVERECORD WHERE AveId = ?").get(r.AveId);
      const cols = Object.keys(r);
      if (exists) {
        db.prepare(`UPDATE AVERECORD SET ${cols.map((c) => `${c}=?`).join(",")}, Source=? WHERE AveId=?`).run(...cols.map((c) => r[c]), source.slice(0, 120), r.AveId);
        upd++;
      } else {
        db.prepare(`INSERT INTO AVERECORD (${cols.join(",")}, Source, CreatedDate) VALUES (${cols.map(() => "?").join(",")},?,?)`).run(...cols.map((c) => r[c]), source.slice(0, 120), now);
        imp++;
      }
    }
  });
  tx();
  return { imported: imp, updated: upd };
}

/** Catalogue + rollup, with optional severity / component-type / framework filters. */
export function aveCatalogue(filters?: { severity?: string; componentType?: string; q?: string }): any {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "AVERECORD")) return { records: [], summary: { total: 0 } };
  const where: string[] = [], args: any[] = [];
  if (filters?.severity) { where.push("UPPER(Severity)=?"); args.push(filters.severity.toUpperCase()); }
  if (filters?.componentType) { where.push("ComponentType=?"); args.push(filters.componentType); }
  if (filters?.q) { where.push("(Title LIKE ? OR AveId LIKE ? OR AttackClass LIKE ?)"); const q = `%${filters.q}%`; args.push(q, q, q); }
  const sql = `SELECT * FROM AVERECORD ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY AivssScore DESC, AveId`;
  const records = db.prepare(sql).all(...args) as any[];
  const all = where.length ? db.prepare("SELECT Severity, ComponentType, AivssScore, MitreAtlas FROM AVERECORD").all() as any[] : records;
  const by = (col: string): Record<string, number> => all.reduce((m: any, r: any) => { const k = s(r[col]) || "—"; m[k] = (m[k] || 0) + 1; return m; }, {});
  const atlasMapped = all.filter((r) => s(r.MitreAtlas).trim()).length;
  return {
    records,
    summary: {
      total: all.length,
      critical: all.filter((r) => /critical/i.test(s(r.Severity))).length,
      high: all.filter((r) => /high/i.test(s(r.Severity))).length,
      avgAivss: all.length ? Math.round((all.reduce((n, r) => n + (Number(r.AivssScore) || 0), 0) / all.length) * 10) / 10 : 0,
      atlasMapped, byComponent: by("ComponentType"), bySeverity: by("Severity"),
    },
  };
}

/** Seed the catalogue from the bundled connector sample (idempotent). */
export function seedAve(): { imported: number } {
  if (getDb("XVULNERABILITY").prepare("SELECT COUNT(*) n FROM AVERECORD").get() && (getDb("XVULNERABILITY").prepare("SELECT COUNT(*) n FROM AVERECORD").get() as { n: number }).n) return { imported: 0 };
  const candidates = [
    path.join(__dirname, "..", "..", "..", "connectors", "ave", "sample.json"),
    path.join(process.cwd(), "connectors", "ave", "sample.json"),
    path.join(process.cwd(), "..", "connectors", "ave", "sample.json"),
  ];
  for (const p of candidates) {
    try {
      if (!fs.existsSync(p)) continue;
      const doc = JSON.parse(fs.readFileSync(p, "utf-8"));
      const recs = Array.isArray(doc) ? doc : (doc.records || doc.ave_records || []);
      const r = importAve(recs, "AVE (bundled sample)");
      return { imported: r.imported };
    } catch { /* try next */ }
  }
  return { imported: 0 };
}

// ── bawbel-scanner findings (per-artifact AVE detections) ─────────────────────
const sevFromLevel = (lvl: string): string => (lvl === "error" ? "HIGH" : lvl === "warning" ? "MEDIUM" : lvl === "note" ? "LOW" : "");

/** Normalize the bawbel-scanner output (AVE-in-SARIF 2.1.0, or a flat {findings:[]}/array) into rows. */
export function normalizeScanFindings(input: any): any[] {
  let doc = input;
  if (typeof input === "string") { try { doc = JSON.parse(input); } catch { return []; } }
  const out: any[] = [];
  const isSarif = doc && (Array.isArray(doc.runs) || String(doc.$schema || "").includes("sarif"));
  if (isSarif) {
    for (const run of doc.runs || []) {
      const rules: Record<string, any> = {};
      try { for (const r of run.tool?.driver?.rules || []) rules[r.id] = r; } catch { /* */ }
      for (const res of run.results || []) {
        const rule = rules[res.ruleId] || {};
        const rp = rule.properties || {}, p = res.properties || {};
        const loc = (res.locations || [])[0]?.physicalLocation || {};
        out.push({
          aveId: s(res.ruleId), ruleId: s(p.rule_id || rule.name), title: s(rule.shortDescription?.text || rule.name),
          severity: s(rp.severity) || sevFromLevel(s(res.level)), aivss: num(rp.aivss_score), confidence: num(p.confidence),
          componentType: s(rp.component_type || p.component_type), file: s(loc.artifactLocation?.uri),
          line: num(loc.region?.startLine), message: s(res.message?.text), evidenceKind: s(p.evidence_kind),
          evidenceStage: s(p.evidence_stage), owaspMcp: s(rp.owasp_mcp), mitreAtlas: s(rp.mitre_atlas),
        });
      }
    }
    return out;
  }
  const arr = Array.isArray(doc) ? doc : (doc.findings || doc.ave_scan_findings || doc.results || []);
  for (const f of arr) {
    if (!f || typeof f !== "object") continue;
    out.push({
      aveId: s(f.ave_id || f.aveId || f.ruleId), ruleId: s(f.rule_id || f.ruleId), title: s(f.title || f.attack_class),
      severity: s(f.severity) || sevFromLevel(s(f.level)) || aveSeverity(num(f.aivss_score ?? f.aivss)),
      aivss: num(f.aivss_score ?? f.aivss), confidence: num(f.confidence), componentType: s(f.component_type),
      file: s(f.file || f.path || f.uri), line: num(f.line ?? f.startLine), message: s(f.message),
      evidenceKind: s(f.evidence_kind), evidenceStage: s(f.evidence_stage || f.detection_stage),
      owaspMcp: s(f.owasp_mcp), mitreAtlas: s(f.mitre_atlas),
    });
  }
  return out;
}

/** Import bawbel-scanner findings into AVESCANFINDING (snapshot by source). Returns counts. */
export function importScanFindings(input: any, source = "bawbel-scanner", scanRef = ""): { imported: number } {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "AVESCANFINDING")) return { imported: 0 };
  const rows = normalizeScanFindings(input).filter((r) => /^AVE-/i.test(r.aveId) || r.ruleId);
  const now = new Date().toISOString();
  let n = 0;
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM AVESCANFINDING WHERE Source = ?").run(source.slice(0, 120));
    const next = () => Number((db.prepare("SELECT COALESCE(MAX(ScanFindingID),0)+1 n FROM AVESCANFINDING").get() as { n: number }).n);
    let id = next();
    const ins = db.prepare(`INSERT INTO AVESCANFINDING (ScanFindingID, AveId, RuleId, Title, Severity, AivssScore, Confidence,
      ComponentType, File, Line, Message, EvidenceKind, EvidenceStage, OwaspMcp, MitreAtlas, Status, Source, ScanRef, CreatedDate, TenantID)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    for (const r of rows) {
      ins.run(id++, r.aveId.toUpperCase(), s(r.ruleId), s(r.title).slice(0, 300), s(r.severity).toUpperCase(), r.aivss, r.confidence,
        s(r.componentType).slice(0, 60), s(r.file).slice(0, 400), r.line, s(r.message).slice(0, 1000), s(r.evidenceKind).slice(0, 60),
        s(r.evidenceStage).slice(0, 60), s(r.owaspMcp), s(r.mitreAtlas), "open", source.slice(0, 120), s(scanRef).slice(0, 200), now, null);
      n++;
    }
  });
  tx();
  return { imported: n };
}

/** Seed the scan-findings view from the bundled connector sample SARIF (idempotent). */
export function seedScanFindings(): { imported: number } {
  const db = getDb("XVULNERABILITY");
  if (has(db, "AVESCANFINDING") && (db.prepare("SELECT COUNT(*) n FROM AVESCANFINDING").get() as { n: number }).n) return { imported: 0 };
  const candidates = [
    path.join(__dirname, "..", "..", "..", "connectors", "bawbel-scanner", "sample.sarif.json"),
    path.join(process.cwd(), "connectors", "bawbel-scanner", "sample.sarif.json"),
    path.join(process.cwd(), "..", "connectors", "bawbel-scanner", "sample.sarif.json"),
  ];
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return importScanFindings(JSON.parse(fs.readFileSync(p, "utf-8")), "bawbel-scanner (bundled sample)"); } catch { /* next */ }
  }
  return { imported: 0 };
}

/** Scan-findings catalogue + rollup (joins AVERECORD for the AVE class severity). */
export function scanFindings(filters?: { severity?: string }): any {
  const db = getDb("XVULNERABILITY");
  if (!has(db, "AVESCANFINDING")) return { findings: [], summary: { total: 0 } };
  const where = filters?.severity ? "WHERE UPPER(Severity)=?" : "";
  const args = filters?.severity ? [filters.severity.toUpperCase()] : [];
  const findings = db.prepare(`SELECT * FROM AVESCANFINDING ${where} ORDER BY AivssScore DESC, Severity, File`).all(...args) as any[];
  const all = db.prepare("SELECT Severity, AivssScore, AveId, File, ComponentType FROM AVESCANFINDING").all() as any[];
  const sv = (r: any) => s(r.Severity).toUpperCase();
  return {
    findings,
    summary: {
      total: all.length,
      critical: all.filter((r) => sv(r) === "CRITICAL").length,
      high: all.filter((r) => sv(r) === "HIGH").length,
      files: new Set(all.map((r) => r.File).filter(Boolean)).size,
      classes: new Set(all.map((r) => r.AveId).filter(Boolean)).size,
      aivssRisk: Math.round(all.reduce((n, r) => n + (Number(r.AivssScore) || 0), 0) * 10) / 10,
    },
  };
}
