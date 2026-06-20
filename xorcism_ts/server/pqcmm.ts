/**
 * pqcmm.ts — PQCMM (Post-Quantum Cryptography Maturity Model, PKI Consortium) assessment.
 *
 * Product-centric quantum-readiness: assess each product / service / asset that relies on
 * cryptography against the 6 PQCMM levels (0 None → 5 Optimized), track current vs target
 * maturity, and roll up the organisation's quantum-readiness posture (how much is still
 * quantum-vulnerable, production-ready, or fully migrated / zero-legacy). Read-only inventory;
 * the assess write is a dedicated endpoint.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface PqcmmLevel { level: number; name: string; summary: string; criteria: string; }
export interface PqcmmRow {
  id: number; subject: string; type: string; assetId: number | null; asset: string | null;
  current: number; currentName: string; target: number | null; gap: number;
  standard: string; cryptoAgile: boolean; zeroLegacy: boolean; hasCBOM: boolean;
  owner: string | null; status: string; assessedDate: string | null; reviewInDays: number | null; reviewOverdue: boolean;
}
export interface PqcmmFinding {
  id: number; subject: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  reason: string; kind: "vulnerable" | "below-target" | "no-target" | "review"; label: string;
}
export interface PqcmmInventory {
  levels: PqcmmLevel[];
  rows: PqcmmRow[];
  findings: PqcmmFinding[];
  summary: {
    assessments: number; byLevel: number[];
    quantumVulnerable: number; productionReady: number; managed: number;
    avgLevel: number | null; maturityScore: number; belowTarget: number; noTarget: number;
    withCBOM: number; cryptoAgile: number; reviewOverdue: number;
  };
}

const LEVEL_NAME = ["None", "Initial", "Foundational", "Advanced", "Managed", "Optimized"];
const CLOSED = /retir|archiv|superseded|obsolete/i;

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const clampLevel = (v: unknown): number => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.max(0, Math.min(5, n)) : 0; };

export function pqcmmLevels(): PqcmmLevel[] {
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return []; }
  if (!has(cc, "PQCMMLEVEL")) return [];
  return cc.prepare("SELECT Level AS level, Name AS name, Summary AS summary, Criteria AS criteria FROM PQCMMLEVEL ORDER BY SortOrder").all() as PqcmmLevel[];
}

/** Full PQCMM inventory: the model + every assessment with its maturity posture + worklist. */
export function pqcmmInventory(tenant: number | null): PqcmmInventory {
  const levels = pqcmmLevels();
  const empty: PqcmmInventory = {
    levels, rows: [], findings: [],
    summary: { assessments: 0, byLevel: [0, 0, 0, 0, 0, 0], quantumVulnerable: 0, productionReady: 0, managed: 0, avgLevel: null, maturityScore: 0, belowTarget: 0, noTarget: 0, withCBOM: 0, cryptoAgile: 0, reviewOverdue: 0 },
  };
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return empty; }
  if (!has(cc, "PQCMMASSESSMENT")) return empty;
  const ac = cols("PQCMMASSESSMENT");
  const tw = tenant != null && ac.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const entries = cc.prepare(`SELECT * FROM PQCMMASSESSMENT ${tw}`).all() as Record<string, unknown>[];
  if (!entries.length) return empty;

  // resolve owners + asset names (cross-DB, best-effort)
  const ownerName = new Map<number, string>(); const assetName = new Map<number, string>();
  try {
    const xo = getDb("XORCISM");
    const oids = [...new Set(entries.map((e) => Number(e.OwnerPersonID)).filter(Boolean))];
    if (oids.length) for (const r of xo.prepare(`SELECT PersonID, FullName FROM PERSON WHERE PersonID IN (${oids.map(() => "?").join(",")})`).all(...oids) as { PersonID: number; FullName: string }[]) ownerName.set(Number(r.PersonID), r.FullName);
    const aids = [...new Set(entries.map((e) => Number(e.AssetID)).filter(Boolean))];
    if (aids.length) for (const r of xo.prepare(`SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN (${aids.map(() => "?").join(",")})`).all(...aids) as { AssetID: number; AssetName: string }[]) assetName.set(Number(r.AssetID), r.AssetName);
  } catch { /* PERSON/ASSET absent */ }

  const rows: PqcmmRow[] = [];
  const findings: PqcmmFinding[] = [];
  for (const e of entries) {
    const id = Number(e.AssessmentID);
    if (CLOSED.test(String(e.Status ?? ""))) continue;
    const current = clampLevel(e.CurrentLevel);
    const target = e.TargetLevel != null && e.TargetLevel !== "" ? clampLevel(e.TargetLevel) : null;
    const gap = target != null ? Math.max(0, target - current) : 0;
    const reviewInDays = daysUntil(e.ReviewDate ? String(e.ReviewDate) : null);
    const reviewOverdue = reviewInDays != null && reviewInDays < 0;
    const subject = String(e.SubjectName ?? "").trim() || `Subject #${id}`;
    rows.push({
      id, subject, type: String(e.SubjectType ?? "").trim() || "—",
      assetId: e.AssetID != null ? Number(e.AssetID) : null,
      asset: e.AssetID != null ? (assetName.get(Number(e.AssetID)) ?? null) : null,
      current, currentName: LEVEL_NAME[current], target, gap,
      standard: String(e.Standard ?? "").trim(),
      cryptoAgile: Number(e.CryptoAgile) === 1, zeroLegacy: Number(e.ZeroLegacy) === 1, hasCBOM: Number(e.HasCBOM) === 1,
      owner: e.OwnerPersonID != null ? (ownerName.get(Number(e.OwnerPersonID)) ?? `Person #${e.OwnerPersonID}`) : null,
      status: String(e.Status ?? "").trim() || "Active",
      assessedDate: e.AssessedDate ? String(e.AssessedDate).slice(0, 10) : null,
      reviewInDays, reviewOverdue,
    });

    // worklist
    if (current === 0)
      findings.push({ id, subject, severity: "High", reason: "quantum-vulnerable", kind: "vulnerable", label: `Quantum-vulnerable (PQCMM Level 0) — relies entirely on classical crypto` });
    else if (gap > 0)
      findings.push({ id, subject, severity: current <= 1 ? "High" : gap >= 2 ? "Medium" : "Low", reason: "below-target", kind: "below-target", label: `Below target — Level ${current} (${LEVEL_NAME[current]}) vs target ${target} (${target != null ? LEVEL_NAME[target] : ""}), gap ${gap}` });
    if (current > 0 && target == null)
      findings.push({ id, subject, severity: "Low", reason: "no-target", kind: "no-target", label: `No target maturity level set` });
    if (reviewOverdue)
      findings.push({ id, subject, severity: "Low", reason: "review", kind: "review", label: `Re-assessment overdue by ${-(reviewInDays ?? 0)}d` });
  }

  const SEV: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  rows.sort((a, b) => a.current - b.current || b.gap - a.gap || a.subject.localeCompare(b.subject));
  findings.sort((a, b) => SEV[a.severity] - SEV[b.severity] || a.subject.localeCompare(b.subject));

  const byLevel = [0, 0, 0, 0, 0, 0];
  for (const r of rows) byLevel[r.current]++;
  const n = rows.length;
  const avgLevel = n ? rows.reduce((s, r) => s + r.current, 0) / n : null;

  return {
    levels, rows, findings,
    summary: {
      assessments: n, byLevel,
      quantumVulnerable: byLevel[0],
      productionReady: rows.filter((r) => r.current >= 2).length,
      managed: rows.filter((r) => r.current >= 4).length,
      avgLevel: avgLevel != null ? Math.round(avgLevel * 10) / 10 : null,
      maturityScore: avgLevel != null ? Math.round((avgLevel / 5) * 100) : 0,
      belowTarget: rows.filter((r) => r.gap > 0).length,
      noTarget: rows.filter((r) => r.target == null).length,
      withCBOM: rows.filter((r) => r.hasCBOM).length,
      cryptoAgile: rows.filter((r) => r.cryptoAgile).length,
      reviewOverdue: rows.filter((r) => r.reviewOverdue).length,
    },
  };
}

// Software whose function depends on the public-key cryptography (RSA / ECC / DH) that a
// quantum computer threatens — VPN, SSH/SFTP, TLS servers, crypto libraries, mail, PKI, browsers,
// databases, code-signing. Matched against the CPE name/title of an asset's software inventory.
const QV_CRYPTO = /openssl|libssl|gnutls|libgcrypt|mbedtls|wolfssl|bouncy|boringssl|libsodium|\bnss\b|openssh|winscp|putty|\bsftp\b|filezilla|openvpn|wireguard|ipsec|strongswan|libreswan|anyconnect|globalprotect|forticlient|proton_vpn|\bvpn\b|apache_http|httpd|nginx|tomcat|lighttpd|haproxy|internet_information|\biis\b|postfix|dovecot|exim|sendmail|mariadb|mysql|postgre|mongodb|gnupg|\bgpg\b|kerberos|chrome|firefox|mozilla|microsoft_edge|\bedge\b|safari|opera|acrobat|certificate|x509|x\.509|keycloak|\bvault\b|active_directory|github|gitlab/i;

function cpeProductLabel(cpeName: string, title: string): string {
  const t = String(title ?? "").trim();
  if (t && t.length <= 60) return t;
  const parts = String(cpeName ?? "").split(":");
  const prod = parts.length > 4 ? parts[4] : "";
  return (prod || cpeName).replace(/_/g, " ").replace(/\s+\d[\d.]*$/, "").trim().slice(0, 60) || "software";
}

/** Bootstrap a PQCMM "CBOM" from the asset crypto inventory: for every asset running software
 *  that depends on quantum-vulnerable public-key cryptography (detected from its CPEs), create a
 *  Level-0 PQCMM subject (target Level 4) listing the detected crypto-bearing components.
 *  Idempotent: skips assets that already have a PQCMM assessment. Returns the counts. */
export function bootstrapPqcmmFromInventory(tenant: number | null, userId: number | null): { created: number; skipped: number; scanned: number } {
  const out = { created: 0, skipped: 0, scanned: 0 };
  let xo, cc; try { xo = getDb("XORCISM"); cc = getDb("XCOMPLIANCE"); } catch { return out; }
  if (!has(cc, "PQCMMASSESSMENT")) return out;
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CPEFORASSET'").get() || !xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CPE'").get()) return out;

  const cfaCols = new Set((xo.prepare(`PRAGMA table_info("CPEFORASSET")`).all() as { name: string }[]).map((c) => c.name));
  const tw = tenant != null && cfaCols.has("TenantID") ? `AND cfa.TenantID = ${tenant}` : "";
  const rows = xo.prepare(
    `SELECT cfa.AssetID AS aid, ast.AssetName AS an, cpe.CPEName AS cn, cpe.CPETitle AS ct
     FROM CPEFORASSET cfa JOIN CPE cpe ON cpe.CPEID = cfa.CPEID JOIN ASSET ast ON ast.AssetID = cfa.AssetID
     WHERE cfa.AssetID IS NOT NULL ${tw}`,
  ).all() as { aid: number; an: string; cn: string; ct: string }[];

  // group detected crypto-bearing software per asset
  const byAsset = new Map<number, { name: string; products: Set<string> }>();
  for (const r of rows) {
    const blob = `${r.cn ?? ""} ${r.ct ?? ""}`;
    if (!QV_CRYPTO.test(blob)) continue;
    const a = byAsset.get(Number(r.aid)) ?? { name: String(r.an ?? `Asset #${r.aid}`), products: new Set<string>() };
    a.products.add(cpeProductLabel(r.cn, r.ct));
    byAsset.set(Number(r.aid), a);
  }
  out.scanned = byAsset.size;
  if (!byAsset.size) return out;

  // already-assessed assets (idempotent)
  const acols = cols("PQCMMASSESSMENT");
  const etw = tenant != null && acols.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const existing = new Set((cc.prepare(`SELECT DISTINCT AssetID FROM PQCMMASSESSMENT ${etw}`).all() as { AssetID: number | null }[]).map((r) => Number(r.AssetID)).filter(Boolean));

  const now = new Date().toISOString();
  const ins = cc.prepare(
    `INSERT INTO PQCMMASSESSMENT (AssessmentGUID, SubjectName, SubjectType, AssetID, CurrentLevel, TargetLevel, Notes, OwnerPersonID, Status, AssessedDate, CreatedDate, TenantID)
     VALUES (?,?,?,?,0,4,?,?,?,?,?,?)`);
  const tx = cc.transaction(() => {
    for (const [aid, a] of byAsset) {
      if (existing.has(aid)) { out.skipped++; continue; }
      const products = [...a.products].slice(0, 12).join(", ");
      ins.run(randomUUID(), a.name.slice(0, 300), "Asset", aid,
        `Auto-detected crypto-bearing software (quantum-vulnerable until assessed): ${products}.`.slice(0, 2000),
        userId, "Active", now.slice(0, 10), now, tenant);
      out.created++;
    }
  });
  tx();
  return out;
}

/** Create or update a PQCMM assessment (upsert by id when provided). */
export function savePqcmmAssessment(
  p: { id?: number; subjectName?: string; subjectType?: string; assetId?: number; currentLevel?: number; targetLevel?: number; standard?: string; cryptoAgile?: boolean; zeroLegacy?: boolean; hasCBOM?: boolean; notes?: string; reviewDate?: string },
  tenant: number | null, userId: number | null,
): { assessmentId: number; currentLevel: number } {
  const cc = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const current = clampLevel(p.currentLevel);
  const target = p.targetLevel != null && p.targetLevel !== undefined && String(p.targetLevel) !== "" ? clampLevel(p.targetLevel) : null;
  const flags = (b: unknown): number => (b ? 1 : 0);

  if (p.id) {
    cc.prepare(
      `UPDATE PQCMMASSESSMENT SET SubjectName=?, SubjectType=?, AssetID=?, CurrentLevel=?, TargetLevel=?, Standard=?,
         CryptoAgile=?, ZeroLegacy=?, HasCBOM=?, Notes=?, ReviewDate=?, AssessedDate=? WHERE AssessmentID=?`,
    ).run((p.subjectName || "").slice(0, 300), (p.subjectType || "").slice(0, 60), p.assetId ?? null, current, target,
      (p.standard || "").slice(0, 120), flags(p.cryptoAgile), flags(p.zeroLegacy), flags(p.hasCBOM),
      (p.notes || "").slice(0, 2000), p.reviewDate || null, now.slice(0, 10), p.id);
    return { assessmentId: p.id, currentLevel: current };
  }
  const r = cc.prepare(
    `INSERT INTO PQCMMASSESSMENT (AssessmentGUID, SubjectName, SubjectType, AssetID, CurrentLevel, TargetLevel, Standard,
       CryptoAgile, ZeroLegacy, HasCBOM, Notes, OwnerPersonID, Status, AssessedDate, ReviewDate, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(randomUUID(), (p.subjectName || "PQCMM subject").slice(0, 300), (p.subjectType || "Asset").slice(0, 60), p.assetId ?? null,
    current, target, (p.standard || "").slice(0, 120), flags(p.cryptoAgile), flags(p.zeroLegacy), flags(p.hasCBOM),
    (p.notes || "").slice(0, 2000), userId, "Active", now.slice(0, 10), p.reviewDate || null, now, tenant);
  return { assessmentId: Number(r.lastInsertRowid), currentLevel: current };
}
