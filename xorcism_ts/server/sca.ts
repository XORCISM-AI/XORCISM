/**
 * sca.ts — Software Composition Analysis (SCA) over the XORCISM CPE / CPEFORASSET /
 * APPLICATION inventory, with first-class SBOM (Software Bill of Materials) support.
 *
 * Two standards are read and written:
 *   • CycloneDX (OWASP)            — bomFormat:"CycloneDX", components[], dependencies[]
 *   • SPDX (Linux Foundation)      — spdxVersion:"SPDX-2.x", packages[], relationships[]
 *
 * An imported SBOM becomes:
 *   • one SBOM row (the document: format, spec version, subject, serial, source, counts)
 *   • COMPONENT rows (rich metadata: name, version, type, PURL, CPE, supplier, license, hash, scope)
 *   • COMPONENTDEPENDENCY edges (the composition graph)
 * Components carrying a CPE are linked back to the target asset's CPE inventory
 * (CPEFORASSET), so SCA feeds the same exposure pipeline as the rest of the platform.
 *
 * Read-only inventory (scaInventory) + composition graph (scaGraph) + import/export.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

// ─────────────────────────────── types ───────────────────────────────
export interface SbomComponent {
  bomRef: string | null; name: string; version: string | null; type: string;
  purl: string | null; cpe: string | null; supplier: string | null; publisher: string | null;
  group: string | null; license: string | null; hash: string | null; scope: string | null;
  description: string | null;
}
export interface SbomDependency { from: string; to: string }
export interface NormalizedSbom {
  format: "CycloneDX" | "SPDX"; specVersion: string; serialNumber: string | null;
  subjectName: string | null; subjectVersion: string | null; toolName: string | null;
  components: SbomComponent[]; dependencies: SbomDependency[];
}

export interface SbomRow {
  id: number; name: string; format: string; specVersion: string; subject: string | null;
  subjectVersion: string | null; serialNumber: string | null; assetId: number | null; asset: string | null;
  componentCount: number; vulnerableCount: number; licenseCount: number; source: string; toolName: string | null;
  createdDate: string | null;
}
export interface ComponentRow {
  id: number; name: string; version: string | null; type: string; purl: string | null;
  cpe: string | null; supplier: string | null; license: string | null; scope: string | null;
  sbomId: number | null; sbom: string | null; assetId: number | null; vulnerable: boolean;
}
export interface ScaFinding {
  id: number; component: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  reason: string; kind: "vulnerable" | "no-license" | "no-version" | "outdated" | "no-sbom"; label: string;
}
export interface ScaInventory {
  sboms: SbomRow[];
  components: ComponentRow[];
  findings: ScaFinding[];
  byType: { type: string; count: number }[];
  byLicense: { license: string; count: number }[];
  bySupplier: { supplier: string; count: number }[];
  summary: {
    sboms: number; components: number; distinctComponents: number;
    byFormat: { cyclonedx: number; spdx: number };
    vulnerable: number; noLicense: number; noVersion: number;
    licenses: number; suppliers: number; dependencies: number;
    cpeLinked: number; assetsCovered: number;
  };
}

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const colset = (db: ReturnType<typeof getDb>, t: string): Set<string> => {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
};
const str = (v: unknown): string | null => { const s = v == null ? "" : String(v).trim(); return s ? s : null; };

// ─────────────────────────────── parsers ───────────────────────────────

/** Flatten a CycloneDX licenses[] array ("expression" or {license:{id|name}}) to a short string. */
function cdxLicense(licenses: any): string | null {
  if (!Array.isArray(licenses)) return null;
  const out: string[] = [];
  for (const l of licenses) {
    if (typeof l === "string") out.push(l);
    else if (l?.expression) out.push(String(l.expression));
    else if (l?.license?.id) out.push(String(l.license.id));
    else if (l?.license?.name) out.push(String(l.license.name));
  }
  return out.length ? [...new Set(out)].join(", ").slice(0, 200) : null;
}
function cdxHash(hashes: any): string | null {
  if (!Array.isArray(hashes)) return null;
  const h = hashes.find((x) => /sha-?256/i.test(String(x?.alg))) || hashes[0];
  return h?.content ? `${h.alg || "hash"}:${h.content}`.slice(0, 160) : null;
}

/** Parse a CycloneDX (OWASP) BOM object → normalized SBOM. */
export function parseCycloneDX(obj: any): NormalizedSbom {
  const meta = obj?.metadata || {};
  const subj = meta.component || {};
  const tool = Array.isArray(meta.tools?.components) ? meta.tools.components[0]
    : Array.isArray(meta.tools) ? meta.tools[0] : meta.tools?.components?.[0];
  const components: SbomComponent[] = (Array.isArray(obj?.components) ? obj.components : []).map((c: any) => ({
    bomRef: str(c["bom-ref"] ?? c.bomRef), name: String(c.name ?? "(unnamed)").slice(0, 300),
    version: str(c.version), type: String(c.type || "library").toLowerCase(),
    purl: str(c.purl), cpe: str(c.cpe),
    supplier: str(c.supplier?.name ?? c.supplier), publisher: str(c.publisher),
    group: str(c.group), license: cdxLicense(c.licenses), hash: cdxHash(c.hashes),
    scope: str(c.scope), description: str(c.description),
  }));
  const dependencies: SbomDependency[] = [];
  for (const d of (Array.isArray(obj?.dependencies) ? obj.dependencies : [])) {
    const from = str(d.ref); if (!from) continue;
    for (const to of (Array.isArray(d.dependsOn) ? d.dependsOn : [])) {
      const t = str(to); if (t) dependencies.push({ from, to: t });
    }
  }
  return {
    format: "CycloneDX", specVersion: String(obj?.specVersion || "1.5"),
    serialNumber: str(obj?.serialNumber),
    subjectName: str(subj.name), subjectVersion: str(subj.version),
    toolName: str(tool?.name), components, dependencies,
  };
}

/** Extract PURL / CPE from an SPDX package's externalRefs[]. */
function spdxRefs(pkg: any): { purl: string | null; cpe: string | null } {
  let purl: string | null = null, cpe: string | null = null;
  for (const r of (Array.isArray(pkg?.externalRefs) ? pkg.externalRefs : [])) {
    const type = String(r?.referenceType || "").toLowerCase();
    const loc = str(r?.referenceLocator);
    if (type === "purl" && !purl) purl = loc;
    else if ((type === "cpe23type" || type === "cpe22type") && !cpe) cpe = loc;
  }
  return { purl, cpe };
}
function spdxLicense(pkg: any): string | null {
  const l = pkg?.licenseConcluded && pkg.licenseConcluded !== "NOASSERTION" ? pkg.licenseConcluded
    : pkg?.licenseDeclared && pkg.licenseDeclared !== "NOASSERTION" ? pkg.licenseDeclared : null;
  return l ? String(l).slice(0, 200) : null;
}
function spdxHash(pkg: any): string | null {
  const cks = Array.isArray(pkg?.checksums) ? pkg.checksums : [];
  const c = cks.find((x: any) => /sha256/i.test(String(x?.algorithm))) || cks[0];
  return c?.checksumValue ? `${c.algorithm || "hash"}:${c.checksumValue}`.slice(0, 160) : null;
}

/** Parse an SPDX (Linux Foundation) document object → normalized SBOM. */
export function parseSPDX(obj: any): NormalizedSbom {
  const pkgs = Array.isArray(obj?.packages) ? obj.packages : [];
  const idToRef = new Map<string, string>();
  const components: SbomComponent[] = pkgs.map((p: any) => {
    const ref = str(p.SPDXID) || str(p.name);
    if (p.SPDXID) idToRef.set(String(p.SPDXID), ref || String(p.SPDXID));
    const { purl, cpe } = spdxRefs(p);
    const supplier = str(p.supplier)?.replace(/^(Organization|Person):\s*/i, "") ?? null;
    return {
      bomRef: ref, name: String(p.name ?? "(unnamed)").slice(0, 300),
      version: str(p.versionInfo), type: String(p.primaryPackagePurpose || "library").toLowerCase(),
      purl, cpe, supplier, publisher: str(p.originator)?.replace(/^(Organization|Person):\s*/i, "") ?? null,
      group: null, license: spdxLicense(p), hash: spdxHash(p),
      scope: null, description: str(p.description) || str(p.summary),
    };
  });
  const dependencies: SbomDependency[] = [];
  for (const r of (Array.isArray(obj?.relationships) ? obj.relationships : [])) {
    if (!/DEPENDS_ON/i.test(String(r?.relationshipType))) continue;
    const from = idToRef.get(String(r.spdxElementId)) || str(r.spdxElementId);
    const to = idToRef.get(String(r.relatedSpdxElement)) || str(r.relatedSpdxElement);
    if (from && to) dependencies.push({ from, to });
  }
  const doc = obj?.creationInfo || {};
  const tool = (Array.isArray(doc.creators) ? doc.creators : []).find((c: string) => /^Tool:/i.test(c));
  return {
    format: "SPDX", specVersion: String(obj?.spdxVersion || "SPDX-2.3").replace(/^SPDX-/, ""),
    serialNumber: str(obj?.documentNamespace),
    subjectName: str(obj?.name), subjectVersion: null,
    toolName: tool ? String(tool).replace(/^Tool:\s*/i, "") : null, components, dependencies,
  };
}

/** Detect the SBOM standard and parse. Throws on unrecognized input. */
export function parseSbom(input: string | object): NormalizedSbom {
  let obj: any = input;
  if (typeof input === "string") {
    try { obj = JSON.parse(input); } catch { throw new Error("not valid JSON (only CycloneDX/SPDX JSON is supported)"); }
  }
  if (obj?.bomFormat === "CycloneDX" || (obj?.specVersion && Array.isArray(obj?.components))) return parseCycloneDX(obj);
  if (typeof obj?.spdxVersion === "string" || Array.isArray(obj?.packages)) return parseSPDX(obj);
  throw new Error("unrecognized SBOM: expected CycloneDX (bomFormat) or SPDX (spdxVersion)");
}

// ─────────────────────────────── import ───────────────────────────────

/** Next id for a legacy table whose id column is NOT an INTEGER PRIMARY KEY (no auto-rowid). */
function nextId(xo: ReturnType<typeof getDb>, table: string, col: string): number {
  return Number((xo.prepare(`SELECT COALESCE(MAX("${col}"),0)+1 AS n FROM "${table}"`).get() as { n: number }).n);
}

/** Find-or-create a CPE row by its cpe:2.3 string, returning the CPEID. CPE.CPEID is a legacy
 *  NOT-NULL column without a PK, so the id is assigned explicitly. */
function ensureCpe(xo: ReturnType<typeof getDb>, cpeName: string): number | null {
  const name = String(cpeName).trim(); if (!name) return null;
  const row = xo.prepare("SELECT CPEID FROM CPE WHERE CPEName = ? LIMIT 1").get(name) as { CPEID: number } | undefined;
  if (row) return row.CPEID;
  const id = nextId(xo, "CPE", "CPEID");
  xo.prepare("INSERT INTO CPE (CPEID, CPEName, Status, CreatedDate) VALUES (?, ?, 'sbom', ?)").run(id, name, new Date().toISOString());
  return id;
}

/**
 * Import a parsed SBOM: persist the document + components + dependency edges, link
 * CPE-bearing components to the target asset, and return a summary. Tenant-scoped.
 */
export function importSbom(
  p: { sbom: NormalizedSbom; name?: string; assetId?: number | null; applicationId?: number | null; source?: string },
  tenant: number | null, userId: number | null,
): { sbomId: number; components: number; dependencies: number; cpeLinks: number; licenses: number; format: string } {
  const xo = getDb("XORCISM");
  const s = p.sbom;
  const now = new Date().toISOString();
  const assetId = p.assetId ?? null;
  const cfaCols = colset(xo, "CPEFORASSET");
  const licenses = new Set<string>();
  for (const c of s.components) if (c.license) licenses.add(c.license);

  const insSbom = xo.prepare(
    `INSERT INTO SBOM (SbomGUID, Name, Format, SpecVersion, SerialNumber, SubjectName, SubjectVersion,
       AssetID, ApplicationID, ComponentCount, VulnerableCount, LicenseCount, Source, ToolName, PersonID, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insComp = xo.prepare(
    `INSERT INTO COMPONENT (ComponentGUID, SbomID, Name, Version, ComponentType, PURL, CPE, CPEID, Supplier, Publisher,
       "Group", License, Hash, BOMRef, Scope, Description, AssetID, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insDep = xo.prepare(
    `INSERT INTO COMPONENTDEPENDENCY (SbomID, FromRef, ToRef, CreatedDate, TenantID) VALUES (?,?,?,?,?)`);

  let cpeLinks = 0;
  const out = { sbomId: 0, components: 0, dependencies: 0, cpeLinks: 0, licenses: licenses.size, format: s.format };
  const tx = xo.transaction(() => {
    const r = insSbom.run(randomUUID(), (p.name || s.subjectName || `${s.format} SBOM`).slice(0, 300), s.format,
      s.specVersion, s.serialNumber, s.subjectName, s.subjectVersion, assetId, p.applicationId ?? null,
      s.components.length, 0, licenses.size, (p.source || "import").slice(0, 40), s.toolName, userId, now, tenant);
    const sbomId = Number(r.lastInsertRowid);
    for (const c of s.components) {
      let cpeId: number | null = null;
      if (c.cpe) {
        cpeId = ensureCpe(xo, c.cpe);
        if (cpeId && assetId && cfaCols.has("AssetID") && cfaCols.has("CPEID")) {
          const exists = xo.prepare("SELECT 1 FROM CPEFORASSET WHERE AssetID=? AND CPEID=? LIMIT 1").get(assetId, cpeId);
          if (!exists) {
            const tcol = cfaCols.has("TenantID");
            const acpeId = nextId(xo, "CPEFORASSET", "AssetCPEID"); // legacy NOT-NULL non-PK id
            xo.prepare(`INSERT INTO CPEFORASSET (AssetCPEID, AssetID, CPEID, CreatedDate${tcol ? ", TenantID" : ""}) VALUES (?,?,?,?${tcol ? ",?" : ""})`)
              .run(...(tcol ? [acpeId, assetId, cpeId, now, tenant] : [acpeId, assetId, cpeId, now]));
            cpeLinks++;
          }
        }
      }
      insComp.run(randomUUID(), sbomId, c.name, c.version, c.type, c.purl, c.cpe, cpeId, c.supplier, c.publisher,
        c.group, c.license, c.hash, c.bomRef, c.scope, c.description, assetId, now, tenant);
    }
    for (const d of s.dependencies) insDep.run(sbomId, d.from, d.to, now, tenant);
    out.sbomId = sbomId; out.components = s.components.length; out.dependencies = s.dependencies.length; out.cpeLinks = cpeLinks;
  });
  tx();
  return out;
}

// ─────────────────────────────── vuln correlation ───────────────────────────────

/** Best-effort: the set of CPEIDs flagged vulnerable in XVULNERABILITY.VULNERABILITYFORCPE. */
function vulnerableCpeIds(): Set<number> {
  try {
    const xv = getDb("XVULNERABILITY");
    if (!has(xv, "VULNERABILITYFORCPE")) return new Set();
    const rows = xv.prepare("SELECT DISTINCT CPEID FROM VULNERABILITYFORCPE WHERE CPEID IS NOT NULL AND COALESCE(isKnownVulnerable,1)=1").all() as { CPEID: number }[];
    return new Set(rows.map((r) => Number(r.CPEID)));
  } catch { return new Set(); }
}

// ──────────────── reachability-based prioritization (Endor/Snyk-style) ────────────────
// A vulnerable dependency only matters if it is actually *reachable* in the running application. We
// derive reachability from each component's SBOM scope (dev/test/optional → not runtime-reachable) and
// then propagate it across the dependency graph (a transitive dep pulled in by a runtime parent is
// reachable too). Reachable + exploitable (KEV/EPSS/CVSS) findings are prioritized; unreachable ones are
// deprioritized — the "noise reduction" headline of the SCA-reachability tools.
export type Reach = "reachable" | "unreachable" | "unknown";
export interface ScaPriorityFinding {
  componentId: number; name: string; version: string | null; scope: string | null;
  sbomId: number | null; assetId: number | null; cpe: string | null;
  reach: Reach; cvss: number | null; kev: boolean; epss: number | null; vulnCount: number;
  priority: number; bucket: "act" | "scheduled" | "deferred" | "review";
}
export interface ScaPriority {
  findings: ScaPriorityFinding[];
  summary: {
    vulnerable: number; reachable: number; unreachable: number; unknown: number;
    act: number; scheduled: number; deferred: number; review: number;
    noiseReductionPct: number; reachablePct: number;
  };
}

const REACH_UNREACHABLE = new Set(["dev", "development", "devdependencies", "test", "optional", "provided", "excluded", "build"]);
const REACH_RUNTIME = new Set(["", "runtime", "required", "compile", "direct", "implementation", "production"]);

function exploitByCpe(cpeIds: number[]): Map<number, { cvss: number | null; kev: boolean; epss: number | null; vulns: number }> {
  const out = new Map<number, { cvss: number | null; kev: boolean; epss: number | null; vulns: number }>();
  if (!cpeIds.length) return out;
  try {
    const xv = getDb("XVULNERABILITY");
    if (!has(xv, "VULNERABILITYFORCPE") || !has(xv, "VULNERABILITY")) return out;
    for (let i = 0; i < cpeIds.length; i += 500) {
      const chunk = cpeIds.slice(i, i + 500);
      const ph = chunk.map(() => "?").join(",");
      const rows = xv.prepare(
        `SELECT fc.CPEID cid, MAX(v.CVSSBaseScore) cvss, MAX(COALESCE(v.KEV,0)) kev, MAX(v.EPSS) epss, COUNT(*) n
         FROM VULNERABILITYFORCPE fc JOIN VULNERABILITY v ON v.VulnerabilityID = fc.VulnerabilityID
         WHERE fc.CPEID IN (${ph}) AND COALESCE(fc.isKnownVulnerable,1)=1
         GROUP BY fc.CPEID`
      ).all(...chunk) as { cid: number; cvss: number | null; kev: number; epss: number | null; n: number }[];
      for (const r of rows) out.set(Number(r.cid), { cvss: r.cvss, kev: Number(r.kev) > 0, epss: r.epss, vulns: r.n });
    }
  } catch { /* XVULNERABILITY unavailable */ }
  return out;
}

export function scaPriority(tenant: number | null): ScaPriority {
  const xo = getDb("XORCISM");
  const empty: ScaPriority = { findings: [], summary: { vulnerable: 0, reachable: 0, unreachable: 0, unknown: 0, act: 0, scheduled: 0, deferred: 0, review: 0, noiseReductionPct: 0, reachablePct: 0 } };
  if (!has(xo, "COMPONENT")) return empty;
  const compCols = colset(xo, "COMPONENT");
  const compTw = tenant != null && compCols.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  type C = { id: number; sbomId: number | null; bomRef: string | null; cpeId: number | null; scope: string | null; name: string; version: string | null; cpe: string | null; assetId: number | null };
  const comps = xo.prepare(
    `SELECT ComponentID id, SbomID sbomId, BOMRef bomRef, CPEID cpeId, Scope scope, Name name, Version version, CPE cpe, AssetID assetId FROM COMPONENT ${compTw}`
  ).all() as C[];
  if (!comps.length) return empty;

  // dependency edges per sbom → adjacency (FromRef -> [ToRef])
  const edgesBySbom = new Map<number, Map<string, string[]>>();
  if (has(xo, "COMPONENTDEPENDENCY")) {
    for (const e of xo.prepare(`SELECT SbomID sbomId, FromRef f, ToRef t FROM COMPONENTDEPENDENCY`).all() as { sbomId: number; f: string; t: string }[]) {
      if (!edgesBySbom.has(e.sbomId)) edgesBySbom.set(e.sbomId, new Map());
      const m = edgesBySbom.get(e.sbomId)!;
      (m.get(e.f) || m.set(e.f, []).get(e.f)!).push(e.t);
    }
  }

  const scopeReach = (s: string | null): Reach => {
    const v = String(s || "").trim().toLowerCase();
    if (REACH_UNREACHABLE.has(v)) return "unreachable";
    if (REACH_RUNTIME.has(v)) return "reachable";
    return "unknown";
  };
  const reach = new Map<number, Reach>();
  for (const c of comps) reach.set(c.id, scopeReach(c.scope));

  // graph propagation: a component reachable from a runtime-scoped seed (and not explicitly unreachable)
  // becomes reachable — captures transitive deps with unknown scope that runtime parents pull in.
  const refKey = (sbomId: number | null, ref: string | null): string => `${sbomId} ${ref}`;
  const byRef = new Map<string, C>();
  for (const c of comps) if (c.bomRef) byRef.set(refKey(c.sbomId, c.bomRef), c);
  for (const [sbomId, adj] of edgesBySbom) {
    const queue: string[] = [];
    for (const c of comps) if (c.sbomId === sbomId && reach.get(c.id) === "reachable" && c.bomRef) queue.push(c.bomRef);
    const seen = new Set<string>(queue);
    while (queue.length) {
      const ref = queue.shift()!;
      for (const to of adj.get(ref) || []) {
        if (seen.has(to)) continue;
        seen.add(to);
        const child = byRef.get(refKey(sbomId, to));
        if (child && reach.get(child.id) !== "unreachable") { reach.set(child.id, "reachable"); queue.push(to); }
      }
    }
  }

  const vulnSet = vulnerableCpeIds();
  const vulnComps = comps.filter((c) => c.cpeId != null && vulnSet.has(Number(c.cpeId)));
  const expl = exploitByCpe([...new Set(vulnComps.map((c) => Number(c.cpeId)))]);
  const reachFactor: Record<Reach, number> = { reachable: 1, unknown: 0.5, unreachable: 0.15 };

  const findings: ScaPriorityFinding[] = vulnComps.map((c) => {
    const r = reach.get(c.id) || "unknown";
    const e = expl.get(Number(c.cpeId)) || { cvss: null, kev: false, epss: null, vulns: 1 };
    const sev = (e.cvss ?? 5) / 10;
    const exploit = e.kev ? 1 : Math.min(1, 0.15 + (e.epss ?? 0));
    let priority = Math.round(100 * reachFactor[r] * (0.6 * sev + 0.4 * exploit));
    if (e.kev && r === "reachable") priority = Math.max(priority, 90);
    let bucket: ScaPriorityFinding["bucket"];
    if (r === "unreachable") bucket = "deferred";
    else if (r === "unknown") bucket = "review";
    else if (e.kev || (e.cvss ?? 0) >= 9 || (e.epss ?? 0) >= 0.5) bucket = "act";
    else bucket = "scheduled";
    return { componentId: c.id, name: c.name, version: c.version, scope: c.scope, sbomId: c.sbomId, assetId: c.assetId, cpe: c.cpe, reach: r, cvss: e.cvss, kev: e.kev, epss: e.epss, vulnCount: e.vulns, priority, bucket };
  }).sort((a, b) => b.priority - a.priority);

  const cnt = (f: (x: ScaPriorityFinding) => boolean): number => findings.filter(f).length;
  const vulnerable = findings.length;
  const unreachable = cnt((x) => x.reach === "unreachable");
  const reachable = cnt((x) => x.reach === "reachable");
  const unknown = cnt((x) => x.reach === "unknown");
  return {
    findings,
    summary: {
      vulnerable, reachable, unreachable, unknown,
      act: cnt((x) => x.bucket === "act"), scheduled: cnt((x) => x.bucket === "scheduled"),
      deferred: cnt((x) => x.bucket === "deferred"), review: cnt((x) => x.bucket === "review"),
      noiseReductionPct: vulnerable ? Math.round((unreachable / vulnerable) * 100) : 0,
      reachablePct: vulnerable ? Math.round((reachable / vulnerable) * 100) : 0,
    },
  };
}

// ─────────────────────────────── inventory ───────────────────────────────

/** Full SCA inventory: SBOM documents, components, license/type/supplier breakdowns + worklist. */
export interface ScaAssetSeverity { critical: number; high: number; medium: number; low: number; components: number; sboms: number }
/** Per-asset SCA severity counts derived from the SBOM components (vulnerable→High, unpinned→Medium,
 *  no-license→Low) — the live SCA scan class for DevSecOps, straight from /sca's SBOM data. */
export function scaSeverityByAsset(tenant: number | null): Map<number, ScaAssetSeverity> {
  const out = new Map<number, ScaAssetSeverity>();
  let xo; try { xo = getDb("XORCISM"); } catch { return out; }
  if (!has(xo, "SBOM") || !has(xo, "COMPONENT")) return out;
  const compCols = colset(xo, "COMPONENT");
  if (!compCols.has("Name")) return out;
  const sbomTw = tenant != null && colset(xo, "SBOM").has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const sbomAsset = new Map<number, number | null>();
  for (const s of xo.prepare(`SELECT SbomID id, AssetID assetId FROM SBOM ${sbomTw}`).all() as any[]) sbomAsset.set(Number(s.id), s.assetId != null ? Number(s.assetId) : null);
  const compTw = tenant != null && compCols.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const vulnSet = vulnerableCpeIds();
  const sbomsByAsset = new Map<number, Set<number>>();
  for (const c of xo.prepare(`SELECT SbomID sbomId, AssetID assetId, CPEID cpeId, Version version, License license FROM COMPONENT ${compTw}`).all() as any[]) {
    const aid = (c.sbomId != null ? sbomAsset.get(Number(c.sbomId)) ?? null : null) ?? (c.assetId != null ? Number(c.assetId) : null);
    if (aid == null) continue;
    let e = out.get(aid); if (!e) { e = { critical: 0, high: 0, medium: 0, low: 0, components: 0, sboms: 0 }; out.set(aid, e); }
    e.components++;
    if (c.sbomId != null) { let set = sbomsByAsset.get(aid); if (!set) { set = new Set(); sbomsByAsset.set(aid, set); } set.add(Number(c.sbomId)); }
    if (c.cpeId != null && vulnSet.has(Number(c.cpeId))) e.high++;
    else if (c.version == null || c.version === "") e.medium++;
    else if (c.license == null || c.license === "") e.low++;
  }
  for (const [aid, set] of sbomsByAsset) { const e = out.get(aid); if (e) e.sboms = set.size; }
  return out;
}

export function scaInventory(tenant: number | null): ScaInventory {
  const empty: ScaInventory = {
    sboms: [], components: [], findings: [], byType: [], byLicense: [], bySupplier: [],
    summary: { sboms: 0, components: 0, distinctComponents: 0, byFormat: { cyclonedx: 0, spdx: 0 },
      vulnerable: 0, noLicense: 0, noVersion: 0, licenses: 0, suppliers: 0, dependencies: 0, cpeLinked: 0, assetsCovered: 0 },
  };
  let xo; try { xo = getDb("XORCISM"); } catch { return empty; }
  if (!has(xo, "SBOM") || !has(xo, "COMPONENT")) return empty;
  const compCols = colset(xo, "COMPONENT");
  if (!compCols.has("Name")) return empty; // not yet migrated
  const tw = (alias: string, has: boolean) => (tenant != null && has ? `WHERE ${alias}TenantID = ${tenant}` : "");
  const sbomTw = tw("s.", colset(xo, "SBOM").has("TenantID")); // qualified: SBOM joins ASSET (both have TenantID)
  const compTw = tw("", compCols.has("TenantID"));

  const sbomRows = xo.prepare(
    `SELECT s.SbomID AS id, s.Name AS name, s.Format AS format, s.SpecVersion AS specVersion,
            s.SubjectName AS subject, s.SubjectVersion AS subjectVersion, s.SerialNumber AS serialNumber,
            s.AssetID AS assetId, a.AssetName AS asset, s.ComponentCount AS componentCount,
            s.LicenseCount AS licenseCount, s.Source AS source, s.ToolName AS toolName, s.CreatedDate AS createdDate
     FROM SBOM s LEFT JOIN ASSET a ON a.AssetID = s.AssetID ${sbomTw} ORDER BY s.SbomID DESC`,
  ).all() as any[];

  const comps = xo.prepare(
    `SELECT ComponentID AS id, Name AS name, Version AS version, COALESCE(ComponentType,'library') AS type,
            PURL AS purl, CPE AS cpe, CPEID AS cpeId, Supplier AS supplier, License AS license, Scope AS scope,
            SbomID AS sbomId, AssetID AS assetId
     FROM COMPONENT ${compTw} ORDER BY Name COLLATE NOCASE`,
  ).all() as any[];

  const vulnSet = vulnerableCpeIds();
  const sbomName = new Map<number, string>(sbomRows.map((s) => [s.id, s.name]));

  const components: ComponentRow[] = comps.map((c) => ({
    id: c.id, name: c.name, version: c.version, type: c.type, purl: c.purl, cpe: c.cpe,
    supplier: c.supplier, license: c.license, scope: c.scope,
    sbomId: c.sbomId, sbom: c.sbomId != null ? sbomName.get(c.sbomId) ?? null : null,
    assetId: c.assetId, vulnerable: c.cpeId != null && vulnSet.has(Number(c.cpeId)),
  }));

  // breakdowns
  const tally = (key: (c: ComponentRow) => string | null) => {
    const m = new Map<string, number>();
    for (const c of components) { const k = key(c); if (k) m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].map(([k, v]) => [k, v] as [string, number]).sort((a, b) => b[1] - a[1]);
  };
  const byType = tally((c) => c.type).map(([type, count]) => ({ type, count }));
  const byLicense = tally((c) => c.license).slice(0, 12).map(([license, count]) => ({ license, count }));
  const bySupplier = tally((c) => c.supplier).slice(0, 12).map(([supplier, count]) => ({ supplier, count }));

  // worklist
  const findings: ScaFinding[] = [];
  for (const c of components) {
    if (c.vulnerable)
      findings.push({ id: c.id, component: `${c.name}${c.version ? " " + c.version : ""}`, severity: "High",
        reason: "Component maps to a known-vulnerable CPE.", kind: "vulnerable", label: "Known-vulnerable component" });
    else if (!c.license)
      findings.push({ id: c.id, component: `${c.name}${c.version ? " " + c.version : ""}`, severity: "Low",
        reason: "No license declared — license-compliance gap.", kind: "no-license", label: "Missing license" });
    if (!c.version)
      findings.push({ id: c.id, component: c.name, severity: "Medium",
        reason: "No version recorded — cannot track vulnerabilities/updates.", kind: "no-version", label: "Unpinned version" });
  }
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  findings.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);

  const dependencies = has(xo, "COMPONENTDEPENDENCY")
    ? (xo.prepare(`SELECT COUNT(*) c FROM COMPONENTDEPENDENCY ${tw("", colset(xo, "COMPONENTDEPENDENCY").has("TenantID"))}`).get() as { c: number }).c : 0;
  const distinct = new Set(components.map((c) => `${c.name}@${c.version ?? ""}`)).size;
  const assetsCovered = new Set(sbomRows.map((s) => s.assetId).filter((x) => x != null)).size;

  return {
    sboms: sbomRows.map((s) => ({ ...s, vulnerableCount: 0 })),
    components: components.slice(0, 1000),
    findings: findings.slice(0, 200),
    byType, byLicense, bySupplier,
    summary: {
      sboms: sbomRows.length, components: components.length, distinctComponents: distinct,
      byFormat: {
        cyclonedx: sbomRows.filter((s) => /cyclonedx/i.test(s.format)).length,
        spdx: sbomRows.filter((s) => /spdx/i.test(s.format)).length,
      },
      vulnerable: components.filter((c) => c.vulnerable).length,
      noLicense: components.filter((c) => !c.license).length,
      noVersion: components.filter((c) => !c.version).length,
      licenses: new Set(components.map((c) => c.license).filter(Boolean)).size,
      suppliers: new Set(components.map((c) => c.supplier).filter(Boolean)).size,
      dependencies, cpeLinked: components.filter((c) => c.cpe).length, assetsCovered,
    },
  };
}

// ─────────────────────────────── graph ───────────────────────────────
export interface ScaGraph {
  nodes: { id: string; label: string; type: string; sub: string | null; vulnerable: boolean }[];
  links: { source: string; target: string; kind: string }[];
  focus: string | null;
}

/** Composition graph for one SBOM (or all): SBOM → components, plus dependency edges. */
export function scaGraph(sbomId: number | null, tenant: number | null): ScaGraph {
  const g: ScaGraph = { nodes: [], links: [], focus: sbomId != null ? `sbom:${sbomId}` : null };
  let xo; try { xo = getDb("XORCISM"); } catch { return g; }
  if (!has(xo, "SBOM") || !colset(xo, "COMPONENT").has("Name")) return g;
  const ttw = tenant != null && colset(xo, "SBOM").has("TenantID") ? `AND s.TenantID = ${tenant}` : "";
  const sboms = xo.prepare(
    `SELECT s.SbomID AS id, s.Name AS name, s.Format AS format FROM SBOM s WHERE 1=1 ${sbomId != null ? "AND s.SbomID = " + Number(sbomId) : ""} ${ttw}`,
  ).all() as { id: number; name: string; format: string }[];
  if (!sboms.length) return g;
  const ids = sboms.map((s) => s.id);
  const vulnSet = vulnerableCpeIds();

  const placeholders = ids.map(() => "?").join(",");
  const comps = xo.prepare(
    `SELECT ComponentID AS id, SbomID AS sbomId, Name AS name, Version AS version, COALESCE(ComponentType,'library') AS type,
            BOMRef AS bomRef, CPEID AS cpeId, License AS license FROM COMPONENT WHERE SbomID IN (${placeholders})`,
  ).all(...ids) as any[];
  const deps = has(xo, "COMPONENTDEPENDENCY")
    ? xo.prepare(`SELECT SbomID AS sbomId, FromRef AS f, ToRef AS t FROM COMPONENTDEPENDENCY WHERE SbomID IN (${placeholders})`).all(...ids) as any[]
    : [];

  for (const s of sboms)
    g.nodes.push({ id: `sbom:${s.id}`, label: s.name, type: "sbom", sub: s.format, vulnerable: false });

  const refToNode = new Map<string, string>(); // "sbomId|bomRef" → node id
  for (const c of comps) {
    const nid = `comp:${c.id}`;
    g.nodes.push({
      id: nid, label: `${c.name}${c.version ? " " + c.version : ""}`, type: c.type,
      sub: c.license || null, vulnerable: c.cpeId != null && vulnSet.has(Number(c.cpeId)),
    });
    g.links.push({ source: `sbom:${c.sbomId}`, target: nid, kind: "contains" });
    if (c.bomRef) refToNode.set(`${c.sbomId}|${c.bomRef}`, nid);
  }
  for (const d of deps) {
    const src = refToNode.get(`${d.sbomId}|${d.f}`), dst = refToNode.get(`${d.sbomId}|${d.t}`);
    if (src && dst) g.links.push({ source: src, target: dst, kind: "depends" });
  }
  return g;
}

// ─────────────────────────────── export ───────────────────────────────

function loadSbomForExport(sbomId: number, tenant: number | null): { sbom: any; comps: any[]; deps: any[] } | null {
  const xo = getDb("XORCISM");
  if (!has(xo, "SBOM")) return null;
  const ttw = tenant != null && colset(xo, "SBOM").has("TenantID") ? "AND TenantID = " + tenant : "";
  const sbom = xo.prepare(`SELECT * FROM SBOM WHERE SbomID = ? ${ttw}`).get(sbomId) as any;
  if (!sbom) return null;
  const comps = xo.prepare("SELECT * FROM COMPONENT WHERE SbomID = ? ORDER BY Name COLLATE NOCASE").all(sbomId) as any[];
  const deps = has(xo, "COMPONENTDEPENDENCY") ? xo.prepare("SELECT * FROM COMPONENTDEPENDENCY WHERE SbomID = ?").all(sbomId) as any[] : [];
  return { sbom, comps, deps };
}

/** Export an SBOM as a CycloneDX 1.5 JSON object (round-trips imported data). */
export function exportCycloneDX(sbomId: number, tenant: number | null): any | null {
  const data = loadSbomForExport(sbomId, tenant); if (!data) return null;
  const { sbom, comps, deps } = data;
  const refOf = (c: any) => c.BOMRef || c.PURL || `${c.Name}@${c.Version || ""}`;
  const components = comps.map((c) => {
    const o: any = { type: c.ComponentType || "library", "bom-ref": refOf(c), name: c.Name };
    if (c.Version) o.version = c.Version;
    if (c.Group) o.group = c.Group;
    if (c.PURL) o.purl = c.PURL;
    if (c.CPE) o.cpe = c.CPE;
    if (c.Supplier) o.supplier = { name: c.Supplier };
    if (c.Publisher) o.publisher = c.Publisher;
    if (c.License) o.licenses = [{ license: { name: c.License } }];
    if (c.Hash && c.Hash.includes(":")) { const [alg, content] = c.Hash.split(/:(.+)/); o.hashes = [{ alg, content }]; }
    if (c.Scope) o.scope = c.Scope;
    if (c.Description) o.description = c.Description;
    return o;
  });
  const depMap = new Map<string, Set<string>>();
  const byId = new Map<number, any>(comps.map((c) => [c.ComponentID, c]));
  for (const d of deps) { if (!depMap.has(d.FromRef)) depMap.set(d.FromRef, new Set()); depMap.get(d.FromRef)!.add(d.ToRef); }
  const dependencies = [...depMap.entries()].map(([ref, on]) => ({ ref, dependsOn: [...on] }));
  return {
    bomFormat: "CycloneDX", specVersion: "1.5",
    serialNumber: sbom.SerialNumber || `urn:uuid:${sbom.SbomGUID || randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: "application", name: "XORCISM", version: "1.1" }] },
      component: sbom.SubjectName ? { type: "application", name: sbom.SubjectName, version: sbom.SubjectVersion || undefined } : undefined,
    },
    components,
    dependencies: dependencies.length ? dependencies : undefined,
  };
}

/** Export an SBOM as an SPDX 2.3 JSON document object. */
export function exportSPDX(sbomId: number, tenant: number | null): any | null {
  const data = loadSbomForExport(sbomId, tenant); if (!data) return null;
  const { sbom, comps, deps } = data;
  const spdxId = (c: any) => `SPDXRef-${String(c.BOMRef || c.Name || c.ComponentID).replace(/[^a-zA-Z0-9.\-]/g, "-")}`;
  const idByRef = new Map<string, string>(comps.map((c) => [c.BOMRef || String(c.ComponentID), spdxId(c)]));
  const packages = comps.map((c) => {
    const externalRefs: any[] = [];
    if (c.PURL) externalRefs.push({ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: c.PURL });
    if (c.CPE) externalRefs.push({ referenceCategory: "SECURITY", referenceType: "cpe23Type", referenceLocator: c.CPE });
    const pkg: any = {
      SPDXID: spdxId(c), name: c.Name, downloadLocation: "NOASSERTION",
      versionInfo: c.Version || undefined,
      licenseConcluded: c.License || "NOASSERTION", licenseDeclared: c.License || "NOASSERTION",
      supplier: c.Supplier ? `Organization: ${c.Supplier}` : "NOASSERTION",
    };
    if (externalRefs.length) pkg.externalRefs = externalRefs;
    if (c.Hash && c.Hash.includes(":")) { const [algorithm, checksumValue] = c.Hash.split(/:(.+)/); pkg.checksums = [{ algorithm: String(algorithm).toUpperCase().replace(/[^A-Z0-9]/g, ""), checksumValue }]; }
    return pkg;
  });
  const relationships = deps.map((d) => ({
    spdxElementId: idByRef.get(d.FromRef) || d.FromRef, relationshipType: "DEPENDS_ON",
    relatedSpdxElement: idByRef.get(d.ToRef) || d.ToRef,
  }));
  return {
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
    name: sbom.Name || sbom.SubjectName || "XORCISM-SBOM",
    documentNamespace: sbom.SerialNumber || `https://xorcism/spdx/${sbom.SbomGUID || randomUUID()}`,
    creationInfo: { created: new Date().toISOString(), creators: ["Tool: XORCISM-1.1"] },
    packages,
    relationships: relationships.length ? relationships : undefined,
  };
}

/** Delete an SBOM and its components/edges (tenant-scoped). */
export function deleteSbom(sbomId: number, tenant: number | null): boolean {
  const xo = getDb("XORCISM");
  if (!has(xo, "SBOM")) return false;
  const ttw = tenant != null && colset(xo, "SBOM").has("TenantID") ? "AND TenantID = " + tenant : "";
  const row = xo.prepare(`SELECT SbomID FROM SBOM WHERE SbomID = ? ${ttw}`).get(sbomId);
  if (!row) return false;
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM COMPONENT WHERE SbomID = ?").run(sbomId);
    if (has(xo, "COMPONENTDEPENDENCY")) xo.prepare("DELETE FROM COMPONENTDEPENDENCY WHERE SbomID = ?").run(sbomId);
    xo.prepare("DELETE FROM SBOM WHERE SbomID = ?").run(sbomId);
  });
  tx();
  return true;
}

/**
 * Seed a representative demo SBOM for the demo tenant so /sca has content out of the box.
 * Idempotent — keyed on a fixed SerialNumber, so it is safe to call at every boot. The demo
 * deliberately includes a known-vulnerable component (log4j-core 2.14.1, Log4Shell CPE), a
 * component with no license (ms) and one with no version (left-pad) so the SCA worklist shows
 * real findings. Links to a demo asset of the tenant when one exists (feeds CPE→asset exposure).
 */
export function seedScaDemo(tenant: number): void {
  const xo = getDb("XORCISM");
  if (!has(xo, "SBOM") || !colset(xo, "SBOM").has("TenantID")) return;
  const serial = "urn:uuid:xorcism-demo-sbom-0001";
  if (xo.prepare("SELECT 1 FROM SBOM WHERE SerialNumber = ? AND TenantID = ?").get(serial, tenant)) return; // already seeded
  const demo = {
    bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: serial, version: 1,
    metadata: { component: { type: "application", name: "xorcism-demo-portal", version: "3.1.0" }, tools: { components: [{ type: "application", name: "syft" }] } },
    components: [
      { type: "library", "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", cpe: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", licenses: [{ license: { id: "Apache-2.0" } }], supplier: { name: "Apache Software Foundation" } },
      { type: "library", "bom-ref": "pkg:npm/express@4.18.2", name: "express", version: "4.18.2", purl: "pkg:npm/express@4.18.2", licenses: [{ license: { id: "MIT" } }], supplier: { name: "OpenJS Foundation" } },
      { type: "library", "bom-ref": "pkg:npm/lodash@4.17.19", name: "lodash", version: "4.17.19", purl: "pkg:npm/lodash@4.17.19", cpe: "cpe:2.3:a:lodash:lodash:4.17.19:*:*:*:*:*:*:*", licenses: [{ license: { id: "MIT" } }] },
      { type: "framework", "bom-ref": "pkg:npm/react@18.2.0", name: "react", version: "18.2.0", purl: "pkg:npm/react@18.2.0", licenses: [{ license: { id: "MIT" } }] },
      { type: "library", "bom-ref": "pkg:pypi/requests@2.31.0", name: "requests", version: "2.31.0", purl: "pkg:pypi/requests@2.31.0", licenses: [{ license: { id: "Apache-2.0" } }], supplier: { name: "Python Packaging Authority" } },
      { type: "library", "bom-ref": "pkg:npm/ms@2.0.0", name: "ms", version: "2.0.0", purl: "pkg:npm/ms@2.0.0" }, // no license → worklist finding
      { type: "library", "bom-ref": "pkg:npm/left-pad", name: "left-pad", purl: "pkg:npm/left-pad" }, // no version → worklist finding
    ],
    dependencies: [
      { ref: "pkg:npm/express@4.18.2", dependsOn: ["pkg:npm/ms@2.0.0"] },
      { ref: "pkg:npm/react@18.2.0", dependsOn: ["pkg:npm/lodash@4.17.19", "pkg:npm/left-pad"] },
    ],
  };
  let assetId: number | null = null;
  try {
    const a = xo.prepare("SELECT AssetID FROM ASSET WHERE TenantID = ? ORDER BY AssetID LIMIT 1").get(tenant) as { AssetID: number } | undefined;
    assetId = a ? Number(a.AssetID) : null;
  } catch { /* asset link is optional */ }
  importSbom({ sbom: parseSbom(demo), name: "Demo application SBOM", assetId, source: "demo" }, tenant, null);
}
