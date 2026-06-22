/**
 * cloudsec.ts — Cloud Security Management (CSPM-style governance pane).
 *
 * One pane over the tenant's cloud estate: assets identified as cloud (ASSET.cloud flag /
 * hosted-by-third-party / a cloud ASSETTAG / a cloud-looking hostname), enriched cross-DB with
 * their vulnerabilities (KEV / critical via ASSETVULNERABILITY ⋈ XVULNERABILITY.VULNERABILITY),
 * public-exposure and encryption posture, plus a CSA CCM coverage reference (the imported CCM
 * catalogue) and a risk-ranked misconfiguration/exposure worklist. Fed by the cloud connectors
 * (Entra ID, Wiz, Lacework, Upwind, Chainguard…). Read-only governance view.
 */
import { getDb } from "./db";

const CLOUD_TAGS = /^(cloud|aws|amazon|azure|gcp|google.?cloud|oci|oracle.?cloud|alibaba|saas|paas|iaas|serverless|lambda|s3|ec2|eks|aks|gke|kubernetes|k8s|container|ecs|fargate|cloudfront|rds|blob|vpc)$/i;
const CLOUD_HOST = /amazonaws\.com|azure|windows\.net|googleusercontent|gcp|cloudapp|herokuapp|cloudfront|\.run\.app/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1 || /^(y|yes|true)$/i.test(String(v ?? "")); }
const critRank = (c: string): number => ({ critical: 4, high: 3, medium: 2, moderate: 2, low: 1 } as Record<string, number>)[String(c).toLowerCase().split(/\s/)[0]] ?? 0;
const providerOf = (tags: string[], host: string, os: string): string => {
  const blob = `${tags.join(" ")} ${host} ${os}`.toLowerCase();
  if (/aws|amazon|ec2|s3|eks|amazonaws/.test(blob)) return "AWS";
  if (/azure|windows\.net|aks|entra/.test(blob)) return "Azure";
  if (/gcp|google|gke|googleusercontent|\.run\.app/.test(blob)) return "GCP";
  if (/oci|oracle/.test(blob)) return "OCI";
  if (/saas/.test(blob)) return "SaaS";
  return "Cloud";
};

export interface CloudInventory { rows: Record<string, unknown>[]; worklist: Record<string, unknown>[]; summary: Record<string, unknown>; }

export function cloudInventory(tenant: number | null): CloudInventory {
  const xo = getDb("XORCISM");
  const empty: CloudInventory = { rows: [], worklist: [], summary: { cloudAssets: 0, publicFacing: 0, unencrypted: 0, criticalAssets: 0, withCriticalVulns: 0, kev: 0, noOwner: 0, thirdParty: 0, byProvider: {}, ccmControls: 0, ccmDomains: 0 } };
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSET'").get()) return empty;
  const ac = cols("XORCISM", "ASSET");
  const sel = (c: string): string => (ac.has(c) ? c : `NULL AS ${c}`);
  const tw = tenant != null && ac.has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const assets = xo.prepare(
    `SELECT AssetID, AssetName, ${sel("AssetCriticalityLevel")}, ${sel("OSName")}, ${sel("hostname")},
            ${sel("ipaddressIPv4")}, ${sel("cloud")}, ${sel("hostedbythirdparty")}, ${sel("isEncrypted")},
            ${sel("PublicFacing")}, ${sel("HostPII")}, ${sel("AssetOwnershipID")}
     FROM ASSET ${tw}`
  ).all() as Record<string, any>[];

  // tags per asset
  const tagsBy = new Map<number, string[]>();
  if (xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETTAG'").get()) {
    for (const t of xo.prepare("SELECT AssetID, Tag FROM ASSETTAG").all() as { AssetID: number; Tag: string }[]) {
      const a = tagsBy.get(Number(t.AssetID)); if (a) a.push(String(t.Tag)); else tagsBy.set(Number(t.AssetID), [String(t.Tag)]);
    }
  }

  const isCloud = (a: Record<string, any>): boolean => {
    if (truthy(a.cloud)) return true;
    const tags = tagsBy.get(Number(a.AssetID)) || [];
    if (tags.some((t) => CLOUD_TAGS.test(t.trim()))) return true;
    if (truthy(a.hostedbythirdparty) && (CLOUD_HOST.test(String(a.hostname ?? "")) || tags.some((t) => /saas|cloud/i.test(t)))) return true;
    if (CLOUD_HOST.test(String(a.hostname ?? "")) || CLOUD_HOST.test(String(a.OSName ?? ""))) return true;
    return false;
  };
  const cloud = assets.filter(isCloud);
  if (!cloud.length) {
    const ccm = ccmRef();
    return { ...empty, summary: { ...empty.summary, ccmControls: ccm.controls, ccmDomains: ccm.domains } };
  }

  // cross-DB vuln enrichment (KEV / critical per asset)
  const vulnBy = new Map<number, { total: number; critical: number; kev: number }>();
  if (xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITY'").get()) {
    const avTw = tenant != null && cols("XORCISM", "ASSETVULNERABILITY").has("TenantID") ? `AND (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    const links = xo.prepare(`SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${avTw}`).all() as { AssetID: number; VulnerabilityID: number }[];
    const cloudIds = new Set(cloud.map((a) => Number(a.AssetID)));
    const relevant = links.filter((l) => cloudIds.has(Number(l.AssetID)));
    const vids = [...new Set(relevant.map((l) => Number(l.VulnerabilityID)))];
    const meta = new Map<number, { kev: boolean; cvss: number | null }>();
    const vc = cols("XVULNERABILITY", "VULNERABILITY");
    if (vids.length && vc.size) {
      const xv = getDb("XVULNERABILITY");
      const g = (c: string): string => (vc.has(c) ? c : `NULL AS ${c}`);
      for (let i = 0; i < vids.length; i += 400) {
        const ch = vids.slice(i, i + 400);
        for (const r of xv.prepare(`SELECT VulnerabilityID, ${g("KEV")}, ${g("CVSSBaseScore")} FROM VULNERABILITY WHERE VulnerabilityID IN (${ch.map(() => "?").join(",")})`).all(...ch) as Record<string, any>[])
          meta.set(Number(r.VulnerabilityID), { kev: truthy(r.KEV), cvss: r.CVSSBaseScore != null && r.CVSSBaseScore !== "" ? Number(r.CVSSBaseScore) : null });
      }
    }
    for (const l of relevant) {
      const aid = Number(l.AssetID); const m = meta.get(Number(l.VulnerabilityID));
      const e = vulnBy.get(aid) || { total: 0, critical: 0, kev: 0 };
      e.total++; if (m?.kev) e.kev++; if (m && m.cvss != null && m.cvss >= 9) e.critical++;
      vulnBy.set(aid, e);
    }
  }

  const rows = cloud.map((a) => {
    const id = Number(a.AssetID);
    const tags = tagsBy.get(id) || [];
    const provider = providerOf(tags, String(a.hostname ?? ""), String(a.OSName ?? ""));
    const v = vulnBy.get(id) || { total: 0, critical: 0, kev: 0 };
    const publicFacing = truthy(a.PublicFacing);
    const encrypted = truthy(a.isEncrypted);
    const crit = String(a.AssetCriticalityLevel ?? "").trim();
    const critical = critRank(crit) >= 4;
    const pii = truthy(a.HostPII);
    const owner = a.AssetOwnershipID != null && String(a.AssetOwnershipID) !== "";
    const flags: string[] = [];
    let score = 0;
    if (publicFacing && (v.kev || v.critical)) { flags.push("Internet-facing with KEV/critical vuln"); score += 50; }
    if (publicFacing && !encrypted) { flags.push("Public-facing & unencrypted"); score += 25; }
    if (pii && !encrypted) { flags.push("Holds PII without encryption"); score += 25; }
    if (critical && !encrypted) { flags.push("Business-critical & unencrypted"); score += 15; }
    if (!owner) { flags.push("No owner"); score += 8; }
    if (v.kev) score += 15;
    score += v.critical * 5 + critRank(crit) * 2 + (publicFacing ? 5 : 0);
    return { id, name: String(a.AssetName ?? `#${id}`), provider, criticality: crit, publicFacing, encrypted, pii,
      hostname: String(a.hostname ?? ""), ip: String(a.ipaddressIPv4 ?? ""), thirdParty: truthy(a.hostedbythirdparty),
      owner, tags: tags.slice(0, 6), vulns: v.total, criticalVulns: v.critical, kev: v.kev, flags, score: Math.min(100, score) };
  });
  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  const byProvider: Record<string, number> = {};
  for (const r of rows) byProvider[r.provider as string] = (byProvider[r.provider as string] || 0) + 1;
  const worklist = rows.filter((r) => r.flags.length).map((r) => ({
    id: r.id, name: r.name, provider: r.provider, severity: r.score >= 50 ? "Critical" : r.score >= 25 ? "High" : r.score >= 10 ? "Medium" : "Low",
    reason: r.flags[0], flags: r.flags, score: r.score,
  })).slice(0, 200);
  const ccm = ccmRef();

  return {
    rows, worklist,
    summary: {
      cloudAssets: rows.length,
      publicFacing: rows.filter((r) => r.publicFacing).length,
      unencrypted: rows.filter((r) => !r.encrypted).length,
      criticalAssets: rows.filter((r) => critRank(r.criticality) >= 4).length,
      withCriticalVulns: rows.filter((r) => r.criticalVulns > 0).length,
      kev: rows.filter((r) => r.kev > 0).length,
      noOwner: rows.filter((r) => !r.owner).length,
      thirdParty: rows.filter((r) => r.thirdParty).length,
      byProvider, ccmControls: ccm.controls, ccmDomains: ccm.domains,
    },
  };
}

/** CSA CCM coverage reference — counts from the imported CCM catalogue (import_csa_ccm.py). */
function ccmRef(): { controls: number; domains: number } {
  try {
    const xo = getDb("XORCISM");
    const vc = xo.prepare("SELECT VocabularyID FROM VOCABULARY WHERE VocabularyName = 'CSA CCM'").get() as { VocabularyID: number } | undefined;
    if (!vc) return { controls: 0, domains: 0 };
    const controls = (xo.prepare("SELECT COUNT(*) c FROM CONTROL WHERE VocabularyID = ?").get(vc.VocabularyID) as { c: number }).c;
    const ids = xo.prepare("SELECT CIS FROM CONTROL WHERE VocabularyID = ? AND CIS IS NOT NULL").all(vc.VocabularyID) as { CIS: string }[];
    const domains = new Set(ids.map((r) => String(r.CIS).split("-")[0])).size;
    return { controls, domains };
  } catch { return { controls: 0, domains: 0 }; }
}
