/**
 * kgraph.ts — Unified security knowledge graph (/knowledge-graph).
 *
 * One queryable graph that fuses entities living in separate XORCISM databases — assets, the
 * software (CPE) they run, the vulnerabilities affecting them, the risks they carry and the
 * incidents that hit them — into an asset-centric blast-radius graph (XORCISM ⋈ XVULNERABILITY ⋈
 * XCOMPLIANCE ⋈ XINCIDENT). Powers blast-radius traversal ("what does CVE-X reach?", "what is the
 * blast radius of asset Y?") and a keyword query, deterministic and offline-safe. Read-only.
 */
import { getDb } from "./db";

export interface KNode { id: string; type: string; label: string; degree: number; meta?: Record<string, unknown> }
export interface KLink { source: string; target: string; rel: string }

const cols = (db: any, t: string): Set<string> => {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
};
const hasTable = (db: any, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

interface Graph { nodes: Map<string, KNode>; links: KLink[] }

/** Build the full knowledge graph (capped to the busiest assets for readability). */
function build(tenant: number | null, limit = 160): Graph {
  const xo = getDb("XORCISM");
  const nodes = new Map<string, KNode>();
  const links: KLink[] = [];
  const ensure = (id: string, type: string, label: string, meta?: Record<string, unknown>): KNode => {
    let n = nodes.get(id);
    if (!n) { n = { id, type, label: String(label).slice(0, 80), degree: 0, meta }; nodes.set(id, n); }
    else if (meta) n.meta = { ...n.meta, ...meta };
    return n;
  };
  const link = (a: string, b: string, rel: string): void => { links.push({ source: a, target: b, rel }); nodes.get(a)!.degree++; nodes.get(b)!.degree++; };

  // ── assets (tenant-scoped) ──
  const aCols = cols(xo, "ASSET");
  const tw = aCols.has("TenantID") && tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  const aArgs = aCols.has("TenantID") && tenant != null ? [tenant] : [];
  const crit = aCols.has("BusinessCriticality") ? "BusinessCriticality" : (aCols.has("Criticality") ? "Criticality" : "NULL");
  const assets = xo.prepare(`SELECT AssetID id, AssetName name, ${crit} crit FROM ASSET ${tw}`).all(...aArgs) as { id: number; name: string; crit: string | null }[];
  const assetById = new Map(assets.map((a) => [a.id, a]));

  // ── asset ↔ vulnerability ──
  const vulnRows = hasTable(xo, "ASSETVULNERABILITY")
    ? xo.prepare(`SELECT AssetID aid, VulnerabilityID vid FROM ASSETVULNERABILITY WHERE COALESCE(FalsePositive,0)=0`).all() as { aid: number; vid: number }[]
    : [];
  // enrich vuln refs + KEV from XVULNERABILITY
  const vidRefs = new Map<number, { ref: string; kev: boolean }>();
  try {
    const xv = getDb("XVULNERABILITY");
    const vcols = cols(xv, "VULNERABILITY");
    const kevExpr = vcols.has("IsKEV") ? "IsKEV" : vcols.has("KEV") ? "KEV" : "0";
    const ids = [...new Set(vulnRows.map((r) => r.vid))];
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
      for (const m of xv.prepare(`SELECT VulnerabilityID id, COALESCE(VULReferential,VULName) ref, ${kevExpr} kev FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { id: number; ref: string; kev: number }[])
        vidRefs.set(m.id, { ref: m.ref, kev: !!m.kev });
    }
  } catch { /* */ }

  // ── asset ↔ software (CPE) ──
  const cpeRows = hasTable(xo, "CPEFORASSET") && hasTable(xo, "CPE")
    ? xo.prepare(`SELECT cfa.AssetID aid, c.CPEName name FROM CPEFORASSET cfa JOIN CPE c ON c.CPEID=cfa.CPEID`).all() as { aid: number; name: string }[]
    : [];

  // ── asset ↔ risk (best-effort: only if RISKREGISTERENTRY carries an AssetID) ──
  let riskRows: { aid: number; rid: number; title: string }[] = [];
  try {
    const xc = getDb("XCOMPLIANCE");
    const rc = cols(xc, "RISKREGISTERENTRY");
    if (rc.has("AssetID")) {
      const titleCol = rc.has("RiskTitle") ? "RiskTitle" : rc.has("Title") ? "Title" : rc.has("RiskName") ? "RiskName" : "'Risk'";
      const idCol = rc.has("RiskRegisterEntryID") ? "RiskRegisterEntryID" : rc.has("EntryID") ? "EntryID" : "rowid";
      riskRows = xc.prepare(`SELECT AssetID aid, ${idCol} rid, ${titleCol} title FROM RISKREGISTERENTRY WHERE AssetID IS NOT NULL`).all() as any[];
    }
  } catch { /* */ }

  // ── asset ↔ incident (best-effort via ALERTFORASSET) ──
  let incRows: { aid: number; iid: number; name: string }[] = [];
  try {
    const xi = getDb("XINCIDENT");
    if (hasTable(xi, "ALERTFORASSET") && hasTable(xi, "ALERT")) {
      incRows = xi.prepare(`SELECT afa.AssetID aid, a.AlertID iid, a.AlertName name FROM ALERTFORASSET afa JOIN ALERT a ON a.AlertID=afa.AlertID`).all() as any[];
    }
  } catch { /* */ }

  // rank assets by total degree (vulns + cpes + risks + incidents), keep the busiest
  const deg = new Map<number, number>();
  const tally = (aid: number) => deg.set(aid, (deg.get(aid) || 0) + 1);
  for (const r of vulnRows) if (assetById.has(r.aid)) tally(r.aid);
  for (const r of cpeRows) if (assetById.has(r.aid)) tally(r.aid);
  for (const r of riskRows) if (assetById.has(r.aid)) tally(r.aid);
  for (const r of incRows) if (assetById.has(r.aid)) tally(r.aid);
  const keptAssets = new Set(
    [...assetById.keys()].sort((a, b) => (deg.get(b) || 0) - (deg.get(a) || 0)).slice(0, limit)
  );

  for (const aid of keptAssets) ensure(`asset:${aid}`, "asset", assetById.get(aid)!.name || `Asset #${aid}`, { criticality: assetById.get(aid)!.crit });
  for (const r of vulnRows) {
    if (!keptAssets.has(r.aid)) continue;
    const info = vidRefs.get(r.vid);
    const id = `vuln:${r.vid}`;
    ensure(id, info?.kev ? "vuln-kev" : "vuln", info?.ref || `Vuln #${r.vid}`, { kev: !!info?.kev });
    link(`asset:${r.aid}`, id, "affected_by");
  }
  for (const r of cpeRows) {
    if (!keptAssets.has(r.aid)) continue;
    const id = `cpe:${r.name}`; ensure(id, "software", r.name.replace(/^cpe:[\d.]*:?[aoh]?:?/, "").split(":").slice(0, 3).join(" ") || r.name);
    link(`asset:${r.aid}`, id, "runs");
  }
  for (const r of riskRows) {
    if (!keptAssets.has(r.aid)) continue;
    const id = `risk:${r.rid}`; ensure(id, "risk", r.title || `Risk #${r.rid}`); link(`asset:${r.aid}`, id, "carries");
  }
  for (const r of incRows) {
    if (!keptAssets.has(r.aid)) continue;
    const id = `incident:${r.iid}`; ensure(id, "incident", r.name || `Incident #${r.iid}`); link(`asset:${r.aid}`, id, "impacted_by");
  }
  return { nodes, links };
}

const TYPES = ["asset", "vuln", "vuln-kev", "software", "risk", "incident"];

export function knowledgeGraph(tenant: number | null, limit = 160): { nodes: KNode[]; links: KLink[]; summary: any } {
  const g = build(tenant, limit);
  const nodes = [...g.nodes.values()];
  const byType: Record<string, number> = {};
  for (const t of TYPES) byType[t] = 0;
  for (const n of nodes) byType[n.type] = (byType[n.type] || 0) + 1;
  return {
    nodes, links: g.links,
    summary: { nodes: nodes.length, links: g.links.length, byType, kev: byType["vuln-kev"] || 0, assets: byType.asset || 0 },
  };
}

/** BFS blast radius from a node id, up to `hops`. */
export function blastRadius(tenant: number | null, startId: string, hops = 2): { nodes: KNode[]; links: KLink[]; start: string } {
  const g = build(tenant, 1000);
  if (!g.nodes.has(startId)) return { nodes: [], links: [], start: startId };
  const adj = new Map<string, { id: string; rel: string }[]>();
  for (const l of g.links) {
    (adj.get(l.source) || adj.set(l.source, []).get(l.source)!).push({ id: l.target, rel: l.rel });
    (adj.get(l.target) || adj.set(l.target, []).get(l.target)!).push({ id: l.source, rel: l.rel });
  }
  const keep = new Set([startId]); let frontier = [startId];
  for (let h = 0; h < hops; h++) {
    const next: string[] = [];
    for (const id of frontier) for (const nb of adj.get(id) || []) if (!keep.has(nb.id)) { keep.add(nb.id); next.push(nb.id); }
    frontier = next;
  }
  const nodes = [...keep].map((id) => g.nodes.get(id)!).filter(Boolean);
  const links = g.links.filter((l) => keep.has(l.source) && keep.has(l.target));
  return { nodes, links, start: startId };
}

/** Keyword / NL-lite query → a focused subgraph + an answer. */
export function queryGraph(tenant: number | null, q: string): { answer: string; focus: string | null; nodes: KNode[]; links: KLink[] } {
  const g = build(tenant, 1000);
  const ql = (q || "").trim().toLowerCase();
  if (!ql) return { answer: "Ask about a CVE, an asset, or 'KEV' / 'crown jewels'.", focus: null, nodes: [], links: [] };

  // CVE / KEV intent
  const cve = (q.toUpperCase().match(/CVE-\d{4}-\d{3,7}/) || [])[0];
  if (cve) {
    const node = [...g.nodes.values()].find((n) => (n.type === "vuln" || n.type === "vuln-kev") && String(n.label).toUpperCase().includes(cve));
    if (node) { const br = blastRadius(tenant, node.id, 2); return { answer: `${cve} affects ${br.nodes.filter((n) => n.type === "asset").length} asset(s) in scope.`, focus: node.id, nodes: br.nodes, links: br.links }; }
    return { answer: `${cve} is not linked to any in-scope asset.`, focus: null, nodes: [], links: [] };
  }
  if (/\bkev\b|known exploit|exploited/.test(ql)) {
    const kevIds = [...g.nodes.values()].filter((n) => n.type === "vuln-kev").map((n) => n.id);
    const keep = new Set(kevIds); for (const l of g.links) if (kevIds.includes(l.target) || kevIds.includes(l.source)) { keep.add(l.source); keep.add(l.target); }
    const nodes = [...keep].map((id) => g.nodes.get(id)!).filter(Boolean);
    const links = g.links.filter((l) => keep.has(l.source) && keep.has(l.target));
    return { answer: `${kevIds.length} known-exploited (KEV) vulnerabilities touch ${nodes.filter((n) => n.type === "asset").length} asset(s).`, focus: null, nodes, links };
  }
  // asset name match
  const asset = [...g.nodes.values()].find((n) => n.type === "asset" && String(n.label).toLowerCase().includes(ql));
  if (asset) { const br = blastRadius(tenant, asset.id, 2); return { answer: `${asset.label}: ${br.nodes.filter((n) => n.type.startsWith("vuln")).length} vuln(s), ${br.nodes.filter((n) => n.type === "software").length} software, ${br.nodes.filter((n) => n.type === "incident").length} incident(s) within 2 hops.`, focus: asset.id, nodes: br.nodes, links: br.links }; }
  // generic label search
  const hits = [...g.nodes.values()].filter((n) => String(n.label).toLowerCase().includes(ql)).slice(0, 30);
  if (hits.length) { const keep = new Set(hits.map((n) => n.id)); const links = g.links.filter((l) => keep.has(l.source) && keep.has(l.target)); for (const l of links) { keep.add(l.source); keep.add(l.target); } return { answer: `${hits.length} node(s) match "${q}".`, focus: hits[0].id, nodes: [...keep].map((id) => g.nodes.get(id)!).filter(Boolean), links }; }
  return { answer: `Nothing matched "${q}".`, focus: null, nodes: [], links: [] };
}
