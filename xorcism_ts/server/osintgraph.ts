/**
 * osintgraph.ts — Palantir-style OSINT link analysis over XTHREAT.INTELEXCHANGE.
 *
 * Resolves the OSINT/CTI feed into an entity-link graph: each intel item is a node, and the
 * CVEs, threat actors, malware, ATT&CK techniques (from the tag columns) and IOCs (domains, IPs,
 * emails, hashes, .onion — defang-aware, parsed from the description) become typed entity nodes
 * linked to it. Entities that recur across items collapse into one node, so co-occurrence and
 * pivots emerge: an analyst can see which actors, infrastructure and CVEs cluster together.
 * Read-only; consumed by the /osint-graph d3 force-graph page.
 */
import { getDb } from "./db";

function has(table: string): boolean {
  try { return !!getDb("XTHREAT").prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); } catch { return false; }
}

const _split = (s: string): string[] => String(s ?? "").split(/[,;\n]+/).map((x) => x.trim()).filter(Boolean);
const _defang = (s: string): string => s.replace(/\[\.\]|\(\.\)|\[dot\]/gi, ".").replace(/\[@\]|\(at\)/gi, "@").replace(/^hxxp/i, "http");
const RE = {
  ip: /\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b/g,
  email: /\b[a-z0-9._%+-]+(?:@|\[@\]|\(at\))[a-z0-9.-]+\[?\.\]?[a-z]{2,}\b/gi,
  onion: /\b[a-z2-7]{16,56}\.onion\b/gi,
  hash: /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi,
  domain: /\b(?:[a-z0-9-]+\[?\.\]?)+[a-z]{2,}\b/gi,
  cve: /CVE-\d{4}-\d{3,7}/gi,
  attack: /\bT\d{4}(?:\.\d{3})?\b/g,
};
const COMMON_TLD_NOISE = /\.(png|jpg|gif|svg|css|js|html|php|json|xml|txt|pdf|md|exe|dll|zip)$/i;

export interface GraphNode { id: string; type: string; label: string; degree: number; source?: string; date?: string; ref?: string; }
export interface GraphLink { source: string; target: string; kind: string; }

export function osintGraph(opts: { limit?: number } = {}): { nodes: GraphNode[]; links: GraphLink[]; summary: Record<string, unknown> } {
  if (!has("INTELEXCHANGE")) return { nodes: [], links: [], summary: { items: 0, entities: 0, links: 0, byType: {} } };
  const db = getDb("XTHREAT");
  const items = db.prepare(
    `SELECT IntelID, IntelName, IntelDescription, IntelReference, IntelSource, IntelDate,
            CveTags, ActorTags, MalwareTags, AttackTags FROM INTELEXCHANGE`
  ).all() as Record<string, any>[];

  const nodes = new Map<string, GraphNode>();
  const links: GraphLink[] = [];
  const linkSeen = new Set<string>();
  const ensure = (id: string, type: string, label: string, extra: Partial<GraphNode> = {}): void => {
    const n = nodes.get(id);
    if (n) { n.degree++; return; }
    nodes.set(id, { id, type, label: label.slice(0, 80), degree: 1, ...extra });
  };
  const link = (a: string, b: string, kind: string): void => {
    const k = `${a}|${b}`; if (linkSeen.has(k)) return; linkSeen.add(k);
    links.push({ source: a, target: b, kind });
  };

  const limit = Math.max(50, Math.min(opts.limit ?? 600, 2000));
  for (const it of items) {
    const itemId = `intel:${it.IntelID}`;
    nodes.set(itemId, { id: itemId, type: "intel", label: String(it.IntelName ?? `Intel #${it.IntelID}`).slice(0, 80), degree: 0,
      source: String(it.IntelSource ?? ""), date: it.IntelDate ? String(it.IntelDate).slice(0, 10) : "", ref: String(it.IntelReference ?? "") });

    const addEntities = (raw: string, type: string, prefix: string, kind: string, normalize?: (s: string) => string): void => {
      for (let v of _split(raw)) {
        v = (normalize ? normalize(v) : v).trim();
        if (!v) continue;
        const id = `${prefix}:${v.toLowerCase()}`;
        ensure(id, type, v); link(itemId, id, kind);
        nodes.get(itemId)!.degree++;
      }
    };
    addEntities(it.CveTags, "cve", "cve", "references", (s) => (RE.cve.exec(s) ? s.toUpperCase() : s).toUpperCase());
    addEntities(it.ActorTags, "actor", "actor", "attributed-to");
    addEntities(it.MalwareTags, "malware", "malware", "uses");
    addEntities(it.AttackTags, "attack", "attack", "technique");

    // IOCs from the description (defang-aware). Order matters: emails/onion/ip before generic domain.
    const text = _defang(String(it.IntelDescription ?? ""));
    const found = new Set<string>();
    const harvest = (re: RegExp, type: string, prefix: string, post?: (s: string) => string): void => {
      re.lastIndex = 0; let m: RegExpExecArray | null;
      while ((m = re.exec(text)) && found.size < 40) {
        let v = _defang(m[0]); if (post) v = post(v); v = v.replace(/[.,;]$/, "").trim();
        if (!v || found.has(v.toLowerCase())) continue;
        found.add(v.toLowerCase());
        const id = `${prefix}:${v.toLowerCase()}`;
        ensure(id, type, v); link(itemId, id, "indicator"); nodes.get(itemId)!.degree++;
      }
    };
    harvest(RE.email, "email", "email");
    harvest(RE.onion, "onion", "onion");
    harvest(RE.hash, "hash", "hash");
    harvest(RE.ip, "ip", "ip");
    // domains last; skip ones already captured as email/onion and obvious file/extension noise
    RE.domain.lastIndex = 0; let dm: RegExpExecArray | null;
    while ((dm = RE.domain.exec(text)) && found.size < 60) {
      let v = _defang(dm[0]).replace(/[.,;]$/, "").toLowerCase();
      if (!v.includes(".") || found.has(v) || COMMON_TLD_NOISE.test(v) || v.endsWith(".onion")) continue;
      if (/@/.test(v) || /^\d+(\.\d+){3}$/.test(v)) continue;
      found.add(v);
      const id = `domain:${v}`; ensure(id, "domain", v); link(itemId, id, "indicator"); nodes.get(itemId)!.degree++;
    }
  }

  // prune to the top-degree nodes (keep all intel items + the highest-degree entities) for a readable graph
  let arr = [...nodes.values()];
  if (arr.length > limit) {
    const intel = arr.filter((n) => n.type === "intel");
    const ents = arr.filter((n) => n.type !== "intel").sort((a, b) => b.degree - a.degree).slice(0, Math.max(0, limit - intel.length));
    const keep = new Set([...intel, ...ents].map((n) => n.id));
    arr = [...intel, ...ents];
    for (let i = links.length - 1; i >= 0; i--) if (!keep.has(links[i].source) || !keep.has(links[i].target)) links.splice(i, 1);
  }
  const byType: Record<string, number> = {};
  for (const n of arr) byType[n.type] = (byType[n.type] || 0) + 1;

  return {
    nodes: arr, links,
    summary: { items: items.length, entities: arr.filter((n) => n.type !== "intel").length, links: links.length,
      byType, topEntities: arr.filter((n) => n.type !== "intel").sort((a, b) => b.degree - a.degree).slice(0, 8).map((n) => ({ label: n.label, type: n.type, degree: n.degree })) },
  };
}
