/**
 * attacktree.ts — attack trees for threat modeling (Schneier-style AND/OR trees).
 *
 * A root attack goal is decomposed via AND/OR gates into leaf attack steps. Each leaf carries a
 * feasibility (High/Medium/Low or 0-1) and a mitigated flag; the tree rolls these up — OR = the
 * easiest child (max), AND = the hardest required child (min) — to a root feasibility and the
 * single easiest attack path. Stored in XORCISM.ATTACKTREE / ATTACKTREENODE, optionally tied to a
 * THREATMODEL.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
const GATES = new Set(["AND", "OR"]);

export function likVal(s: string, mitigated: boolean): number {
  if (mitigated) return 0.05;
  const t = String(s ?? "").trim().toLowerCase();
  const n = Number(t);
  if (!Number.isNaN(n) && t !== "") return Math.max(0, Math.min(1, n > 1 ? n / 100 : n));
  if (/^(high|h|likely|easy)/.test(t)) return 0.9;
  if (/^(low|l|unlikely|hard|difficult)/.test(t)) return 0.15;
  return 0.5; // medium / unknown
}
const band = (v: number): string => (v >= 0.7 ? "High" : v >= 0.35 ? "Medium" : v > 0 ? "Low" : "None");

interface NodeRow {
  id: number; treeId: number; parentId: number | null; label: string; gate: string; description: string;
  likelihood: string; cost: string; difficulty: string; mitigated: boolean; mitigationNote: string;
  attackPattern: string; order: number;
}

function loadNodes(treeId: number): NodeRow[] {
  const db = getDb("XORCISM");
  return (db.prepare(
    `SELECT AttackTreeNodeID, AttackTreeID, ParentNodeID, Label, Gate, Description, Likelihood, Cost,
            Difficulty, Mitigated, MitigationNote, AttackPattern, SortOrder
     FROM ATTACKTREENODE WHERE AttackTreeID = ? ORDER BY SortOrder, AttackTreeNodeID`
  ).all(treeId) as Record<string, any>[]).map((r) => ({
    id: Number(r.AttackTreeNodeID), treeId: Number(r.AttackTreeID),
    parentId: r.ParentNodeID != null ? Number(r.ParentNodeID) : null,
    label: String(r.Label ?? ""), gate: GATES.has(String(r.Gate ?? "").toUpperCase()) ? String(r.Gate).toUpperCase() : "",
    description: String(r.Description ?? ""), likelihood: String(r.Likelihood ?? ""), cost: String(r.Cost ?? ""),
    difficulty: String(r.Difficulty ?? ""), mitigated: Number(r.Mitigated) === 1, mitigationNote: String(r.MitigationNote ?? ""),
    attackPattern: String(r.AttackPattern ?? ""), order: Number(r.SortOrder ?? 0),
  }));
}

/** Recursively compute a node's feasibility (0-1) + the easiest leaf path under it. */
function compute(nodeId: number, byParent: Map<number | null, NodeRow[]>, byId: Map<number, NodeRow>, seen = new Set<number>()): { value: number; path: string[] } {
  if (seen.has(nodeId)) return { value: 0, path: [] };
  seen.add(nodeId);
  const n = byId.get(nodeId)!;
  const kids = byParent.get(nodeId) || [];
  if (!kids.length || !n.gate) {
    return { value: likVal(n.likelihood, n.mitigated), path: [n.label] };
  }
  const childResults = kids.map((k) => compute(k.id, byParent, byId, seen));
  if (n.gate === "AND") {
    // all required → hardest child gates the value; path is the union (all must happen)
    let min = Infinity; const path: string[] = [];
    for (const c of childResults) { min = Math.min(min, c.value); path.push(...c.path); }
    if (n.mitigated) min = Math.min(min, 0.05);
    return { value: min === Infinity ? 0 : min, path: [n.label, ...path] };
  }
  // OR → easiest child wins
  let best = childResults[0]; for (const c of childResults) if (c.value > best.value) best = c;
  let v = best.value; if (n.mitigated) v = Math.min(v, 0.05);
  return { value: v, path: [n.label, ...best.path] };
}

export function getAttackTree(id: number, tenant: number | null): { tree: Record<string, unknown>; nodes: NodeRow[]; rootId: number | null; feasibility: number; band: string; easiestPath: string[] } | null {
  const db = getDb("XORCISM");
  const tw = tenant != null && cols("ATTACKTREE").has("TenantID") ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const tree = db.prepare(`SELECT * FROM ATTACKTREE WHERE AttackTreeID = ? ${tw}`).get(...(tw ? [id, tenant] : [id])) as Record<string, unknown> | undefined;
  if (!tree) return null;
  const nodes = loadNodes(id);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const byParent = new Map<number | null, NodeRow[]>();
  for (const n of nodes) { const a = byParent.get(n.parentId); if (a) a.push(n); else byParent.set(n.parentId, [n]); }
  const root = nodes.find((n) => n.parentId == null) || null;
  const r = root ? compute(root.id, byParent, byId) : { value: 0, path: [] };
  return { tree, nodes, rootId: root?.id ?? null, feasibility: Math.round(r.value * 100), band: band(r.value), easiestPath: r.path };
}

export function listAttackTrees(tenant: number | null): { trees: Record<string, unknown>[]; summary: Record<string, unknown> } {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTREE'").get()) return { trees: [], summary: { trees: 0, nodes: 0, leaves: 0, mitigated: 0, highRisk: 0 } };
  const tw = tenant != null && cols("ATTACKTREE").has("TenantID") ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = db.prepare(`SELECT * FROM ATTACKTREE ${tw} ORDER BY AttackTreeID DESC`).all(...(tw ? [tenant] : [])) as Record<string, any>[];
  let nodeTotal = 0, leafTotal = 0, mitTotal = 0, highRisk = 0;
  const trees = rows.map((t) => {
    const full = getAttackTree(Number(t.AttackTreeID), tenant)!;
    const leaves = full.nodes.filter((n) => !n.gate || !(full.nodes.some((c) => c.parentId === n.id)));
    nodeTotal += full.nodes.length; leafTotal += leaves.length;
    mitTotal += full.nodes.filter((n) => n.mitigated).length;
    if (full.feasibility >= 70) highRisk++;
    return { id: Number(t.AttackTreeID), name: String(t.Name ?? `Attack tree #${t.AttackTreeID}`), goal: String(t.Goal ?? ""),
      threatModelId: t.ThreatModelID != null ? Number(t.ThreatModelID) : null,
      nodes: full.nodes.length, leaves: leaves.length, feasibility: full.feasibility, band: full.band, easiestPath: full.easiestPath };
  });
  return { trees, summary: { trees: trees.length, nodes: nodeTotal, leaves: leafTotal, mitigated: mitTotal, highRisk } };
}

export function createAttackTree(p: { name: string; goal?: string; description?: string; threatModelId?: number | null }, tenant: number | null): { id: number; rootId: number } {
  const db = getDb("XORCISM");
  const now = new Date().toISOString();
  const tc = cols("ATTACKTREE");
  const id = (db.prepare("SELECT COALESCE(MAX(AttackTreeID),0)+1 n FROM ATTACKTREE").get() as { n: number }).n;
  const rec: Record<string, unknown> = { AttackTreeID: id, AttackTreeGUID: randomUUID(), Name: (p.name || "Attack tree").slice(0, 200),
    Goal: (p.goal || p.name || "").slice(0, 300), Description: (p.description || "").slice(0, 2000),
    ThreatModelID: p.threatModelId ?? null, CreatedDate: now, TenantID: tenant };
  const keys = Object.keys(rec).filter((k) => tc.has(k));
  db.prepare(`INSERT INTO ATTACKTREE (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  // root node = the goal (OR gate by default)
  const rootId = addNodeRaw(id, null, p.goal || p.name || "Attacker goal", "OR", "", "", false, tenant);
  return { id, rootId };
}

function addNodeRaw(treeId: number, parentId: number | null, label: string, gate: string, description: string, likelihood: string, mitigated: boolean, tenant: number | null): number {
  const db = getDb("XORCISM");
  const nc = cols("ATTACKTREENODE");
  const id = (db.prepare("SELECT COALESCE(MAX(AttackTreeNodeID),0)+1 n FROM ATTACKTREENODE").get() as { n: number }).n;
  const order = (db.prepare("SELECT COALESCE(MAX(SortOrder),0)+1 n FROM ATTACKTREENODE WHERE AttackTreeID=? AND ParentNodeID IS ?").get(treeId, parentId) as { n: number }).n;
  const rec: Record<string, unknown> = { AttackTreeNodeID: id, AttackTreeID: treeId, ParentNodeID: parentId,
    Label: (label || "Step").slice(0, 300), Gate: GATES.has(String(gate).toUpperCase()) ? String(gate).toUpperCase() : "",
    Description: (description || "").slice(0, 2000), Likelihood: (likelihood || "").slice(0, 40), Mitigated: mitigated ? 1 : 0,
    SortOrder: order, CreatedDate: new Date().toISOString(), TenantID: tenant };
  const keys = Object.keys(rec).filter((k) => nc.has(k));
  db.prepare(`INSERT INTO ATTACKTREENODE (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
  return id;
}

export function addAttackTreeNode(p: { treeId: number; parentId: number; label: string; gate?: string; description?: string; likelihood?: string; mitigated?: boolean }, tenant: number | null): { id: number } {
  if (!Number.isInteger(p.treeId) || !Number.isInteger(p.parentId)) throw new Error("treeId + parentId required");
  if (!String(p.label ?? "").trim()) throw new Error("label required");
  return { id: addNodeRaw(p.treeId, p.parentId, p.label, p.gate || "", p.description || "", p.likelihood || "", !!p.mitigated, tenant) };
}

export function updateAttackTreeNode(p: { nodeId: number; label?: string; gate?: string; likelihood?: string; mitigated?: boolean; mitigationNote?: string }, tenant: number | null): { ok: boolean } {
  const db = getDb("XORCISM");
  const nc = cols("ATTACKTREENODE");
  const set: string[] = []; const args: unknown[] = [];
  if (p.label != null && nc.has("Label")) { set.push("Label = ?"); args.push(String(p.label).slice(0, 300)); }
  if (p.gate != null && nc.has("Gate")) { set.push("Gate = ?"); args.push(GATES.has(String(p.gate).toUpperCase()) ? String(p.gate).toUpperCase() : ""); }
  if (p.likelihood != null && nc.has("Likelihood")) { set.push("Likelihood = ?"); args.push(String(p.likelihood).slice(0, 40)); }
  if (p.mitigated != null && nc.has("Mitigated")) { set.push("Mitigated = ?"); args.push(p.mitigated ? 1 : 0); }
  if (p.mitigationNote != null && nc.has("MitigationNote")) { set.push("MitigationNote = ?"); args.push(String(p.mitigationNote).slice(0, 1000)); }
  if (!set.length) return { ok: false };
  args.push(p.nodeId);
  const r = db.prepare(`UPDATE ATTACKTREENODE SET ${set.join(", ")} WHERE AttackTreeNodeID = ?`).run(...args);
  return { ok: r.changes > 0 };
}

export function deleteAttackTreeNode(nodeId: number, tenant: number | null): { ok: boolean; deleted: number } {
  const db = getDb("XORCISM");
  // delete the node + its descendants (cycle-guarded BFS)
  const all = db.prepare("SELECT AttackTreeNodeID, ParentNodeID FROM ATTACKTREENODE").all() as { AttackTreeNodeID: number; ParentNodeID: number | null }[];
  const childrenOf = new Map<number, number[]>();
  for (const n of all) if (n.ParentNodeID != null) { const a = childrenOf.get(n.ParentNodeID); if (a) a.push(n.AttackTreeNodeID); else childrenOf.set(n.ParentNodeID, [n.AttackTreeNodeID]); }
  const toDel: number[] = []; const q = [nodeId]; const seen = new Set<number>();
  while (q.length) { const x = q.shift()!; if (seen.has(x)) continue; seen.add(x); toDel.push(x); for (const c of childrenOf.get(x) || []) q.push(c); }
  const ph = toDel.map(() => "?").join(",");
  const r = db.prepare(`DELETE FROM ATTACKTREENODE WHERE AttackTreeNodeID IN (${ph})`).run(...toDel);
  return { ok: r.changes > 0, deleted: r.changes };
}
