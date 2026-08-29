/**
 * attackflow.ts — MITRE CTID Attack Flow (github.com/center-for-threat-informed-defense/attack-flow).
 *
 * Attack Flow is a language (a STIX 2.1 extension, Apache 2.0) for describing how adversaries SEQUENCE
 * and combine ATT&CK techniques to reach their goals — a directed graph of behaviours rather than a
 * flat technique list. This module ingests Attack Flow **STIX 2.1 bundles** (the canonical machine-
 * readable exchange format, `.json` — the Builder's `.afb` is exported to STIX first) and stores them
 * as a graph so the /attack-flow cockpit can list, visualise and ATT&CK-map real-world adversary flows
 * (the project ships a corpus of ~40 incidents: SolarWinds, NotPetya, Conti, Equifax, …).
 *
 * Language objects (all STIX SDOs under the "Attack Flow" extension-definition):
 *   attack-flow      — root: name, scope (incident/campaign/threat-actor/malware/…), start_refs[]
 *   attack-action    — one behaviour: name, technique_id (ATT&CK), tactic_id, description, effect_refs[]
 *   attack-asset     — a target touched by actions (asset_refs)
 *   attack-condition — a branch: description, on_true_refs[] / on_false_refs[]
 *   attack-operator  — AND/OR join of paths: operator, effect_refs[]
 * The graph is the union of effect_refs / on_true_refs / on_false_refs (control flow) + asset_refs.
 *
 * Tables in XTHREAT (RBAC XTHREAT.ATTACKTECHNIQUE, like the other ATT&CK-facing threat cockpits).
 * ATT&CK coverage is cross-referenced against XTHREAT.ATTACKTECHNIQUE(AttackID, Name).
 */
import { allocId, getDb } from "./db";

const now = (): string => new Date().toISOString();
const tw = (t: number | null): string => (t == null ? "TenantID IS NULL" : "(TenantID = ? OR TenantID IS NULL)");

export const FLOW_SCOPES = ["incident", "campaign", "threat-actor", "malware", "emulation-plan", "attack-tree", "other"];
const NODE_KINDS = new Set(["attack-action", "attack-asset", "attack-condition", "attack-operator"]);

export function ensureAttackFlowTables(): void {
  getDb("XTHREAT").exec(`
    CREATE TABLE IF NOT EXISTS ATTACKFLOW(
      FlowID INTEGER PRIMARY KEY, TenantID INTEGER, StixId TEXT, Name TEXT, Scope TEXT,
      Description TEXT, Author TEXT, Confidence INTEGER, ExternalRefs TEXT, Source TEXT,
      Created TEXT, Modified TEXT, ImportedDate TEXT);
    CREATE TABLE IF NOT EXISTS ATTACKFLOWNODE(
      NodeID INTEGER PRIMARY KEY, FlowID INTEGER, StixId TEXT, Kind TEXT, Name TEXT,
      TechniqueId TEXT, TacticId TEXT, Description TEXT, Confidence INTEGER,
      ExecStart TEXT, ExecEnd TEXT, Operator TEXT, IsStart INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ATTACKFLOWEDGE(
      EdgeID INTEGER PRIMARY KEY, FlowID INTEGER, SrcStixId TEXT, DstStixId TEXT, Kind TEXT);
    CREATE INDEX IF NOT EXISTS ix_attackflow_tenant ON ATTACKFLOW(TenantID);
    CREATE INDEX IF NOT EXISTS ix_aflownode_flow ON ATTACKFLOWNODE(FlowID);
    CREATE INDEX IF NOT EXISTS ix_aflowedge_flow ON ATTACKFLOWEDGE(FlowID);
  `);
}

// ── STIX bundle parser ────────────────────────────────────────────────────────────
export interface ParsedNode {
  stixId: string; kind: string; name: string; techniqueId: string; tacticId: string;
  description: string; confidence: number | null; execStart: string; execEnd: string;
  operator: string; isStart: boolean;
}
export interface ParsedEdge { src: string; dst: string; kind: string }
export interface ParsedFlow {
  stixId: string; name: string; scope: string; description: string; author: string;
  confidence: number | null; externalRefs: any[]; created: string; modified: string;
  nodes: ParsedNode[]; edges: ParsedEdge[];
}

/** Parse an Attack Flow STIX 2.1 bundle into a flow + node + edge graph. Throws on non-flow bundles. */
export function parseBundle(bundle: any): ParsedFlow {
  if (!bundle || typeof bundle !== "object") throw new Error("not a JSON object");
  const objects: any[] = Array.isArray(bundle.objects) ? bundle.objects
    : (bundle.type === "attack-flow" || bundle.type === "attack-action" ? [bundle] : []);
  if (!objects.length) throw new Error("no STIX objects found (expected a bundle with an attack-flow)");

  const flow = objects.find((o) => o && o.type === "attack-flow");
  if (!flow) throw new Error("no attack-flow object in bundle — not an Attack Flow export");

  // author identity (created_by_ref → identity.name)
  const idById = new Map(objects.filter((o) => o && o.type === "identity").map((o) => [o.id, o.name || ""]));
  const author = (flow.created_by_ref && idById.get(flow.created_by_ref)) || [...idById.values()][0] || "";

  const start = new Set<string>(Array.isArray(flow.start_refs) ? flow.start_refs : []);
  const nodes: ParsedNode[] = [];
  const edges: ParsedEdge[] = [];

  for (const o of objects) {
    if (!o || !NODE_KINDS.has(o.type)) continue;
    const name = o.name || (o.type === "attack-condition" ? (o.description || "condition")
      : o.type === "attack-operator" ? `${o.operator || "OP"}` : o.type.replace("attack-", ""));
    nodes.push({
      stixId: o.id, kind: o.type, name: String(name).slice(0, 300),
      techniqueId: o.technique_id || "", tacticId: o.tactic_id || "",
      description: o.description || "", confidence: typeof o.confidence === "number" ? o.confidence : null,
      execStart: o.execution_start || "", execEnd: o.execution_end || "",
      operator: o.operator || "", isStart: start.has(o.id),
    });
    for (const dst of (o.effect_refs || [])) edges.push({ src: o.id, dst, kind: "effect" });
    for (const dst of (o.on_true_refs || [])) edges.push({ src: o.id, dst, kind: "on_true" });
    for (const dst of (o.on_false_refs || [])) edges.push({ src: o.id, dst, kind: "on_false" });
    for (const dst of (o.asset_refs || [])) edges.push({ src: o.id, dst, kind: "asset" });
  }
  // keep only edges whose endpoints are real nodes
  const ids = new Set(nodes.map((n) => n.stixId));
  const clean = edges.filter((e) => ids.has(e.src) && ids.has(e.dst));

  return {
    stixId: flow.id, name: flow.name || "Attack Flow", scope: flow.scope || "other",
    description: flow.description || "", author, confidence: typeof flow.confidence === "number" ? flow.confidence : null,
    externalRefs: Array.isArray(flow.external_references) ? flow.external_references : [],
    created: flow.created || now(), modified: flow.modified || now(), nodes, edges: clean,
  };
}

// ── persistence ─────────────────────────────────────────────────────────────────
export function importBundle(tenant: number | null, bundle: any, source = ""): { id: number; name: string; actions: number; techniques: number } {
  ensureAttackFlowTables();
  const p = parseBundle(bundle);
  const db = getDb("XTHREAT");
  // idempotent by (StixId, TenantID): replace an existing import of the same flow in place
  const ex = db.prepare(`SELECT FlowID FROM ATTACKFLOW WHERE StixId=? AND ${tw(tenant)}`).get(...(tenant == null ? [p.stixId] : [p.stixId, tenant])) as any;
  let id: number;
  if (ex) {
    id = ex.FlowID;
    db.prepare("DELETE FROM ATTACKFLOWNODE WHERE FlowID=?").run(id);
    db.prepare("DELETE FROM ATTACKFLOWEDGE WHERE FlowID=?").run(id);
    db.prepare("UPDATE ATTACKFLOW SET Name=?, Scope=?, Description=?, Author=?, Confidence=?, ExternalRefs=?, Source=?, Created=?, Modified=?, ImportedDate=? WHERE FlowID=?")
      .run(p.name, p.scope, p.description, p.author, p.confidence, JSON.stringify(p.externalRefs), source, p.created, p.modified, now(), id);
  } else {
    id = allocId(db, "ATTACKFLOW", "FlowID");
    db.prepare("INSERT INTO ATTACKFLOW (FlowID, TenantID, StixId, Name, Scope, Description, Author, Confidence, ExternalRefs, Source, Created, Modified, ImportedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .run(id, tenant, p.stixId, p.name, p.scope, p.description, p.author, p.confidence, JSON.stringify(p.externalRefs), source, p.created, p.modified, now());
  }
  const insN = db.prepare("INSERT INTO ATTACKFLOWNODE (NodeID, FlowID, StixId, Kind, Name, TechniqueId, TacticId, Description, Confidence, ExecStart, ExecEnd, Operator, IsStart) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");
  let nid = allocId(db, "ATTACKFLOWNODE", "NodeID");
  for (const n of p.nodes) { insN.run(nid++, id, n.stixId, n.kind, n.name, n.techniqueId, n.tacticId, n.description, n.confidence, n.execStart, n.execEnd, n.operator, n.isStart ? 1 : 0); }
  const insE = db.prepare("INSERT INTO ATTACKFLOWEDGE (EdgeID, FlowID, SrcStixId, DstStixId, Kind) VALUES (?,?,?,?,?)");
  let eid = allocId(db, "ATTACKFLOWEDGE", "EdgeID");
  for (const e of p.edges) { insE.run(eid++, id, e.src, e.dst, e.kind); }

  const techniques = new Set(p.nodes.filter((n) => /^T\d/.test(n.techniqueId)).map((n) => n.techniqueId)).size;
  const actions = p.nodes.filter((n) => n.kind === "attack-action").length;
  return { id, name: p.name, actions, techniques };
}

export function deleteFlow(id: number, tenant: number | null): { ok: boolean } {
  ensureAttackFlowTables();
  const db = getDb("XTHREAT");
  const ex = db.prepare(`SELECT FlowID FROM ATTACKFLOW WHERE FlowID=? AND ${tw(tenant)}`).get(...(tenant == null ? [id] : [id, tenant]));
  if (!ex) return { ok: false };
  db.prepare("DELETE FROM ATTACKFLOWNODE WHERE FlowID=?").run(id);
  db.prepare("DELETE FROM ATTACKFLOWEDGE WHERE FlowID=?").run(id);
  db.prepare("DELETE FROM ATTACKFLOW WHERE FlowID=?").run(id);
  return { ok: true };
}

// ── read: dashboard + detail ──────────────────────────────────────────────────────
function techCatalogue(): Map<string, string> {
  try {
    const db = getDb("XTHREAT");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").get()) return new Map();
    return new Map((db.prepare("SELECT AttackID AS id, Name AS name FROM ATTACKTECHNIQUE WHERE AttackID LIKE 'T%'").all() as { id: string; name: string }[]).map((r) => [r.id, r.name]));
  } catch { return new Map(); }
}

export function attackFlowDashboard(tenant: number | null): any {
  ensureAttackFlowTables();
  const db = getDb("XTHREAT");
  const args = tenant == null ? [] : [tenant];
  const rows = db.prepare(`SELECT * FROM ATTACKFLOW WHERE ${tw(tenant)} ORDER BY FlowID DESC`).all(...args) as any[];
  const cat = techCatalogue();
  const allTech = new Set<string>();
  const flows = rows.map((f) => {
    const nodes = db.prepare("SELECT Kind, TechniqueId FROM ATTACKFLOWNODE WHERE FlowID=?").all(f.FlowID) as any[];
    const tech = new Set(nodes.filter((n) => /^T\d/.test(n.TechniqueId)).map((n) => n.TechniqueId));
    tech.forEach((t) => allTech.add(t));
    const mapped = [...tech].filter((t) => cat.has(t)).length;
    return {
      id: f.FlowID, stixId: f.StixId, name: f.Name, scope: f.Scope, author: f.Author,
      description: f.Description, confidence: f.Confidence, source: f.Source, created: f.Created, importedDate: f.ImportedDate,
      actions: nodes.filter((n) => n.Kind === "attack-action").length, nodes: nodes.length,
      techniques: tech.size, mappedTechniques: mapped,
    };
  });
  return {
    flows,
    summary: {
      flows: flows.length,
      actions: flows.reduce((n, f) => n + f.actions, 0),
      techniques: allTech.size,
      mapped: [...allTech].filter((t) => cat.has(t)).length,
      catalogueLoaded: cat.size > 0,
    },
    scopes: FLOW_SCOPES,
  };
}

/** Longest-path layering over control-flow edges (effect/on_true/on_false), so the graph reads left→right. */
function assignDepths(nodeIds: string[], edges: ParsedEdge[], starts: Set<string>): Map<string, number> {
  const ctrl = edges.filter((e) => e.kind !== "asset");
  const depth = new Map<string, number>(nodeIds.map((id) => [id, starts.has(id) ? 0 : -1]));
  // ensure every node has a base; nodes with no incoming control edge start at 0
  const hasIncoming = new Set(ctrl.map((e) => e.dst));
  for (const id of nodeIds) if (!hasIncoming.has(id) && depth.get(id) === -1) depth.set(id, 0);
  for (const id of nodeIds) if (depth.get(id) === -1) depth.set(id, 0);
  // relax longest path (bounded passes to tolerate cycles)
  for (let pass = 0; pass < nodeIds.length; pass++) {
    let changed = false;
    for (const e of ctrl) {
      const d = (depth.get(e.src) ?? 0) + 1;
      if (d > (depth.get(e.dst) ?? 0)) { depth.set(e.dst, d); changed = true; }
    }
    if (!changed) break;
  }
  return depth;
}

export function attackFlowDetail(id: number, tenant: number | null): any {
  ensureAttackFlowTables();
  const db = getDb("XTHREAT");
  const f = db.prepare(`SELECT * FROM ATTACKFLOW WHERE FlowID=? AND ${tw(tenant)}`).get(...(tenant == null ? [id] : [id, tenant])) as any;
  if (!f) return null;
  const nrows = db.prepare("SELECT * FROM ATTACKFLOWNODE WHERE FlowID=? ORDER BY NodeID").all(id) as any[];
  const erows = db.prepare("SELECT SrcStixId AS src, DstStixId AS dst, Kind AS kind FROM ATTACKFLOWEDGE WHERE FlowID=?").all(id) as ParsedEdge[];
  const cat = techCatalogue();
  const starts = new Set(nrows.filter((n) => n.IsStart).map((n) => n.StixId));
  const depth = assignDepths(nrows.map((n) => n.StixId), erows, starts);

  const nodes = nrows.map((n) => ({
    stixId: n.StixId, kind: n.Kind, name: n.Name, techniqueId: n.TechniqueId, tacticId: n.TacticId,
    techniqueName: n.TechniqueId && cat.get(n.TechniqueId) ? cat.get(n.TechniqueId) : "",
    mapped: !!(n.TechniqueId && cat.has(n.TechniqueId)),
    description: n.Description, confidence: n.Confidence, execStart: n.ExecStart, execEnd: n.ExecEnd,
    operator: n.Operator, isStart: !!n.IsStart, depth: depth.get(n.StixId) ?? 0,
  }));

  // ATT&CK coverage
  const tset = new Map<string, { id: string; name: string; mapped: boolean; count: number }>();
  for (const n of nrows) {
    if (!/^T\d/.test(n.TechniqueId)) continue;
    const e = tset.get(n.TechniqueId) || { id: n.TechniqueId, name: cat.get(n.TechniqueId) || "", mapped: cat.has(n.TechniqueId), count: 0 };
    e.count++; tset.set(n.TechniqueId, e);
  }
  const coverage = [...tset.values()].sort((a, b) => a.id.localeCompare(b.id));

  return {
    flow: {
      id: f.FlowID, stixId: f.StixId, name: f.Name, scope: f.Scope, description: f.Description,
      author: f.Author, confidence: f.Confidence, source: f.Source, created: f.Created, modified: f.Modified,
      externalRefs: (() => { try { return JSON.parse(f.ExternalRefs || "[]"); } catch { return []; } })(),
    },
    nodes, edges: erows, coverage,
    stats: {
      actions: nrows.filter((n) => n.Kind === "attack-action").length,
      assets: nrows.filter((n) => n.Kind === "attack-asset").length,
      conditions: nrows.filter((n) => n.Kind === "attack-condition").length,
      operators: nrows.filter((n) => n.Kind === "attack-operator").length,
      techniques: coverage.length, mapped: coverage.filter((c) => c.mapped).length,
      maxDepth: Math.max(0, ...nodes.map((n) => n.depth)),
    },
  };
}

// ── ATT&CK Navigator layer export ─────────────────────────────────────────────────
/** Build an ATT&CK Navigator 5.0 layer for a flow (technique score = occurrence count, capped). */
export function navigatorLayer(id: number, tenant: number | null): Record<string, unknown> | null {
  ensureAttackFlowTables();
  const db = getDb("XTHREAT");
  const f = db.prepare(`SELECT Name FROM ATTACKFLOW WHERE FlowID=? AND ${tw(tenant)}`).get(...(tenant == null ? [id] : [id, tenant])) as { Name: string } | undefined;
  if (!f) return null;
  const rows = db.prepare("SELECT TechniqueId FROM ATTACKFLOWNODE WHERE FlowID=?").all(id) as { TechniqueId: string }[];
  const counts = new Map<string, number>();
  for (const r of rows) if (/^T\d/.test(r.TechniqueId)) counts.set(r.TechniqueId, (counts.get(r.TechniqueId) || 0) + 1);
  const maxN = Math.max(1, ...counts.values());
  const techniques = [...counts.entries()].map(([tid, n]) => ({
    techniqueID: tid, score: Math.round((n / maxN) * 100), enabled: true,
    comment: n > 1 ? `${n}× in this attack flow` : "used in this attack flow",
  }));
  return {
    name: `Attack Flow — ${f.Name}`.slice(0, 120), versions: { attack: "15", navigator: "5.0.0", layer: "4.5" },
    domain: "enterprise-attack", description: `ATT&CK techniques used in the "${f.Name}" attack flow (MITRE CTID Attack Flow, exported by XORCISM).`,
    techniques, gradient: { colors: ["#a9c6ff", "#0b3d91"], minValue: 0, maxValue: 100 },
    legendItems: [], sorting: 3, hideDisabled: true,
  };
}

// ── demo ────────────────────────────────────────────────────────────────────────
/** A compact hand-built Attack Flow (5 actions) so /attack-flow is populated on the demo tenant. */
export function seedAttackFlowDemo(tenant: number): void {
  ensureAttackFlowTables();
  const db = getDb("XTHREAT");
  const stixId = "attack-flow--demo-0000-0000-0000-phishing01";
  if (db.prepare("SELECT 1 FROM ATTACKFLOW WHERE StixId=? AND TenantID=?").get(stixId, tenant)) return;
  const A = (u: string, tech: string, tac: string, name: string, desc: string, eff: string[]) => ({
    type: "attack-action", id: `attack-action--demo-${u}`, spec_version: "2.1",
    name, technique_id: tech, tactic_id: tac, description: desc, effect_refs: eff.map((x) => `attack-action--demo-${x}`),
  });
  const bundle = {
    type: "bundle", id: "bundle--demo-attackflow",
    objects: [
      { type: "identity", id: "identity--demo-af", name: "XORCISM demo" },
      { type: "attack-flow", id: stixId, spec_version: "2.1", created_by_ref: "identity--demo-af",
        name: "Demo — Phishing to Ransomware", scope: "incident",
        description: "Illustrative flow: spear-phishing → execution → credential theft → lateral movement → encryption.",
        start_refs: ["attack-action--demo-a1"], created: now(), modified: now() },
      A("a1", "T1566.001", "TA0001", "Spearphishing Attachment", "Victim opens a malicious attachment.", ["a2"]),
      A("a2", "T1204.002", "TA0002", "User Execution: Malicious File", "Macro executes a loader.", ["a3"]),
      A("a3", "T1003.001", "TA0006", "LSASS Memory", "Credentials dumped from LSASS.", ["a4"]),
      A("a4", "T1021.002", "TA0008", "SMB/Windows Admin Shares", "Lateral movement to file servers.", ["a5"]),
      A("a5", "T1486", "TA0040", "Data Encrypted for Impact", "Ransomware encrypts shares.", []),
    ],
  };
  try { importBundle(tenant, bundle, "demo"); } catch { /* demo only */ }
}
