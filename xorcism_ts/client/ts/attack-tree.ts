/** attack-tree.ts — attack trees (/attack-tree). List trees, render an AND/OR tree with rolled-up
 * feasibility + easiest path, add/mitigate nodes, create new trees. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface NodeRow { id: number; parentId: number | null; label: string; gate: string; likelihood: string; mitigated: boolean; }
interface TreeDetail { tree: any; nodes: NodeRow[]; rootId: number | null; feasibility: number; band: string; easiestPath: string[]; }
interface ListItem { id: number; name: string; goal: string; nodes: number; leaves: number; feasibility: number; band: string; easiestPath: string[]; }

let TREES: ListItem[] = [];
let SEL: number | null = null;
let DETAIL: TreeDetail | null = null;
let addParent = 0;

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #a78bfa;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 4000);
}
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="at-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const fcls = (b: string): string => `f-${["High", "Medium", "Low", "None"].includes(b) ? b : "None"}`;

function nodeTree(node: NodeRow, byParent: Map<number | null, NodeRow[]>): string {
  const kids = byParent.get(node.id) || [];
  const isLeaf = !kids.length;
  const inner = `<span class="atn${node.mitigated ? " mit" : ""}">
    ${node.gate ? `<span class="gate ${node.gate}">${node.gate}</span>` : ""}
    <span class="nlbl">${esc(node.label)}</span>
    ${isLeaf && node.likelihood ? `<span class="feas ${fcls(node.likelihood.charAt(0).toUpperCase() + node.likelihood.slice(1).toLowerCase())}">${esc(node.likelihood)}</span>` : ""}
    ${node.mitigated ? `<span class="muted" style="font-size:10px">mitigated</span>` : ""}
    <button class="nbtn" data-add="${node.id}" title="Add sub-node">+</button>
    <button class="nbtn" data-mit="${node.id}" title="Toggle mitigated">${node.mitigated ? "↺" : "🛡"}</button>
    ${node.parentId != null ? `<button class="nbtn" data-del="${node.id}" title="Delete subtree">✕</button>` : ""}
  </span>`;
  if (isLeaf) return `<li>${inner}</li>`;
  return `<li>${inner}<ul>${kids.slice().map((k) => nodeTree(k, byParent)).join("")}</ul></li>`;
}

function renderDetail(): void {
  const d = DETAIL; if (!d) { $("at-canvas").innerHTML = `<div class="muted">Select a tree on the left, or create one.</div>`; return; }
  const byParent = new Map<number | null, NodeRow[]>();
  for (const n of d.nodes) { const a = byParent.get(n.parentId); if (a) a.push(n); else byParent.set(n.parentId, [n]); }
  const root = d.nodes.find((n) => n.parentId == null);
  const path = d.easiestPath.length ? d.easiestPath.map((p, i) => `${i ? " → " : ""}<b>${esc(p)}</b>`).join("") : "—";
  $("at-canvas").innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <h3 style="margin:0;font-size:16px;color:#e2e8f0;flex:1">${esc(d.tree.Name)} <span class="feas ${fcls(d.band)}">${d.feasibility}% ${esc(d.band)}</span></h3>
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:8px">Goal: ${esc(d.tree.Goal || d.tree.Name)}</div>
    ${root ? `<ul class="tree">${nodeTree(root, byParent)}</ul>` : "<div class='muted'>empty tree</div>"}
    <div class="path">🎯 Easiest attack path (feasibility ${d.feasibility}%): ${path}</div>`;
  $("at-canvas").querySelectorAll<HTMLButtonElement>("button.nbtn").forEach((b) => {
    if (b.dataset.add) b.addEventListener("click", () => openNodeModal(Number(b.dataset.add)));
    if (b.dataset.mit) b.addEventListener("click", () => void toggleMit(Number(b.dataset.mit)));
    if (b.dataset.del) b.addEventListener("click", () => void delNode(Number(b.dataset.del)));
  });
}

function render(): void {
  const trees = TREES;
  const totalLeaves = trees.reduce((s, t) => s + t.leaves, 0);
  const cards = [
    card("Attack trees", String(trees.length), "modeled goals"),
    card("Total nodes", String(trees.reduce((s, t) => s + t.nodes, 0)), `${totalLeaves} leaf attacks`),
    card("High-feasibility", String(trees.filter((t) => t.feasibility >= 70).length), "goals reachable", trees.some((t) => t.feasibility >= 70) ? "#f87171" : "#34d399"),
  ].join("");
  const list = trees.length ? trees.map((t) => `<div class="at-li${t.id === SEL ? " sel" : ""}" data-id="${t.id}">
      <div class="nm">${esc(t.name)} <span class="feas ${fcls(t.band)}">${t.feasibility}%</span></div>
      <div class="meta">${t.nodes} nodes · ${t.leaves} leaves</div></div>`).join("")
    : `<div class="muted" style="padding:10px">No attack trees yet.</div>`;
  $("at-body").innerHTML = `<div class="at-cards">${cards}</div>
    <div class="at-layout"><div class="at-list" id="at-list">${list}</div><div class="at-detail" id="at-canvas"></div></div>`;
  $("at-list").querySelectorAll<HTMLElement>(".at-li").forEach((el) => el.addEventListener("click", () => void selectTree(Number(el.dataset.id))));
  renderDetail();
}

function loadList(): Promise<void> {
  return fetch("/api/attack-tree").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((d: { trees: ListItem[] }) => { TREES = d.trees; if (SEL == null && TREES.length) SEL = TREES[0].id; render(); if (SEL != null) void selectTree(SEL); })
    .catch((e) => { $("at-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
async function selectTree(id: number): Promise<void> {
  SEL = id;
  document.querySelectorAll(".at-li").forEach((x) => x.classList.toggle("sel", Number((x as HTMLElement).dataset.id) === id));
  try { DETAIL = await (await fetch(`/api/attack-tree/${id}`)).json(); } catch { DETAIL = null; }
  renderDetail();
}
async function refresh(): Promise<void> { await loadList(); }

function jpost(u: string, b: unknown): Promise<any> { return fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) }).then(async (r) => { const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d; }); }
async function toggleMit(nodeId: number): Promise<void> {
  const n = DETAIL?.nodes.find((x) => x.id === nodeId); if (!n) return;
  try { await jpost("/api/attack-tree/node/update", { nodeId, mitigated: !n.mitigated }); await selectTree(SEL!); await loadList(); } catch (e) { toast(`⚠️ ${esc(e)}`); }
}
async function delNode(nodeId: number): Promise<void> {
  if (!window.confirm("Delete this node and its subtree?")) return;
  try { await jpost("/api/attack-tree/node/delete", { nodeId }); await selectTree(SEL!); await loadList(); } catch (e) { toast(`⚠️ ${esc(e)}`); }
}

function openNodeModal(parentId: number): void { addParent = parentId; ($("atn-label") as HTMLInputElement).value = ""; ($("atn-gate") as HTMLSelectElement).value = ""; $("atn-err").textContent = ""; $("at-node-modal").classList.add("open"); ($("atn-label") as HTMLInputElement).focus(); }
function gateChanged(): void { $("atn-lik-wrap").style.display = ($("atn-gate") as HTMLSelectElement).value ? "none" : ""; }

document.addEventListener("DOMContentLoaded", () => {
  $("at-new").addEventListener("click", () => { for (const id of ["atm-name", "atm-goal", "atm-desc"]) ($(id) as HTMLInputElement).value = ""; $("atm-err").textContent = ""; $("at-tree-modal").classList.add("open"); ($("atm-name") as HTMLInputElement).focus(); });
  $("atm-cancel").addEventListener("click", () => $("at-tree-modal").classList.remove("open"));
  $("atm-create").addEventListener("click", async () => {
    const name = ($("atm-name") as HTMLInputElement).value.trim(); if (!name) { $("atm-err").textContent = "⚠️ Name required."; return; }
    try { await jpost("/api/attack-tree", { name, goal: ($("atm-goal") as HTMLInputElement).value.trim(), description: ($("atm-desc") as HTMLTextAreaElement).value.trim() });
      $("at-tree-modal").classList.remove("open"); SEL = null; await loadList(); toast("✅ Attack tree created"); } catch (e) { $("atm-err").textContent = `⚠️ ${e}`; }
  });
  $("atn-gate").addEventListener("change", gateChanged);
  $("atn-cancel").addEventListener("click", () => $("at-node-modal").classList.remove("open"));
  $("atn-add").addEventListener("click", async () => {
    const label = ($("atn-label") as HTMLInputElement).value.trim(); if (!label) { $("atn-err").textContent = "⚠️ Label required."; return; }
    const gate = ($("atn-gate") as HTMLSelectElement).value; const likelihood = gate ? "" : ($("atn-lik") as HTMLSelectElement).value;
    try { await jpost("/api/attack-tree/node", { treeId: SEL, parentId: addParent, label, gate, likelihood });
      $("at-node-modal").classList.remove("open"); await selectTree(SEL!); await loadList(); } catch (e) { $("atn-err").textContent = `⚠️ ${e}`; }
  });
  [$("at-tree-modal"), $("at-node-modal")].forEach((m) => m.addEventListener("click", (e) => { if (e.target === m) m.classList.remove("open"); }));
  void loadList();
});
