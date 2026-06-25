/**
 * knowledge-graph.ts — client for the unified security knowledge graph (/knowledge-graph).
 * d3 force-directed graph over /api/knowledge-graph (asset ↔ software ↔ vuln ↔ risk ↔ incident),
 * with a keyword/CVE/KEV query box (focuses the blast radius) and click-to-walk neighbours.
 */
declare const d3: any;
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface N { id: string; type: string; label: string; degree: number; meta?: any; x?: number; y?: number }
interface L { source: any; target: any; rel: string }

const COLOR: Record<string, string> = { asset: "#60a5fa", vuln: "#fbbf24", "vuln-kev": "#f87171", software: "#a78bfa", risk: "#fb923c", incident: "#f472b6" };
const TYPELABEL: Record<string, string> = { asset: "Asset", vuln: "Vulnerability", "vuln-kev": "KEV vuln", software: "Software", risk: "Risk", incident: "Incident" };
let ALL: { nodes: N[]; links: L[] } = { nodes: [], links: [] };
let sim: any = null;

async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}

function kpi(summary: any): void {
  const k = $("kg-kpi"); if (!k) return;
  k.innerHTML = `<span class="k"><b>${summary.nodes}</b> nodes</span><span class="k"><b>${summary.links}</b> links</span><span class="k"><b>${summary.assets}</b> assets</span><span class="k" style="color:#fca5a5"><b>${summary.kev}</b> KEV</span>`;
  const lg = $("kg-legend"); if (lg) lg.innerHTML = Object.keys(COLOR).map((t) => `<span class="lg"><span class="dot" style="background:${COLOR[t]}"></span>${esc(TYPELABEL[t])} ${summary.byType?.[t] ?? 0}</span>`).join("");
}

function draw(nodes: N[], links: L[]): void {
  const host = $("kg-graph"); if (!host) return;
  host.innerHTML = "";
  const W = host.clientWidth || 900, H = host.clientHeight || 600;
  const svg = d3.select(host).append("svg").attr("width", W).attr("height", H).attr("viewBox", [0, 0, W, H]);
  const g = svg.append("g");
  svg.call(d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e: any) => g.attr("transform", e.transform)));
  // copy so d3 can mutate source/target into objects
  const ln = links.map((l) => ({ ...l }));
  const nd = nodes.map((n) => ({ ...n }));
  sim = d3.forceSimulation(nd)
    .force("link", d3.forceLink(ln).id((d: any) => d.id).distance(60).strength(0.4))
    .force("charge", d3.forceManyBody().strength(-160))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide(14));
  const link = g.append("g").attr("stroke", "#2d3250").attr("stroke-opacity", 0.7).selectAll("line").data(ln).join("line").attr("stroke-width", 1);
  const node = g.append("g").selectAll("g").data(nd).join("g").style("cursor", "pointer")
    .call(d3.drag()
      .on("start", (e: any, d: any) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (e: any, d: any) => { d.fx = e.x; d.fy = e.y; })
      .on("end", (e: any, d: any) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
  node.append("circle").attr("r", (d: any) => Math.min(13, 5 + Math.sqrt(d.degree))).attr("fill", (d: any) => COLOR[d.type] || "#64748b").attr("stroke", "#0b0e1a").attr("stroke-width", 1.5);
  node.append("text").text((d: any) => d.label.length > 22 ? d.label.slice(0, 22) + "…" : d.label).attr("x", 12).attr("y", 4).attr("font-size", "10px").attr("fill", "#cbd5e1");
  node.append("title").text((d: any) => `${TYPELABEL[d.type] || d.type}: ${d.label}`);
  node.on("click", (_e: any, d: any) => inspect(d.id));
  sim.on("tick", () => {
    link.attr("x1", (d: any) => d.source.x).attr("y1", (d: any) => d.source.y).attr("x2", (d: any) => d.target.x).attr("y2", (d: any) => d.target.y);
    node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
  });
}

function inspect(id: string): void {
  const node = ALL.nodes.find((n) => n.id === id); if (!node) return;
  const neigh = ALL.links.filter((l) => (l.source.id || l.source) === id || (l.target.id || l.target) === id)
    .map((l) => { const oid = (l.source.id || l.source) === id ? (l.target.id || l.target) : (l.source.id || l.source); return { node: ALL.nodes.find((n) => n.id === oid), rel: l.rel }; })
    .filter((x) => x.node);
  const side = $("kg-side"); if (!side) return;
  side.innerHTML = `<div class="nm" style="font-size:14px">${esc(node.label)}</div>
    <div class="muted" style="font-size:12px;margin:2px 0 8px">${esc(TYPELABEL[node.type] || node.type)}${node.meta?.kev ? " · <span style='color:#fca5a5'>KEV</span>" : ""}${node.meta?.criticality ? " · " + esc(node.meta.criticality) : ""}</div>
    <button class="btn" style="font-size:12px;padding:5px 11px;margin-bottom:9px" id="kg-blast">⛯ Blast radius (2 hops)</button>
    <div class="muted" style="font-size:11px;text-transform:uppercase;margin-bottom:4px">Neighbours (${neigh.length})</div>
    ${neigh.slice(0, 60).map((x) => `<div class="neigh" data-id="${esc(x.node!.id)}"><span class="dot" style="background:${COLOR[x.node!.type] || "#64748b"}"></span> <b>${esc(x.rel)}</b> → ${esc(x.node!.label)}</div>`).join("") || "<div class='muted'>No neighbours in view.</div>"}`;
  side.querySelectorAll<HTMLElement>(".neigh").forEach((el) => el.addEventListener("click", () => inspect(el.dataset.id!)));
  $("kg-blast")?.addEventListener("click", () => void blast(id));
}

async function blast(id: string): Promise<void> {
  try { const d = await getJson(`/api/knowledge-graph/blast/${encodeURIComponent(id)}?hops=2`); ALL = d; draw(d.nodes, d.links); setAnswer(`Blast radius of the selected node: ${d.nodes.length} nodes, ${d.links.length} links.`); inspect(id); }
  catch (e) { setAnswer(`⚠️ ${(e as Error).message}`); }
}
function setAnswer(html: string): void { const a = $("kg-answer"); if (a) { a.innerHTML = html; a.style.display = ""; } }

async function loadFull(): Promise<void> {
  try { const d = await getJson("/api/knowledge-graph?limit=180"); ALL = d; kpi(d.summary); draw(d.nodes, d.links); const a = $("kg-answer"); if (a) a.style.display = "none"; }
  catch (e) { const h = $("kg-graph"); if (h) h.innerHTML = `<div class="muted" style="padding:24px">⚠️ ${esc((e as Error).message)}</div>`; }
}

async function ask(): Promise<void> {
  const q = ($("kg-q") as HTMLInputElement)?.value.trim(); if (!q) return;
  try {
    const d = await getJson("/api/knowledge-graph/query", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ q }) });
    setAnswer(`<b>${esc(d.answer)}</b>`);
    if (d.nodes.length) { ALL = { nodes: d.nodes, links: d.links }; draw(d.nodes, d.links); if (d.focus) setTimeout(() => inspect(d.focus), 50); }
  } catch (e) { setAnswer(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  $("kg-ask")?.addEventListener("click", () => void ask());
  $("kg-q")?.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void ask(); });
  $("kg-reset")?.addEventListener("click", () => void loadFull());
  void loadFull();
});
