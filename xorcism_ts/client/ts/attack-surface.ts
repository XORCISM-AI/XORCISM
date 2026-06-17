/**
 * attack-surface.ts — ASSET attack-surface map. Force-directed graph (d3-force)
 * of the tenant's assets and what they touch: applications, CPEs/components,
 * vulnerabilities, organisations, responsible persons, threats, incidents,
 * related assets and tags. Data comes ready-built (nodes + links) from the
 * server (/api/asset-graph), tenant-scoped. `?asset=<id>` focuses on one asset.
 */
import { initI18n } from "./i18n";

// d3 is loaded via CDN (<script> tag).
declare const d3: any;

function $(id: string): HTMLElement { return document.getElementById(id)!; }

interface GNode { id: string; type: string; label: string; sub?: string; db?: string; table?: string; idCol?: string; idVal?: string }
interface GLink { source: any; target: any; label: string }
interface Graph { nodes: GNode[]; links: GLink[]; focus: string | null }

const TYPE_COLORS: Record<string, string> = {
  asset: "#3b82f6", application: "#84cc16", cpe: "#06b6d4",
  vulnerability: "#9ca3af", organisation: "#a78bfa", person: "#22d3ee",
  threat: "#e0567f", incident: "#f97316", tag: "#94a3b8",
};
const SEV_COLORS: Record<string, string> = {
  KEV: "#b91c1c", Critical: "#ef4444", High: "#f97316", Medium: "#f59e0b", Low: "#eab308",
};
const TYPE_LABEL: Record<string, string> = {
  asset: "Asset", application: "Application", cpe: "CPE / component",
  vulnerability: "Vulnerability", organisation: "Organisation", person: "Person",
  threat: "Threat", incident: "Incident", tag: "Tag",
};

function colorFor(n: GNode): string {
  if (n.type === "vulnerability" && n.sub && SEV_COLORS[n.sub]) return SEV_COLORS[n.sub];
  return TYPE_COLORS[n.type] || "#6b7280";
}
function escapeHtml(s: string): string {
  return String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c] as string));
}

let data: Graph = { nodes: [], links: [], focus: null };
const hidden = new Set<string>();
let sim: any = null, zoomB: any = null, gRoot: any = null, currentAsset: number | null = null;

function toast(msg: string): void {
  const el = $("as-toast");
  el.textContent = msg; el.style.display = "block";
  setTimeout(() => (el.style.display = "none"), 3500);
}

async function load(assetId: number | null): Promise<void> {
  currentAsset = assetId;
  try {
    const r = await fetch("/api/asset-graph" + (assetId ? `?assetId=${assetId}` : ""));
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    data = await r.json() as Graph;
  } catch (e) {
    toast("Load error: " + String(e));
    return;
  }
  fillAssetList();
  updateScope();
  render();
}

function fillAssetList(): void {
  const dl = $("as-assets") as HTMLDataListElement;
  dl.innerHTML = "";
  for (const n of data.nodes.filter((x) => x.type === "asset").sort((a, b) => a.label.localeCompare(b.label))) {
    const o = document.createElement("option");
    o.value = n.label;
    dl.appendChild(o);
  }
}

function updateScope(): void {
  const f = currentAsset ? data.nodes.find((n) => n.id === `asset:${currentAsset}`) : null;
  $("as-scope").textContent = currentAsset
    ? `Focused on asset #${currentAsset}` + (f ? ` — ${f.label}` : "")
    : "Whole tenant attack surface (top assets by risk)";
  const fb = $("as-focusbar");
  if (currentAsset && f) {
    fb.style.display = "block";
    fb.innerHTML = `Focus: <b>${escapeHtml(f.label)}</b> &nbsp;<a href="#" id="as-clearfocus" style="color:#7c83fd">clear ✕</a>`;
    const c = document.getElementById("as-clearfocus");
    if (c) c.onclick = (e) => { e.preventDefault(); void load(null); };
  } else {
    fb.style.display = "none";
  }
}

function visibleGraph(): { nodes: GNode[]; links: GLink[] } {
  const nodes = data.nodes.filter((n) => !hidden.has(n.type));
  const ok = new Set(nodes.map((n) => n.id));
  const links = data.links.filter((l) => {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    return ok.has(s) && ok.has(t);
  }).map((l) => ({
    source: typeof l.source === "object" ? l.source.id : l.source,
    target: typeof l.target === "object" ? l.target.id : l.target,
    label: l.label,
  }));
  return { nodes: nodes.map((n) => ({ ...n })), links };
}

function render(): void {
  const showLabels = ($("as-labels") as HTMLInputElement).checked;
  const g = visibleGraph();

  const svgEl = $("as-svg") as unknown as SVGSVGElement;
  const W = svgEl.clientWidth || 800, H = svgEl.clientHeight || 600;
  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();
  gRoot = svg.append("g");
  zoomB = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (ev: any) => gRoot.attr("transform", ev.transform));
  svg.call(zoomB);

  const link = gRoot.append("g").selectAll("line").data(g.links).join("line").attr("class", "link");
  const linkLabel = gRoot.append("g").selectAll("text").data(g.links).join("text")
    .attr("class", "linklabel").style("display", showLabels ? null : "none").text((d: GLink) => d.label);

  const node = gRoot.append("g").selectAll("g").data(g.nodes, (d: GNode) => d.id).join("g")
    .attr("class", (d: GNode) => "node" + (d.id === data.focus ? " focus" : ""))
    .call(d3.drag()
      .on("start", (ev: any, d: any) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (ev: any, d: any) => { d.fx = ev.x; d.fy = ev.y; })
      .on("end", (ev: any) => { if (!ev.active) sim.alphaTarget(0); }))
    .on("click", (_ev: any, d: GNode) => showDetails(d));

  node.append("circle")
    .attr("r", (d: GNode) => (d.type === "asset" ? 10 : d.type === "vulnerability" ? 7 : 6))
    .attr("fill", (d: GNode) => colorFor(d));
  node.append("text").attr("x", 12).attr("y", 3)
    .text((d: GNode) => (d.label.length > 28 ? d.label.slice(0, 27) + "…" : d.label));
  node.append("title").text((d: GNode) => `${TYPE_LABEL[d.type] || d.type}\n${d.label}${d.sub ? "\n" + d.sub : ""}`);

  sim = d3.forceSimulation(g.nodes)
    .force("link", d3.forceLink(g.links).id((d: GNode) => d.id).distance((l: GLink) => ((l.source as any).type === "asset" && (l.target as any).type === "asset" ? 130 : 80)).strength(0.5))
    .force("charge", d3.forceManyBody().strength(-240))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide(20))
    .on("tick", () => {
      link.attr("x1", (d: any) => d.source.x).attr("y1", (d: any) => d.source.y)
          .attr("x2", (d: any) => d.target.x).attr("y2", (d: any) => d.target.y);
      linkLabel.attr("x", (d: any) => (d.source.x + d.target.x) / 2).attr("y", (d: any) => (d.source.y + d.target.y) / 2);
      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

  buildLegend();
  $("as-counts").textContent = `${g.nodes.length} nodes · ${g.links.length} edges`;
  $("as-details").style.display = "none";
}

function buildLegend(): void {
  const counts = new Map<string, number>();
  for (const n of data.nodes) counts.set(n.type, (counts.get(n.type) || 0) + 1);
  const types = [...counts.keys()].sort((a, b) => (TYPE_LABEL[a] || a).localeCompare(TYPE_LABEL[b] || b));
  const el = $("as-legend");
  el.innerHTML = "";
  for (const tp of types) {
    const it = document.createElement("div");
    it.className = "it" + (hidden.has(tp) ? " off" : "");
    it.innerHTML = `<span class="dot" style="background:${TYPE_COLORS[tp] || "#6b7280"}"></span>${TYPE_LABEL[tp] || tp} <span class="as-stat">(${counts.get(tp)})</span>`;
    it.onclick = () => { if (hidden.has(tp)) hidden.delete(tp); else hidden.add(tp); render(); };
    el.appendChild(it);
  }
}

function showDetails(d: GNode): void {
  d3.selectAll(".node").classed("sel", (n: GNode) => n.id === d.id);
  const box = $("as-details");
  box.style.display = "block";
  const linkable = !!(d.db && d.table && d.idCol && d.idVal);
  const isAsset = d.type === "asset";
  box.innerHTML =
    `<span class="close" id="as-det-close">&#10005;</span>` +
    `<h4 style="color:${colorFor(d)}">${escapeHtml(TYPE_LABEL[d.type] || d.type)}</h4>` +
    `<div style="color:var(--text-soft);margin-bottom:4px">${escapeHtml(d.label)}</div>` +
    (d.sub ? `<div class="as-stat" style="margin-bottom:8px">${escapeHtml(d.sub)}</div>` : "") +
    (isAsset && d.idVal !== String(currentAsset)
      ? `<button class="btn btn-primary btn-sm" id="as-focus-node" style="margin:0 6px 8px 0">🎯 Focus on this asset</button>` : "") +
    (linkable ? `<button class="btn btn-ghost btn-sm" id="as-open-form" style="margin-bottom:8px">🔗 Open form (${escapeHtml(d.table!)})</button>` : "");
  $("as-det-close").onclick = () => { box.style.display = "none"; d3.selectAll(".node").classed("sel", false); };
  const fb = document.getElementById("as-focus-node");
  if (fb) fb.onclick = () => void load(Number(d.idVal));
  const of = document.getElementById("as-open-form");
  if (of) of.onclick = () => {
    const url = `/?db=${encodeURIComponent(d.db!)}&table=${encodeURIComponent(d.table!)}` +
      `&editCol=${encodeURIComponent(d.idCol!)}&editVal=${encodeURIComponent(d.idVal!)}`;
    window.open(url, "_blank", "noopener");
  };
}

function fitView(): void {
  if (zoomB) d3.select($("as-svg")).transition().duration(400).call(zoomB.transform, d3.zoomIdentity);
}
function exportSvg(): void {
  const clone = $("as-svg").cloneNode(true) as SVGElement;
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  const blob = new Blob(['<?xml version="1.0"?>\n' + clone.outerHTML], { type: "image/svg+xml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "attack-surface.svg";
  a.click();
}

function focusByName(): void {
  const name = ($("as-search") as HTMLInputElement).value.trim().toLowerCase();
  if (!name) return;
  const n = data.nodes.find((x) => x.type === "asset" && x.label.toLowerCase() === name)
    || data.nodes.find((x) => x.type === "asset" && x.label.toLowerCase().includes(name));
  if (!n || !n.idVal) { toast("No matching asset in the current graph."); return; }
  void load(Number(n.idVal));
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("as-focus").onclick = focusByName;
  ($("as-search") as HTMLInputElement).addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") { e.preventDefault(); focusByName(); }
  });
  $("as-all").onclick = () => void load(null);
  $("as-reload").onclick = () => void load(currentAsset);
  $("as-fit").onclick = fitView;
  $("as-export").onclick = exportSvg;
  ($("as-labels") as HTMLInputElement).onchange = () => {
    const show = ($("as-labels") as HTMLInputElement).checked;
    d3.selectAll(".linklabel").style("display", show ? null : "none");
  };

  const q = Number(new URLSearchParams(location.search).get("asset"));
  void load(Number.isFinite(q) && q > 0 ? q : null);
});
