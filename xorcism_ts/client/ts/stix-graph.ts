/**
 * stix-graph.ts — Graphical visualization of STIX 2.1 bundles (OpenCTI style).
 * Force-directed node-link graph (d3-force): STIX objects = nodes colored by
 * type, relations (SRO `relationship`) + embedded references = edges.
 * Sources: examples from the stix/ folder, .json upload, JSON paste.
 */

import { initI18n, t } from "./i18n";

// d3 is loaded via CDN (<script> tag) — no typing needed.
declare const d3: any;

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

// Colors by STIX type (close to OpenCTI)
const COLORS: Record<string, string> = {
  "threat-actor": "#e0567f", "intrusion-set": "#e0701f", campaign: "#d4526e",
  malware: "#e8543f", "malware-analysis": "#f0795a", tool: "#6a8caf",
  "attack-pattern": "#f59e0b", vulnerability: "#ef4444", indicator: "#22c55e",
  infrastructure: "#06b6d4", identity: "#3b82f6", location: "#14b8a6",
  "observed-data": "#8b5cf6", report: "#a78bfa", note: "#a78bfa",
  opinion: "#a78bfa", grouping: "#a78bfa", "course-of-action": "#10b981",
  incident: "#f97316", "marking-definition": "#94a3b8", "x-hunt": "#2dd4bf",
  // SCO
  "ipv4-addr": "#64748b", "ipv6-addr": "#64748b", "domain-name": "#0ea5e9",
  url: "#0ea5e9", file: "#9ca3af", "network-traffic": "#22d3ee",
  software: "#84cc16", "email-addr": "#0ea5e9", "user-account": "#a3a3a3",
  "windows-registry-key": "#9ca3af", "autonomous-system": "#64748b",
};
function colorFor(type: string): string {
  return COLORS[type] || "#6b7280";
}

// STIX → XORCISM entity link: STIX type → (database, table, name column). Clicking on
// a node offers to open the corresponding form (located by name). Verified columns.
const STIX_ENTITY_MAP: Record<string, { db: string; table: string; col: string }> = {
  "threat-actor": { db: "XTHREAT", table: "THREATACTOR", col: "ThreatActorName" },
  "intrusion-set": { db: "XTHREAT", table: "ATTACKGROUP", col: "Name" },
  "malware": { db: "XTHREAT", table: "ATTACKSOFTWARE", col: "Name" },
  "tool": { db: "XTHREAT", table: "ATTACKSOFTWARE", col: "Name" },
  "attack-pattern": { db: "XTHREAT", table: "ATTACKTECHNIQUE", col: "Name" },
  "course-of-action": { db: "XTHREAT", table: "ATTACKMITIGATION", col: "Name" },
  "vulnerability": { db: "XVULNERABILITY", table: "VULNERABILITY", col: "VULReferential" },
  "campaign": { db: "XTHREAT", table: "THREATCAMPAIGN", col: "ThreatCampaignTitle" },
  "incident": { db: "XINCIDENT", table: "INCIDENT", col: "IncidentName" },
  "indicator": { db: "XTHREAT", table: "IOC", col: "IOCName" },
  "x-hunt": { db: "XTHREAT", table: "HUNT", col: "HuntName" },
  // identity: handled dynamically (cf. entityFor) according to identity_class (PERSON vs ORGANISATION).
};

// Target entity of a STIX node. identity → PERSON (identity_class=individual) otherwise
// ORGANISATION; the other types via the static mapping table.
function entityFor(d: SNode): { db: string; table: string; col: string } | null {
  if (d.type === "identity") {
    const cls = String(d.raw?.identity_class || "").toLowerCase();
    return cls === "individual"
      ? { db: "XORCISM", table: "PERSON", col: "FullName" }
      : { db: "XORCISM", table: "ORGANISATION", col: "OrganisationName" };
  }
  return STIX_ENTITY_MAP[d.type] ?? null;
}

interface SNode { id: string; type: string; label: string; raw: any; placeholder?: boolean }
interface SLink { source: any; target: any; label: string; embedded?: boolean }

function displayName(o: any): string {
  return (
    o.name || o.value || o.display_name || o.path || o.subject ||
    (o.definition_type ? `${o.name || o.definition_type}` : "") ||
    (o.id ? o.id.split("--")[0] : o.type) || o.type
  );
}

// Extracts the list of STIX objects from a bundle / envelope / array / object.
function extractObjects(data: any): any[] {
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object") {
    if (data.type === "bundle" && Array.isArray(data.objects)) return data.objects;
    if (Array.isArray(data.objects)) return data.objects; // TAXII envelope
    if (data.type && data.id) return [data];
  }
  throw new Error("Contenu STIX non reconnu (bundle, enveloppe ou objet attendu).");
}

const EMBED_SKIP = new Set(["source_ref", "target_ref"]); // handled by the relation

// Builds nodes + edges from the objects.
function buildGraph(objects: any[], showEmbedded: boolean): { nodes: SNode[]; links: SLink[] } {
  const nodes = new Map<string, SNode>();
  const links: SLink[] = [];

  const ensure = (id: string): void => {
    if (id && !nodes.has(id)) {
      nodes.set(id, { id, type: id.split("--")[0] || "unknown", label: id.split("--")[0], raw: null, placeholder: true });
    }
  };

  // 1) nodes (everything except bundle and relationship)
  for (const o of objects) {
    if (!o || !o.id || o.type === "bundle") continue;
    if (o.type === "relationship") continue;
    nodes.set(o.id, { id: o.id, type: o.type, label: displayName(o), raw: o });
  }

  // 2) edges: relations (SRO)
  for (const o of objects) {
    if (o && o.type === "relationship" && o.source_ref && o.target_ref) {
      ensure(o.source_ref);
      ensure(o.target_ref);
      links.push({ source: o.source_ref, target: o.target_ref, label: o.relationship_type || "related-to" });
    }
  }

  // 3) edges: optional embedded references (_ref / _refs)
  if (showEmbedded) {
    for (const o of objects) {
      if (!o || !o.id || o.type === "bundle" || o.type === "relationship") continue;
      for (const k of Object.keys(o)) {
        if (EMBED_SKIP.has(k)) continue;
        const v = (o as any)[k];
        if (k.endsWith("_ref") && typeof v === "string" && v.includes("--")) {
          ensure(v);
          links.push({ source: o.id, target: v, label: k.replace(/_ref$/, ""), embedded: true });
        } else if (k.endsWith("_refs") && Array.isArray(v)) {
          for (const ref of v) {
            if (typeof ref === "string" && ref.includes("--")) {
              ensure(ref);
              links.push({ source: o.id, target: ref, label: k.replace(/_refs$/, ""), embedded: true });
            }
          }
        }
      }
    }
  }

  return { nodes: Array.from(nodes.values()), links };
}

// ── Render state ───────────────────────────────────────────────────────────────
let sim: any = null;
let zoomB: any = null;
let gRoot: any = null;
let selectedId: string | null = null;

function toast(msg: string): void {
  const el = $("sg-toast");
  el.textContent = msg;
  el.style.display = "block";
  setTimeout(() => (el.style.display = "none"), 3500);
}

function render(objects: any[]): void {
  const showEmbedded = ($("sg-embedded") as HTMLInputElement).checked;
  const showLabels = ($("sg-labels") as HTMLInputElement).checked;
  let graph: { nodes: SNode[]; links: SLink[] };
  try {
    graph = buildGraph(objects, showEmbedded);
  } catch (e) {
    toast(String(e));
    return;
  }

  const svgEl = $("sg-svg") as unknown as SVGSVGElement;
  const W = svgEl.clientWidth || 800;
  const H = svgEl.clientHeight || 600;
  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();

  gRoot = svg.append("g");
  zoomB = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (ev: any) => gRoot.attr("transform", ev.transform));
  svg.call(zoomB);

  // Edges
  const link = gRoot.append("g").selectAll("line")
    .data(graph.links).join("line")
    .attr("class", (d: SLink) => "link" + (d.embedded ? " embedded" : ""));

  const linkLabel = gRoot.append("g").selectAll("text")
    .data(graph.links).join("text")
    .attr("class", "linklabel")
    .style("display", showLabels ? null : "none")
    .text((d: SLink) => d.label);

  // Nodes
  const node = gRoot.append("g").selectAll("g")
    .data(graph.nodes, (d: SNode) => d.id).join("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (ev: any, d: any) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (ev: any, d: any) => { d.fx = ev.x; d.fy = ev.y; })
      .on("end", (ev: any, d: any) => { if (!ev.active) sim.alphaTarget(0); /* keeps the fixed position */ }))
    .on("click", (_ev: any, d: SNode) => showDetails(d));

  node.append("circle")
    .attr("r", (d: SNode) => (d.placeholder ? 5 : 8))
    .attr("fill", (d: SNode) => colorFor(d.type))
    .attr("opacity", (d: SNode) => (d.placeholder ? 0.45 : 1));

  node.append("text")
    .attr("x", 11).attr("y", 3)
    .text((d: SNode) => (d.label.length > 26 ? d.label.slice(0, 25) + "…" : d.label));

  node.append("title").text((d: SNode) => `${d.type}\n${d.id}`);

  sim = d3.forceSimulation(graph.nodes)
    .force("link", d3.forceLink(graph.links).id((d: SNode) => d.id).distance(95).strength(0.6))
    .force("charge", d3.forceManyBody().strength(-260))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide(22))
    .on("tick", () => {
      link.attr("x1", (d: any) => d.source.x).attr("y1", (d: any) => d.source.y)
          .attr("x2", (d: any) => d.target.x).attr("y2", (d: any) => d.target.y);
      linkLabel.attr("x", (d: any) => (d.source.x + d.target.x) / 2)
               .attr("y", (d: any) => (d.source.y + d.target.y) / 2);
      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

  buildLegend(graph.nodes);
  $("sg-counts").textContent =
    `${graph.nodes.length} objets · ${graph.links.length} relations`;
  selectedId = null;
  $("sg-details").style.display = "none";
}

function buildLegend(nodes: SNode[]): void {
  const types = Array.from(new Set(nodes.map((n) => n.type))).sort();
  $("sg-legend").innerHTML = types.map((tp) =>
    `<span class="it"><span class="dot" style="background:${colorFor(tp)}"></span>${tp}</span>`
  ).join("");
}

function showDetails(d: SNode): void {
  selectedId = d.id;
  d3.selectAll(".node").classed("sel", (n: SNode) => n.id === d.id);
  const box = $("sg-details");
  box.style.display = "block";
  const raw = d.raw ? JSON.stringify(d.raw, null, 2) : "(objet référencé non présent dans le bundle)";
  // Link to the corresponding XORCISM form (if the STIX type is mapped + name present).
  const ent = entityFor(d);
  const linkable = !!(ent && d.label);
  box.innerHTML =
    `<span class="close" id="sg-det-close">&#10005;</span>` +
    `<h4 style="color:${colorFor(d.type)}">${d.type}</h4>` +
    `<div style="color:var(--text-soft);margin-bottom:4px">${escapeHtml(d.label)}</div>` +
    `<div style="color:var(--text-dim);font-size:10px;word-break:break-all;margin-bottom:8px">${d.id}</div>` +
    (linkable
      ? `<button class="btn btn-primary btn-sm" id="sg-open-form" style="margin-bottom:8px">🔗 Ouvrir le formulaire (${ent!.table})</button>`
      : "") +
    `<pre>${escapeHtml(raw)}</pre>`;
  $("sg-det-close").onclick = () => { box.style.display = "none"; d3.selectAll(".node").classed("sel", false); };
  if (linkable) {
    const btn = document.getElementById("sg-open-form");
    if (btn) btn.onclick = () => {
      const url = `/?db=${encodeURIComponent(ent!.db)}&table=${encodeURIComponent(ent!.table)}` +
        `&editCol=${encodeURIComponent(ent!.col)}&editVal=${encodeURIComponent(d.label)}`;
      window.open(url, "_blank", "noopener"); // opens the explorer (edit form) in a new tab
    };
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c] as string));
}

// ── Data inputs ──────────────────────────────────────────────────────────
function visualizeFromText(text: string): void {
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    toast(t("toast.jsonInvalid"));
    return;
  }
  try {
    render(extractObjects(data));
  } catch (e) {
    toast(String(e));
  }
}

// TAXII server hookup (via same-origin server proxy /api/taxii/*)
async function initTaxii(): Promise<void> {
  let status: any;
  try {
    status = await (await fetch("/api/taxii/status")).json();
  } catch {
    return;
  }
  if (!status || !status.reachable) return;
  $("sg-taxii-sec").style.display = "";
  $("sg-taxii-target").textContent = `${status.url} · ${status.apiRoot}`;
  try {
    const cols: any[] = await (await fetch("/api/taxii/collections")).json();
    const sel = $("sg-taxii-col") as HTMLSelectElement;
    cols.forEach((c) => {
      const o = document.createElement("option");
      o.value = c.id;
      o.textContent = c.title || c.id;
      sel.appendChild(o);
    });
  } catch {
    /* ignore */
  }

  $("sg-taxii-load").onclick = async () => {
    const col = ($("sg-taxii-col") as HTMLSelectElement).value;
    if (!col) {
      toast(t("toast.chooseTaxiiCollection"));
      return;
    }
    const limit = ($("sg-taxii-limit") as HTMLInputElement).value || "500";
    try {
      const r = await fetch(`/api/taxii/objects?collection=${encodeURIComponent(col)}&limit=${encodeURIComponent(limit)}`);
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
      const text = await r.text();
      ($("sg-json") as HTMLTextAreaElement).value = text;
      visualizeFromText(text);
    } catch (e) {
      toast("TAXII: " + String(e));
    }
  };
}

async function loadExamples(): Promise<void> {
  try {
    const r = await fetch("/api/stix-examples");
    if (!r.ok) return;
    const names: string[] = await r.json();
    const sel = $("sg-examples") as HTMLSelectElement;
    names.forEach((n) => {
      const o = document.createElement("option");
      o.value = n;
      o.textContent = n;
      sel.appendChild(o);
    });
  } catch {
    /* ignore */
  }
}

function fitView(): void {
  if (!zoomB) return;
  d3.select($("sg-svg")).transition().duration(400).call(zoomB.transform, d3.zoomIdentity);
}

function exportSvg(): void {
  const svgEl = $("sg-svg");
  const clone = svgEl.cloneNode(true) as SVGElement;
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  const blob = new Blob(['<?xml version="1.0"?>\n' + clone.outerHTML], { type: "image/svg+xml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "stix-graph.svg";
  a.click();
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void loadExamples();
  void initTaxii();

  $("sg-render").onclick = () => visualizeFromText(($("sg-json") as HTMLTextAreaElement).value);
  $("sg-clear").onclick = () => {
    ($("sg-json") as HTMLTextAreaElement).value = "";
    d3.select($("sg-svg")).selectAll("*").remove();
    $("sg-legend").innerHTML = "";
    $("sg-counts").textContent = "";
    $("sg-details").style.display = "none";
  };
  $("sg-zin").onclick = () => { if (zoomB) d3.select($("sg-svg")).transition().duration(200).call(zoomB.scaleBy, 1.3); };
  $("sg-zout").onclick = () => { if (zoomB) d3.select($("sg-svg")).transition().duration(200).call(zoomB.scaleBy, 0.75); };
  $("sg-fit").onclick = fitView;
  $("sg-export").onclick = exportSvg;

  // Loads the XTHREAT hunts (HUNT + ATT&CK/IOC links) as a STIX bundle.
  $("sg-load-hunts").onclick = async () => {
    try {
      const r = await fetch("/api/stix/hunts");
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
      const text = await r.text();
      ($("sg-json") as HTMLTextAreaElement).value = text;
      visualizeFromText(text);
    } catch (e) {
      toast("Hunts: " + String(e));
    }
  };

  // Loads the XTHREAT threat reports (THREATREPORT → STIX report, linked to the
  // ATT&CK techniques / CVEs they mention) as a STIX bundle.
  $("sg-load-reports").onclick = async () => {
    try {
      const r = await fetch("/api/stix/reports");
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
      const text = await r.text();
      ($("sg-json") as HTMLTextAreaElement).value = text;
      visualizeFromText(text);
    } catch (e) {
      toast("Reports: " + String(e));
    }
  };

  // Per-hunt / per-report pickers: populate from the catalogue and load just the one selected.
  const fillPick = async (selId: string, table: string, idCol: string, labelCol: string): Promise<void> => {
    try {
      const r = await fetch(`/api/lookup?db=XTHREAT&table=${table}&idCol=${idCol}&labelCol=${labelCol}`);
      if (!r.ok) return;
      const list = (await r.json()) as { id: unknown; label: unknown }[];
      const sel = $(selId) as HTMLSelectElement;
      for (const o of (Array.isArray(list) ? list : [])) {
        if (o.label == null || String(o.label).trim() === "") continue;
        const opt = document.createElement("option");
        opt.value = String(o.id); opt.textContent = String(o.label);
        sel.appendChild(opt);
      }
    } catch { /* lookup unavailable */ }
  };
  void fillPick("sg-hunt-pick", "HUNT", "HuntID", "HuntName");
  void fillPick("sg-report-pick", "THREATREPORT", "ThreatReportID", "ThreatReportName");
  const loadOne = async (url: string, label: string): Promise<void> => {
    try {
      const r = await fetch(url);
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
      const text = await r.text();
      ($("sg-json") as HTMLTextAreaElement).value = text;
      visualizeFromText(text);
    } catch (e) { toast(label + ": " + String(e)); }
  };
  ($("sg-hunt-pick") as HTMLSelectElement).onchange = (e) => {
    const id = (e.target as HTMLSelectElement).value;
    if (id) void loadOne(`/api/stix/hunts?id=${encodeURIComponent(id)}`, "Hunt");
  };
  ($("sg-report-pick") as HTMLSelectElement).onchange = (e) => {
    const id = (e.target as HTMLSelectElement).value;
    if (id) void loadOne(`/api/stix/reports?id=${encodeURIComponent(id)}`, "Report");
  };

  ($("sg-examples") as HTMLSelectElement).onchange = async (e) => {
    const name = (e.target as HTMLSelectElement).value;
    if (!name) return;
    try {
      const r = await fetch("/api/stix-example?name=" + encodeURIComponent(name));
      if (!r.ok) throw new Error("Exemple introuvable");
      const text = await r.text();
      ($("sg-json") as HTMLTextAreaElement).value = text;
      visualizeFromText(text);
    } catch (err) {
      toast(String(err));
    }
  };

  // Custom file selector (the native control is localized by the browser).
  $("sg-file-btn").onclick = () => ($("sg-file") as HTMLInputElement).click();
  ($("sg-file") as HTMLInputElement).onchange = (e) => {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (!f) return;
    $("sg-file-name").textContent = f.name; // displays the name of the chosen file
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || "");
      ($("sg-json") as HTMLTextAreaElement).value = text;
      visualizeFromText(text);
    };
    reader.readAsText(f);
  };

  // Re-render on options change (if a graph is loaded)
  const rerun = () => {
    const txt = ($("sg-json") as HTMLTextAreaElement).value.trim();
    if (txt) visualizeFromText(txt);
  };
  ($("sg-embedded") as HTMLInputElement).onchange = rerun;
  ($("sg-labels") as HTMLInputElement).onchange = () => {
    const show = ($("sg-labels") as HTMLInputElement).checked;
    d3.selectAll(".linklabel").style("display", show ? null : "none");
  };
});
