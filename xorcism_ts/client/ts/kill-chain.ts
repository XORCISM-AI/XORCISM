/**
 * kill-chain.ts — Kill chain graph (/kill-chain).
 * The enterprise ATT&CK tactics, in matrix order, are the phases of the kill
 * chain (Reconnaissance → … → Impact), drawn left-to-right as a connected spine.
 * Pick an adversary (ATT&CK group) to overlay the techniques it uses in each
 * phase, revealing its kill-chain coverage and progression. Data: /api/kill-chain.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

declare const d3: any;
function $(id: string): HTMLElement { return document.getElementById(id)!; }

interface Tech { attackId: string; name: string }
interface Phase { order: number; attackId: string; name: string; shortName: string; url: string; total: number; used: Tech[] }
interface KC { phases: Phase[]; group: { attackId: string; name: string; description: string } | null; coverage: { covered: number; total: number; techniques: number } }

const PW = 158, GAP = 28, X0 = 22, HEAD_Y = 26, HEAD_H = 50, TECH_Y0 = 96, ROW_H = 22;
let groups: { attackId: string; name: string }[] = [];
let byName = new Map<string, string>();
let zoomB: any = null, gRoot: any = null;

function toast(m: string): void { const el = $("kc-toast"); el.textContent = m; el.style.display = "block"; setTimeout(() => (el.style.display = "none"), 3500); }
async function jget(u: string): Promise<any> { const r = await fetch(u); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }

function phaseColor(p: Phase): string {
  if (!p.used.length) return "#171b30";
  const a = 0.25 + Math.min(1, p.used.length / 16) * 0.6;
  return `rgba(239,68,68,${a.toFixed(2)})`;
}

async function loadGroups(): Promise<void> {
  try { groups = await jget("/api/kill-chain/groups"); } catch { groups = []; }
  byName = new Map(groups.map((g) => [g.name.toLowerCase(), g.attackId]));
  $("kc-groups").innerHTML = groups.map((g) => `<option value="${g.name.replace(/"/g, "&quot;")}"></option>`).join("");
}

async function loadGraph(groupRef: string | null): Promise<void> {
  let d: KC;
  try { d = await jget("/api/kill-chain" + (groupRef ? `?group=${encodeURIComponent(groupRef)}` : "")); }
  catch (e) { toast(String(e)); return; }
  render(d);
}

function render(d: KC): void {
  const svgEl = $("kc-svg") as unknown as SVGSVGElement;
  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();
  svg.append("defs").append("marker").attr("id", "kc-arrow").attr("viewBox", "0 -5 10 10")
    .attr("refX", 9).attr("refY", 0).attr("markerWidth", 7).attr("markerHeight", 7).attr("orient", "auto")
    .append("path").attr("d", "M0,-4L8,0L0,4").attr("fill", "#64748b");
  gRoot = svg.append("g");
  zoomB = d3.zoom().scaleExtent([0.2, 3]).on("zoom", (ev: any) => gRoot.attr("transform", ev.transform));
  svg.call(zoomB);

  const xOf = (i: number): number => X0 + i * (PW + GAP);
  const maxTech = Math.max(1, ...d.phases.map((p) => p.used.length));

  // Kill-chain spine: arrows between consecutive phase headers.
  for (let i = 0; i < d.phases.length - 1; i++) {
    gRoot.append("line").attr("class", "spine")
      .attr("x1", xOf(i) + PW).attr("y1", HEAD_Y + HEAD_H / 2)
      .attr("x2", xOf(i + 1)).attr("y2", HEAD_Y + HEAD_H / 2)
      .attr("marker-end", "url(#kc-arrow)");
  }

  const trunc = (s: string, n: number): string => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  d.phases.forEach((p, i) => {
    const x = xOf(i);
    const g = gRoot.append("g");
    // phase header
    g.append("rect").attr("class", "ph-head").attr("x", x).attr("y", HEAD_Y).attr("width", PW).attr("height", HEAD_H).attr("rx", 7)
      .attr("fill", phaseColor(p)).attr("stroke", p.used.length ? "#ef4444" : "#2d3250").attr("stroke-width", 1.4);
    g.append("text").attr("class", "ph-order").attr("x", x + 8).attr("y", HEAD_Y + 14).text(`${p.order + 1}. ${p.attackId}`);
    g.append("text").attr("class", "ph-name").attr("x", x + 8).attr("y", HEAD_Y + 30).text(trunc(p.name, 22));
    g.append("text").attr("class", "ph-meta").attr("x", x + 8).attr("y", HEAD_Y + 43)
      .text(p.used.length ? fmt("kc.nTechniques", { u: p.used.length, t: p.total }) : fmt("kc.techniques", { t: p.total }));

    // technique chips for the selected adversary
    p.used.forEach((te, j) => {
      const ty = TECH_Y0 + j * ROW_H;
      const tg = gRoot.append("g").attr("class", "tech")
        .on("click", () => window.open(`/?db=XTHREAT&table=ATTACKTECHNIQUE&editCol=AttackID&editVal=${encodeURIComponent(te.attackId)}`, "_blank", "noopener"));
      tg.append("line").attr("class", "tlink").attr("x1", x + 12).attr("y1", HEAD_Y + HEAD_H).attr("x2", x + 12).attr("y2", ty - 6);
      tg.append("circle").attr("cx", x + 12).attr("cy", ty - 4).attr("r", 3).attr("fill", "#7c83fd");
      tg.append("text").attr("class", "tech-id").attr("x", x + 20).attr("y", ty - 7).text(te.attackId);
      tg.append("text").attr("x", x + 20).attr("y", ty + 3).text(trunc(te.name, 22));
      tg.append("title").text(`${te.attackId} — ${te.name}`);
    });
  });

  // initial transform: fit width
  const W = svgEl.clientWidth || 1000;
  const fullW = xOf(d.phases.length - 1) + PW + 20;
  const k = Math.min(1, (W - 20) / fullW);
  svg.call(zoomB.transform, d3.zoomIdentity.translate(10, 0).scale(k));

  $("kc-cov").innerHTML = d.group
    ? fmt("kc.coverageGroup", { name: `<b>${d.group.name}</b>`, id: d.group.attackId, c: d.coverage.covered, t: d.coverage.total, n: d.coverage.techniques })
    : fmt("kc.coverageNone", { n: d.coverage.total });
}

function applyGroup(): void {
  const raw = ($("kc-search") as HTMLInputElement).value.trim();
  if (!raw) { void loadGraph(null); return; }
  const id = byName.get(raw.toLowerCase())
    || groups.find((g) => g.attackId.toLowerCase() === raw.toLowerCase())?.attackId
    || groups.find((g) => g.name.toLowerCase().includes(raw.toLowerCase()))?.attackId;
  if (!id) { toast(t("kc.noGroup")); return; }
  void loadGraph(id);
}

function fitView(): void {
  const svgEl = $("kc-svg") as unknown as SVGSVGElement;
  if (zoomB) d3.select(svgEl).transition().duration(400).call(zoomB.transform, d3.zoomIdentity.translate(10, 0).scale(Math.min(1, (svgEl.clientWidth - 20) / 2780)));
}
function exportSvg(): void {
  const clone = $("kc-svg").cloneNode(true) as SVGElement;
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  const blob = new Blob(['<?xml version="1.0"?>\n' + clone.outerHTML], { type: "image/svg+xml" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "kill-chain.svg"; a.click();
}

document.addEventListener("DOMContentLoaded", async () => {
  initI18n();
  $("kc-apply").onclick = applyGroup;
  $("kc-clear").onclick = () => { ($("kc-search") as HTMLInputElement).value = ""; void loadGraph(null); };
  $("kc-zin").onclick = () => { if (zoomB) d3.select("#kc-svg").transition().duration(200).call(zoomB.scaleBy, 1.3); };
  $("kc-zout").onclick = () => { if (zoomB) d3.select("#kc-svg").transition().duration(200).call(zoomB.scaleBy, 0.75); };
  $("kc-fit").onclick = fitView;
  $("kc-export").onclick = exportSvg;
  ($("kc-search") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") { e.preventDefault(); applyGroup(); } });
  await loadGroups();
  const q = new URLSearchParams(location.search).get("group");
  if (q) { ($("kc-search") as HTMLInputElement).value = groups.find((g) => g.attackId === q)?.name || q; }
  void loadGraph(q);
});
