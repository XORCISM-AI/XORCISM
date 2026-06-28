/**
 * sca.ts — Software Composition Analysis (/sca). SBOM inventory + components +
 * license/type/supplier breakdowns + worklist + composition graph, with CycloneDX/SPDX
 * import and export. Data from /api/sca, graph from /api/sca/graph.
 */
import { initI18n, t } from "./i18n";
declare const d3: any;
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface SbomRow { id: number; name: string; format: string; specVersion: string; subject: string | null; subjectVersion: string | null; serialNumber: string | null; assetId: number | null; asset: string | null; componentCount: number; vulnerableCount: number; licenseCount: number; source: string; toolName: string | null; createdDate: string | null; }
interface CompRow { id: number; name: string; version: string | null; type: string; purl: string | null; cpe: string | null; supplier: string | null; license: string | null; scope: string | null; sbomId: number | null; sbom: string | null; assetId: number | null; vulnerable: boolean; }
interface Finding { id: number; component: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; reason: string; kind: string; label: string; }
interface Inventory {
  sboms: SbomRow[]; components: CompRow[]; findings: Finding[];
  byType: { type: string; count: number }[]; byLicense: { license: string; count: number }[]; bySupplier: { supplier: string; count: number }[];
  summary: { sboms: number; components: number; distinctComponents: number; byFormat: { cyclonedx: number; spdx: number }; vulnerable: number; noLicense: number; noVersion: number; licenses: number; suppliers: number; dependencies: number; cpeLinked: number; assetsCovered: number; };
}
interface GNode { id: string; label: string; type: string; sub: string | null; vulnerable: boolean; }
interface GLink { source: any; target: any; kind: string; }

let assets: { id: number; label: string }[] = [];

const fmtPill = (f: string): string => /spdx/i.test(f)
  ? `<span class="pill p-spdx">SPDX</span>` : `<span class="pill p-cdx">CycloneDX</span>`;
function card(lbl: string, val: string, foot: string, color?: string, cls = "sc-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}
function bars(items: { name: string; count: number }[]): string {
  const max = Math.max(1, ...items.map((i) => i.count));
  return `<div class="sc-bars">${items.map((i) => `<div class="sc-bar">
    <span class="nm" title="${esc(i.name)}">${esc(i.name)}</span>
    <span class="tk"><i style="width:${Math.round((i.count / max) * 100)}%"></i></span>
    <span class="ct">${i.count}</span></div>`).join("")}</div>`;
}

function sbomRowHtml(s: SbomRow): string {
  return `<tr>
    <td><div class="pname lnk" data-graph="${s.id}">${esc(s.name)}</div>
      <div class="muted" style="font-size:11px">${s.subject ? esc(s.subject) + (s.subjectVersion ? " " + esc(s.subjectVersion) : "") + " · " : ""}${s.toolName ? esc(s.toolName) + " · " : ""}${esc(s.source)}${s.createdDate ? " · " + esc(String(s.createdDate).slice(0, 10)) : ""}</div></td>
    <td>${fmtPill(s.format)} <span class="muted" style="font-size:11px">${esc(s.specVersion)}</span></td>
    <td>${s.asset ? `<a href="/?db=XORCISM&table=ASSET&filterCol=AssetID&filterVal=${s.assetId}">${esc(s.asset)}</a>` : '<span class="muted">—</span>'}</td>
    <td style="text-align:right">${s.componentCount}</td>
    <td style="text-align:right">${s.licenseCount}</td>
    <td style="white-space:nowrap">
      <a class="ico" title="${t("sca.act.exportCdx")}" href="/api/sca/export?sbom=${s.id}&format=cyclonedx">⬇ CDX</a>
      <a class="ico" title="${t("sca.act.exportSpdx")}" href="/api/sca/export?sbom=${s.id}&format=spdx">⬇ SPDX</a>
      <button class="ico" title="${t("sca.act.viewGraph")}" data-graph="${s.id}">◔</button>
      <button class="ico" title="${t("sca.act.deleteSbom")}" data-del="${s.id}">✕</button>
    </td>
  </tr>`;
}
function compRowHtml(c: CompRow): string {
  return `<tr>
    <td><span class="pname">${esc(c.name)}</span>${c.vulnerable ? ` <span class="pill vuln">${t("sca.vuln")}</span>` : ""}
      ${c.sbom ? `<div class="muted" style="font-size:11px">${esc(c.sbom)}</div>` : ""}</td>
    <td>${c.version ? esc(c.version) : '<span class="muted">—</span>'}</td>
    <td><span class="tag">${esc(c.type)}</span></td>
    <td>${c.license ? esc(c.license) : `<span class="muted">${t("sca.none")}</span>`}</td>
    <td>${c.supplier ? esc(c.supplier) : '<span class="muted">—</span>'}</td>
    <td class="mono">${esc(c.purl || c.cpe || "")}</td>
  </tr>`;
}
function findingHtml(f: Finding): string {
  const color = f.kind === "vulnerable" ? "#ef4444" : f.kind === "no-version" ? "#fbbf24" : "#94a3b8";
  return `<li><span class="dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:${color}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="/?db=XORCISM&table=COMPONENT&filterCol=ComponentID&filterVal=${f.id}">${esc(f.component)}</a> — ${esc(f.label)}
    <span class="muted" style="font-size:11px"> ${esc(f.reason)}</span></li>`;
}

const SAMPLE_CDX = JSON.stringify({
  bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: "urn:uuid:demo-cdx-0001", version: 1,
  metadata: { component: { type: "application", name: "demo-web-app", version: "2.4.0" }, tools: { components: [{ type: "application", name: "syft" }] } },
  components: [
    { type: "library", "bom-ref": "pkg:npm/express@4.18.2", name: "express", version: "4.18.2", purl: "pkg:npm/express@4.18.2", licenses: [{ license: { id: "MIT" } }], supplier: { name: "OpenJS Foundation" } },
    { type: "library", "bom-ref": "pkg:npm/lodash@4.17.19", name: "lodash", version: "4.17.19", purl: "pkg:npm/lodash@4.17.19", cpe: "cpe:2.3:a:lodash:lodash:4.17.19:*:*:*:*:*:*:*", licenses: [{ license: { id: "MIT" } }] },
    { type: "framework", "bom-ref": "pkg:npm/react@18.2.0", name: "react", version: "18.2.0", purl: "pkg:npm/react@18.2.0", licenses: [{ license: { id: "MIT" } }] },
    { type: "library", "bom-ref": "pkg:npm/ms@2.0.0", name: "ms", version: "2.0.0", purl: "pkg:npm/ms@2.0.0" },
  ],
  dependencies: [
    { ref: "pkg:npm/express@4.18.2", dependsOn: ["pkg:npm/ms@2.0.0"] },
    { ref: "pkg:npm/react@18.2.0", dependsOn: ["pkg:npm/lodash@4.17.19"] },
  ],
}, null, 2);
const SAMPLE_SPDX = JSON.stringify({
  spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: "demo-spdx-doc",
  documentNamespace: "https://example/spdx/demo", creationInfo: { created: "2026-06-20T00:00:00Z", creators: ["Tool: trivy"] },
  packages: [
    { SPDXID: "SPDXRef-openssl", name: "openssl", versionInfo: "3.0.11", licenseConcluded: "Apache-2.0", supplier: "Organization: OpenSSL", externalRefs: [{ referenceCategory: "SECURITY", referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*" }, { referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:deb/openssl@3.0.11" }] },
    { SPDXID: "SPDXRef-zlib", name: "zlib", versionInfo: "1.2.13", licenseConcluded: "Zlib", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:deb/zlib@1.2.13" }] },
    { SPDXID: "SPDXRef-curl", name: "curl", versionInfo: "8.4.0", licenseConcluded: "curl", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:deb/curl@8.4.0" }] },
  ],
  relationships: [
    { spdxElementId: "SPDXRef-curl", relationshipType: "DEPENDS_ON", relatedSpdxElement: "SPDXRef-openssl" },
    { spdxElementId: "SPDXRef-curl", relationshipType: "DEPENDS_ON", relatedSpdxElement: "SPDXRef-zlib" },
  ],
}, null, 2);

async function doImport(): Promise<void> {
  const stat = $("sc-impstat"), btn = $("sc-import") as HTMLButtonElement;
  const content = ($("sc-json") as HTMLTextAreaElement).value.trim();
  if (!content) { stat.innerHTML = `⚠️ ${t("sca.imp.paste")}`; return; }
  const name = ($("sc-name") as HTMLInputElement).value.trim();
  const assetId = ($("sc-asset") as HTMLSelectElement).value;
  btn.disabled = true; stat.textContent = t("sca.imp.importing");
  try {
    const body: any = { content, source: "upload" };
    if (name) body.name = name;
    if (assetId) body.assetId = Number(assetId);
    const r = await fetch("/api/sca/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    stat.innerHTML = fmt("sca.imp.ok", { format: esc(d.format), id: esc(d.sbomId), comps: esc(d.components), deps: esc(d.dependencies), lics: esc(d.licenses) }) + (d.cpeLinks ? fmt("sca.imp.okCpe", { n: esc(d.cpeLinks) }) : "") + ".";
    await load(d.sbomId);
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

async function delSbom(id: number): Promise<void> {
  if (!confirm(fmt("sca.del.confirm", { id }))) return;
  const r = await fetch(`/api/sca/${id}`, { method: "DELETE" });
  if (r.ok) await load(null); else alert(t("sca.del.failed"));
}

// ─────────────────────────────── graph ───────────────────────────────
const TYPE_COL: Record<string, string> = { sbom: "#0ea5e9", application: "#22d3ee", framework: "#a78bfa", library: "#64748b", "operating-system": "#f59e0b", container: "#34d399", file: "#94a3b8" };
async function renderGraph(sbomId: number | null): Promise<void> {
  const host = $("sc-graph"); host.innerHTML = "";
  let g: { nodes: GNode[]; links: GLink[]; focus: string | null };
  try { const r = await fetch("/api/sca/graph" + (sbomId != null ? `?sbom=${sbomId}` : "")); g = await r.json(); }
  catch { host.innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("sca.graph.unavailable")}</div>`; return; }
  if (!g.nodes.length) { host.innerHTML = `<div class="muted" style="padding:40px;text-align:center">${t("sca.graph.empty")}</div>`; return; }
  const W = host.clientWidth || 900, H = 460;
  const svg = d3.select(host).append("svg").attr("viewBox", `0 0 ${W} ${H}`);
  const gRoot = svg.append("g");
  svg.call(d3.zoom().scaleExtent([0.2, 4]).on("zoom", (ev: any) => gRoot.attr("transform", ev.transform)));
  const link = gRoot.append("g").selectAll("line").data(g.links).join("line").attr("class", (l: GLink) => `link ${l.kind}`);
  const node = gRoot.append("g").selectAll("g").data(g.nodes, (d: GNode) => d.id).join("g")
    .call(d3.drag()
      .on("start", (ev: any, d: any) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (ev: any, d: any) => { d.fx = ev.x; d.fy = ev.y; })
      .on("end", (ev: any, d: any) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
  node.append("circle")
    .attr("r", (d: GNode) => d.type === "sbom" ? 9 : 5)
    .attr("fill", (d: GNode) => d.vulnerable ? "#ef4444" : (TYPE_COL[d.type] || "#64748b"))
    .attr("stroke", (d: GNode) => d.type === "sbom" ? "#7dd3fc" : "#0d1020").attr("stroke-width", 1.5);
  node.append("title").text((d: GNode) => `${d.label}${d.sub ? "\n" + d.sub : ""}${d.vulnerable ? "\n⚠ known-vulnerable" : ""}`);
  node.filter((d: GNode) => d.type === "sbom").append("text").attr("x", 12).attr("y", 4).text((d: GNode) => d.label);
  const sim = d3.forceSimulation(g.nodes)
    .force("link", d3.forceLink(g.links).id((d: GNode) => d.id).distance((l: GLink) => (l.kind === "contains" ? 60 : 40)).strength(0.4))
    .force("charge", d3.forceManyBody().strength(-120))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide(12));
  sim.on("tick", () => {
    link.attr("x1", (l: any) => l.source.x).attr("y1", (l: any) => l.source.y).attr("x2", (l: any) => l.target.x).attr("y2", (l: any) => l.target.y);
    node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
  });
}

async function load(focusSbom: number | null): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/sca"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("sc-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  const cards = [
    card(t("sca.card.sboms"), String(s.sboms), fmt("sca.card.sboms.f", { cdx: s.byFormat.cyclonedx, spdx: s.byFormat.spdx }), "#38bdf8", "sc-card sc-hero"),
    card(t("sca.card.components"), String(s.components), fmt("sca.card.components.f", { distinct: s.distinctComponents, deps: s.dependencies })),
    card(t("sca.card.vulnerable"), String(s.vulnerable), t("sca.card.vulnerable.f"), s.vulnerable ? "#ef4444" : "#34d399"),
    card(t("sca.card.noLicense"), String(s.noLicense), fmt("sca.card.noLicense.f", { n: s.licenses }), s.noLicense ? "#fbbf24" : "#34d399"),
    card(t("sca.card.noVersion"), String(s.noVersion), t("sca.card.noVersion.f"), s.noVersion ? "#fb923c" : "#34d399"),
    card(t("sca.card.cpeLinked"), String(s.cpeLinked), fmt("sca.card.cpeLinked.f", { n: s.assetsCovered })),
  ].join("");

  const assetOpts = `<option value="">${t("sca.imp.noAsset")}</option>` + assets.map((a) => `<option value="${a.id}">${esc(a.label)}</option>`).join("");
  const importPanel = `<div class="sc-panel"><div class="sc-section" style="margin-top:0">${t("sca.imp.title")}</div>
    <div class="sc-form">
      <textarea id="sc-json" placeholder="${t("sca.imp.placeholder")}"></textarea>
      <div class="sc-samples">${t("sca.imp.loadSample")} <a id="sc-s-cdx">CycloneDX</a> · <a id="sc-s-spdx">SPDX</a> &nbsp;|&nbsp; ${t("sca.imp.orFile")}
        <input type="file" id="sc-file" accept=".json,application/json" style="display:inline-block;font-size:11px"></div>
      <div class="sc-row">
        <div class="sc-fld"><label>${t("sca.imp.name")}</label><input id="sc-name" type="text" placeholder="${t("sca.imp.namePh")}" style="min-width:220px"></div>
        <div class="sc-fld"><label>${t("sca.imp.linkAsset")}</label><select id="sc-asset" style="min-width:200px">${assetOpts}</select></div>
        <button id="sc-import" class="sc-go">${t("sca.imp.btn")}</button>
      </div>
      <div class="sc-stat" id="sc-impstat"></div>
    </div></div>`;

  const charts = `<div class="sc-grid2">
    <div class="sc-panel"><div class="sc-section" style="margin-top:0">${t("sca.chart.byType")}</div>
      ${d.byType.length ? bars(d.byType.map((t) => ({ name: t.type, count: t.count }))) : `<div class="muted">${t("sca.chart.noComponents")}</div>`}</div>
    <div class="sc-panel"><div class="sc-section" style="margin-top:0">${t("sca.chart.topLicenses")}</div>
      ${d.byLicense.length ? bars(d.byLicense.map((l) => ({ name: l.license, count: l.count }))) : `<div class="muted">${t("sca.chart.noLicenses")}</div>`}</div>
  </div>`;

  const sbomTable = d.sboms.length ? `<table class="sc"><thead><tr>
      <th>${t("sca.th.sbom")}</th><th>${t("sca.th.format")}</th><th>${t("sca.th.asset")}</th><th style="text-align:right">${t("sca.th.comp")}</th><th style="text-align:right">${t("sca.th.lic")}</th><th>${t("sca.th.actions")}</th>
    </tr></thead><tbody>${d.sboms.map(sbomRowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">${t("sca.sbom.empty")}</div>`;

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 80).map(findingHtml).join("")}</ul>${d.findings.length > 80 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("sca.more", { n: d.findings.length - 80 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("sca.noFindings")}</div>`;

  const compTable = d.components.length ? `<table class="sc"><thead><tr>
      <th>${t("sca.th.component")}</th><th>${t("sca.th.version")}</th><th>${t("sca.th.type")}</th><th>${t("sca.th.license")}</th><th>${t("sca.th.supplier")}</th><th>${t("sca.th.purlCpe")}</th>
    </tr></thead><tbody>${d.components.slice(0, 300).map(compRowHtml).join("")}</tbody></table>
    ${d.components.length > 300 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("sca.comp.showing", { n: d.components.length })} <a href="/?db=XORCISM&table=COMPONENT">${t("sca.comp.explorer")}</a></div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("sca.comp.empty")}</div>`;

  $("sc-body").innerHTML = `<div class="sc-cards">${cards}</div>
    ${importPanel}
    ${charts}
    <div id="sc-reach"></div>
    <div class="sc-section">${fmt("sca.sec.sboms", { n: d.sboms.length })}</div>${sbomTable}
    <div class="sc-section">${t("sca.sec.graph")}</div>
    <div id="sc-graph"></div>
    <div class="glegend">
      <span class="l"><span class="sw" style="background:#0ea5e9"></span>SBOM</span>
      <span class="l"><span class="sw" style="background:#22d3ee"></span>${t("sca.gl.application")}</span>
      <span class="l"><span class="sw" style="background:#a78bfa"></span>${t("sca.gl.framework")}</span>
      <span class="l"><span class="sw" style="background:#64748b"></span>${t("sca.gl.library")}</span>
      <span class="l"><span class="sw" style="background:#ef4444"></span>${t("sca.gl.vulnerable")}</span>
      <span class="l">${t("sca.gl.edges")}</span>
    </div>
    <div class="sc-section">${fmt("sca.sec.worklist", { n: d.findings.length })}</div>${findings}
    <div class="sc-section">${fmt("sca.sec.components", { n: d.components.length })}</div>${compTable}
    <div class="legend" style="font-size:11px;color:#64748b;margin-top:12px">${t("sca.legend")}</div>`;

  // wire interactions
  ($("sc-import") as HTMLButtonElement).addEventListener("click", () => void doImport());
  $("sc-s-cdx").addEventListener("click", () => { ($("sc-json") as HTMLTextAreaElement).value = SAMPLE_CDX; });
  $("sc-s-spdx").addEventListener("click", () => { ($("sc-json") as HTMLTextAreaElement).value = SAMPLE_SPDX; });
  ($("sc-file") as HTMLInputElement).addEventListener("change", (ev) => {
    const f = (ev.target as HTMLInputElement).files?.[0]; if (!f) return;
    const rd = new FileReader(); rd.onload = () => { ($("sc-json") as HTMLTextAreaElement).value = String(rd.result || ""); if (!($("sc-name") as HTMLInputElement).value) ($("sc-name") as HTMLInputElement).value = f.name.replace(/\.json$/i, ""); }; rd.readAsText(f);
  });
  document.querySelectorAll<HTMLElement>("[data-graph]").forEach((el) => el.addEventListener("click", () => void renderGraph(Number(el.dataset.graph))));
  document.querySelectorAll<HTMLElement>("[data-del]").forEach((el) => el.addEventListener("click", () => void delSbom(Number(el.dataset.del))));

  void renderGraph(focusSbom);
  void loadReach();
}

// ── reachability-based prioritization panel (Endor/Snyk-style) ──────────────────────
interface ReachFinding { name: string; version: string | null; scope: string | null; reach: string; cvss: number | null; kev: boolean; epss: number | null; vulnCount: number; priority: number; bucket: string; }
interface ScaPriorityResp { findings: ReachFinding[]; summary: { vulnerable: number; reachable: number; unreachable: number; unknown: number; act: number; scheduled: number; deferred: number; review: number; noiseReductionPct: number; reachablePct: number }; }
const reachColor = (r: string): string => r === "reachable" ? "#ef4444" : r === "unreachable" ? "#64748b" : "#f59e0b";
const bucketColor = (b: string): string => b === "act" ? "#ef4444" : b === "scheduled" ? "#f59e0b" : b === "deferred" ? "#64748b" : "#38bdf8";

async function loadReach(): Promise<void> {
  const host = document.getElementById("sc-reach"); if (!host) return;
  let d: ScaPriorityResp;
  try { const r = await fetch("/api/sca/priority"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch { host.innerHTML = ""; return; }
  const s = d.summary;
  if (!s.vulnerable) {
    host.innerHTML = `<div class="sc-panel"><div class="sc-section" style="margin-top:0">${t("sca.reach.title")}</div><div class="muted">${t("sca.reach.none")}</div></div>`;
    return;
  }
  const badge = (txt: string, color: string): string => `<span style="background:${color}22;color:${color};border-radius:6px;padding:2px 8px;font-size:11px;font-weight:600">${txt}</span>`;
  const rows = d.findings.slice(0, 40).map((f) => `<tr>
    <td><b>${esc(f.name)}</b> <span class="muted">${esc(f.version || "")}</span>${f.scope ? ` <span class="muted" style="font-size:10px">[${esc(f.scope)}]</span>` : ""}</td>
    <td style="color:${reachColor(f.reach)};font-weight:600">${esc(t("sca.reach.r." + f.reach) || f.reach)}</td>
    <td>${f.kev ? `<span style="color:#ef4444;font-weight:700">KEV</span> ` : ""}${f.cvss != null ? `CVSS ${esc(f.cvss)}` : ""}${f.epss != null ? ` · EPSS ${(f.epss * 100).toFixed(0)}%` : ""}</td>
    <td style="text-align:right;font-weight:700">${f.priority}</td>
    <td>${badge(esc(t("sca.reach.b." + f.bucket) || f.bucket), bucketColor(f.bucket))}</td>
  </tr>`).join("");
  host.innerHTML = `<div class="sc-panel">
    <div class="sc-section" style="margin-top:0">${t("sca.reach.title")}</div>
    <div class="muted" style="font-size:12px;margin:-4px 0 10px">${t("sca.reach.sub")}</div>
    <div class="sc-cards" style="margin-bottom:12px">
      ${card(t("sca.reach.noise"), s.noiseReductionPct + "%", fmt("sca.reach.noise.f", { u: s.unreachable, v: s.vulnerable }), "#34d399")}
      ${card(t("sca.reach.act"), String(s.act), t("sca.reach.act.f"), s.act ? "#ef4444" : "#34d399")}
      ${card(t("sca.reach.scheduled"), String(s.scheduled), t("sca.reach.scheduled.f"), "#f59e0b")}
      ${card(t("sca.reach.deferred"), String(s.deferred), fmt("sca.reach.deferred.f", { n: s.review }), "#64748b")}
    </div>
    <table class="sc"><thead><tr><th>${t("sca.reach.th.dep")}</th><th>${t("sca.reach.th.reach")}</th><th>${t("sca.reach.th.risk")}</th><th style="text-align:right">${t("sca.reach.th.prio")}</th><th>${t("sca.reach.th.bucket")}</th></tr></thead><tbody>${rows}</tbody></table>
  </div>`;
}

async function loadAssets(): Promise<void> {
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=ASSET&idCol=AssetID&labelCol=AssetName");
    if (r.ok) { const d = await r.json(); assets = (Array.isArray(d) ? d : d.rows || []).map((x: any) => ({ id: x.id ?? x.AssetID ?? x.value, label: x.label ?? x.AssetName ?? x.text ?? String(x.id) })); }
  } catch { /* optional */ }
}

document.addEventListener("DOMContentLoaded", async () => { initI18n(); await loadAssets(); await load(null); });
