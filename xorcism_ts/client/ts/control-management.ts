/**
 * control-management.ts — NIST SP 800-53 control-management cockpit (/control-management).
 * Browse the 1,196-control Rev 5 catalogue from /api/control-management; set implementation status +
 * SP 800-53A assessment (inline or in the detail modal, which also shows the full control text and the
 * ATT&CK crosswalk); manage POA&M items; watch coverage / assessment / POA&M posture + the gap worklist.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Ctrl {
  id: number; ref: string; title: string; family: string; familyCode: string; enhancement: boolean;
  baselines: string[]; status: string; responsibility: string; ownerPersonId: number | null; owner: string;
  targetDate: string; narrative: string; reviewed: string; assessment: string; attackCount: number;
}
interface Fam { code: string; name: string; total: number; implemented: number; partial: number; planned: number; notImpl: number; na: number; inherited: number; unassigned: number; coveragePct: number; }
interface Gap { id: number; ref: string; title: string; family: string; familyCode: string; baselines: string[]; status: string; score: number; }
interface Poam { id: number; controlId: number | null; ref: string; title: string; severity: string; status: string; ownerPersonId: number | null; owner: string; scheduled: string; actual: string; overdue: boolean; open: boolean; }
interface Data {
  controls: Ctrl[]; families: Fam[]; gaps: Gap[]; poam: Poam[]; persons: { id: number; name: string }[];
  statuses: string[]; responsibilities: string[]; assessmentResults: string[]; poamStatuses: string[]; poamSeverities: string[];
  summary: Record<string, any>;
}

let DATA: Data | null = null;
const FILTER = { q: "", family: "", baseline: "", status: "", hideEnh: false, onlyGaps: false };
const GAP_SET = new Set(["", "Partially Implemented", "Planned", "Not Implemented"]);
const RENDER_CAP = 400;
let DETAIL_ID = 0;

function statusClass(s: string): string {
  return s === "Implemented" ? "c-Implemented" : s === "Partially Implemented" ? "c-Partial"
    : s === "Planned" ? "c-Planned" : s === "Not Implemented" ? "c-NotImpl"
    : s === "Not Applicable" ? "c-NA" : s === "Inherited" ? "c-Inherited" : "c-Unassigned";
}
function assessBadge(a: string): string {
  if (a === "Satisfied") return `<span class="asmt a-Satisfied" title="Satisfied">SAT</span>`;
  if (a === "Other Than Satisfied") return `<span class="asmt a-Other" title="Other than satisfied">OTH</span>`;
  if (a === "Not Assessed") return `<span class="asmt a-None">N/A</span>`;
  return `<span class="muted">—</span>`;
}
function blBadges(b: string[]): string { return b.map((x) => `<span class="bl bl-${x}" title="${x === "L" ? "Low" : x === "M" ? "Moderate" : x === "H" ? "High" : "Privacy"} baseline">${x}</span>`).join(""); }
function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="cm-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
function techUrl(id: string): string { const p = id.split("."); return `https://attack.mitre.org/techniques/${p[0]}${p[1] ? "/" + p[1] : ""}/`; }

function statusSelect(c: Ctrl): string {
  const opts = [`<option value=""${c.status === "" ? " selected" : ""}>— Unassigned —</option>`]
    .concat(DATA!.statuses.map((s) => `<option${s === c.status ? " selected" : ""}>${esc(s)}</option>`)).join("");
  return `<select class="st" data-id="${c.id}">${opts}</select>`;
}
function respSelect(c: Ctrl): string {
  const opts = [`<option value=""${c.responsibility === "" ? " selected" : ""}>—</option>`]
    .concat(DATA!.responsibilities.map((s) => `<option${s === c.responsibility ? " selected" : ""}>${esc(s)}</option>`)).join("");
  return `<select class="rs" data-id="${c.id}">${opts}</select>`;
}
function rowHtml(c: Ctrl): string {
  return `<tr data-id="${c.id}">
    <td><span class="dotc ${statusClass(c.status)}"></span><span class="cref${c.enhancement ? " enh" : ""}" data-detail="${c.id}" style="cursor:pointer">${esc(c.ref)}</span></td>
    <td><span class="ctitle">${esc(c.title)}</span></td>
    <td><span class="muted" style="font-size:11px">${esc(c.familyCode)}</span></td>
    <td>${c.baselines.length ? blBadges(c.baselines) : "<span class='muted'>—</span>"}</td>
    <td>${statusSelect(c)}</td>
    <td>${assessBadge(c.assessment)}</td>
    <td>${respSelect(c)}</td>
    <td>${c.owner ? esc(c.owner) : "<span class='muted'>—</span>"}</td>
    <td>${c.attackCount ? `<span class="att" title="${c.attackCount} ATT&CK techniques mitigated">⚔ ${c.attackCount}</span>` : "<span class='muted'>—</span>"}</td>
    <td><button class="edit-btn" data-detail="${c.id}" title="Open detail (text, ATT&CK, assessment, POA&M)">&#9998;</button></td>
  </tr>`;
}

function applyFilters(): Ctrl[] {
  if (!DATA) return [];
  return DATA.controls.filter((c) =>
    (!FILTER.q || `${c.ref} ${c.title} ${c.family}`.toLowerCase().includes(FILTER.q)) &&
    (!FILTER.family || c.familyCode === FILTER.family) &&
    (!FILTER.baseline || c.baselines.includes(FILTER.baseline)) &&
    (!FILTER.status || (FILTER.status === "Unassigned" ? c.status === "" : c.status === FILTER.status)) &&
    (!FILTER.hideEnh || !c.enhancement) &&
    (!FILTER.onlyGaps || GAP_SET.has(c.status)));
}
function renderTable(): void {
  const rows = applyFilters();
  const host = $("cm-table-host");
  const shown = rows.slice(0, RENDER_CAP);
  host.innerHTML = rows.length
    ? `<table class="cm"><thead><tr><th>Ref</th><th>Title</th><th>Fam</th><th>BL</th><th>Status</th><th>53A</th><th>Responsibility</th><th>Owner</th><th>ATT&CK</th><th></th></tr></thead><tbody>${shown.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:14px 0">No controls match the current filters.</div>`;
  host.querySelectorAll<HTMLSelectElement>("select.st").forEach((s) => s.addEventListener("change", () => void saveImpl(Number(s.dataset.id), { status: s.value })));
  host.querySelectorAll<HTMLSelectElement>("select.rs").forEach((s) => s.addEventListener("change", () => void saveImpl(Number(s.dataset.id), { responsibility: s.value })));
  host.querySelectorAll<HTMLElement>("[data-detail]").forEach((b) => b.addEventListener("click", () => openDetail(Number(b.dataset.detail))));
  const cnt = $("cm-count");
  if (cnt) cnt.textContent = rows.length > RENDER_CAP ? `(showing ${RENDER_CAP} of ${rows.length} — refine to see the rest)` : `(${rows.length} of ${DATA?.controls.length ?? 0})`;
}

function famHtml(f: Fam): string {
  const seg = (n: number, cls: string, t: string): string => n ? `<div class="${cls}" style="width:${(n / f.total) * 100}%" title="${t}: ${n}"></div>` : "";
  return `<div class="fam" data-code="${esc(f.code)}">
    <div class="top"><span class="code">${esc(f.code)}</span><span class="nm">${esc(f.name)}</span><span class="cnt">${f.total}</span></div>
    <div class="barwrap">${seg(f.implemented, "seg-impl", "Implemented")}${seg(f.partial, "seg-part", "Partial")}${seg(f.planned, "seg-plan", "Planned")}${seg(f.notImpl, "seg-no", "Not implemented")}${seg(f.inherited, "seg-inh", "Inherited")}${seg(f.na, "seg-na", "Not applicable")}</div>
    <div class="pct">${f.coveragePct}% covered · ${f.implemented} impl · ${f.unassigned} unassigned</div>
  </div>`;
}

function poamRow(p: Poam): string {
  const opts = DATA!.poamStatuses.map((s) => `<option${s === p.status ? " selected" : ""}>${esc(s)}</option>`).join("");
  return `<tr>
    <td>${p.ref ? `<span class="cref" data-detail-ref="${esc(p.ref)}" style="cursor:pointer">${esc(p.ref)}</span>` : "<span class='muted'>—</span>"}</td>
    <td><span class="ctitle">${esc(p.title)}</span>${p.overdue ? '<span class="ovd">overdue</span>' : ""}</td>
    <td>${p.severity ? `<span class="sev-${esc(p.severity)}">${esc(p.severity)}</span>` : "<span class='muted'>—</span>"}</td>
    <td><select class="ps" data-poam="${p.id}">${opts}</select></td>
    <td>${p.owner ? esc(p.owner) : "<span class='muted'>—</span>"}</td>
    <td>${p.scheduled ? esc(p.scheduled) : "<span class='muted'>—</span>"}</td>
  </tr>`;
}

function buildBody(): void {
  const s = DATA!.summary;
  if (!s.loaded || !s.total) {
    $("cm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ The NIST SP 800-53 catalogue isn't loaded yet.
      Run <code>python xorcism_python/importers/import_nist800-53.py</code> to import the 1,196 Rev 5 controls.</div>`;
    return;
  }
  const bl = s.byBaseline || {}; const a = s.assessment || {}; const mp = s.mappings || {}; const pm = s.poam || {};
  const cw = (k: string): number => (mp.byFramework && mp.byFramework[k] && mp.byFramework[k].controls) || 0;
  const cards = [
    card("Controls", String(s.total), `${s.base} base · ${s.enhancements} enh · ${s.familyCount} families`),
    card("Coverage", `${s.coveragePct}%`, `${s.implemented} implemented · ${s.unassigned} unassigned`, s.coveragePct >= 80 ? "#34d399" : s.coveragePct >= 40 ? "#fbbf24" : "#f87171"),
    card("Assessed (53A)", `${a.satisfied || 0}✓`, `${a.otherThanSatisfied || 0} other-than-satisfied`, (a.otherThanSatisfied || 0) ? "#fbbf24" : (a.satisfied || 0) ? "#34d399" : undefined),
    card("Gaps", String(s.gapCount), "in a baseline, needs work", s.gapCount ? "#f87171" : "#34d399"),
    card("POA&M", `${pm.open || 0}`, `${pm.overdue || 0} overdue · ${pm.total || 0} total`, (pm.overdue || 0) ? "#f87171" : (pm.open || 0) ? "#fbbf24" : "#34d399"),
    card("Crosswalks", mp.loaded ? `${Object.keys(mp.byFramework || {}).length}` : "—", mp.loaded ? `frameworks · ${mp.attackTechniques} ATT&CK · ${cw("D3FEND")} D3FEND · ${cw("CSF")} CSF ctrl` : "run the crosswalk importers", mp.loaded ? "#c084fc" : undefined),
  ];

  const order: [string, string][] = [["Implemented", "c-Implemented"], ["Partially Implemented", "c-Partial"], ["Planned", "c-Planned"], ["Not Implemented", "c-NotImpl"], ["Not Applicable", "c-NA"], ["Inherited", "c-Inherited"], ["Unassigned", "c-Unassigned"]];
  const byStatus = order.filter(([k]) => (s.byStatus?.[k] ?? 0) > 0).map(([k, cls]) =>
    `<span class="bd" data-status="${esc(k)}"><span class="dotc ${cls}"></span>${esc(k)} <b>${s.byStatus[k]}</b></span>`).join("");

  const blRow = s.baselinesLoaded ? `<div class="cm-section">Baselines (NIST SP 800-53B)</div><div class="blrow">
    ${(["low", "moderate", "high", "privacy"] as const).map((k) => `<div class="blcard"><div class="t">${k}</div><div class="v">${bl[k].implemented}<span class="muted" style="font-size:13px">/${bl[k].total}</span></div><div class="foot muted" style="font-size:11px">implemented</div></div>`).join("")}
  </div>` : "";

  const gaps = DATA!.gaps.length
    ? `<ul class="worklist">${DATA!.gaps.slice(0, 25).map((g) => `<li><span class="pri">#${esc(String(g.score))}</span><span class="cref" data-detail-ref="${esc(g.ref)}" style="cursor:pointer">${esc(g.ref)}</span> <span class="ctitle">${esc(g.title)}</span> ${blBadges(g.baselines)} <span class="muted" style="margin-left:auto;font-size:12px">${esc(g.status)}</span></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">✓ No open gaps in any baseline.</div>`;

  const poamTable = DATA!.poam.length
    ? `<table class="cm"><thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Status</th><th>Owner</th><th>Scheduled</th></tr></thead><tbody>${DATA!.poam.map(poamRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No POA&M items yet. Open a control and click <b>+ POA&M</b>, or use <b>+ New POA&M</b>.</div>`;

  const filters = `<div class="filters">
    <input id="cm-search" type="search" placeholder="Search ref / title / family…" style="flex:1;min-width:200px">
    <select id="cm-family"><option value="">All families</option>${DATA!.families.map((f) => `<option value="${esc(f.code)}">${esc(f.code)} — ${esc(f.name)}</option>`).join("")}</select>
    <select id="cm-baseline"><option value="">All baselines</option><option value="L">Low</option><option value="M">Moderate</option><option value="H">High</option><option value="P">Privacy</option></select>
    <select id="cm-status"><option value="">All statuses</option>${DATA!.statuses.map((x) => `<option>${esc(x)}</option>`).join("")}<option>Unassigned</option></select>
    <label class="chk"><input type="checkbox" id="cm-baseonly"> base only</label>
    <label class="chk"><input type="checkbox" id="cm-gaponly"> gaps only</label>
    <span id="cm-count" class="muted" style="font-size:12px"></span></div>`;

  $("cm-body").innerHTML = `<div class="cm-cards">${cards.join("")}</div>
    <div class="cm-section">By status</div><div class="breakdown">${byStatus}</div>
    ${blRow}
    <div class="cm-section">Coverage by family</div><div class="fam-grid">${DATA!.families.map(famHtml).join("")}</div>
    <div class="cm-section">Gap worklist (${DATA!.gaps.length}) — highest-priority baseline gaps first</div>${gaps}
    <div class="cm-section">POA&M <span class="act"><button class="btn-2nd" id="cm-poam-new">+ New POA&M</button></span></div>${poamTable}
    <div class="cm-section">Controls</div>${filters}<div id="cm-table-host"></div>
    <div class="legend" style="font-size:11px;color:#64748b;margin-top:12px">↳ Set <b>status</b> / <b>responsibility</b> inline, or click a <b>ref</b> / ✎ to open the control (full text, ATT&CK crosswalk, 800-53A assessment, POA&M).
      Catalogue <code>import_nist800-53.py</code>; text <code>import_nist80053_details.py</code>; baselines <code>import_nist80053_baselines.py</code>; ATT&CK <code>import_attack_80053_mappings.py</code>.</div>`;

  ($("cm-search") as HTMLInputElement).value = FILTER.q;
  ($("cm-family") as HTMLSelectElement).value = FILTER.family;
  ($("cm-baseline") as HTMLSelectElement).value = FILTER.baseline;
  ($("cm-status") as HTMLSelectElement).value = FILTER.status;
  ($("cm-baseonly") as HTMLInputElement).checked = FILTER.hideEnh;
  ($("cm-gaponly") as HTMLInputElement).checked = FILTER.onlyGaps;

  $("cm-search").addEventListener("input", () => { FILTER.q = ($("cm-search") as HTMLInputElement).value.trim().toLowerCase(); renderTable(); });
  $("cm-family").addEventListener("change", () => { FILTER.family = ($("cm-family") as HTMLSelectElement).value; renderTable(); });
  $("cm-baseline").addEventListener("change", () => { FILTER.baseline = ($("cm-baseline") as HTMLSelectElement).value; renderTable(); });
  $("cm-status").addEventListener("change", () => { FILTER.status = ($("cm-status") as HTMLSelectElement).value; renderTable(); });
  $("cm-baseonly").addEventListener("change", () => { FILTER.hideEnh = ($("cm-baseonly") as HTMLInputElement).checked; renderTable(); });
  $("cm-gaponly").addEventListener("change", () => { FILTER.onlyGaps = ($("cm-gaponly") as HTMLInputElement).checked; renderTable(); });
  $("cm-poam-new").addEventListener("click", () => openPoamCreate(null));
  $("cm-body").querySelectorAll<HTMLElement>(".bd[data-status]").forEach((el) => el.addEventListener("click", () => { FILTER.status = el.dataset.status === FILTER.status ? "" : (el.dataset.status || ""); ($("cm-status") as HTMLSelectElement).value = FILTER.status; renderTable(); }));
  $("cm-body").querySelectorAll<HTMLElement>(".fam[data-code]").forEach((el) => el.addEventListener("click", () => { FILTER.family = el.dataset.code === FILTER.family ? "" : (el.dataset.code || ""); ($("cm-family") as HTMLSelectElement).value = FILTER.family; renderTable(); }));
  $("cm-body").querySelectorAll<HTMLElement>("[data-detail-ref]").forEach((el) => el.addEventListener("click", () => openDetailByRef(el.dataset.detailRef || "")));
  $("cm-body").querySelectorAll<HTMLSelectElement>("select.ps").forEach((el) => el.addEventListener("change", () => void updatePoam(Number(el.dataset.poam), { status: el.value })));
  renderTable();
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/control-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); DATA = await r.json(); }
  catch (e) { $("cm-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  buildBody();
}

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #22c55e;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 5000);
}

async function saveImpl(controlId: number, patch: Record<string, unknown>): Promise<void> {
  try {
    const r = await fetch("/api/control-management/implementation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ controlId, ...patch }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load(); toast("✅ Saved");
  } catch (e) { toast(`⚠️ ${e}`); }
}

// ── control detail modal ────────────────────────────────────────────────────────
function refToId(ref: string): number | null { const c = DATA?.controls.find((x) => x.ref === ref); return c ? c.id : null; }
function openDetailByRef(ref: string): void { const id = refToId(ref); if (id) openDetail(id); }

async function openDetail(id: number): Promise<void> {
  DETAIL_ID = id;
  $("cm-d-ref").textContent = "…"; $("cm-d-meta").textContent = ""; $("cm-d-body").innerHTML = `<div class="muted">Loading…</div>`;
  $("cm-d-err").textContent = ""; $("cm-modal").classList.add("open");
  let d: any;
  try { const r = await fetch(`/api/control-management/control/${id}`); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cm-d-body").innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; return; }

  $("cm-d-ref").textContent = d.ref;
  $("cm-d-meta").innerHTML = `${esc(d.title)} · ${esc(d.family)} ${blBadges(d.baselines || [])}`;

  const panels: string[] = [];
  if (d.statement) panels.push(`<div class="panel"><h4>Control statement</h4><div class="prose">${esc(d.statement)}</div></div>`);
  if (d.guidance) panels.push(`<div class="panel"><h4>Discussion / guidance</h4><div class="prose">${esc(d.guidance)}</div></div>`);
  if (d.params) panels.push(`<div class="panel"><h4>Parameters (ODPs)</h4><div class="prose">${esc(d.params)}</div></div>`);
  if (d.related && d.related.length) panels.push(`<div class="panel"><h4>Related controls</h4><div class="chips">${d.related.map((r: string) => `<span class="relchip" data-rel="${esc(r)}">${esc(r)}</span>`).join("")}</div></div>`);
  const chipList = (items: any[], linked: boolean, cap: number): string => {
    const shown = items.slice(0, cap);
    const more = items.length - shown.length;
    const chips = shown.map((t: any) => {
      const nm = t.name ? " " + esc(String(t.name).slice(0, 64)) : "";
      return linked
        ? `<a class="techchip" href="${techUrl(t.id)}" target="_blank" rel="noopener" title="${esc(t.name)}">${esc(t.id)}${nm}</a>`
        : `<span class="techchip" title="${esc(t.name)}">${esc(t.id)}${nm}</span>`;
    }).join("");
    return chips + (more > 0 ? `<span class="muted" style="font-size:11px;align-self:center">+${more} more</span>` : "");
  };
  const att = (d.mappings && d.mappings["ATT&CK"]) || [];
  if (att.length) panels.push(`<div class="panel"><h4>ATT&CK techniques mitigated (${att.length})</h4><div class="chips">${chipList(att, true, 40)}</div></div>`);
  // direct crosswalks first, composed/bridged frameworks (rel "via …") last
  const isComposed = (fw: string): boolean => /^via /i.test(d.mappings[fw][0]?.rel || "");
  const others = Object.keys(d.mappings || {}).filter((k) => k !== "ATT&CK");
  others.sort((a, b) => ((isComposed(a) ? 1 : 0) - (isComposed(b) ? 1 : 0)) || a.localeCompare(b));
  for (const fw of others) {
    const items = d.mappings[fw];
    const rel = items[0]?.rel || "";
    const composed = /^via /i.test(rel);
    panels.push(`<div class="panel"><h4>${esc(fw)} (${items.length})${composed ? ` <span class="muted" style="text-transform:none;font-weight:400">· indirect, ${esc(rel)}</span>` : ""}</h4><div class="chips">${chipList(items, false, 30)}</div></div>`);
  }
  if (d.poam && d.poam.length) panels.push(`<div class="panel"><h4>POA&M for this control (${d.poam.length})</h4><ul class="poam-mini">${d.poam.map((p: any) => `<li><span class="sev-${esc(p.severity)}">${esc(p.severity || "—")}</span> ${esc(p.title)} <span class="muted" style="margin-left:auto">${esc(p.status)}${p.scheduled ? " · " + esc(p.scheduled) : ""}</span></li>`).join("")}</ul></div>`);
  if (!panels.length) panels.push(`<div class="muted" style="margin-bottom:10px">No control text imported. Run <code>import_nist80053_details.py</code>.</div>`);
  $("cm-d-body").innerHTML = panels.join("");
  $("cm-d-body").querySelectorAll<HTMLElement>("[data-rel]").forEach((el) => el.addEventListener("click", () => openDetailByRef(el.dataset.rel || "")));

  // populate the editable implementation + assessment form
  const im = d.implementation || {};
  const fill = (id: string, opts: string[], blank: string, val: string): void => {
    ($(id) as HTMLSelectElement).innerHTML = [`<option value="">${blank}</option>`].concat(opts.map((x) => `<option>${esc(x)}</option>`)).join("");
    ($(id) as HTMLSelectElement).value = val || "";
  };
  fill("cm-d-status", DATA!.statuses, "— Unassigned —", im.status || "");
  fill("cm-d-resp", DATA!.responsibilities, "—", im.responsibility || "");
  fill("cm-d-aresult", DATA!.assessmentResults, "— Not assessed —", im.assessmentResult || "");
  const ownerOpts = [`<option value="">—</option>`].concat(DATA!.persons.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`)).join("");
  ($("cm-d-owner") as HTMLSelectElement).innerHTML = ownerOpts; ($("cm-d-owner") as HTMLSelectElement).value = im.ownerPersonId != null ? String(im.ownerPersonId) : "";
  ($("cm-d-assessor") as HTMLSelectElement).innerHTML = ownerOpts; ($("cm-d-assessor") as HTMLSelectElement).value = im.assessorPersonId != null ? String(im.assessorPersonId) : "";
  ($("cm-d-target") as HTMLInputElement).value = im.targetDate || "";
  ($("cm-d-narr") as HTMLTextAreaElement).value = im.narrative || "";
  ($("cm-d-adate") as HTMLInputElement).value = im.assessedDate || "";
  ($("cm-d-aremarks") as HTMLTextAreaElement).value = im.assessmentRemarks || "";
}
function closeDetail(): void { $("cm-modal").classList.remove("open"); }
async function saveDetail(): Promise<void> {
  if (!DETAIL_ID) return;
  const btn = $("cm-d-save") as HTMLButtonElement; btn.disabled = true; $("cm-d-err").textContent = "Saving…";
  try {
    const body = {
      controlId: DETAIL_ID,
      status: ($("cm-d-status") as HTMLSelectElement).value,
      responsibility: ($("cm-d-resp") as HTMLSelectElement).value,
      ownerPersonId: ($("cm-d-owner") as HTMLSelectElement).value,
      targetDate: ($("cm-d-target") as HTMLInputElement).value,
      narrative: ($("cm-d-narr") as HTMLTextAreaElement).value,
      assessmentResult: ($("cm-d-aresult") as HTMLSelectElement).value,
      assessedDate: ($("cm-d-adate") as HTMLInputElement).value,
      assessorPersonId: ($("cm-d-assessor") as HTMLSelectElement).value,
      assessmentRemarks: ($("cm-d-aremarks") as HTMLTextAreaElement).value,
    };
    const r = await fetch("/api/control-management/implementation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeDetail(); await load(); toast("✅ Control updated");
  } catch (e) { $("cm-d-err").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

// ── POA&M create ────────────────────────────────────────────────────────────────
function openPoamCreate(controlId: number | null): void {
  const ctrlOpts = [`<option value="">— none —</option>`].concat(
    (DATA?.controls || []).map((c) => `<option value="${c.id}">${esc(c.ref)} — ${esc(c.title)}</option>`)).join("");
  const sel = $("cm-p-control") as HTMLSelectElement; sel.innerHTML = ctrlOpts; sel.value = controlId != null ? String(controlId) : "";
  ($("cm-p-sev") as HTMLSelectElement).innerHTML = [`<option value="">—</option>`].concat((DATA?.poamSeverities || []).map((x) => `<option>${esc(x)}</option>`)).join("");
  ($("cm-p-status") as HTMLSelectElement).innerHTML = (DATA?.poamStatuses || []).map((x) => `<option${x === "Open" ? " selected" : ""}>${esc(x)}</option>`).join("");
  ($("cm-p-owner") as HTMLSelectElement).innerHTML = [`<option value="">—</option>`].concat((DATA?.persons || []).map((p) => `<option value="${p.id}">${esc(p.name)}</option>`)).join("");
  for (const id of ["cm-p-title", "cm-p-sched"]) ($(id) as HTMLInputElement).value = "";
  for (const id of ["cm-p-weak", "cm-p-plan", "cm-p-miles"]) ($(id) as HTMLTextAreaElement).value = "";
  $("cm-p-err").textContent = "";
  $("cm-poam-modal").classList.add("open");
  ($("cm-p-title") as HTMLInputElement).focus();
}
function closePoam(): void { $("cm-poam-modal").classList.remove("open"); }
async function savePoam(): Promise<void> {
  const title = ($("cm-p-title") as HTMLInputElement).value.trim();
  const err = $("cm-p-err"); if (!title) { err.textContent = "⚠️ Enter a title."; return; }
  const btn = $("cm-p-save") as HTMLButtonElement; btn.disabled = true; err.textContent = "Creating…";
  try {
    const body = {
      title, controlId: ($("cm-p-control") as HTMLSelectElement).value || null,
      severity: ($("cm-p-sev") as HTMLSelectElement).value || undefined,
      status: ($("cm-p-status") as HTMLSelectElement).value || undefined,
      ownerPersonId: ($("cm-p-owner") as HTMLSelectElement).value || null,
      scheduledCompletionDate: ($("cm-p-sched") as HTMLInputElement).value || undefined,
      weaknessDescription: ($("cm-p-weak") as HTMLTextAreaElement).value || undefined,
      remediationPlan: ($("cm-p-plan") as HTMLTextAreaElement).value || undefined,
      milestones: ($("cm-p-miles") as HTMLTextAreaElement).value || undefined,
    };
    const r = await fetch("/api/control-management/poam", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closePoam(); await load(); toast("✅ POA&M created");
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}
async function updatePoam(poamId: number, patch: Record<string, unknown>): Promise<void> {
  try {
    const r = await fetch("/api/control-management/poam/update", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ poamId, ...patch }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load(); toast("✅ POA&M updated");
  } catch (e) { toast(`⚠️ ${e}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  $("cm-d-cancel").addEventListener("click", closeDetail);
  $("cm-d-save").addEventListener("click", () => void saveDetail());
  $("cm-d-poam").addEventListener("click", () => { if (DETAIL_ID) { closeDetail(); openPoamCreate(DETAIL_ID); } });
  $("cm-modal").addEventListener("click", (e) => { if (e.target === $("cm-modal")) closeDetail(); });
  $("cm-p-cancel").addEventListener("click", closePoam);
  $("cm-p-save").addEventListener("click", () => void savePoam());
  $("cm-poam-modal").addEventListener("click", (e) => { if (e.target === $("cm-poam-modal")) closePoam(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDetail(); closePoam(); } });
  void load();
});
