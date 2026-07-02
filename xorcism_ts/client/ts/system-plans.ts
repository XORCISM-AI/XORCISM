/**
 * system-plans.ts — System Plans cockpit (/system-plans), NIST SP 800-18r2.
 * List/create plans (Security/Privacy/C-SCRM/Consolidated); per-plan view = editable header,
 * the 7-step RMF journey stepper, the 21 plan elements grouped by RMF step (each with its RMF-task
 * mapping, status, content, control refs + AI draft), completeness, and OSCAL/Markdown export.
 * All from /api/system-plans*.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
// i18n: session-ui exposes the translator as window.t; fall back to the English default.
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
function translateChrome(): void {
  document.querySelectorAll<HTMLElement>("[data-t]").forEach((el) => { el.textContent = t(el.getAttribute("data-t")!, (el.textContent || "").trim()); });
}
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function send(method: string, u: string, b?: any): Promise<any> { const r = await fetch(u, { method, credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: b ? JSON.stringify(b) : undefined }); return r.json().catch(() => ({})); }

let META: any = { planTypes: [], rmfSteps: [], impactLevels: [], operationalStatus: [] };
const catCls = (c: string): string => `cat-${(c || "").toLowerCase()}`;
const opts = (arr: any[], sel: string, kv?: (x: any) => [string, string]): string =>
  arr.map((o) => { const [v, l] = kv ? kv(o) : [o, o]; return `<option value="${esc(v)}"${sel === v ? " selected" : ""}>${esc(l)}</option>`; }).join("");
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => (el.className = ""), 2000); }

// ── List view ─────────────────────────────────────────────────────────────────
async function load(): Promise<void> {
  try { META = await getJSON("/api/system-plans/meta"); } catch { /* meta optional */ }
  let plans: any[] = [];
  try { plans = (await getJSON("/api/system-plans")).plans || []; }
  catch (e) { $("sp-body").innerHTML = `<div class="muted" style="padding:20px">${t("sp.failLoad", "Failed to load")}: ${esc(String(e))}</div>`; return; }
  const rows = plans.map((p) => {
    const typeLabel = (META.planTypes.find((x: any) => x.key === p.PlanType) || {}).label || p.PlanType;
    return `<tr>
      <td><a href="#" data-open="${p.PlanID}" style="color:#a5b4fc;text-decoration:none;font-weight:600">${esc(p.Name)}</a><div class="muted" style="font-size:11px">${esc(p.SystemIdentifier)}</div></td>
      <td><span class="tag type">${esc(typeLabel)}</span></td>
      <td>${p.OverallCategorization ? `<span class="tag ${catCls(p.OverallCategorization)}">${esc(String(p.OverallCategorization).toUpperCase())}</span>` : "<span class='muted'>—</span>"}</td>
      <td><span class="tag">${esc(p.CurrentRmfStep)}</span></td>
      <td><span class="bar"><i style="width:${p.completeness}%"></i></span> <span class="muted" style="font-size:11px">${p.completeness}%</span></td>
      <td style="white-space:nowrap">
        <button class="sp-btn sm" data-open="${p.PlanID}">${t("sp.open", "Open")}</button>
        <button class="sp-btn sm" data-oscal="${p.PlanID}" title="OSCAL SSP">OSCAL</button>
        <button class="sp-btn sm" data-md="${p.PlanID}" title="Markdown">MD</button>
        <button class="sp-btn sm" data-del="${p.PlanID}" title="${t("sp.delete", "Delete")}">✕</button>
      </td></tr>`;
  }).join("") || `<tr><td colspan="6" class="muted">${t("sp.empty", "No system plans yet. Create one — it seeds the 21 SP 800-18r2 elements across the 7 RMF steps.")}</td></tr>`;

  $("sp-body").innerHTML = `
    <div style="display:flex;align-items:center;margin-bottom:10px">
      <div class="muted" style="font-size:12px">${plans.length} ${t("sp.plans", "plan(s)")}</div>
      <span style="flex:1"></span>
      <button class="sp-btn pri" id="sp-new">＋ ${t("sp.newPlan", "New system plan")}</button>
    </div>
    <table class="sp"><thead><tr>
      <th>${t("sp.h.system", "System / identifier")}</th><th>${t("sp.h.type", "Plan type")}</th><th>${t("sp.h.cat", "Categorization")}</th>
      <th>${t("sp.h.step", "RMF step")}</th><th>${t("sp.h.complete", "Completeness")}</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table>`;

  $("sp-new").onclick = openCreate;
  document.querySelectorAll<HTMLElement>("[data-open]").forEach((el) => el.onclick = (e) => { e.preventDefault(); openPlan(Number(el.dataset.open)); });
  document.querySelectorAll<HTMLElement>("[data-oscal]").forEach((el) => el.onclick = () => window.open(`/api/system-plans/${el.dataset.oscal}/oscal`, "_blank"));
  document.querySelectorAll<HTMLElement>("[data-md]").forEach((el) => el.onclick = () => window.open(`/api/system-plans/${el.dataset.md}/markdown`, "_blank"));
  document.querySelectorAll<HTMLElement>("[data-del]").forEach((el) => el.onclick = async () => { if (!confirm(t("sp.delConfirm", "Delete this system plan and all its elements?"))) return; await send("DELETE", `/api/system-plans/${el.dataset.del}`); load(); });
}

// ── Create modal ──────────────────────────────────────────────────────────────
function closeModal(): void { $("sp-modal").classList.remove("on"); }
function openCreate(): void {
  const impacts = META.impactLevels.length ? META.impactLevels : ["low", "moderate", "high"];
  $("sp-modal-inner").innerHTML = `
    <h2>＋ ${t("sp.newPlan", "New system plan")}</h2>
    <div class="fld"><label>${t("sp.f.name", "System name")} *</label><input id="c-name" placeholder="e.g. Customer Portal"></div>
    <div class="grid2">
      <div class="fld"><label>${t("sp.f.type", "Plan type")}</label><select id="c-type">${opts(META.planTypes, "security", (x: any) => [x.key, x.label])}</select></div>
      <div class="fld"><label>${t("sp.f.id", "System identifier")}</label><input id="c-id" placeholder="${t("sp.f.idPh", "auto if blank")}"></div>
    </div>
    <div class="fld"><label>${t("sp.f.systype", "System type")}</label><input id="c-stype" placeholder="e.g. Major application (cloud PaaS)"></div>
    <div class="fld"><label>${t("sp.f.overview", "System overview")}</label><textarea id="c-ov" rows="2" placeholder="${t("sp.f.overviewPh", "Mission / business functions the system supports")}"></textarea></div>
    <div class="grid2">
      <div class="fld"><label>${t("sp.f.ao", "Authorizing official")}</label><input id="c-ao"></div>
      <div class="fld"><label>${t("sp.f.owner", "System owner")}</label><input id="c-owner"></div>
    </div>
    <div class="grid3">
      <div class="fld"><label>${t("sp.f.conf", "Confidentiality")}</label><select id="c-ci"><option value="">—</option>${opts(impacts, "")}</select></div>
      <div class="fld"><label>${t("sp.f.integ", "Integrity")}</label><select id="c-ii"><option value="">—</option>${opts(impacts, "")}</select></div>
      <div class="fld"><label>${t("sp.f.avail", "Availability")}</label><select id="c-ai"><option value="">—</option>${opts(impacts, "")}</select></div>
    </div>
    <div class="fld"><label>${t("sp.f.asset", "System asset ID (optional)")}</label><input id="c-asset" placeholder="ASSET.AssetID"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
      <button class="sp-btn" id="c-cancel">${t("sp.cancel", "Cancel")}</button>
      <button class="sp-btn pri" id="c-save">${t("sp.create", "Create plan")}</button>
    </div>`;
  $("sp-modal").classList.add("on");
  $("c-cancel").onclick = closeModal;
  $("c-save").onclick = async () => {
    const name = ($("c-name") as HTMLInputElement).value.trim(); if (!name) { toast(t("sp.nameReq", "System name required")); return; }
    const v = (id: string) => ($(id) as HTMLInputElement).value.trim();
    const r = await send("POST", "/api/system-plans", {
      name, planType: v("c-type"), systemIdentifier: v("c-id") || undefined, systemType: v("c-stype"), systemOverview: v("c-ov"),
      authorizingOfficial: v("c-ao"), systemOwner: v("c-owner"), confImpact: v("c-ci"), integImpact: v("c-ii"), availImpact: v("c-ai"),
      assetId: v("c-asset") ? Number(v("c-asset")) : undefined,
    });
    closeModal();
    if (r && r.planId) openPlan(r.planId); else load();
  };
}

// ── Plan view ─────────────────────────────────────────────────────────────────
async function openPlan(id: number): Promise<void> {
  let d: any;
  try { d = await getJSON(`/api/system-plans/${id}`); } catch (e) { toast(String(e)); return; }
  const p = d.plan;
  const impacts = META.impactLevels.length ? META.impactLevels : ["low", "moderate", "high"];
  const opStatus = META.operationalStatus.length ? META.operationalStatus : ["under-development", "operational", "disposition"];
  const patch = async (body: any) => { await send("PATCH", `/api/system-plans/${id}`, body); };

  const steps = d.journey.map((s: any) => `
    <div class="step${s.active ? " active" : ""}" data-step="${s.key}" title="${esc(s.desc)}">
      <div class="o">${t("sp.rmf", "RMF")} ${s.order}</div><div class="n">${esc(s.label)}</div>
      <div class="p">${s.done}/${s.total} · ${s.pct}%</div><div class="sbar"><i style="width:${s.pct}%"></i></div>
    </div>`).join("");

  const sectionsHtml = d.journey.map((s: any) => {
    const els = d.elements.filter((e: any) => e.RmfStep === s.key);
    if (!els.length) return "";
    return `<div class="stepsec">${s.order}. ${esc(s.label)}</div>` + els.map((e: any) => elementCard(e)).join("");
  }).join("");

  $("sp-body").innerHTML = `
    <div style="margin-bottom:8px"><a href="#" id="sp-back" style="color:#94a3b8;text-decoration:none">&#8592; ${t("sp.allPlans", "All plans")}</a></div>
    <div class="sp-hero">
      <div class="sp-score">${d.completeness}%</div>
      <div style="flex:1;min-width:240px">
        <div style="font-size:17px;font-weight:700;color:#e7ebf3">${esc(p.Name)} <span class="tag type">${esc((META.planTypes.find((x: any) => x.key === p.PlanType) || {}).label || p.PlanType)}</span></div>
        <div class="muted" style="font-size:12px">${esc(p.SystemIdentifier)}${p.AssetName ? ` · ${esc(p.AssetName)}` : ""} · ${t("sp.overall", "overall")} ${p.OverallCategorization ? `<b style="color:#e2e8f0">${esc(String(p.OverallCategorization).toUpperCase())}</b>` : "—"}</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="sp-btn" id="sp-oscal">⬇ OSCAL SSP</button>
        <button class="sp-btn" id="sp-md">⬇ Markdown</button>
      </div>
    </div>

    <div class="hdr-grid">
      <div class="fld"><label>${t("sp.f.type", "Plan type")}</label><select id="h-type">${opts(META.planTypes, p.PlanType, (x: any) => [x.key, x.label])}</select></div>
      <div class="fld"><label>${t("sp.f.id", "System identifier")}</label><input class="in" id="h-id" value="${esc(p.SystemIdentifier)}"></div>
      <div class="fld"><label>${t("sp.f.opstatus", "Operational status")}</label><select id="h-op">${opts(opStatus, p.OperationalStatus)}</select></div>
      <div class="fld"><label>${t("sp.f.step", "Current RMF step")}</label><select id="h-step">${opts(META.rmfSteps, p.CurrentRmfStep, (x: any) => [x.key, x.label])}</select></div>
      <div class="fld"><label>${t("sp.f.conf", "Confidentiality")}</label><select id="h-ci"><option value="">—</option>${opts(impacts, (p.ConfImpact || ""))}</select></div>
      <div class="fld"><label>${t("sp.f.integ", "Integrity")}</label><select id="h-ii"><option value="">—</option>${opts(impacts, (p.IntegImpact || ""))}</select></div>
      <div class="fld"><label>${t("sp.f.avail", "Availability")}</label><select id="h-ai"><option value="">—</option>${opts(impacts, (p.AvailImpact || ""))}</select></div>
      <div class="fld"><label>${t("sp.f.ao", "Authorizing official")}</label><input class="in" id="h-ao" value="${esc(p.AuthorizingOfficial || "")}"></div>
      <div class="fld"><label>${t("sp.f.owner", "System owner")}</label><input class="in" id="h-owner" value="${esc(p.SystemOwner || "")}"></div>
      <div class="fld"><label>${t("sp.f.authdec", "Authorization decision")}</label><input class="in" id="h-dec" value="${esc(p.AuthorizationDecision || "")}" placeholder="ATO / ATO w/ conditions / Denial"></div>
    </div>

    <div class="steps">${steps}</div>
    <div>${sectionsHtml}</div>`;

  $("sp-back").onclick = (e) => { e.preventDefault(); load(); };
  $("sp-oscal").onclick = () => window.open(`/api/system-plans/${id}/oscal`, "_blank");
  $("sp-md").onclick = () => window.open(`/api/system-plans/${id}/markdown`, "_blank");
  // Header field auto-save
  const hInput = (id2: string, field: string) => { const el = $(id2) as HTMLInputElement | HTMLSelectElement; el.onchange = async () => { await patch({ [field]: el.value }); if (["planType", "confImpact", "integImpact", "availImpact"].includes(field)) openPlan(id); }; };
  hInput("h-type", "planType"); hInput("h-id", "systemIdentifier"); hInput("h-op", "operationalStatus"); hInput("h-step", "currentRmfStep");
  hInput("h-ci", "confImpact"); hInput("h-ii", "integImpact"); hInput("h-ai", "availImpact");
  hInput("h-ao", "authorizingOfficial"); hInput("h-owner", "systemOwner"); hInput("h-dec", "authorizationDecision");
  // Clicking a journey step sets the current RMF step
  document.querySelectorAll<HTMLElement>("[data-step]").forEach((el) => el.onclick = async () => { await patch({ currentRmfStep: el.dataset.step }); openPlan(id); });
  // Element wiring
  d.elements.forEach((e: any) => wireElement(id, e));
}

function elementCard(e: any): string {
  const statusSel = ["todo", "in-progress", "complete", "na"];
  return `<div class="el" data-el="${e.ElementID}">
    <div class="top">
      <span class="title">${esc(e.Title)}</span>
      ${e.Optional ? `<span class="tag">${t("sp.optional", "optional")}</span>` : ""}
      <span class="rmf" title="${t("sp.rmfMap", "Source RMF task(s)")}">RMF: ${esc(e.RmfTasks)}</span>
      <span style="flex:1"></span>
      <select data-status="${e.ElementID}" class="st-${esc(e.Status)}">${opts(statusSel, e.Status, (s: string) => [s, t("sp.status." + s, s)])}</select>
    </div>
    <div class="ov">${esc(e.Overview)}</div>
    <textarea data-content="${e.ElementID}" placeholder="${t("sp.contentPh", "Document this element…")}">${esc(e.Content || "")}</textarea>
    ${e.ElementKey === "control-impl-details" ? `<div class="row"><label class="muted" style="font-size:11px">${t("sp.controls", "SP 800-53 controls")}</label><input class="in" style="flex:1" data-ctl="${e.ElementID}" value="${esc(e.ControlRefs || "")}" placeholder="AC-2, AU-2, SC-7…"></div>` : ""}
    <div class="row">
      <button class="sp-btn sm" data-draft="${e.ElementID}">🤖 ${t("sp.aiDraft", "AI draft")}</button>
      <button class="sp-btn sm pri" data-save="${e.ElementID}">${t("sp.save", "Save")}</button>
      <span class="muted" style="font-size:11px" data-saved="${e.ElementID}"></span>
    </div>
  </div>`;
}

function wireElement(planId: number, e: any): void {
  const eid = e.ElementID;
  const contentEl = document.querySelector(`[data-content="${eid}"]`) as HTMLTextAreaElement | null;
  const ctlEl = document.querySelector(`[data-ctl="${eid}"]`) as HTMLInputElement | null;
  const statusEl = document.querySelector(`[data-status="${eid}"]`) as HTMLSelectElement | null;
  const savedEl = document.querySelector(`[data-saved="${eid}"]`) as HTMLElement | null;
  const doSave = async () => {
    await send("PATCH", `/api/system-plans/${planId}/element/${eid}`, {
      content: contentEl?.value ?? undefined, status: statusEl?.value ?? undefined, controlRefs: ctlEl ? ctlEl.value : undefined,
    });
    if (savedEl) { savedEl.textContent = "✓ " + t("sp.savedAt", "saved"); setTimeout(() => (savedEl.textContent = ""), 1500); }
  };
  (document.querySelector(`[data-save="${eid}"]`) as HTMLElement).onclick = doSave;
  if (statusEl) statusEl.onchange = () => { statusEl.className = "st-" + statusEl.value; doSave(); };
  (document.querySelector(`[data-draft="${eid}"]`) as HTMLElement).onclick = async () => {
    const btn = document.querySelector(`[data-draft="${eid}"]`) as HTMLButtonElement; btn.disabled = true; btn.textContent = "…";
    try {
      const r = await send("POST", `/api/system-plans/${planId}/element/${eid}/draft`);
      if (r && r.draft && contentEl) { contentEl.value = r.draft; toast(r.offline ? t("sp.draftOffline", "Offline draft inserted") : `${t("sp.draftAi", "AI draft inserted")} (${r.model})`); }
    } finally { btn.disabled = false; btn.textContent = "🤖 " + t("sp.aiDraft", "AI draft"); }
  };
}

document.addEventListener("DOMContentLoaded", () => { translateChrome(); load(); });
