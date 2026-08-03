/**
 * ai-risk-loop.ts — Operational AI Risk Management loop cockpit (/ai-risk-loop).
 * IDENTIFY → ASSESS → MITIGATE → MONITOR with a detail panel showing the full traceability chain
 * (AI System → Context → Risk → Assessment → Control → Owner → Evidence → Monitoring → Decision).
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void { const el = $("toast"); el.textContent = msg; el.className = ok ? "toast-ok" : "toast-err"; el.style.opacity = "1"; setTimeout(() => (el.style.opacity = "0"), 2400); }
function opt(v: string, cur: string): string { return `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(v)}</option>`; }

const j = (o: unknown): string => JSON.stringify(o);
async function api(url: string, method = "GET", body?: unknown): Promise<any> {
  const r = await fetch(url, method === "GET" ? {} : { method, headers: { "Content-Type": "application/json" }, body: body ? j(body) : undefined });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.status === 204 ? {} : r.json();
}

interface Ctl { linkId: number; controlRef: string; controlName: string; controlOwner: string; designEffective: string; operatingEffective: string; evidenceRef: string | null; notes: string | null }
interface Kri { kriId: number; name: string; metric: string; threshold: number | null; direction: string; currentValue: number | null; action: string | null; lastChecked: string | null; breached: boolean }
interface Log { logId: number; kind: string; detail: string; createdDate: string }
interface Ev { evId: number; linkId: number | null; sha256: string; filename: string; size: number; contentType: string | null; title: string | null; createdDate: string }
const fmtSize = (n: number): string => (n < 1024 ? n + " B" : n < 1048576 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB");
interface Risk {
  riskId: number; aiSystemId: number | null; systemName: string; title: string; riskArea: string; description: string;
  context: Record<string, string>; lifecyclePhase: string; owner: string; stage: string; status: string;
  inherentLikelihood: number | null; inherentImpact: number | null; inherentScore: number; inherentBand: string;
  residualLikelihood: number | null; residualImpact: number | null; residualScore: number; residualBand: string;
  factors: Record<string, string>; treatment: string; acceptanceBy: string | null; acceptanceDate: string | null; acceptanceRationale: string | null;
  controls: Ctl[]; kris: Kri[]; log: Log[]; evidence: Ev[];
}
interface Loop {
  risks: Risk[]; systems: { id: number; name: string; riskTier: string }[];
  controls: { ref: string; name: string; owner: string; evidence: string; riskDomains: string[] }[];
  vocab: Record<string, string[]>;
  summary: { total: number; highCritResidual: number; unowned: number; controlsNoEvidence: number; kriBreaches: number; overdueMonitor: number; monitored: number; accepted: number; avgResidual: number; byStage: Record<string, number>; failurePatterns: { id: string; label: string; count: number }[] };
}

let DATA: Loop;
const STAGE_DESC: Record<string, string> = { identify: "Know what can go wrong", assess: "Significance, not just existence", mitigate: "Turn decisions into controls", monitor: "Because AI risk changes" };
const bnd = (b: string): string => `<span class="bnd ${b}">${b}</span>`;
const scoreOf = (l: number | null, i: number | null): number => (l && i ? l * i : 0);

async function load(): Promise<void> {
  try { DATA = await api("/api/ai-risk-loop"); }
  catch (e) { $("rl-table").innerHTML = `<div style="color:#64748b">${t("rl.loadFail")}: ${esc(e)}</div>`; return; }
  const s = DATA.summary;

  // loop strip
  const stages = DATA.vocab.stages;
  $("rl-loop").innerHTML = stages.map((st, i) =>
    `<div class="lstage${i === stages.length - 1 ? " loopback" : ""}"><div class="n">${String(i + 1)}. ${esc(st)}</div>` +
    `<div class="c">${s.byStage[st] || 0}</div><div class="d">${esc(t("rl.stage." + st, STAGE_DESC[st]))}</div>` +
    `${i < stages.length - 1 ? '<span class="arrow">→</span>' : '<span class="arrow" style="color:#14532d">↺</span>'}</div>`).join("");

  $("rl-kpis").innerHTML = [
    ["total", s.total, "#e2e8f0"], ["highcrit", s.highCritResidual, s.highCritResidual ? "#fca5a5" : "#6ee7b7"],
    ["kribreach", s.kriBreaches, s.kriBreaches ? "#fca5a5" : "#6ee7b7"], ["unowned", s.unowned, s.unowned ? "#fca5a5" : "#6ee7b7"],
    ["noevidence", s.controlsNoEvidence, s.controlsNoEvidence ? "#fcd34d" : "#6ee7b7"], ["monitored", s.monitored, "#c4b5fd"],
    ["avgres", s.avgResidual, "#c4b5fd"],
  ].map(([k, v, c]) => `<div class="kpi"><div class="v" style="color:${c}">${v}</div><div class="l">${t("rl.kpi." + k)}</div></div>`).join("");

  $("rl-fail").innerHTML = s.failurePatterns.length
    ? s.failurePatterns.map((f) => `<span class="chip">⚠ ${esc(f.label)} · ${f.count}</span>`).join("")
    : `<span class="chip ok">✓ ${t("rl.noFail")}</span>`;

  // table
  const head = `<tr><th>${t("rl.col.system")}</th><th>${t("rl.col.risk")}</th><th>${t("rl.col.area")}</th><th>${t("rl.col.inherent")}</th><th>${t("rl.col.residual")}</th><th>${t("rl.col.treatment")}</th><th>${t("rl.col.owner")}</th><th>${t("rl.col.controls")}</th><th>${t("rl.col.kri")}</th><th>${t("rl.col.stage")}</th></tr>`;
  const rows = DATA.risks.map((r) => {
    const brk = r.kris.some((k) => k.breached);
    const evOk = r.controls.length && r.controls.every((c) => c.evidenceRef);
    return `<tr class="rrow" data-id="${r.riskId}">` +
      `<td>${esc(r.systemName)}</td><td style="font-weight:600;color:#e7ebf3">${esc(r.title)}</td><td>${esc(r.riskArea)}</td>` +
      `<td>${bnd(r.inherentBand)} ${r.inherentScore || ""}</td><td>${bnd(r.residualBand)} ${r.residualScore || ""}</td>` +
      `<td>${r.treatment ? `<span class="pill">${esc(r.treatment)}</span>` : "—"}</td>` +
      `<td>${r.owner ? esc(r.owner) : `<span class="brk">${t("rl.none")}</span>`}</td>` +
      `<td>${r.controls.length}${evOk ? " ✓" : r.controls.length ? " ⚠" : ""}</td>` +
      `<td>${r.kris.length}${brk ? ` <span class="brk">⚠${t("rl.breach")}</span>` : ""}</td>` +
      `<td><span class="pill">${esc(r.stage)}</span></td></tr>`;
  }).join("");
  $("rl-table").innerHTML = DATA.risks.length ? `<table class="rl"><thead>${head}</thead><tbody>${rows}</tbody></table>` : `<div style="color:#64748b">${t("rl.empty")}</div>`;
  $("rl-table").querySelectorAll<HTMLElement>("tr.rrow").forEach((tr) => tr.addEventListener("click", () => openDetail(Number(tr.dataset.id))));

  fillForm();
}

function fillForm(): void {
  const sysSel = `<option value="">—</option>` + DATA.systems.map((x) => `<option value="${x.id}">${esc(x.name)}</option>`).join("");
  ($("f-system") as HTMLSelectElement).innerHTML = sysSel;
  ($("f-area") as HTMLSelectElement).innerHTML = DATA.vocab.areas.map((a) => `<option>${esc(a)}</option>`).join("");
  ($("f-lifecycle") as HTMLSelectElement).innerHTML = DATA.vocab.lifecycle.map((a) => `<option>${esc(a)}</option>`).join("");
  ($("f-owner") as HTMLSelectElement).innerHTML = `<option value="">—</option>` + DATA.vocab.owners.map((a) => `<option>${esc(a)}</option>`).join("");
}

// ── Detail panel (traceability + edit) ───────────────────────────────────────────────────────
let CUR: Risk | null = null;
function closeDetail(): void { $("detail").style.display = "none"; $("backdrop").style.display = "none"; CUR = null; }
async function refreshDetail(id: number): Promise<void> { CUR = await api(`/api/ai-risk-loop/${id}`); renderDetail(); }

async function openDetail(id: number): Promise<void> {
  try { CUR = await api(`/api/ai-risk-loop/${id}`); } catch (e) { toast(String(e), false); return; }
  $("backdrop").style.display = "block"; $("detail").style.display = "block"; renderDetail();
}

function ctlLibOptions(): string {
  return `<option value="">${t("rl.d.pickControl")}</option>` + DATA.controls.map((c) => `<option value="${esc(c.ref)}" data-name="${esc(c.name)}" data-owner="${esc(c.owner)}">${esc(c.ref)} — ${esc(c.name)}</option>`).join("");
}

function renderDetail(): void {
  const r = CUR!; const v = DATA.vocab;
  const kv = (k: string, val: string): string => val ? `<div class="kv"><b>${esc(k)}:</b> ${esc(val)}</div>` : "";
  const eff = v.effectiveness;
  const accepted = r.treatment === "accept" || r.status === "accepted";
  $("detail").innerHTML = `
    <button class="close-x" id="d-close">✕</button>
    <h2>${esc(r.title)}</h2>
    <div style="font-size:11.5px;color:#94a3b8">${esc(r.systemName)} · ${esc(r.riskArea)} · ${esc(r.lifecyclePhase)}</div>
    <div class="trace">${["AI System", "Context", "Risk", "Assessment", "Control", "Owner", "Evidence", "Monitoring", "Decision"].map((x) => `<b>${x}</b>`).join(" <span>→</span> ")}</div>

    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
      <label style="font-size:11px;color:#94a3b8">${t("rl.d.stage")}</label><select class="mini" id="d-stage">${v.stages.map((x) => opt(x, r.stage)).join("")}</select>
      <label style="font-size:11px;color:#94a3b8">${t("rl.d.status")}</label><select class="mini" id="d-status">${v.statuses.map((x) => opt(x, r.status)).join("")}</select>
      <label style="font-size:11px;color:#94a3b8">${t("rl.d.owner")}</label><select class="mini" id="d-owner"><option value="">—</option>${v.owners.map((x) => opt(x, r.owner)).join("")}</select>
      <button class="btn-ai btn-sm" id="d-del" style="margin-left:auto;color:#fca5a5">${t("rl.d.delete")}</button>
    </div>

    <div class="dsect"><h4>① ${t("rl.d.identify")}</h4>
      <div class="kv">${esc(r.description)}</div>
      ${kv(t("rl.f.purpose"), r.context.purpose || "")}${kv(t("rl.f.data"), r.context.data || "")}
      ${kv(t("rl.f.deps"), r.context.dependencies || r.context.deps || "")}${kv(t("rl.f.oblig"), r.context.obligations || r.context.oblig || "")}
      ${kv("Affected", r.context.affected || "")}${kv("Actors", r.context.actors || "")}
    </div>

    <div class="dsect"><h4>② ${t("rl.d.assess")}</h4>
      <div style="display:flex;gap:14px;flex-wrap:wrap">
        <div><div class="kv"><b>${t("rl.d.inherent")}</b> ${bnd(r.inherentBand)} <span id="d-iscore">${r.inherentScore || ""}</span></div>
          L <select class="mini di" data-f="inherentLikelihood">${[1,2,3,4,5].map((n) => opt(String(n), String(r.inherentLikelihood || ""))).join("")}</select>
          × I <select class="mini di" data-f="inherentImpact">${[1,2,3,4,5].map((n) => opt(String(n), String(r.inherentImpact || ""))).join("")}</select></div>
        <div><div class="kv"><b>${t("rl.d.residual")}</b> ${bnd(r.residualBand)} <span id="d-rscore">${r.residualScore || ""}</span></div>
          L <select class="mini di" data-f="residualLikelihood">${[1,2,3,4,5].map((n) => opt(String(n), String(r.residualLikelihood || ""))).join("")}</select>
          × I <select class="mini di" data-f="residualImpact">${[1,2,3,4,5].map((n) => opt(String(n), String(r.residualImpact || ""))).join("")}</select></div>
      </div>
      <div class="kv" style="margin-top:6px"><b>${t("rl.d.factors")}:</b> ${["severity", "reversibility", "autonomy", "humanOversight", "dataSensitivity", "thirdParty", "regulatory"].map((f) => r.factors[f] ? `${f}=${esc(r.factors[f])}` : "").filter(Boolean).join(" · ") || "—"}</div>
    </div>

    <div class="dsect"><h4>③ ${t("rl.d.mitigate")}</h4>
      <div style="margin-bottom:6px"><label style="font-size:11px;color:#94a3b8">${t("rl.d.treatment")}</label>
        <select class="mini" id="d-treatment"><option value="">—</option>${v.treatments.map((x) => opt(x, r.treatment)).join("")}</select></div>
      ${r.controls.map((c) => `<div class="ctl-item" data-link="${c.linkId}">
        <div style="display:flex;justify-content:space-between"><b>${esc(c.controlRef)} — ${esc(c.controlName)}</b><span class="close-x" style="position:static;font-size:14px" data-unlink="${c.linkId}">✕</span></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;align-items:center">
          ${t("rl.d.design")} <select class="mini ce" data-link="${c.linkId}" data-k="designEffective">${eff.map((x) => opt(x, c.designEffective)).join("")}</select>
          ${t("rl.d.operating")} <select class="mini ce" data-link="${c.linkId}" data-k="operatingEffective">${eff.map((x) => opt(x, c.operatingEffective)).join("")}</select>
          ${t("rl.d.evidence")} <input class="mini cev" data-link="${c.linkId}" value="${esc(c.evidenceRef || "")}" style="width:150px" placeholder="log / report ref">
        </div></div>`).join("")}
      <div style="display:flex;gap:6px;margin-top:4px"><select class="mini" id="d-ctl-pick" style="flex:1">${ctlLibOptions()}</select><button class="btn-ai btn-sm" id="d-ctl-add">＋</button></div>
      ${accepted ? `<div class="dsect" style="border:none;margin-top:8px"><h4>${t("rl.d.decision")}</h4>
        <div class="row"><div class="fld"><label>${t("rl.d.acceptBy")}</label><input class="mini" id="d-acc-by" value="${esc(r.acceptanceBy || "")}"></div>
        <div class="fld"><label>${t("rl.d.acceptDate")}</label><input class="mini" id="d-acc-date" type="date" value="${esc(r.acceptanceDate || "")}"></div></div>
        <div class="fld"><label>${t("rl.d.rationale")}</label><input class="mini" id="d-acc-rat" value="${esc(r.acceptanceRationale || "")}" placeholder="Why the residual risk is acceptable"></div>
        <button class="btn-ai btn-sm" id="d-acc-save" style="margin-top:6px">${t("rl.save")}</button></div>` : ""}
    </div>

    <div class="dsect"><h4>④ ${t("rl.d.monitor")}</h4>
      ${r.kris.map((k) => `<div class="kri-item">
        <div style="display:flex;justify-content:space-between"><b>${esc(k.name)}</b><span class="close-x" style="position:static;font-size:14px" data-delkri="${k.kriId}">✕</span></div>
        <div class="kv">${esc(k.metric)} · ${t("rl.d.threshold")} ${esc(k.direction)} ${k.threshold ?? "—"} ${k.breached ? `<span class="brk">⚠ ${t("rl.breach")}</span>` : ""}</div>
        <div style="margin-top:3px">${t("rl.d.current")} <input class="mini kv-cur" data-kri="${k.kriId}" type="number" step="any" value="${k.currentValue ?? ""}" style="width:80px"></div>
        ${k.action ? `<div class="kv" style="color:#94a3b8">↳ ${esc(k.action)}</div>` : ""}</div>`).join("")}
      <div class="row" style="margin-top:4px"><input class="mini" id="k-name" placeholder="${t("rl.d.kriName")}"><input class="mini" id="k-metric" placeholder="metric"><input class="mini" id="k-thr" type="number" step="any" placeholder="threshold" style="width:90px"><select class="mini" id="k-dir">${v.kriDirection.map((x) => `<option>${x}</option>`).join("")}</select></div>
      <input class="mini" id="k-action" placeholder="${t("rl.d.kriAction")}" style="width:100%;margin-bottom:6px"><button class="btn-ai btn-sm" id="k-add">＋ ${t("rl.d.addKri")}</button>
    </div>

    <div class="dsect"><h4>${t("rl.d.evTitle")}</h4>
      ${r.evidence.map((e) => `<div class="log-item" style="display:flex;justify-content:space-between;align-items:center">
        <span>📎 <a href="/api/blob/${esc(e.sha256)}" download="${esc(e.filename)}" style="color:#93c5fd">${esc(e.filename)}</a> <span style="color:#64748b">${fmtSize(e.size)}${e.linkId ? " · control" : ""}</span></span>
        <span class="close-x" style="position:static;font-size:14px" data-delev="${e.evId}">✕</span></div>`).join("") || `<div style="font-size:11px;color:#64748b">${t("rl.d.noEvidence")}</div>`}
      <div style="display:flex;gap:6px;margin-top:6px;align-items:center"><input type="file" id="ev-file" style="font-size:11px;color:#94a3b8"><button class="btn-ai btn-sm" id="ev-up">${t("rl.d.upload")}</button></div>
      <div style="font-size:10.5px;color:#64748b;margin-top:4px">${t("rl.d.evNote")}</div>
    </div>

    <div class="dsect"><h4>↺ ${t("rl.d.loop")}</h4>
      <div style="display:flex;gap:6px;margin-bottom:6px"><select class="mini" id="e-kind">${v.logKinds.map((x) => `<option>${esc(x)}</option>`).join("")}</select><input class="mini" id="e-detail" placeholder="${t("rl.d.finding")}" style="flex:1"><button class="btn-ai btn-sm" id="e-add">${t("rl.d.record")}</button></div>
      <div style="font-size:10.5px;color:#64748b;margin-bottom:6px">${t("rl.d.loopNote")}</div>
      ${r.log.map((l) => `<div class="log-item"><b style="color:#c4b5fd">${esc(l.kind)}</b> · ${esc((l.createdDate || "").slice(0, 10))}<div class="kv">${esc(l.detail)}</div></div>`).join("")}
    </div>`;
  bindDetail();
}

function bindDetail(): void {
  const r = CUR!;
  const upd = async (patch: Record<string, unknown>): Promise<void> => { try { await api(`/api/ai-risk-loop/${r.riskId}`, "PATCH", patch); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } };
  $("d-close").onclick = closeDetail;
  ($("d-stage") as HTMLSelectElement).onchange = (e) => upd({ stage: (e.target as HTMLSelectElement).value });
  ($("d-status") as HTMLSelectElement).onchange = (e) => upd({ status: (e.target as HTMLSelectElement).value });
  ($("d-owner") as HTMLSelectElement).onchange = (e) => upd({ owner: (e.target as HTMLSelectElement).value });
  ($("d-treatment") as HTMLSelectElement).onchange = (e) => upd({ treatment: (e.target as HTMLSelectElement).value });
  $("d-del").onclick = async () => { if (!confirm(t("rl.d.confirmDel"))) return; try { await api(`/api/ai-risk-loop/${r.riskId}`, "DELETE"); closeDetail(); await load(); } catch (e) { toast(String(e), false); } };
  $("detail").querySelectorAll<HTMLSelectElement>("select.di").forEach((s) => s.onchange = () => {
    const f = s.dataset.f!; upd({ [f]: Number(s.value) });
  });
  // control library add
  $("d-ctl-add").onclick = async () => {
    const sel = $("d-ctl-pick") as HTMLSelectElement; const o = sel.selectedOptions[0]; if (!sel.value) return;
    try { await api(`/api/ai-risk-loop/${r.riskId}/control`, "POST", { controlRef: sel.value, controlName: o.dataset.name, controlOwner: o.dataset.owner }); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); }
  };
  $("detail").querySelectorAll<HTMLElement>("[data-unlink]").forEach((x) => x.onclick = async () => { try { await api(`/api/ai-risk-loop/control/${x.dataset.unlink}`, "DELETE"); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } });
  $("detail").querySelectorAll<HTMLSelectElement>("select.ce").forEach((s) => s.onchange = async () => { try { await api(`/api/ai-risk-loop/control/${s.dataset.link}`, "PATCH", { [s.dataset.k!]: s.value }); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } });
  $("detail").querySelectorAll<HTMLInputElement>("input.cev").forEach((i) => i.onchange = async () => { try { await api(`/api/ai-risk-loop/control/${i.dataset.link}`, "PATCH", { evidenceRef: i.value }); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } });
  // acceptance
  const accSave = document.getElementById("d-acc-save"); if (accSave) accSave.onclick = () => upd({ acceptanceBy: (document.getElementById("d-acc-by") as HTMLInputElement).value, acceptanceDate: (document.getElementById("d-acc-date") as HTMLInputElement).value, acceptanceRationale: (document.getElementById("d-acc-rat") as HTMLInputElement).value });
  // KRIs
  $("k-add").onclick = async () => {
    const name = (document.getElementById("k-name") as HTMLInputElement).value.trim(); if (!name) return;
    try { await api(`/api/ai-risk-loop/${r.riskId}/kri`, "POST", { name, metric: (document.getElementById("k-metric") as HTMLInputElement).value, threshold: (document.getElementById("k-thr") as HTMLInputElement).value, direction: (document.getElementById("k-dir") as HTMLSelectElement).value, action: (document.getElementById("k-action") as HTMLInputElement).value }); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); }
  };
  $("detail").querySelectorAll<HTMLInputElement>("input.kv-cur").forEach((i) => i.onchange = async () => { try { await api(`/api/ai-risk-loop/kri/${i.dataset.kri}`, "PATCH", { currentValue: i.value }); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } });
  $("detail").querySelectorAll<HTMLElement>("[data-delkri]").forEach((x) => x.onclick = async () => { try { await api(`/api/ai-risk-loop/kri/${x.dataset.delkri}`, "DELETE"); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } });
  // evidence (CAS) upload + delete
  $("ev-up").onclick = async () => {
    const inp = document.getElementById("ev-file") as HTMLInputElement; const f = inp.files && inp.files[0];
    if (!f) { toast(t("rl.d.pickFile"), false); return; }
    if (f.size > 25 * 1024 * 1024) { toast(t("rl.d.tooBig"), false); return; }
    const b64 = await new Promise<string>((resolve, reject) => { const rd = new FileReader(); rd.onload = () => resolve(String(rd.result).split(",")[1] || ""); rd.onerror = reject; rd.readAsDataURL(f); });
    try { await api(`/api/ai-risk-loop/${r.riskId}/evidence/upload`, "POST", { fileName: f.name, contentType: f.type, dataBase64: b64 }); toast(t("rl.d.evUploaded")); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); }
  };
  $("detail").querySelectorAll<HTMLElement>("[data-delev]").forEach((x) => x.onclick = async () => { try { await api(`/api/ai-risk-loop/evidence/${x.dataset.delev}`, "DELETE"); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); } });
  // loop event
  $("e-add").onclick = async () => {
    try { await api(`/api/ai-risk-loop/${r.riskId}/event`, "POST", { kind: (document.getElementById("e-kind") as HTMLSelectElement).value, detail: (document.getElementById("e-detail") as HTMLInputElement).value }); toast(t("rl.d.recorded")); await refreshDetail(r.riskId); await load(); } catch (e) { toast(String(e), false); }
  };
}

// ── Create + top buttons ──────────────────────────────────────────────────────────────────────
function bindTop(): void {
  $("rl-new").onclick = () => { const w = $("rl-form-wrap") as HTMLDetailsElement; w.open = true; w.scrollIntoView({ behavior: "smooth" }); };
  $("rl-seed").onclick = async () => { try { await api("/api/ai-risk-loop/seed", "POST", {}); toast(t("rl.seeded")); await load(); } catch (e) { toast(String(e), false); } };
  $("backdrop").onclick = closeDetail;
  $("f-add").onclick = async () => {
    const title = (document.getElementById("f-title") as HTMLInputElement).value.trim();
    if (!title) { toast(t("rl.needTitle"), false); return; }
    const sysV = (document.getElementById("f-system") as HTMLSelectElement).value;
    const body = {
      title, aiSystemId: sysV || null, riskArea: (document.getElementById("f-area") as HTMLSelectElement).value,
      lifecyclePhase: (document.getElementById("f-lifecycle") as HTMLSelectElement).value, owner: (document.getElementById("f-owner") as HTMLSelectElement).value,
      description: (document.getElementById("f-desc") as HTMLTextAreaElement).value,
      context: { purpose: (document.getElementById("f-purpose") as HTMLInputElement).value, data: (document.getElementById("f-data") as HTMLInputElement).value, dependencies: (document.getElementById("f-deps") as HTMLInputElement).value, obligations: (document.getElementById("f-oblig") as HTMLInputElement).value },
    };
    try { const res = await api("/api/ai-risk-loop", "POST", body); toast(t("rl.created")); (document.getElementById("f-title") as HTMLInputElement).value = ""; await load(); openDetail(res.risk.riskId); } catch (e) { toast(String(e), false); }
  };
}

initI18n().then(() => { bindTop(); return load(); });
