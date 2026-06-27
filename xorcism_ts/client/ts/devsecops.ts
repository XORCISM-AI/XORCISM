/** devsecops.ts — DevSecOps operations cockpit (/devsecops). Reads /api/devsecops. */
// NB: import as T — `t` is used as a map param in this file (.map((t) => …)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 2400); }
const SEVS = ["None", "Low", "Medium", "High", "Critical"];
let DATA: any = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const cellSym: Record<string, string> = { pass: "✓", fail: "✗", ran: "•", none: "·" };

function load(): void {
  fetch("/api/devsecops").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    DATA = d; const s = d.summary;
    if (!d.apps.length) {
      $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${T("dso.empty")}</div>`;
      wireActions(); return;
    }
    const cards = [
      card(T("dso.cApps"), String(s.apps), fmt("dso.cAppsF", { n: s.fullyCovered })),
      card(T("dso.cCoverage"), s.avgCoverage + "%", fmt("dso.cCoverageF", { n: d.scanTypes.length }), s.avgCoverage >= 70 ? "#4ade80" : "#fbbf24"),
      card(T("dso.cGate"), s.gatePassRate != null ? s.gatePassRate + "%" : "—", fmt("dso.cGateF", { n: s.blockedApps }), s.blockedApps ? "#f87171" : "#4ade80"),
      card(T("dso.cOpen"), `${s.openCritical} / ${s.openHigh}`, T("dso.cOpenF"), s.openCritical ? "#f87171" : "#fbbf24"),
      card("MTTR", s.mttrDays != null ? s.mttrDays + " " + T("dso.days") : "—", `${fmt("dso.remediatedN", { n: s.remediated })}${s.openStreaks ? ` · ${fmt("dso.openN", { n: s.openStreaks })}${s.oldestOpenDays != null ? `, ${fmt("dso.oldest", { n: s.oldestOpenDays })}` : ""}` : ""}`, "#a78bfa"),
      card(T("dso.cScans"), String(s.scansLast30d), T("dso.cScansF")),
      card(T("dso.cAsvs"), s.asvsAvgCoverage != null ? s.asvsAvgCoverage + "%" : "—", `${fmt("dso.asvsAppN", { n: s.asvsApps })}${s.asvsFailed ? ` · ${fmt("dso.asvsFailedN", { n: s.asvsFailed })}` : ""}`, "#34d399"),
    ].join("");

    const head = `<th>${T("dso.thApp")}</th><th>${T("dso.thLang")}</th><th>${T("dso.thCrit")}</th>` + d.scanTypes.map((ty: string) => `<th class="c" title="${esc(ty)}">${esc(ty.slice(0, 4))}</th>`).join("") + `<th class="c">${T("dso.thCritHigh")}</th><th class="c">${T("dso.thGate")}</th><th>${T("dso.thCoverage")}</th><th class="c">ASVS</th>`;
    const rows = d.apps.map((a: any) => {
      const cells = a.matrix.map((m: any) => `<td class="c"><span class="cell c-${m.status}" title="${esc(m.type)} · ${esc(m.tool)}${m.status === "none" ? " · " + esc(T("dso.notRun")) : ` · C${m.critical}/H${m.high}${m.gate ? ` · ${esc(T("dso.gate"))} ≤${m.gate}` : ""}`}">${cellSym[m.status]}</span></td>`).join("");
      return `<tr>
        <td><span class="nm">${esc(a.name)}</span>${a.repo ? `<div class="mono">${esc(a.repo)}</div>` : ""}</td>
        <td class="muted">${esc(a.language || "—")}</td>
        <td><span class="crat cr-${esc(a.criticality)}">${esc(a.criticality)}</span></td>
        ${cells}
        <td class="c">${a.openCritical ? `<span class="crit">${a.openCritical}</span>` : "0"}/${a.openHigh ? `<span class="high">${a.openHigh}</span>` : "0"}</td>
        <td class="c"><span class="gs gs-${a.gateStatus}">${a.gateStatus === "pass" ? T("dso.pass") : a.gateStatus === "fail" ? T("dso.block") : "—"}</span></td>
        <td><span class="bar"><i style="width:${a.coveragePct}%"></i></span> <span class="muted" style="font-size:11px">${a.coverage}/${d.scanTypes.length}</span></td>
        <td class="c">${a.asvs ? `<button class="btn-sm2" data-asvs="${a.id}" title="ASVS L${a.asvs.level} · ${a.asvs.verified}/${a.asvs.applicable} ${esc(T("dso.verified"))}${a.asvs.failed ? ` · ${a.asvs.failed} ${esc(T("dso.failed"))}` : ""}"${a.asvs.failed ? ' style="border-color:#f87171"' : ""}>L${a.asvs.level} · ${a.asvs.pct}%</button>` : `<button class="btn-sm2" data-asvs="${a.id}" title="${esc(T("dso.setAsvs"))}">+ ASVS</button>`}</td></tr>`;
    }).join("");

    const gates = d.gates.filter((g: any) => g.scope === "global").map((g: any) => `<div class="gaterow">
      <span class="gt">${esc(g.scanType)}</span><span class="muted">${T("dso.maxSeverity")}</span>
      <select class="dn" data-gate="${esc(g.scanType)}">${SEVS.map((s2) => `<option${s2 === g.maxSeverity ? " selected" : ""}>${s2}</option>`).join("")}</select>
      <span class="muted" style="font-size:11px">${g.blockOnFail ? T("dso.blocks") : T("dso.warns")}</span></div>`).join("");

    const wl = d.worklist.length
      ? `<table class="t"><thead><tr><th>${T("dso.thApp")}</th><th>${T("dso.thScan")}</th><th>${T("dso.thTool")}</th><th class="c">${T("dso.thCritShort")}</th><th class="c">${T("dso.thHighShort")}</th><th>${T("dso.thGate")}</th></tr></thead><tbody>${d.worklist.slice(0, 30).map((w: any) => `<tr>
          <td><span class="nm">${esc(w.app)}</span> <span class="crat cr-${esc(w.criticality)}" style="font-size:9px">${esc(w.criticality)}</span></td>
          <td>${esc(w.scanType)}</td><td class="mono">${esc(w.tool)}</td>
          <td class="c">${w.critical ? `<span class="crit">${w.critical}</span>` : "0"}</td><td class="c">${w.high ? `<span class="high">${w.high}</span>` : "0"}</td>
          <td>${w.status === "fail" ? `<span class="gs gs-fail">${fmt("dso.blockedLe", { g: esc(w.gate) })}</span>` : `<span class="muted">${T("dso.openCritical")}</span>`}</td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">${T("dso.noFailures")}</div>`;

    const scans = d.scans.slice(0, 20).map((sc: any) => `<tr><td>${esc(sc.app)}</td><td>${esc(sc.scanType)}</td><td class="mono">${esc(sc.tool)}</td>
      <td class="c">${sc.critical ? `<span class="crit">${sc.critical}</span>` : 0}/${sc.high ? `<span class="high">${sc.high}</span>` : 0}/${sc.medium}/${sc.low}</td>
      <td>${sc.gatePassed === false ? `<span class="gs gs-fail">fail</span>` : sc.gatePassed === true ? `<span class="gs gs-pass">pass</span>` : `<span class="muted">—</span>`}</td>
      <td class="muted" style="font-size:11px">${esc(String(sc.ranAt || "").slice(0, 10))}</td></tr>`).join("");

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">${T("dso.secCoverage")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none;font-weight:400">${T("dso.legend")}</span></div>
      <table class="t"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>
      <div class="grid2" style="margin-top:18px">
        <div class="panel"><div class="sec" style="margin-top:0">${T("dso.secGates")}</div>${gates || "<div class='muted'>—</div>"}</div>
        <div class="panel"><div class="sec" style="margin-top:0">${T("dso.secByClass")}</div>${d.byType.map((ty: any) => `<div class="gaterow"><span class="gt">${esc(ty.type)}</span><span class="bar"><i style="width:${Math.round((ty.apps / d.apps.length) * 100)}%"></i></span><span class="muted" style="font-size:11px">${fmt("dso.appsN", { n: ty.apps, total: d.apps.length })}${ty.fails ? ` · <span class="crit">${fmt("dso.failingN", { n: ty.fails })}</span>` : ""}</span></div>`).join("")}</div>
      </div>
      <div class="sec">${fmt("dso.secWorklist", { n: d.worklist.length })}</div>${wl}
      <div class="sec">${T("dso.secRecent")}</div><table class="t"><thead><tr><th>${T("dso.thApp")}</th><th>${T("dso.thScan")}</th><th>${T("dso.thTool")}</th><th class="c">C/H/M/L</th><th>${T("dso.thGate")}</th><th>${T("dso.thRan")}</th></tr></thead><tbody>${scans}</tbody></table>`;

    document.querySelectorAll<HTMLSelectElement>("[data-gate]").forEach((sel) => sel.addEventListener("change", () => {
      fetch("/api/devsecops/gate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scanType: sel.dataset.gate, maxSeverity: sel.value }) })
        .then((r) => r.json()).then(() => { toast(fmt("dso.gateSet", { g: sel.dataset.gate || "", s: sel.value })); load(); }).catch(() => toast(T("dso.failedToast")));
    }));
    document.querySelectorAll<HTMLButtonElement>("[data-asvs]").forEach((b) => b.addEventListener("click", () => openAsvs(Number(b.dataset.asvs))));
    wireActions();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function closeModal(): void { $("modal").classList.remove("show"); }

// ── OWASP ASVS verification modal (per app) ──────────────────────────────────────────
let asvsDirty = false;
function openAsvs(appId: number): void {
  fetch(`/api/devsecops/asvs/${appId}`).then((r) => r.json()).then((d) => { if (d.error) return void toast(d.error); renderAsvs(appId, d); }).catch(() => toast("Failed"));
}
function renderAsvs(appId: number, d: any): void {
  const c = d.coverage;
  const byCh: Record<string, any[]> = {};
  for (const r of d.requirements) (byCh[r.chapter || "—"] = byCh[r.chapter || "—"] || []).push(r);
  const chCov: Record<string, any> = {};
  for (const c of d.byChapter || []) chCov[c.chapter] = c;
  const levels = [0, 1, 2, 3].map((l) => `<option value="${l}"${l === d.targetLevel ? " selected" : ""}>${l === 0 ? T("dso.levelNone") : "L" + l}</option>`).join("");
  const sCls = (s: string): string => s === "Verified" ? "color:#4ade80" : s === "Failed" ? "color:#f87171" : /n\/?a/i.test(s) ? "color:#64748b" : "color:#94a3b8";
  const chBadge = (ch: string): string => { const c = chCov[ch]; return c ? `<span style="font-weight:400;color:${c.failed ? "#f87171" : c.pct >= 80 ? "#34d399" : "#94a3b8"}">${c.verified}/${c.applicable} · ${c.pct}%${c.failed ? ` · ${c.failed}✗` : ""}</span>` : ""; };
  const groups = Object.keys(byCh).map((ch) => `<div style="margin-top:8px"><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.4px;display:flex;justify-content:space-between;align-items:baseline">${esc(ch)}${chBadge(ch)}</div>${byCh[ch].map((r) => `<div style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:12px;border-bottom:1px solid #1e2133">
      <span class="mono" style="min-width:62px" title="${esc(r.statement)}">${esc(r.shortcode)}</span>
      <span style="flex:1;color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.statement)}">${esc(r.statement)}</span>
      <select class="dn" data-req="${esc(r.shortcode)}" style="${sCls(r.status)}">${d.statuses.map((s: string) => `<option${s === r.status ? " selected" : ""}>${esc(s)}</option>`).join("")}</select></div>`).join("")}</div>`).join("");
  $("mbox").innerHTML = `<h3>OWASP ASVS — ${esc(d.app)}</h3>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><label style="margin:0;color:#94a3b8;font-size:12px">${T("dso.targetLevel")}</label><select id="asvs-level" class="dn">${levels}</select>
      <span class="muted" style="font-size:12px;flex:1">${d.targetLevel ? `${c.verified}/${c.inScope} ${T("dso.verified")} · <b style="color:#34d399">${c.pct}%</b>${c.failed ? ` · <span style="color:#f87171">${c.failed} ${T("dso.failed")}</span>` : ""}${c.na ? ` · ${c.na} N/A` : ""}` : T("dso.setTargetLevel")}</span></div>
    <div style="max-height:52vh;overflow:auto">${groups || `<div class='muted' style='padding:10px 0'>${T("dso.pickLevel")}</div>`}</div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px"><span class="muted" style="font-size:11px">${fmt("dso.catalogueN", { n: d.catalogueSize })}</span><button class="btn-sm2" id="asvs-close">${T("dso.close")}</button></div>`;
  $("modal").classList.add("show");
  $("asvs-close").onclick = () => { closeModal(); if (asvsDirty) { asvsDirty = false; load(); } };
  $("asvs-level").addEventListener("change", (e) => {
    asvsDirty = true;
    fetch(`/api/devsecops/asvs/${appId}/level`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ level: Number((e.target as HTMLSelectElement).value) }) })
      .then((r) => r.json()).then(() => openAsvs(appId)).catch(() => toast("Failed"));
  });
  document.querySelectorAll<HTMLSelectElement>("[data-req]").forEach((sel) => sel.addEventListener("change", () => {
    asvsDirty = true; sel.style.cssText = sCls(sel.value);
    fetch(`/api/devsecops/asvs/${appId}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ shortcode: sel.dataset.req, status: sel.value }) })
      .then((r) => r.json()).then(() => toast(fmt("dso.reqSet", { req: sel.dataset.req || "", s: sel.value }))).catch(() => toast(T("dso.failedToast")));
  }));
}
function openApp(): void {
  $("mbox").innerHTML = `<h3>${T("dso.registerApp")}</h3>
    <label>${T("dso.fNameReq")}</label><input id="a-name" placeholder="payments-api">
    <label>${T("dso.fRepo")}</label><input id="a-repo" placeholder="github.com/acme/payments-api">
    <div class="row3"><div><label>${T("dso.fLanguage")}</label><input id="a-lang" placeholder="Go"></div><div><label>${T("dso.fTeam")}</label><input id="a-team"></div><div style="grid-column:span 2"><label>${T("dso.fCriticality")}</label><select id="a-crit"><option>Low</option><option>Medium</option><option selected>High</option><option>Critical</option></select></div></div>
    <label>${T("dso.fPipeline")}</label><input id="a-pipe" placeholder="https://ci.acme.dev/payments-api">
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px"><button class="btn-sm2" id="a-cancel">${T("dso.cancel")}</button><button class="btn" id="a-save">${T("dso.register")}</button></div>`;
  $("modal").classList.add("show");
  $("a-cancel").onclick = closeModal;
  $("a-save").onclick = () => {
    const name = ($("a-name") as HTMLInputElement).value.trim(); if (!name) return void toast(T("dso.nameRequired"));
    fetch("/api/devsecops/app", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, repo: ($("a-repo") as HTMLInputElement).value.trim(), language: ($("a-lang") as HTMLInputElement).value.trim(), team: ($("a-team") as HTMLInputElement).value.trim(), criticality: ($("a-crit") as HTMLSelectElement).value, pipelineUrl: ($("a-pipe") as HTMLInputElement).value.trim() }) })
      .then((r) => r.json()).then((d) => { if (d.error) throw new Error(d.error); closeModal(); toast(T("dso.appRegistered")); load(); }).catch((e) => toast(fmt("dso.failedE", { e: e.message })));
  };
}
function openScan(): void {
  const apps = (DATA?.apps || []) as any[];
  $("mbox").innerHTML = `<h3>${T("dso.recordScan")}</h3>
    <label>${T("dso.fAppReq")}</label><select id="s-app">${apps.map((a) => `<option value="${a.id}">${esc(a.name)}</option>`).join("")}</select>
    <div class="row3" style="grid-template-columns:1fr 1fr"><div><label>${T("dso.fScanClassReq")}</label><select id="s-type">${(DATA?.scanTypes || []).map((ty: string) => `<option>${ty}</option>`).join("")}</select></div><div><label>${T("dso.fTool")}</label><input id="s-tool" placeholder="semgrep"></div></div>
    <label>${T("dso.fFindings")}</label>
    <div class="row3"><div><label style="font-size:10px">Critical</label><input id="s-c" type="number" value="0"></div><div><label style="font-size:10px">High</label><input id="s-h" type="number" value="0"></div><div><label style="font-size:10px">Medium</label><input id="s-m" type="number" value="0"></div><div><label style="font-size:10px">Low</label><input id="s-l" type="number" value="0"></div></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px"><button class="btn-sm2" id="s-cancel">${T("dso.cancel")}</button><button class="btn" id="s-save">${T("dso.record")}</button></div>`;
  $("modal").classList.add("show");
  $("s-cancel").onclick = closeModal;
  $("s-save").onclick = () => {
    const body = { appId: Number(($("s-app") as HTMLSelectElement).value), scanType: ($("s-type") as HTMLSelectElement).value, tool: ($("s-tool") as HTMLInputElement).value.trim() || undefined, critical: +($("s-c") as HTMLInputElement).value, high: +($("s-h") as HTMLInputElement).value, medium: +($("s-m") as HTMLInputElement).value, low: +($("s-l") as HTMLInputElement).value };
    fetch("/api/devsecops/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => r.json()).then((d) => { if (d.error) throw new Error(d.error); closeModal(); toast(d.gatePassed === false ? T("dso.scanBlocked") : T("dso.scanPassed")); load(); }).catch((e) => toast(fmt("dso.failedE", { e: e.message })));
  };
}
function wireActions(): void { $("btn-newapp").onclick = openApp; $("btn-scan").onclick = openScan; $("modal").onclick = (e) => { if (e.target === $("modal")) closeModal(); }; }

document.addEventListener("DOMContentLoaded", () => { initI18n(); load(); });
