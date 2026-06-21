/**
 * connectors.ts — "Connectors" page: registry, parameters form,
 * job launching (async) and live status/log tracking.
 */

import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
// Escapes HTML metacharacters before interpolation into innerHTML (stored-XSS guard
// for user-controlled values: scan targets, worker names, cron, connector data).
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, type: "ok" | "err" = "ok"): void {
  const el = $("toast"); el.textContent = msg;
  el.className = type === "err" ? "toast-err" : "toast-ok";
  (el as HTMLElement).style.opacity = "1";
  setTimeout(() => ((el as HTMLElement).style.opacity = "0"), 2800);
}
async function jget(u: string): Promise<any> {
  const r = await fetch(u);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}
async function jpost(u: string, b: unknown): Promise<any> {
  const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
}

// User preference: workers directory (where nmap, nikto, metasploit… live).
async function loadWorkerPath(): Promise<void> {
  const inp = $("wk-path") as HTMLInputElement;
  try {
    const r = await jget("/api/prefs/worker-path");
    inp.value = r && typeof r.value === "string" ? r.value : "";
  } catch { /* preference absent */ }
  let timer: number | undefined;
  inp.addEventListener("input", () => {
    if (timer) clearTimeout(timer);
    timer = window.setTimeout(async () => {
      try {
        await fetch("/api/prefs/worker-path", {
          method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ value: inp.value.trim() }),
        });
        const s = $("wk-path-saved"); s.style.opacity = "1";
        setTimeout(() => (s.style.opacity = "0"), 1200);
      } catch { /* ignore */ }
    }, 500);
  });
}

interface Param { name: string; type: string; required?: boolean; default?: unknown; values?: unknown[]; help?: string; pattern?: string }
interface Connector { id: string; name: string; type: string; category?: string; description?: string; intrusive?: boolean; parameters: Param[] }

let connectors: Connector[] = [];
let engagements: any[] = [];
let selected: Connector | null = null;
let pollTimer: number | undefined;

async function loadEngagements(): Promise<void> {
  try { engagements = await jget("/api/engagements"); } catch { engagements = []; }
  const sel = $("cn-engagement") as HTMLSelectElement;
  sel.innerHTML = `<option value="">—</option>`;
  engagements.forEach((e) => {
    const o = document.createElement("option");
    o.value = String(e.EngagementID);
    o.textContent = e.name + (e.active ? "" : " (inactif)");
    sel.appendChild(o);
  });
  sel.onchange = showScopeHint;
}

function showScopeHint(): void {
  const id = ($("cn-engagement") as HTMLSelectElement).value;
  const e = engagements.find((x) => String(x.EngagementID) === id);
  let scope: string[] = [];
  try { scope = e ? JSON.parse(e.scope || "[]") : []; } catch { scope = []; }
  $("cn-eng-scope").textContent = scope.length ? "Périmètre : " + scope.join(", ") : "";
}

async function loadConnectors(): Promise<void> {
  connectors = await jget("/api/connectors");
  populateFilters();
  applyFilters();
}

// Populates the Category / Type dropdowns (with per-option counts) from the loaded
// connectors, preserving the current selection across reloads.
function populateFilters(): void {
  const catSel = $("cn-cat") as HTMLSelectElement;
  const typeSel = $("cn-type") as HTMLSelectElement;
  const cats = new Map<string, number>();
  const types = new Map<string, number>();
  for (const c of connectors) {
    const cat = c.category || "autres";
    cats.set(cat, (cats.get(cat) || 0) + 1);
    const ty = c.type || "?";
    types.set(ty, (types.get(ty) || 0) + 1);
  }
  const curCat = catSel.value, curType = typeSel.value;
  catSel.length = 1; typeSel.length = 1; // keep the leading "all" option
  [...cats.keys()].sort((a, b) => a.localeCompare(b)).forEach((k) => {
    const o = document.createElement("option"); o.value = k; o.textContent = `${k} (${cats.get(k)})`; catSel.appendChild(o);
  });
  [...types.keys()].sort((a, b) => a.localeCompare(b)).forEach((k) => {
    const o = document.createElement("option"); o.value = k; o.textContent = `${k} (${types.get(k)})`; typeSel.appendChild(o);
  });
  catSel.value = curCat; typeSel.value = curType;
}

// Reads the search box + category/type dropdowns + "intrusive only" toggle, filters the
// connector list accordingly and renders it (with a result count). Mirrors the tool catalogue.
function applyFilters(): void {
  const q = (($("cn-search") as HTMLInputElement | null)?.value || "").trim().toLowerCase();
  const cat = ($("cn-cat") as HTMLSelectElement | null)?.value || "";
  const type = ($("cn-type") as HTMLSelectElement | null)?.value || "";
  const intrOnly = !!($("cn-intr") as HTMLInputElement | null)?.checked;
  let matched = connectors;
  if (q) matched = matched.filter((c) => `${c.name} ${c.id} ${c.category || ""} ${c.type || ""} ${c.description || ""}`.toLowerCase().includes(q));
  if (cat) matched = matched.filter((c) => (c.category || "autres") === cat);
  if (type) matched = matched.filter((c) => (c.type || "?") === type);
  if (intrOnly) matched = matched.filter((c) => c.intrusive);
  renderConnectorList(matched);
  const cnt = $("cn-count"); if (cnt) cnt.textContent = connectors.length ? `(${matched.length}/${connectors.length})` : "";
}

// Renders the connector list grouped by category from an already-filtered list.
function renderConnectorList(matched: Connector[]): void {
  const host = $("cn-list");
  host.innerHTML = "";
  if (!connectors.length) { host.innerHTML = `<span class="hint">${t("conn.none")}</span>`; return; }
  if (!matched.length) { host.innerHTML = `<span class="hint">${t("conn.noMatch")}</span>`; return; }
  const byCat: Record<string, Connector[]> = {};
  matched.forEach((c) => { (byCat[c.category || "autres"] ||= []).push(c); });
  Object.keys(byCat).sort().forEach((cat) => {
    const h = document.createElement("div");
    h.className = "meta"; h.style.cssText = "margin:8px 0 4px;color:var(--accent);font-size:10px;text-transform:uppercase";
    h.textContent = cat;
    host.appendChild(h);
    byCat[cat].forEach((c) => {
      const it = document.createElement("div");
      it.className = "cn-item"; it.dataset.id = c.id;
      if (selected && selected.id === c.id) it.classList.add("sel");
      it.innerHTML =
        `<span><span class="nm">${esc(c.name)}</span><div class="meta">${esc(c.type)}</div></span>` +
        (c.intrusive ? `<span class="pill intr">intrusif</span>` : "");
      it.onclick = () => selectConnector(c, it);
      host.appendChild(it);
    });
  });
}

function selectConnector(c: Connector, el: HTMLElement): void {
  selected = c;
  document.querySelectorAll(".cn-item").forEach((x) => x.classList.remove("sel"));
  el.classList.add("sel");
  $("cn-empty").style.display = "none";
  $("cn-form-card").style.display = "";
  $("cn-form-title").textContent = c.name;
  $("cn-warn").style.display = c.intrusive ? "" : "none";
  // Engagement required as soon as a parameter of type "target" or "url" exists
  const needsEng = (c.parameters || []).some((p) => p.type === "target" || p.type === "url");
  $("cn-eng-wrap").style.display = needsEng ? "" : "none";

  const form = $("cn-form");
  form.innerHTML = "";
  for (const p of c.parameters || []) {
    const lab = document.createElement("label");
    lab.textContent = p.name + (p.required ? " *" : "");
    form.appendChild(lab);
    let input: HTMLElement;
    if (p.type === "enum") {
      const sel = document.createElement("select");
      (p.values || []).forEach((v) => {
        const o = document.createElement("option");
        o.value = String(v); o.textContent = String(v);
        if (String(v) === String(p.default ?? "")) o.selected = true;
        sel.appendChild(o);
      });
      input = sel;
    } else if (p.type === "bool") {
      const cb = document.createElement("input");
      cb.type = "checkbox"; cb.style.width = "auto"; cb.checked = !!p.default;
      input = cb;
    } else {
      const i = document.createElement("input");
      i.type = p.type === "int" ? "number" : "text";
      if (p.default != null) i.value = String(p.default);
      i.placeholder = p.type;
      input = i;
    }
    (input as HTMLElement).id = `p_${p.name}`;
    form.appendChild(input);
    if (p.help) {
      const h = document.createElement("div"); h.className = "hint"; h.textContent = p.help;
      form.appendChild(h);
    }
  }
}

function collectParams(): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const p of selected?.parameters || []) {
    const el = document.getElementById(`p_${p.name}`) as HTMLInputElement | HTMLSelectElement | null;
    if (!el) continue;
    if (p.type === "bool") out[p.name] = (el as HTMLInputElement).checked;
    else if ((el as HTMLInputElement).value !== "") out[p.name] = (el as HTMLInputElement).value;
  }
  return out;
}

async function run(): Promise<void> {
  if (!selected) return;
  const params = collectParams();
  const needsEng = (selected.parameters || []).some((p) => p.type === "target" || p.type === "url");
  const engagement = needsEng ? Number(($("cn-engagement") as HTMLSelectElement).value) || undefined : undefined;
  if (needsEng && !engagement) { toast(t("conn.engRequired"), "err"); return; }
  const worker = ($("cn-worker") as HTMLSelectElement).value || "local";
  if (selected.intrusive && !confirm(t("conn.confirmIntrusive"))) return;

  const recurring = ($("cn-recur") as HTMLInputElement)?.checked;
  try {
    if (recurring) {
      const cron = ($("cn-cron") as HTMLInputElement).value.trim();
      if (!cron) { toast(t("conn.cronReq"), "err"); return; }
      const { scheduleId } = await jpost("/api/schedules", { connector: selected.id, params, engagement, worker, cron });
      toast(`${t("conn.scheduled")} #${scheduleId} (${cron})`);
      loadSchedules();
    } else {
      const { jobId } = await jpost("/api/connectors/run", { connector: selected.id, params, engagement, worker });
      toast(`Job #${jobId} ${t("conn.queued")}`);
      loadJobs();
      watchJob(jobId);
    }
  } catch (e) {
    toast(String(e), "err");
  }
}

// Frequency presets → cron expression
const CRON_PRESETS: Record<string, string> = {
  every15: "*/15 * * * *", every30: "*/30 * * * *", hourly: "0 * * * *",
  daily: "0 2 * * *", weekly: "0 3 * * 1", monthly: "0 4 1 * *",
};

async function loadSchedules(): Promise<void> {
  let scheds: any[] = [];
  try { scheds = await jget("/api/schedules"); } catch { return; }
  const tb = $("cn-schedules");
  tb.innerHTML = "";
  if (!scheds.length) {
    tb.innerHTML = `<tr><td colspan="5" class="hint">${t("conn.noSchedules")}</td></tr>`;
    return;
  }
  scheds.forEach((s) => {
    const tr = document.createElement("tr");
    const on = Number(s.enabled) === 1;
    tr.innerHTML =
      `<td>${esc(s.connector)}</td><td>${esc(s.target ?? "")}</td>` +
      `<td style="font-family:monospace;font-size:11px">${esc(s.cron)}</td>` +
      `<td><span class="st ${on ? "running" : "queued"}">${on ? t("conn.schedOn") : t("conn.schedOff")}</span></td>`;
    const td = document.createElement("td");
    const toggle = document.createElement("button");
    toggle.className = "btn btn-ghost btn-sm"; toggle.style.cssText = "padding:2px 7px;font-size:11px";
    toggle.textContent = on ? t("conn.pause") : t("conn.resume");
    toggle.onclick = async () => {
      try { await jpost(`/api/schedules/${s.ScheduleID}/enabled`, { enabled: !on }); await loadSchedules(); }
      catch (e) { toast(String(e), "err"); }
    };
    const del = document.createElement("button");
    del.className = "btn btn-ghost btn-sm"; del.style.cssText = "padding:2px 7px;font-size:11px;margin-left:4px";
    del.textContent = "✕";
    del.onclick = async () => {
      if (!confirm(t("conn.schedDelConfirm"))) return;
      try { await jpost(`/api/schedules/${s.ScheduleID}/delete`, {}); await loadSchedules(); }
      catch (e) { toast(String(e), "err"); }
    };
    td.appendChild(toggle); td.appendChild(del); tr.appendChild(td);
    tb.appendChild(tr);
  });
}

// Wires the "recurrence" block of the form (toggle + presets → cron)
function wireRecurrence(): void {
  const chk = $("cn-recur") as HTMLInputElement;
  const opts = $("cn-recur-opts");
  const preset = $("cn-recur-preset") as HTMLSelectElement;
  const cron = $("cn-cron") as HTMLInputElement;
  const runBtn = $("cn-run");
  const syncBtn = () => { runBtn.textContent = chk.checked ? t("conn.schedule") : t("conn.run"); };
  chk.onchange = () => { opts.style.display = chk.checked ? "" : "none"; syncBtn(); };
  preset.onchange = () => {
    if (preset.value === "custom") { cron.focus(); return; }
    cron.value = CRON_PRESETS[preset.value] || cron.value;
  };
  syncBtn();
}

async function createEngagement(): Promise<void> {
  const name = ($("eng-name") as HTMLInputElement).value.trim();
  const scope = ($("eng-scope") as HTMLTextAreaElement).value;
  const roe = ($("eng-roe") as HTMLInputElement).value;
  if (!name) { toast(t("conn.engNameReq"), "err"); return; }
  try {
    await jpost("/api/engagements", { name, scope, roe });
    ($("eng-name") as HTMLInputElement).value = "";
    ($("eng-scope") as HTMLTextAreaElement).value = "";
    ($("eng-roe") as HTMLInputElement).value = "";
    await loadEngagements();
    toast(t("conn.engCreated"));
  } catch (e) {
    toast(String(e), "err");
  }
}

let workers: any[] = [];
async function loadWorkers(): Promise<void> {
  try { workers = await jget("/api/workers"); } catch { workers = []; }
  // Execution selector: local + remote workers
  const sel = $("cn-worker") as HTMLSelectElement;
  const cur = sel.value || "local";
  sel.innerHTML = `<option value="local">local</option>`;
  workers.forEach((w) => {
    const o = document.createElement("option");
    o.value = w.name; o.textContent = `${w.name} (${w.status || "?"})`;
    sel.appendChild(o);
  });
  sel.value = cur;
  // Administration table
  const tb = $("cn-workers");
  tb.innerHTML = "";
  if (!workers.length) {
    tb.innerHTML = `<tr><td colspan="4" class="hint">${t("conn.wNone")}</td></tr>`;
    return;
  }
  workers.forEach((w) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(w.name)}</td><td><span class="st ${esc(w.status || "queued")}">${esc(w.status || "?")}</span></td>` +
      `<td class="hint">${esc(w.last_seen || "—")}</td>`;
    const td = document.createElement("td");
    const b = document.createElement("button");
    b.className = "btn btn-ghost btn-sm"; b.style.cssText = "padding:2px 7px;font-size:11px";
    b.textContent = "✕";
    b.onclick = async () => {
      if (!confirm(t("conn.wDelConfirm"))) return;
      try { await jpost(`/api/workers/${w.WorkerID}/delete`, {}); await loadWorkers(); } catch (e) { toast(String(e), "err"); }
    };
    td.appendChild(b); tr.appendChild(td); tb.appendChild(tr);
  });
}

async function createWorkerUI(): Promise<void> {
  const name = ($("wk-name") as HTMLInputElement).value.trim();
  const caps = ($("wk-caps") as HTMLInputElement).value.split(/[\s,;]+/).map((c) => c.trim()).filter(Boolean);
  if (!name) { toast(t("conn.wNameReq"), "err"); return; }
  try {
    const { token } = await jpost("/api/workers", { name, capabilities: caps });
    ($("wk-name") as HTMLInputElement).value = "";
    ($("wk-caps") as HTMLInputElement).value = "";
    const box = $("wk-token");
    box.style.display = "";
    box.textContent = `${t("conn.wTokenOnce")} (${name}) : ${token}`;
    await loadWorkers();
  } catch (e) {
    toast(String(e), "err");
  }
}

async function loadJobs(): Promise<void> {
  let jobs: any[] = [];
  try { jobs = await jget("/api/jobs?limit=30"); } catch { return; }
  const tb = $("cn-jobs");
  tb.innerHTML = "";
  jobs.forEach((j) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${j.JobID}</td><td>${esc(j.connector)}</td><td>${esc(j.target ?? "")}</td>` +
      `<td><span class="st ${esc(j.status)}">${esc(j.status)}</span></td>`;
    const td = document.createElement("td");
    const b = document.createElement("button");
    b.className = "btn btn-ghost btn-sm"; b.style.cssText = "padding:2px 7px;font-size:11px";
    b.textContent = t("conn.view");
    b.onclick = () => watchJob(j.JobID);
    td.appendChild(b); tr.appendChild(td);
    tb.appendChild(tr);
  });
}

async function watchJob(id: number): Promise<void> {
  if (pollTimer) clearInterval(pollTimer);
  $("cn-log-card").style.display = "";
  const tick = async () => {
    let j: any;
    try { j = await jget(`/api/jobs/${id}`); } catch { return; }
    $("cn-log-title").textContent = `Job #${j.JobID} — ${j.connector} (${j.status})`;
    $("cn-summary").textContent = j.result_summary ? `import: ${j.result_summary}` : (j.error || "");
    $("cn-log").textContent = j.log || "(en attente…)";
    const pre = $("cn-log"); pre.scrollTop = pre.scrollHeight;
    if (j.status === "done" || j.status === "failed" || j.status === "error") {
      if (pollTimer) clearInterval(pollTimer);
      loadJobs();
    }
  };
  await tick();
  pollTimer = window.setInterval(tick, 1500);
}

// Deep link from the ASSET form: ?connector=<id>&target=<url>
// → pre-selects the connector and fills the target.
function applyConnectorDeepLink(): void {
  const qp = new URLSearchParams(location.search);
  const cid = qp.get("connector");
  if (!cid) return;
  const c = connectors.find((x) => x.id === cid);
  const el = document.querySelector(`.cn-item[data-id="${cid}"]`) as HTMLElement | null;
  if (!c || !el) return;
  selectConnector(c, el);
  const target = qp.get("target");
  if (target) {
    const tp = (c.parameters || []).find((p) => p.type === "target" || p.type === "url");
    if (tp) {
      const inp = document.getElementById(`p_${tp.name}`) as HTMLInputElement | null;
      if (inp) inp.value = target;
    }
  }
  $("cn-form-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("cn-search") as HTMLInputElement | null)?.addEventListener("input", applyFilters);
  ($("cn-cat") as HTMLSelectElement | null)?.addEventListener("change", applyFilters);
  ($("cn-type") as HTMLSelectElement | null)?.addEventListener("change", applyFilters);
  ($("cn-intr") as HTMLInputElement | null)?.addEventListener("change", applyFilters);
  void loadConnectors().then(applyConnectorDeepLink);
  void loadWorkerPath();
  void loadEngagements();
  void loadWorkers();
  void loadJobs();
  void loadSchedules();
  wireRecurrence();
  $("cn-run").onclick = run;
  $("eng-create").onclick = createEngagement;
  $("wk-create").onclick = createWorkerUI;
  $("cn-refresh").onclick = loadJobs;
  setInterval(loadJobs, 5000);
  setInterval(loadWorkers, 8000);
  setInterval(loadSchedules, 15000);

  // OCIL 2.0 — export selector + file import/validation
  let ocilMode: "import" | "validate" = "import";
  void (async () => {
    try {
      const r = await fetch("/api/ocil/questionnaires");
      if (!r.ok) return;
      const list = (await r.json()) as { QuestionnaireID: number; QuestionnaireName: string | null }[];
      const sel = $("ocil-qn") as HTMLSelectElement;
      for (const qn of list) {
        const o = document.createElement("option");
        o.value = String(qn.QuestionnaireID);
        o.textContent = qn.QuestionnaireName || `#${qn.QuestionnaireID}`;
        sel.appendChild(o);
      }
    } catch { /* list unavailable: the "All" export is still possible */ }
  })();
  ($("ocil-qn") as HTMLSelectElement).onchange = (e) => {
    const v = (e.target as HTMLSelectElement).value;
    ($("ocil-export") as HTMLAnchorElement).href = "/api/ocil/export" + (v ? `?ids=${encodeURIComponent(v)}` : "");
  };
  $("ocil-validate").onclick = () => { ocilMode = "validate"; ($("ocil-file") as HTMLInputElement).click(); };
  $("ocil-import").onclick = () => { ocilMode = "import"; ($("ocil-file") as HTMLInputElement).click(); };
  ($("ocil-file") as HTMLInputElement).onchange = async (e) => {
    const inp = e.target as HTMLInputElement;
    const f = inp.files?.[0];
    inp.value = "";
    if (!f) return;
    const msg = $("ocil-msg");
    msg.textContent = "…";
    try {
      const xml = await f.text();
      if (ocilMode === "validate") {
        const r = await fetch("/api/ocil/validate", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ xml }),
        });
        const d = await r.json().catch(() => ({}));
        if (d.ok) { msg.textContent = t("conn.ocilValid"); toast(t("conn.ocilValid"), "ok"); }
        else {
          msg.textContent = t("conn.ocilInvalid") + "\n" + ((d.errors as string[]) || []).map((x) => "• " + x).join("\n");
          toast(t("conn.ocilInvalid"), "err");
        }
        return;
      }
      const r = await fetch("/api/ocil/import", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ xml }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { msg.textContent = (d.error as string) || t("conn.ocilError"); toast(t("conn.ocilError"), "err"); return; }
      msg.textContent = `${t("conn.ocilImported")} — questionnaires:${d.questionnaires}, questions:${d.questions}, choix:${d.choices}, liens:${d.links}`;
      toast(t("conn.ocilImported"), "ok");
    } catch (err) {
      msg.textContent = (err as Error).message;
      toast(t("conn.ocilError"), "err");
    }
  };
});
