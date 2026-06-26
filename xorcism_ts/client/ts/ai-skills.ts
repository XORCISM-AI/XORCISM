/** ai-skills.ts — client for AI Operations (/ai-skills): Skills/Prompt library, AI activity log,
 *  agent handover routing, and the AI provider. Tabbed single page. */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
let DATA: any = null;
let TAB = "library";
let CAN = false;

function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
async function api(method: string, url: string, body?: unknown): Promise<any> {
  const r = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}

function tabs(): string {
  const t = (id: string, label: string) => `<div class="tab${TAB === id ? " on" : ""}" data-tab="${id}">${label}</div>`;
  return `<div class="tabs">${t("library", "Skills &amp; Prompts")}${t("activity", "Activity log")}${t("routing", "Agentic flow")}${t("provider", "AI provider")}</div>`;
}

function libraryTab(): string {
  const s = DATA.skills as any[];
  const cards = s.map((k) => `<div class="sk">
    <div style="display:flex;justify-content:space-between;gap:8px;align-items:start">
      <h3>${esc(k.name)}</h3><span class="pill k-${esc(k.kind)}">${esc(k.kind)}</span>
    </div>
    <div class="d">${esc(k.description)}</div>
    <div style="margin:6px 0">${(k.tags || []).map((t: string) => `<span class="tag">${esc(t)}</span>`).join("")}</div>
    <div class="muted" style="font-size:11px">v${esc(k.version)} · used ${esc(k.usedCount)}× · ${esc(k.visibility)}${k.category ? " · " + esc(k.category) : ""}</div>
    <div style="margin-top:8px;display:flex;gap:6px;align-items:center">
      ${CAN ? `<button class="btn sm tog" data-id="${k.id}" data-en="${k.enabled ? 1 : 0}">${k.enabled ? "Enabled ✓" : "Disabled"}</button>
      <button class="btn sm edit" data-id="${k.id}">Edit</button>
      <button class="btn sm use" data-id="${k.id}">Use</button>` : `<span class="muted" style="font-size:11px">${k.enabled ? "enabled" : "disabled"}</span>`}
    </div></div>`).join("");
  return `<div class="block"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h2 style="margin:0">Library — ${s.length} skills &amp; prompts</h2>
      ${CAN ? `<button class="btn" id="newSkill">+ New skill / prompt</button>` : ""}
    </div>
    ${s.length ? `<div class="skgrid">${cards}</div>` : `<div class="muted" style="padding:10px">No skills yet. ${CAN ? "Create one — it becomes reusable across copilots." : ""}</div>`}</div>`;
}

function activityTab(): string {
  const a = DATA.activity as any[];
  const by = DATA.byActor || {};
  const chips = Object.entries(by).sort((x: any, y: any) => y[1] - x[1]).slice(0, 8)
    .map(([k, v]) => `<span class="tag">${esc(k)}: ${esc(v as any)}</span>`).join("");
  const rows = a.map((x) => `<tr>
    <td class="muted" style="font-size:11px;white-space:nowrap">${esc((x.createdDate || "").replace("T", " ").slice(0, 16))}</td>
    <td><span class="nm">${esc(x.actor)}</span></td>
    <td><span class="tag">${esc(x.action)}</span></td>
    <td class="muted">${esc(x.entityType || "")}${x.entityKey ? " " + esc(x.entityKey) : ""}</td>
    <td>${esc(x.summary)}</td>
    <td class="muted" style="font-size:11px">${esc(x.model || "")}${x.tokensIn ? ` · ${esc(x.tokensIn)}/${esc(x.tokensOut || 0)} tok` : ""}</td>
    <td><span class="tag">${esc(x.outcome)}</span></td></tr>`).join("");
  return `<div class="block"><h2>AI activity &amp; decision provenance — ${DATA.summary.activity} total</h2>
    <div style="margin-bottom:8px">${chips}</div>
    <table class="t"><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Entity</th><th>Summary</th><th>Model</th><th>Outcome</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="7" class="muted" style="padding:14px;text-align:center">No AI activity recorded yet. Copilot runs and orchestrator decisions are logged here automatically.</td></tr>`}</tbody></table>
    <div class="muted" style="font-size:11px;margin-top:6px">Record-keeping for AI governance — EU AI Act Art. 12, ISO/IEC 42001, NIST AI RMF MEASURE/MANAGE.</div></div>`;
}

function routingTab(): string {
  const h = DATA.handover;
  const groups = new Map<string, any[]>();
  for (const e of h.edges) { if (!groups.has(e.from)) groups.set(e.from, []); groups.get(e.from)!.push(e); }
  const blocks = [...groups.entries()].map(([from, edges]) => `<div style="margin-bottom:10px">
    <div class="nm" style="margin-bottom:4px">${esc(from)}${from === "croc-orchestrator" ? ' <span class="tag">hub</span>' : ""}</div>
    ${edges.map((e) => `<div style="display:flex;gap:8px;align-items:center;padding:3px 0 3px 14px;font-size:12px">
      <span class="ht t-${esc(e.type)}">${esc(e.type)}</span>
      <span>→ <b>${esc(e.to)}</b></span>
      <span class="muted">${esc(e.trigger)}</span>
      ${e.source === "custom" && CAN ? `<button class="btn sm delRoute" data-id="${e.id}">✕</button>` : `<span class="muted" style="font-size:10px">${esc(e.source)}</span>`}
    </div>`).join("")}
  </div>`).join("");
  return `<div class="block"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h2 style="margin:0">Agentic flow — CROC agent handover routing</h2>
      ${CAN ? `<button class="btn" id="newRoute">+ Add handover</button>` : ""}
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:10px">How the CROC orchestrator hands work to the analyst copilots. <b>delegate</b> = run in background · <b>consult</b> = ask &amp; return · <b>transfer</b> = move · <b>escalate</b> = to a human. Default routes mirror the orchestrator; add your own.</div>
    ${blocks}</div>`;
}

function providerTab(): string {
  const p = DATA.provider;
  return `<div class="block"><h2>AI provider</h2>
    <div class="cards" style="margin-bottom:0">
      ${card("Provider", p.provider, p.local ? "on your infrastructure" : "external API", p.local ? "#34d399" : "#fbbf24")}
      ${card("Model", p.model, "default model")}
      ${card("Endpoint", (p.url || "—").replace(/^https?:\/\//, "").slice(0, 28), "", "#94a3b8")}
      ${card("Status", p.configured ? "configured" : "not set", p.local ? "local-first" : "API key required", p.configured ? "#34d399" : "#f87171")}
    </div>
    <div class="muted" style="font-size:12px;margin-top:10px">Set via environment (never the UI): <a class="code">XOR_AI_PROVIDER</a>=ollama | openai | anthropic | azure,
    plus the matching <a class="code">OLLAMA_*</a> / <a class="code">OPENAI_*</a> / <a class="code">ANTHROPIC_*</a> / <a class="code">AZURE_OPENAI_*</a> variables.
    Local Ollama is the privacy-first default — nothing leaves your machine.</div></div>`;
}

function render(): void {
  const body = $("body"); if (!body) return;
  CAN = !!DATA.canRun;
  const s = DATA.summary;
  const cards = [
    card("Skills", s.skills, "reusable methods"),
    card("Prompts", s.prompts, "reusable prompts"),
    card("Enabled", s.enabled, "injected into copilots", "#34d399"),
    card("Activity", s.activity, "AI decisions logged"),
    card("Handover routes", s.routes, "agentic flow"),
  ].join("");
  const tab = TAB === "activity" ? activityTab() : TAB === "routing" ? routingTab() : TAB === "provider" ? providerTab() : libraryTab();
  body.innerHTML = `<div class="cards">${cards}</div>${tabs()}${tab}`;
  body.querySelectorAll<HTMLElement>(".tab").forEach((t) => t.onclick = () => { TAB = t.dataset.tab!; render(); });
  wire();
}

function wire(): void {
  const body = $("body")!;
  body.querySelectorAll<HTMLButtonElement>(".tog").forEach((b) => b.onclick = async () => {
    try { DATA = await api("POST", `/api/ai-skills/skill/${b.dataset.id}/toggle`, { enabled: b.dataset.en !== "1" }); render(); } catch (e) { alert((e as Error).message); }
  });
  body.querySelectorAll<HTMLButtonElement>(".use").forEach((b) => b.onclick = async () => {
    try { DATA = await api("POST", `/api/ai-skills/skill/${b.dataset.id}/use`, { by: "manual" }); render(); } catch (e) { alert((e as Error).message); }
  });
  body.querySelectorAll<HTMLButtonElement>(".edit").forEach((b) => b.onclick = () => openSkillModal(DATA.skills.find((x: any) => x.id === Number(b.dataset.id))));
  const ns = $("newSkill"); if (ns) ns.onclick = () => openSkillModal(null);
  const nr = $("newRoute"); if (nr) nr.onclick = () => openRouteModal();
  body.querySelectorAll<HTMLButtonElement>(".delRoute").forEach((b) => b.onclick = async () => {
    try { DATA = await api("DELETE", `/api/ai-skills/handover/${b.dataset.id}`); render(); } catch (e) { alert((e as Error).message); }
  });
}

function modal(html: string): void { const m = $("modal")!, box = $("modalBox")!; box.innerHTML = html; m.classList.add("on"); m.onclick = (e) => { if (e.target === m) m.classList.remove("on"); }; }
function closeModal(): void { $("modal")!.classList.remove("on"); }

function openSkillModal(k: any): void {
  const v = k || { kind: "skill", visibility: "tenant", enabled: true };
  modal(`<h2 style="margin:0 0 12px">${k ? "Edit" : "New"} skill / prompt</h2>
    <div class="row">
      <label>Name<input id="f_name" value="${esc(v.name || "")}"></label>
      <label>Kind<select id="f_kind"><option value="skill"${v.kind === "skill" ? " selected" : ""}>skill</option><option value="prompt"${v.kind === "prompt" ? " selected" : ""}>prompt</option></select></label>
    </div>
    <div class="row">
      <label>Category<input id="f_cat" value="${esc(v.category || "")}"></label>
      <label>Visibility<select id="f_vis">${(DATA.visibilities || ["private", "tenant", "public"]).map((x: string) => `<option${x === v.visibility ? " selected" : ""}>${x}</option>`).join("")}</select></label>
    </div>
    <div class="row"><label style="flex:1 1 100%">Description<input id="f_desc" value="${esc(v.description || "")}"></label></div>
    <div class="row"><label style="flex:1 1 100%">Tags (comma-separated)<input id="f_tags" value="${esc((v.tags || []).join(", "))}"></label></div>
    <div style="font-size:11px;color:#94a3b8;margin-bottom:3px">Content (markdown — the operating method / prompt injected into copilots)</div>
    <textarea id="f_content">${esc(v.content || "")}</textarea>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" id="m_cancel">Cancel</button><button class="btn" id="m_save" style="background:#14532d;border-color:#166534;color:#bbf7d0">Save</button>
    </div>`);
  $("m_cancel")!.onclick = closeModal;
  $("m_save")!.onclick = async () => {
    const b: any = { id: k ? k.id : 0, name: (<HTMLInputElement>$("f_name")).value, kind: (<HTMLSelectElement>$("f_kind")).value,
      category: (<HTMLInputElement>$("f_cat")).value, visibility: (<HTMLSelectElement>$("f_vis")).value,
      description: (<HTMLInputElement>$("f_desc")).value, tags: (<HTMLInputElement>$("f_tags")).value, content: (<HTMLTextAreaElement>$("f_content")).value };
    if (!b.name.trim()) return alert("Name required");
    try { DATA = await api("POST", "/api/ai-skills/skill", b); closeModal(); render(); } catch (e) { alert((e as Error).message); }
  };
}

function openRouteModal(): void {
  const agents = [...new Set((DATA.handover.nodes as any[]).map((n) => n.id))];
  const opt = (sel?: string) => agents.map((a) => `<option${a === sel ? " selected" : ""}>${a}</option>`).join("");
  modal(`<h2 style="margin:0 0 12px">Add agent handover</h2>
    <div class="row">
      <label>From<select id="r_from">${opt("croc-orchestrator")}</select></label>
      <label>To<select id="r_to">${opt()}</select></label>
      <label>Type<select id="r_type">${(DATA.handover.types || []).map((t: string) => `<option>${t}</option>`).join("")}</select></label>
    </div>
    <div class="row"><label style="flex:1 1 100%">Trigger (when this handover fires)<input id="r_trigger" placeholder="e.g. ransomware / data exfiltration"></label></div>
    <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" id="m_cancel">Cancel</button><button class="btn" id="m_save" style="background:#14532d;border-color:#166534;color:#bbf7d0">Add</button>
    </div>`);
  $("m_cancel")!.onclick = closeModal;
  $("m_save")!.onclick = async () => {
    const b = { from: (<HTMLSelectElement>$("r_from")).value, to: (<HTMLSelectElement>$("r_to")).value, type: (<HTMLSelectElement>$("r_type")).value, trigger: (<HTMLInputElement>$("r_trigger")).value };
    try { DATA = await api("POST", "/api/ai-skills/handover", b); closeModal(); render(); } catch (e) { alert((e as Error).message); }
  };
}

async function load(): Promise<void> {
  try { DATA = await api("GET", "/api/ai-skills"); render(); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
document.addEventListener("DOMContentLoaded", () => { void load(); });
