/** trust-center.ts — admin config for the Trust Center (/trust-center). Edit branding + published
 * frameworks + sub-processors, toggle live panels, publish, and copy the public /trust/<slug> link. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Cfg { slug: string; enabled: boolean; companyName: string; title: string; intro: string; contactEmail: string;
  subprocessors: { name: string; purpose: string; location: string }[]; frameworks: { name: string; status: string }[];
  showControls: boolean; showUptime: boolean; showPolicies: boolean; }
interface Data { config: Cfg; posture: any; publicUrl: string | null; canEdit: boolean; }

let DATA: Data | null = null;

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #22c55e;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 5000);
}

function kvRows(items: { name: string; status?: string; purpose?: string; location?: string }[], kind: "fw" | "sp"): string {
  return items.map((it, i) => kind === "fw"
    ? `<div class="kv" data-i="${i}"><input class="fw-name" placeholder="Framework (e.g. SOC 2)" value="${esc(it.name)}"><input class="fw-status" placeholder="Status" value="${esc(it.status || "")}"><button class="rm" data-rm="fw" data-i="${i}">✕</button></div>`
    : `<div class="kv" data-i="${i}"><input class="sp-name" placeholder="Sub-processor" value="${esc(it.name)}"><input class="sp-purpose" placeholder="Purpose" value="${esc(it.purpose || "")}"><input class="sp-loc" placeholder="Location" value="${esc(it.location || "")}"><button class="rm" data-rm="sp" data-i="${i}">✕</button></div>`).join("");
}

function render(): void {
  if (!DATA) return;
  const c = DATA.config; const p = DATA.posture || {};
  const stat = (v: string, l: string): string => `<div class="stat"><div class="v">${v}</div><div class="l">${esc(l)}</div></div>`;
  const preview = `
    ${c.showControls && p.controls ? stat(`${p.controls.coveragePct}%`, "NIST 800-53 coverage") : ""}
    ${c.showUptime && p.uptime ? stat(`${p.uptime.avgUptime}%`, "Avg uptime") : ""}
    ${c.showPolicies ? stat(String(p.policies ?? 0), "Policies") : ""}
    ${stat(String(p.audits ?? 0), "Audits / assessments")}`;
  const liveFw = (p.frameworksLive || []).map((f: any) => `<span class="bd" style="font-size:12px;background:#0f1117;border:1px solid #2d3250;border-radius:6px;padding:3px 9px;color:#cbd5e1;margin:0 4px 4px 0;display:inline-block">${esc(f.name)} · ${esc(f.status)}</span>`).join("");

  $("tc-body").innerHTML = `<div class="tc-grid">
    <div>
      <div class="panel">
        <h3>Publication</h3>
        <label class="chk"><input type="checkbox" id="tc-enabled" ${c.enabled ? "checked" : ""}> Publish the Trust Center (make /trust/<slug> public)</label>
        <label>Public slug</label><input id="tc-slug" value="${esc(c.slug)}" placeholder="acme">
        <div class="pubrow"><code id="tc-url">${DATA.publicUrl ? location.origin + DATA.publicUrl : "— save to generate —"}</code>
          <button class="btn-2nd" id="tc-copy">Copy</button><a class="btn-2nd" id="tc-open" href="${DATA.publicUrl || "#"}" target="_blank" rel="noopener">Open</a></div>
      </div>
      <div class="panel">
        <h3>Branding</h3>
        <label>Company name</label><input id="tc-company" value="${esc(c.companyName)}" placeholder="Acme Inc.">
        <label>Page title</label><input id="tc-title" value="${esc(c.title)}">
        <label>Intro / message</label><textarea id="tc-intro" placeholder="Security is foundational to how we operate…">${esc(c.intro)}</textarea>
        <label>Contact email</label><input id="tc-contact" value="${esc(c.contactEmail)}" placeholder="security@acme.com">
      </div>
      <div class="panel">
        <h3>Live panels</h3>
        <label class="chk"><input type="checkbox" id="tc-showControls" ${c.showControls ? "checked" : ""}> NIST 800-53 control coverage</label>
        <label class="chk"><input type="checkbox" id="tc-showUptime" ${c.showUptime ? "checked" : ""}> Monitoring uptime</label>
        <label class="chk"><input type="checkbox" id="tc-showPolicies" ${c.showPolicies ? "checked" : ""}> Policies count</label>
      </div>
    </div>
    <div>
      <div class="panel">
        <h3>Live posture (preview)</h3>${preview}
        ${liveFw ? `<div style="margin-top:8px">${liveFw}</div>` : ""}
      </div>
      <div class="panel">
        <h3>Published frameworks <button class="btn-2nd" id="tc-add-fw" style="float:right">+ Add</button></h3>
        <div id="tc-fw">${kvRows(c.frameworks, "fw")}</div>
      </div>
      <div class="panel">
        <h3>Sub-processors <button class="btn-2nd" id="tc-add-sp" style="float:right">+ Add</button></h3>
        <div id="tc-sp">${kvRows(c.subprocessors, "sp")}</div>
      </div>
      <div class="panel">
        <div class="err" id="tc-err"></div>
        <button class="btn-save" id="tc-save"${DATA.canEdit ? "" : " disabled title='admin required'"}>Save &amp; publish</button>
      </div>
    </div></div>`;
  wire();
}

function collect(): Partial<Cfg> {
  const v = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
  const ck = (id: string) => (document.getElementById(id) as HTMLInputElement).checked;
  const fw = Array.from(document.querySelectorAll<HTMLElement>("#tc-fw .kv")).map((r) => ({ name: (r.querySelector(".fw-name") as HTMLInputElement).value.trim(), status: (r.querySelector(".fw-status") as HTMLInputElement).value.trim() })).filter((x) => x.name);
  const sp = Array.from(document.querySelectorAll<HTMLElement>("#tc-sp .kv")).map((r) => ({ name: (r.querySelector(".sp-name") as HTMLInputElement).value.trim(), purpose: (r.querySelector(".sp-purpose") as HTMLInputElement).value.trim(), location: (r.querySelector(".sp-loc") as HTMLInputElement).value.trim() })).filter((x) => x.name);
  return { enabled: ck("tc-enabled"), slug: v("tc-slug"), companyName: v("tc-company"), title: v("tc-title"), intro: v("tc-intro"), contactEmail: v("tc-contact"), showControls: ck("tc-showControls"), showUptime: ck("tc-showUptime"), showPolicies: ck("tc-showPolicies"), frameworks: fw, subprocessors: sp };
}

function wire(): void {
  $("tc-copy").addEventListener("click", () => { const u = ($("tc-url").textContent || ""); if (u.startsWith("http")) { void navigator.clipboard.writeText(u); toast("✅ Link copied"); } });
  $("tc-add-fw").addEventListener("click", () => { if (!DATA) return; DATA.config = collect() as Cfg; DATA.config.frameworks.push({ name: "", status: "In progress" }); render(); });
  $("tc-add-sp").addEventListener("click", () => { if (!DATA) return; DATA.config = collect() as Cfg; DATA.config.subprocessors.push({ name: "", purpose: "", location: "" }); render(); });
  document.querySelectorAll<HTMLElement>("[data-rm]").forEach((b) => b.addEventListener("click", () => {
    if (!DATA) return; const merged = collect() as Cfg; const i = Number(b.dataset.i);
    if (b.dataset.rm === "fw") merged.frameworks.splice(i, 1); else merged.subprocessors.splice(i, 1);
    DATA.config = merged; render();
  }));
  $("tc-save").addEventListener("click", () => void save());
}

async function save(): Promise<void> {
  const btn = $("tc-save") as HTMLButtonElement; btn.disabled = true; $("tc-err").textContent = "Saving…";
  try {
    const r = await fetch("/api/trust-center/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(collect()) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load(); toast("✅ Trust Center saved" + (d.config.enabled ? " & published" : ""));
  } catch (e) { $("tc-err").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/trust-center"); if (!r.ok) throw new Error(`HTTP ${r.status}`); DATA = await r.json(); }
  catch (e) { $("tc-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  render();
}

document.addEventListener("DOMContentLoaded", () => void load());
