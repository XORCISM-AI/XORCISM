/**
 * evidence-catalogue.ts — Evidence Catalogue cockpit (/evidence-catalogue).
 * Central library of audit/compliance evidence: KPIs, type/freshness filters, search, add (file→CAS or
 * URL), per-row validity edit, audit linking and download.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function val(id: string): string { return (document.getElementById(id) as HTMLInputElement).value.trim(); }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string, ok = true): void { const el = $("toast"); el.textContent = msg; el.className = ok ? "toast-ok" : "toast-err"; el.style.opacity = "1"; setTimeout(() => (el.style.opacity = "0"), 2400); }
const fmtSize = (n: number | null): string => (n == null ? "" : n < 1024 ? n + " B" : n < 1048576 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB");

interface Item { id: number; name: string; description: string | null; type: string | null; owner: string | null; source: string | null; tags: string[]; framework: string | null; controlRef: string | null; validFrom: string | null; validUntil: string | null; url: string | null; sha256: string | null; size: number | null; fresh: string; audits: number[]; }
interface Data { items: Item[]; summary: { total: number; valid: number; expiring: number; expired: number; noValidity: number; withFile: number; byType: Record<string, number> }; types: string[]; audits: { id: number; name: string }[]; }

let DATA: Data | null = null;
let fType = ""; let fFresh = ""; let q = "";

async function api(url: string, method = "GET", body?: unknown): Promise<any> {
  const r = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}

async function load(): Promise<void> {
  try { DATA = await api("/api/evidence-catalogue"); } catch (e) { $("ev-table").innerHTML = `<div style="color:#64748b">${t("ev.loadFail")}: ${esc(e)}</div>`; return; }
  const d = DATA!; const s = d.summary;
  (["f-type"] as const).forEach((id) => { const el = $(id) as HTMLSelectElement; if (!el.options.length) el.innerHTML = `<option value=""></option>` + d.types.map((x) => `<option>${esc(x)}</option>`).join(""); });
  $("ev-kpis").innerHTML = [
    ["total", s.total, "#e2e8f0"], ["valid", s.valid, "#6ee7b7"], ["expiring", s.expiring, "#fcd34d"], ["expired", s.expired, "#fca5a5"], ["withFile", s.withFile, "#93c5fd"],
  ].map(([k, v, c]) => `<div class="kpi"><div class="v" style="color:${c}">${v}</div><div class="l">${t("ev.kpi." + k)}</div></div>`).join("");
  $("ev-facets").innerHTML = `<span class="chip ${fFresh === "" ? "on" : ""}" data-fresh="">${t("ev.all")}</span>` +
    ["valid", "expiring", "expired"].map((f) => `<span class="chip ${fFresh === f ? "on" : ""}" data-fresh="${f}">${t("ev.fr." + f)}</span>`).join("") +
    `&nbsp;` + Object.keys(s.byType).sort().map((ty) => `<span class="chip ${fType === ty ? "on" : ""}" data-type="${esc(ty)}">${esc(ty)} ${s.byType[ty]}</span>`).join("");
  $("ev-facets").querySelectorAll<HTMLElement>("[data-fresh]").forEach((c) => c.onclick = () => { fFresh = c.dataset.fresh!; render(); load2(); });
  $("ev-facets").querySelectorAll<HTMLElement>("[data-type]").forEach((c) => c.onclick = () => { fType = fType === c.dataset.type ? "" : c.dataset.type!; render(); load2(); });
  render();
}
function load2(): void { /* re-highlight chips */ if (DATA) { const s = DATA.summary; $("ev-facets").querySelectorAll<HTMLElement>("[data-fresh]").forEach((c) => c.classList.toggle("on", c.dataset.fresh === fFresh)); void s; } }

function render(): void {
  if (!DATA) return;
  let items = DATA.items;
  if (fType) items = items.filter((i) => (i.type || "Other") === fType);
  if (fFresh) items = items.filter((i) => i.fresh === fFresh);
  if (q) { const ql = q.toLowerCase(); items = items.filter((i) => (i.name + " " + (i.owner || "") + " " + (i.controlRef || "") + " " + (i.framework || "") + " " + i.tags.join(" ")).toLowerCase().includes(ql)); }
  const auditOpts = `<option value="">＋ audit…</option>` + DATA.audits.map((a) => `<option value="${a.id}">${esc(a.name)}</option>`).join("");
  const rows = items.map((i) => {
    const file = i.sha256 ? `<a class="dl" href="/api/blob/${esc(i.sha256)}" download="${esc(i.name)}">📎 ${fmtSize(i.size)}</a>` : i.url ? `<a class="dl" href="${esc(i.url)}" target="_blank" rel="noopener">🔗 URL</a>` : `<span style="color:#64748b">—</span>`;
    return `<tr>
      <td><b>${esc(i.name)}</b>${i.description ? `<div style="font-size:10.5px;color:#64748b">${esc(i.description)}</div>` : ""}${i.tags.map((tg) => `<span class="tag">${esc(tg)}</span>`).join("")}</td>
      <td>${esc(i.type || "")}</td>
      <td style="color:#cbd5e1">${esc(i.owner || "")}${i.source ? `<div style="font-size:10px;color:#64748b">${esc(i.source)}</div>` : ""}</td>
      <td style="font-size:10.5px;color:#a5b4fc">${esc(i.framework || "")}${i.controlRef ? " · " + esc(i.controlRef) : ""}</td>
      <td><input type="date" value="${esc(i.validUntil || "")}" data-vu="${i.id}" style="width:120px"> <span class="fr ${i.fresh}">${t("ev.fr." + i.fresh)}</span></td>
      <td>${file}</td>
      <td>${i.audits.length ? `<span class="tag">🔗 ${i.audits.length}</span>` : ""}<select data-linkaudit="${i.id}" style="width:110px">${auditOpts}</select></td>
      <td><span class="x" data-del="${i.id}" title="${t("ev.delete")}">✕</span></td>
    </tr>`;
  }).join("");
  $("ev-table").innerHTML = `<table class="ev"><thead><tr>
    <th>${t("ev.col.name")}</th><th>${t("ev.col.type")}</th><th>${t("ev.col.owner")}</th><th>${t("ev.col.control")}</th>
    <th>${t("ev.col.validity")}</th><th>${t("ev.col.file")}</th><th>${t("ev.col.audits")}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  $("ev-table").querySelectorAll<HTMLElement>("[data-del]").forEach((x) => x.onclick = async () => { if (!confirm(t("ev.confirmDel"))) return; try { await api(`/api/evidence-catalogue/${x.dataset.del}`, "DELETE"); await load(); } catch (e) { toast(String(e), false); } });
  $("ev-table").querySelectorAll<HTMLInputElement>("[data-vu]").forEach((el) => el.onchange = async () => { try { await api(`/api/evidence-catalogue/${el.dataset.vu}`, "PATCH", { validUntil: el.value }); toast(t("ev.saved")); await load(); } catch (e) { toast(String(e), false); } });
  $("ev-table").querySelectorAll<HTMLSelectElement>("[data-linkaudit]").forEach((el) => el.onchange = async () => { if (!el.value) return; try { await api(`/api/evidence-catalogue/${el.dataset.linkaudit}/audit`, "POST", { auditId: Number(el.value) }); toast(t("ev.linked")); await load(); } catch (e) { toast(String(e), false); } });
}

async function add(): Promise<void> {
  if (!val("f-name") && !(document.getElementById("f-file") as HTMLInputElement).files?.length) { toast(t("ev.needName"), false); return; }
  const meta = { name: val("f-name"), type: val("f-type"), owner: val("f-owner"), source: val("f-source"), framework: val("f-framework"), controlRef: val("f-control"), validFrom: val("f-vf"), validUntil: val("f-vu"), tags: val("f-tags"), description: val("f-desc"), url: val("f-url") };
  const file = (document.getElementById("f-file") as HTMLInputElement).files?.[0];
  try {
    if (file) {
      if (file.size > 25 * 1024 * 1024) { toast(t("ev.tooBig"), false); return; }
      const b64 = await new Promise<string>((res, rej) => { const rd = new FileReader(); rd.onload = () => res(String(rd.result).split(",")[1] || ""); rd.onerror = rej; rd.readAsDataURL(file); });
      await api("/api/evidence-catalogue/upload", "POST", { ...meta, fileName: file.name, contentType: file.type, dataBase64: b64 });
    } else {
      await api("/api/evidence-catalogue", "POST", meta);
    }
    ["f-name", "f-owner", "f-source", "f-framework", "f-control", "f-vf", "f-vu", "f-tags", "f-desc", "f-url"].forEach((id) => (document.getElementById(id) as HTMLInputElement).value = "");
    (document.getElementById("f-file") as HTMLInputElement).value = "";
    toast(t("ev.added")); await load();
  } catch (e) { toast(String(e), false); }
}

initI18n().then(() => {
  $("f-add").onclick = add;
  ($("ev-search") as HTMLInputElement).oninput = (e) => { q = (e.target as HTMLInputElement).value; render(); };
  return load();
});
