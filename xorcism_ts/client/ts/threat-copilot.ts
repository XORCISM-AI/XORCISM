/**
 * threat-copilot.ts — Threat-Intel Copilot (/threat-copilot).
 * Decision-ready triage (Act/Prioritise/Track) + a multi-mode analyst (Ask/Investigate/Draft/Challenge)
 * that shows the queries it ran and the sources it cited. Exvora-inspired; grounded in XORCISM data.
 */
export {}; // module scope (keeps $/esc local) — esbuild bundles this entry standalone
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
// i18n: session-ui exposes the translator as window.t; fall back to the English default.
function t(k: string, fb: string): string { const fn = (window as any).t; const v = fn ? fn(k) : k; return v === k ? fb : v; }
// Translate the static HTML chrome via custom data-t* attributes (English preserved as fallback → FR-only keys).
function translateChrome(): void {
  document.querySelectorAll<HTMLElement>("[data-t]").forEach((el) => { el.childNodes.length && el.firstChild && el.firstChild.nodeType === 3 ? (el.firstChild.textContent = t(el.getAttribute("data-t")!, (el.firstChild.textContent || "").trim())) : (el.textContent = t(el.getAttribute("data-t")!, (el.textContent || "").trim())); });
  document.querySelectorAll<HTMLElement>("[data-t-html]").forEach((el) => { el.innerHTML = t(el.getAttribute("data-t-html")!, el.innerHTML); });
  document.querySelectorAll<HTMLElement>("[data-t-ph]").forEach((el) => { el.setAttribute("placeholder", t(el.getAttribute("data-t-ph")!, el.getAttribute("placeholder") || "")); });
}

interface DecisionItem { vid: number; cve: string; title: string; decision: "Act" | "Prioritise" | "Track"; confidence: string; kev: boolean; epss: number | null; cvss: number | null; ssvc: string | null; assets: number; why: string; }
interface Feed { scope: string; summary: { act: number; prioritise: number; track: number; total: number }; items: DecisionItem[]; }
interface CopilotQuery { label: string; detail: string; count?: number }
interface CopilotSource { type: string; ref: string; label: string }
interface CopilotAnswer { mode: string; answer: string; queries: CopilotQuery[]; sources: CopilotSource[]; model: string; offline: boolean }

let mode = "ask";
const pct = (e: number | null): string => (e == null ? "—" : `${(e * 100).toFixed(0)}%`);

// ── Affected-assets expander (reuses the fusion endpoint) ────────────────────────
interface ImpactedAsset { id: number; name: string; criticality: string | null; businessValue: number | null; address: string | null; publicFacing: boolean; }
function assetItemHtml(a: ImpactedAsset): string {
  const link = `/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}`;
  const meta = [a.criticality ? esc(a.criticality) : "", a.publicFacing ? t("tcp.internetFacing", "internet-facing") : "", a.address ? esc(a.address) : ""].filter(Boolean).join(" · ");
  return `<a href="${link}" style="display:inline-block;background:#0f1322;border:1px solid #2d3250;border-radius:6px;padding:4px 9px;font-size:12px;color:#e2e8f0;text-decoration:none;margin:2px 4px 2px 0"><b>${esc(a.name)}</b>${meta ? ` <span class="muted" style="font-size:11px">${meta}</span>` : ""}</a>`;
}
async function toggleAssets(btn: HTMLButtonElement): Promise<void> {
  const vid = Number(btn.dataset.aff);
  const tr = btn.closest("tr") as HTMLTableRowElement | null; if (!tr) return;
  const next = tr.nextElementSibling as HTMLElement | null;
  if (next && next.classList.contains("tc-asset-detail")) { next.remove(); btn.innerHTML = btn.innerHTML.replace("▴", "▾"); return; }
  btn.innerHTML = btn.innerHTML.replace("▾", "▴");
  const detail = document.createElement("tr"); detail.className = "tc-asset-detail";
  detail.innerHTML = `<td colspan="7" style="background:#0b0d14"><div class="tc-asset-box" style="padding:8px 6px">${esc(t("tcp.loadingAssets", "Loading assets…"))}</div></td>`;
  tr.parentElement!.insertBefore(detail, tr.nextSibling);
  try {
    const r = await fetch(`/api/fusion/vuln/${vid}/assets`);
    const dd = await r.json(); if (!r.ok) throw new Error(dd.error || `HTTP ${r.status}`);
    const list = (dd.assets || []) as ImpactedAsset[];
    detail.querySelector(".tc-asset-box")!.innerHTML = list.length
      ? `<div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">${esc(t("tcp.impactedAssets", "Impacted assets"))} (${list.length})</div>${list.map(assetItemHtml).join("")}`
      : `<span class="muted">${esc(t("tcp.noAssets", "No affected assets found."))}</span>`;
  } catch (e) { detail.querySelector(".tc-asset-box")!.innerHTML = `<span class="muted">⚠️ ${esc(e)}</span>`; }
}

async function loadFeed(): Promise<void> {
  try {
    const r = await fetch("/api/threat-copilot/feed");
    const d = (await r.json()) as Feed;
    if (!r.ok) throw new Error((d as unknown as { error?: string }).error || `HTTP ${r.status}`);
    $("tc-scope").textContent = `— ${t("tcp.scope", "scope")}: ${d.scope === "estate" ? t("tcp.scopeEstate", "your asset estate") : t("tcp.scopeGlobal", "global KEV / high-EPSS frontier")}`;
    $("tc-chips").innerHTML =
      `<div class="tc-chip act"><div class="n">${d.summary.act}</div><div class="l">${t("tcp.actNow", "Act now")}</div></div>` +
      `<div class="tc-chip prioritise"><div class="n">${d.summary.prioritise}</div><div class="l">${t("tcp.prioritise", "Prioritise")}</div></div>` +
      `<div class="tc-chip track"><div class="n">${d.summary.track}</div><div class="l">${t("tcp.track", "Track")}</div></div>` +
      `<div class="tc-chip scope"><div class="n">${d.summary.total}</div><div class="l">${t("tcp.scoredTotal", "scored total")}</div></div>`;
    const body = $("tc-feed-body");
    if (!d.items.length) { body.innerHTML = `<tr><td colspan="7" class="muted">${t("tcp.noScored", "No scored vulnerabilities found.")}</td></tr>`; return; }
    body.innerHTML = d.items.map((i) => {
      const cveCell = i.vid
        ? `<a href="/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=VulnerabilityID&filterVal=${i.vid}" title="${t("tcp.viewAv", "View matching ASSETVULNERABILITYs")}" style="text-decoration:none"><span class="cve">${esc(i.cve)}</span></a>`
        : `<span class="cve">${esc(i.cve)}</span>`;
      const assetsCell = i.assets
        ? (i.vid
          ? `<button class="tc-aff" data-aff="${i.vid}" title="${t("tcp.viewAssets", "View affected assets")}" style="background:#1e2440;border:1px solid #2d3250;color:#cbd5e1;border-radius:6px;padding:1px 7px;font-size:11.5px;cursor:pointer">${i.assets} ▾</button>`
          : String(i.assets))
        : "—";
      return `<tr>
        <td><span class="pill ${i.decision}">${esc(i.decision)}</span></td>
        <td>${cveCell}${i.kev ? ` <span class="kev" title="${t("tcp.kevTitle", "CISA KEV — actively exploited")}">KEV</span>` : ""}<div class="muted" style="font-size:11px;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.title)}</div></td>
        <td style="max-width:280px">${esc(i.why)}</td>
        <td>${pct(i.epss)}</td>
        <td>${i.cvss == null ? "—" : esc(i.cvss)}</td>
        <td>${assetsCell}</td>
        <td>${esc(i.confidence)}</td>
      </tr>`;
    }).join("");
    body.querySelectorAll<HTMLButtonElement>(".tc-aff").forEach((b) => b.onclick = () => void toggleAssets(b));
  } catch (e) { $("tc-feed-body").innerHTML = `<tr><td colspan="7" class="muted">⚠️ ${esc(String(e))}</td></tr>`; }
}

async function run(): Promise<void> {
  const q = ($("tc-q") as HTMLTextAreaElement).value.trim();
  const btn = $("tc-run") as HTMLButtonElement; btn.disabled = true;
  $("tc-status").textContent = t("tcp.thinking", "Thinking…"); $("tc-answer").style.display = "none"; $("tc-metawrap").style.display = "none";
  try {
    const r = await fetch("/api/threat-copilot/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode, question: q }) });
    const d = (await r.json()) as CopilotAnswer;
    if (!r.ok) throw new Error((d as unknown as { error?: string }).error || `HTTP ${r.status}`);
    $("tc-answer").textContent = d.answer; $("tc-answer").style.display = "block";
    $("tc-prov").innerHTML = d.offline ? `<span class="badge-off">${t("tcp.offlineSynth", "offline synthesis")}</span>` : `<span class="badge-ai">${t("tcp.localAi", "local AI")}: ${esc(d.model)}</span>`;
    $("tc-queries").innerHTML = d.queries.map((qq) => `<div class="tc-q">${esc(qq.label)}${qq.count != null ? ` <span class="c">(${qq.count})</span>` : ""}<div class="muted" style="font-size:10.5px">${esc(qq.detail)}</div></div>`).join("") || `<div class="muted">${t("tcp.none", "none")}</div>`;
    $("tc-sources").innerHTML = d.sources.map((s) => `<span class="src"><span class="t">${esc(s.type)}</span> ${esc(s.label)}</span>`).join("") || `<div class="muted">${t("tcp.none", "none")}</div>`;
    $("tc-metawrap").style.display = "flex";
    $("tc-status").textContent = "";
  } catch (e) { $("tc-status").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  translateChrome();
  document.querySelectorAll<HTMLButtonElement>(".tc-mode").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tc-mode").forEach((x) => x.classList.remove("active"));
    b.classList.add("active"); mode = b.dataset.mode || "ask";
  }));
  $("tc-run").addEventListener("click", () => void run());
  ($("tc-q") as HTMLTextAreaElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter" && (e as KeyboardEvent).ctrlKey) void run(); });
  void loadFeed();
});
