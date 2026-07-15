/**
 * report-mapper.ts — Report ATT&CK Mapper studio (native MITRE TRAM, /report-mapper).
 * Paste report text → map each sentence to ATT&CK techniques (keyword + AI) with confidence +
 * evidence, review/accept, save to THREATREPORT + REPORTMAPPING, export a Navigator layer.
 */
import { initI18n } from "./i18n";

interface TechMapping { attackId: string; name: string; confidence: number; source: string }
interface MappedSentence { order: number; text: string; mappings: TechMapping[] }
interface MapResult { sentences: MappedSentence[]; summary: { sentences: number; mapped: number; techniques: number; engine: string; aiReachable: boolean } }
interface MappedReport { id: number; name: string; source: string; created: string | null; mappings: number; techniques: number }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

let LAST: MapResult | null = null;

const SAMPLE = `In March 2026, the threat actor launched a spearphishing campaign, sending emails with a malicious link to employees in the finance department. When a victim clicked the link, a weaponized document with a VBA macro was downloaded. The macro executed an encoded PowerShell command that downloaded the second stage from the command and control server. The malware established persistence by creating a scheduled task named "MicrosoftEdgeUpdate". It then used rundll32 to load a malicious DLL. The actor dumped credentials from LSASS memory and later used Mimikatz to escalate privileges. Lateral movement was performed over RDP to reach the domain controller. Before deploying ransomware, the operators executed vssadmin to delete volume shadow copies. Finally, data was exfiltrated over the existing HTTPS C2 channel to an attacker-controlled server.`;

function techTag(m: TechMapping, si: number, ti: number): string {
  const pct = Math.round(m.confidence * 100);
  return `<div class="rm-tag">
    <input type="checkbox" class="rm-chk rm-accept" data-s="${si}" data-t="${ti}" ${m.confidence >= 0.5 ? "checked" : ""}>
    <a class="rm-tid" href="https://attack.mitre.org/techniques/${esc(m.attackId.replace(".", "/"))}/" target="_blank" rel="noopener">${esc(m.attackId)}</a>
    <span class="rm-tname">${esc(m.name)}</span>
    <span class="rm-src ${esc(m.source)}">${esc(m.source)}</span>
    <span class="rm-bar"><span style="width:${pct}%"></span></span><span class="rm-conf">${pct}%</span>
  </div>`;
}

function render(r: MapResult): void {
  LAST = r;
  const s = r.summary;
  $("rm-engine").textContent = s.aiReachable ? "keyword + AI" : "keyword (offline)";
  $("rm-engine").className = "rm-badge " + (s.aiReachable ? "b-ai" : "b-kw");
  $("rm-stats").innerHTML = [
    ["Sentences", String(s.sentences)],
    ["Mapped", String(s.mapped)],
    ["Techniques", String(s.techniques)],
    ["Engine", s.engine],
  ].map(([l, v]) => `<div class="rm-kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("rm-body").innerHTML = r.sentences.map((sen, si) => {
    const tech = sen.mappings.length
      ? `<div class="rm-tech">${sen.mappings.map((m, ti) => techTag(m, si, ti)).join("")}</div>`
      : `<span class="muted">— no technique —</span>`;
    return `<tr class="${sen.mappings.length ? "" : "rm-nomap"}"><td class="muted">${sen.order + 1}</td><td class="rm-sent">${esc(sen.text)}</td><td>${tech}</td></tr>`;
  }).join("");
  $("rm-results").style.display = "";
}

async function doMap(): Promise<void> {
  const text = ($("rm-text") as HTMLTextAreaElement).value.trim();
  if (text.length < 30) { toast("Paste at least ~30 characters of report text"); return; }
  const btn = $("rm-map") as HTMLButtonElement; btn.disabled = true;
  $("rm-status").textContent = "Mapping to ATT&CK…";
  try {
    const r = await fetch("/api/report-mapper/map", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, useAi: ($("rm-useai") as HTMLInputElement).checked }),
    });
    if (!r.ok) { const e = await r.json().catch(() => ({})); toast(e.error || `Error ${r.status}`); return; }
    render(await r.json() as MapResult);
    $("rm-status").textContent = "";
  } catch (e) { toast((e as Error).message); }
  finally { btn.disabled = false; }
}

async function doSave(): Promise<void> {
  if (!LAST) return;
  const name = ($("rm-name") as HTMLInputElement).value.trim() || "Mapped report";
  // collect accepted mappings per sentence
  const accepted = new Set<string>();
  document.querySelectorAll<HTMLInputElement>(".rm-accept:checked").forEach((c) => accepted.add(`${c.dataset.s}:${c.dataset.t}`));
  const sentences = LAST.sentences.map((sen, si) => ({
    order: sen.order, text: sen.text, disposition: "accept",
    mappings: sen.mappings.filter((_, ti) => accepted.has(`${si}:${ti}`)).map((m) => ({ attackId: m.attackId, name: m.name, confidence: m.confidence })),
  })).filter((s) => s.mappings.length);
  if (!sentences.length) { toast("Tick at least one technique to accept"); return; }
  const btn = $("rm-save") as HTMLButtonElement; btn.disabled = true;
  try {
    const r = await fetch("/api/report-mapper/save", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, text: ($("rm-text") as HTMLTextAreaElement).value.slice(0, 8000), source: "Report Mapper", sentences }),
    });
    const d = await r.json();
    if (r.ok) { $("rm-save-status").textContent = `Saved report #${d.reportId} (${d.mappings} mappings)`; void loadReports(); }
    else toast(d.error || "Save failed");
  } catch (e) { toast((e as Error).message); }
  finally { btn.disabled = false; }
}

async function loadReports(): Promise<void> {
  try {
    const r = await fetch("/api/report-mapper/reports");
    if (!r.ok) return;
    const d = await r.json() as { reports: MappedReport[] };
    $("rm-reports").innerHTML = d.reports.length
      ? d.reports.map((rp) => `<tr>
          <td class="rm-sent">${esc(rp.name)}</td><td class="muted">${esc(rp.source)}</td>
          <td>${rp.techniques}</td><td>${rp.mappings}</td>
          <td><a class="rm-link" href="/api/report-mapper/navigator/${rp.id}" target="_blank" rel="noopener">Navigator layer ↓</a></td></tr>`).join("")
      : `<tr><td colspan="5" class="muted">No mapped reports yet.</td></tr>`;
  } catch { /* ignore */ }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  void loadReports();
  $("rm-map").addEventListener("click", () => void doMap());
  $("rm-save").addEventListener("click", () => void doSave());
  $("rm-sample").addEventListener("click", () => { ($("rm-text") as HTMLTextAreaElement).value = SAMPLE; ($("rm-name") as HTMLInputElement).value = "Sample spearphishing → ransomware campaign"; });
});
