/**
 * questionnaire-assistant.ts — Security Questionnaire Auto-Answer (/questionnaire-assistant).
 * Paste questions → drafted answers from XORCISM's knowledge base (library + policies + controls +
 * assurance posture) via /api/questionnaire-assistant, each with sources + confidence + "save to library".
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Ans { question: string; answer: string; sources: string[]; confidence: string; fromLibrary: boolean; ai: boolean; }
interface LibRow { id: number; question: string; answer: string; tags: string; usedCount: number; }

let lastAnswers: Ans[] = [];

function answerCard(a: Ans, i: number): string {
  const conf = `<span class="conf ${esc(a.confidence)}">${esc(t("qa.conf." + a.confidence) || a.confidence)}</span>`;
  const flags = (a.fromLibrary ? `<span class="tag">${t("qa.fromLib")}</span>` : "") + (a.ai ? `<span class="tag">AI</span>` : `<span class="tag">${t("qa.offline")}</span>`);
  return `<div class="qa-item" data-i="${i}">
    <div class="qa-q">${esc(a.question)}</div>
    <div class="qa-a"><textarea class="qa-edit">${esc(a.answer)}</textarea></div>
    <div class="qa-meta">
      ${conf}${flags}
      ${a.sources.length ? `<span class="src">↳ ${a.sources.map(esc).join(" · ")}</span>` : ""}
      <button class="qa-save" data-save="${i}">${t("qa.save")}</button>
    </div>
  </div>`;
}

async function run(): Promise<void> {
  const text = ($("qa-input") as HTMLTextAreaElement).value.trim();
  if (!text) return;
  const btn = $("qa-run") as HTMLButtonElement;
  btn.disabled = true; $("qa-status").textContent = t("qa.drafting");
  try {
    const r = await fetch("/api/questionnaire-assistant/answer", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json() as { answers: Ans[]; ai: boolean; model: string };
    lastAnswers = d.answers || [];
    const status = $("qa-status");
    status.className = "qa-ai" + (d.ai ? " up" : "");
    status.textContent = d.ai ? fmt("qa.aiOn", { model: d.model }) : t("qa.aiOff");
    $("qa-results").innerHTML = lastAnswers.length
      ? `<div class="qa-row" style="margin:0 0 8px"><b>${fmt("qa.drafted", { n: lastAnswers.length })}</b> <button id="qa-csv" class="qa-save">${t("qa.exportCsv")}</button></div>` + lastAnswers.map(answerCard).join("")
      : `<div class="muted">${t("qa.noResults")}</div>`;
    wireResults();
  } catch (e) { $("qa-status").textContent = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

function wireResults(): void {
  document.querySelectorAll<HTMLElement>("[data-save]").forEach((el) => el.addEventListener("click", () => void saveOne(Number(el.dataset.save), el)));
  const csv = document.getElementById("qa-csv");
  if (csv) csv.addEventListener("click", exportCsv);
}

async function saveOne(i: number, btn: HTMLElement): Promise<void> {
  const card = btn.closest(".qa-item"); if (!card) return;
  const answer = (card.querySelector(".qa-edit") as HTMLTextAreaElement).value.trim();
  const question = lastAnswers[i]?.question; if (!question || !answer) return;
  try {
    const r = await fetch("/api/questionnaire-assistant/save", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question, answer }) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    btn.textContent = t("qa.saved"); (btn as HTMLButtonElement).disabled = true;
    void loadLibrary();
  } catch (e) { btn.textContent = `⚠️ ${esc(e)}`; }
}

function exportCsv(): void {
  const rows = [["question", "answer", "confidence", "sources"]].concat(
    lastAnswers.map((a) => [a.question, a.answer, a.confidence, a.sources.join("; ")]));
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const link = document.createElement("a"); link.href = url; link.download = "questionnaire-answers.csv"; link.click();
  URL.revokeObjectURL(url);
}

async function loadLibrary(): Promise<void> {
  let d: { library: LibRow[] };
  try { const r = await fetch("/api/questionnaire-assistant/library"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch { $("qa-library").innerHTML = `<div class="muted">${t("qa.libEmpty")}</div>`; return; }
  const lib = d.library || [];
  $("qa-library").innerHTML = lib.length
    ? `<table class="qa"><thead><tr><th>${t("qa.th.q")}</th><th>${t("qa.th.a")}</th><th style="text-align:right">${t("qa.th.used")}</th><th></th></tr></thead><tbody>${lib.map((l) => `<tr>
        <td>${esc(l.question)}</td><td>${esc(l.answer)}</td><td style="text-align:right">${l.usedCount}</td>
        <td><a class="src" data-del="${l.id}" style="cursor:pointer">✕</a></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted">${t("qa.libEmpty")}</div>`;
  document.querySelectorAll<HTMLElement>("[data-del]").forEach((el) => el.addEventListener("click", async () => {
    await fetch(`/api/questionnaire-assistant/library/${el.dataset.del}`, { method: "DELETE" }); void loadLibrary();
  }));
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("qa-run") as HTMLButtonElement).addEventListener("click", () => void run());
  void loadLibrary();
});
