/**
 * ask.ts — "Ask the threat model" page: queries the local AI (Ollama) via
 * /api/ai/ask, which does RAG over the XORCISM data (KEV/assets, ATT&CK, hunts).
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }

const EXAMPLE_KEYS = ["ask.ex1", "ask.ex2", "ask.ex3", "ask.ex4"];

async function refreshStatus(): Promise<void> {
  const el = $("ai-status");
  try {
    const s = await (await fetch("/api/ai/status")).json() as { reachable: boolean; model: string };
    if (s.reachable) { el.textContent = `🟢 Ollama · ${s.model}`; el.className = "ai-badge ai-up"; }
    else { el.textContent = t("hunt.aiDown"); el.className = "ai-badge ai-down"; }
  } catch {
    el.textContent = t("hunt.aiDown"); el.className = "ai-badge ai-down";
  }
}

async function ask(): Promise<void> {
  const q = ($("ask-q") as HTMLTextAreaElement).value.trim();
  if (!q) return;
  const out = $("ask-answer");
  const src = $("ask-sources");
  const btn = $("ask-btn") as HTMLButtonElement;
  out.textContent = t("ask.thinking");
  src.textContent = "";
  btn.disabled = true;
  try {
    const r = await fetch("/api/ai/ask", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: q }),
    });
    const d = await r.json() as { answer?: string; sources?: string[]; model?: string; error?: string };
    if (!r.ok) { out.textContent = "⚠️ " + (d.error || `${t("hunt.errHttp")} ${r.status}`); }
    else {
      out.textContent = d.answer || t("hunt.emptyResp");
      src.textContent = (d.sources && d.sources.length)
        ? `${t("ask.contextLabel")} ${d.sources.join(", ")} · ${t("hunt.modelLabel")} ${d.model}`
        : `${t("ask.noContext")} ${d.model}`;
    }
  } catch (e) {
    out.textContent = "⚠️ " + String(e);
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  const ex = $("ask-examples");
  for (const k of EXAMPLE_KEYS) {
    const label = t(k);
    const b = document.createElement("button");
    b.textContent = label;
    b.onclick = () => { ($("ask-q") as HTMLTextAreaElement).value = label; void ask(); };
    ex.appendChild(b);
  }
  $("ask-btn").onclick = () => void ask();
  ($("ask-q") as HTMLTextAreaElement).addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter" && (e as KeyboardEvent).ctrlKey) { e.preventDefault(); void ask(); }
  });
  void refreshStatus();
});
