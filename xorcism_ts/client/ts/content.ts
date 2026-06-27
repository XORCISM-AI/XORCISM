/**
 * content.ts — Content hub (/content). Export/import shareable XORCISM content
 * (attack playbooks, Sigma rules bundle, OpenVEX) as portable files.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function toast(m: string): void { const el = $("co-toast"); el.textContent = m; el.style.display = "block"; setTimeout(() => (el.style.display = "none"), 3500); }

async function download(url: string, name: string): Promise<void> {
  try {
    const r = await fetch(url); if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const blob = await r.blob(); const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name; a.click();
    toast(fmt("chub.exported", { name }));
  } catch (e) { toast(String(e)); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  document.querySelectorAll("button[data-export]").forEach((b) => b.addEventListener("click", () => {
    const el = b as HTMLElement; void download(el.dataset.export!, el.dataset.name || "export.json");
  }));

  ($("co-pb-import") as HTMLInputElement).addEventListener("change", async (ev) => {
    const file = (ev.target as HTMLInputElement).files?.[0]; if (!file) return;
    try {
      const payload = JSON.parse(await file.text());
      const r = await fetch("/api/pentest/playbooks/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      toast(fmt("chub.imported", { n: d.imported }) + (d.skipped ? fmt("chub.skipped", { n: d.skipped }) : ""));
    } catch (e) { toast(String(e)); }
  });

  // best-effort counts
  fetch("/api/pentest/playbooks").then((r) => r.ok ? r.json() : []).then((p) => { $("co-pb-cnt").textContent = fmt("chub.pbCount", { n: p.length }); }).catch(() => {});
});
