/**
 * chatops.ts — client for the in-app ChatOps console (/chatops). Sends commands to
 * /api/chatops/command and renders the (Slack-mrkdwn-ish) replies as a chat thread.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
const QUICK = ["posture", "digest", "exposures", "obligations", "ai", "queue", "help"];

/** Minimal Slack-mrkdwn → HTML (escape first). */
function mrkdwn(s: string): string {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*([^*]+)\*/g, "<b>$1</b>")
    .replace(/_([^_]+)_/g, "<i>$1</i>")
    .replace(/:white_check_mark:/g, "✅").replace(/:lock:/g, "🔒").replace(/:tada:/g, "🎉")
    .replace(/:red_circle:/g, "🔴").replace(/:large_yellow_circle:/g, "🟡");
}

function add(role: "you" | "bot", text: string): void {
  const log = $("log"); if (!log) return;
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.innerHTML = `<div class="av">${role === "you" ? "you" : "🤖"}</div><div class="bub">${role === "you" ? esc(text) : mrkdwn(text)}</div>`;
  log.appendChild(div); log.scrollTop = log.scrollHeight;
}

async function send(text: string): Promise<void> {
  const t = text.trim(); if (!t) return;
  add("you", t);
  try {
    const r = await fetch("/api/chatops/command", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: t }) });
    const d = await r.json();
    add("bot", d.text || d.error || "(no reply)");
  } catch (e) { add("bot", `⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  const q = $("quick");
  if (q) for (const c of QUICK) { const b = document.createElement("button"); b.className = "q"; b.textContent = c; b.addEventListener("click", () => void send(c)); q.appendChild(b); }
  const inp = $("inp") as HTMLInputElement;
  const fire = (): void => { const v = inp.value; inp.value = ""; void send(v); };
  $("send")?.addEventListener("click", fire);
  inp?.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") fire(); });
  add("bot", "*XORCISM ChatOps.* Type `help` for commands, or tap a quick command above.");
});
