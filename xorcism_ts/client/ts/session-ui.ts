/**
 * session-ui.ts — Injects into the top bar: the current user,
 * an Admin link (if admin) and a logout button. Included on all
 * the authenticated pages.
 */

import { t, createLanguageSelect } from "./i18n";
import { createThemeSelect } from "./theme"; // also applies the stored theme (import → initTheme)
import { passkeySupported, registerPasskey, listPasskeys, deletePasskey, PasskeyInfo } from "./passkey";

// The language selector is now hosted in the Settings panel: we
// tell initLanguageSelector (other bundle) NOT to mount one in the
// top bar. Set as soon as the module loads (the bar is already parsed).
document.querySelector(".topbar")?.setAttribute("data-lang-external", "1");

function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

// "Settings" panel: user preferences (display, security…).
// Hosts the language selector, the PIN and the passkey management.
function openSettings(me: any): void {
  const bg = document.createElement("div");
  bg.style.cssText =
    "position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:2000";
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  const card = document.createElement("div");
  card.style.cssText =
    "background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:18px;width:460px;max-width:94vw";

  const title = document.createElement("div");
  title.style.cssText = "font-size:15px;font-weight:600;color:var(--text);margin-bottom:14px";
  title.textContent = `⚙️ ${t("nav.settings")}`;
  card.appendChild(title);

  // A titled section (e.g. Display, Security).
  const section = (label: string): HTMLDivElement => {
    const s = document.createElement("div");
    s.style.cssText = "margin-bottom:16px";
    const h = document.createElement("div");
    h.style.cssText =
      "font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim);" +
      "margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:4px";
    h.textContent = label;
    s.appendChild(h);
    return s;
  };
  // A label ↔ control row.
  const row = (labelText: string, control: HTMLElement): HTMLDivElement => {
    const r = document.createElement("div");
    r.style.cssText =
      "display:flex;align-items:center;justify-content:space-between;gap:12px;margin:6px 0";
    const l = document.createElement("span");
    l.style.cssText = "font-size:13px;color:var(--text-soft)";
    l.textContent = labelText;
    r.appendChild(l);
    r.appendChild(control);
    return r;
  };

  // ── Display: theme + language ──
  const display = section(t("settings.display"));
  display.appendChild(row(t("settings.theme"), createThemeSelect()));
  display.appendChild(row(t("common.language"), createLanguageSelect()));
  card.appendChild(display);

  // ── Security: PIN + passkeys ──
  const security = section(t("settings.security"));
  const pinBtn = document.createElement("button");
  pinBtn.className = "btn btn-ghost btn-sm";
  pinBtn.textContent = t("nav.setPin") + (me.pinSet ? " ✓" : "");
  pinBtn.title = me.pinSet ? t("tip.pinChange") : t("tip.pinSet");
  pinBtn.onclick = async () => {
    const pin = prompt(t("dialog.pinPrompt"));
    if (pin === null) return;
    const body = pin.trim() === "" ? { clear: true } : { pin: pin.trim() };
    try {
      const r = await fetch("/api/auth/set-pin", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { alert(d.error || "Échec."); return; }
      me.pinSet = !!d.pinSet;
      pinBtn.textContent = t("nav.setPin") + (d.pinSet ? " ✓" : "");
      alert(d.pinSet ? "PIN enregistré." : "PIN retiré.");
    } catch {
      alert("Échec réseau.");
    }
  };
  security.appendChild(row(t("settings.pin"), pinBtn));

  if (passkeySupported()) {
    const pkBtn = document.createElement("button");
    pkBtn.className = "btn btn-ghost btn-sm";
    pkBtn.textContent = t("passkey.manage");
    pkBtn.title = t("passkey.manage");
    pkBtn.onclick = openPasskeyManager;
    security.appendChild(row(t("settings.passkeys"), pkBtn));
  }
  card.appendChild(security);

  // ── Notifications: which events auto-create a notification ──
  const notif = section(t("settings.notifications"));
  const notifBtn = document.createElement("button");
  notifBtn.className = "btn btn-ghost btn-sm";
  notifBtn.textContent = t("settings.manageRules");
  notifBtn.title = t("settings.manageRules");
  notifBtn.onclick = openNotificationRules;
  notif.appendChild(row(t("settings.notifEvents"), notifBtn));
  card.appendChild(notif);

  const footer = document.createElement("div");
  footer.style.cssText = "display:flex;justify-content:flex-end";
  const closeBtn = document.createElement("button");
  closeBtn.className = "btn btn-ghost btn-sm";
  closeBtn.textContent = t("modal.close") || "Fermer";
  closeBtn.onclick = () => bg.remove();
  footer.appendChild(closeBtn);
  card.appendChild(footer);

  bg.appendChild(card);
  document.body.appendChild(bg);
}

// Notification rules manager: which events auto-create a notification for the current user.
// Each event has an on/off toggle, a minimum-severity threshold, and a "Test" button.
interface NotifRule { key: string; label: string; description: string; category: string; level: string; defaultEnabled: boolean; enabled: boolean; minLevel: string; configured: boolean; }
function openNotificationRules(): void {
  const bg = document.createElement("div");
  bg.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:2001";
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  const card = document.createElement("div");
  card.style.cssText = "background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:18px;width:560px;max-width:94vw;max-height:88vh;display:flex;flex-direction:column";
  card.innerHTML =
    `<div style="font-size:15px;font-weight:600;color:var(--text);margin-bottom:2px">🔔 ${t("settings.notifRulesTitle")}</div>` +
    `<div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${t("settings.notifRulesHint")}</div>`;
  const list = document.createElement("div");
  list.style.cssText = "overflow:auto;border:1px solid var(--border);border-radius:8px;background:var(--bg);margin-bottom:12px";
  card.appendChild(list);

  function levelSelect(cur: string): HTMLSelectElement {
    const s = document.createElement("select");
    s.className = "btn btn-ghost btn-sm";
    s.style.cssText = "font-size:11px;padding:2px 4px";
    for (const [v, l] of [["info", "Info+"], ["warning", "Warning+"], ["error", "Error only"]]) {
      const o = document.createElement("option"); o.value = v; o.textContent = l; if (v === cur) o.selected = true; s.appendChild(o);
    }
    return s;
  }

  async function put(key: string, body: Record<string, unknown>): Promise<void> {
    await fetch(`/api/notification-rules/${encodeURIComponent(key)}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  }

  function render(events: NotifRule[]): void {
    list.innerHTML = "";
    let lastCat = "";
    for (const ev of events) {
      if (ev.category !== lastCat) {
        lastCat = ev.category;
        const h = document.createElement("div");
        h.style.cssText = "font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim);padding:8px 10px 4px;background:var(--surface-2);position:sticky;top:0";
        h.textContent = ev.category;
        list.appendChild(h);
      }
      const r = document.createElement("div");
      r.style.cssText = "display:flex;align-items:center;gap:8px;padding:8px 10px;border-top:1px solid var(--border)";
      const main = document.createElement("div"); main.style.cssText = "flex:1;min-width:0";
      main.innerHTML = `<div style="font-size:13px;color:var(--text)">${esc(ev.label)}</div>` +
        `<div style="font-size:11px;color:var(--text-muted)">${esc(ev.description)}</div>`;
      // toggle
      const toggle = document.createElement("input"); toggle.type = "checkbox"; toggle.checked = ev.enabled;
      toggle.style.cssText = "width:16px;height:16px;cursor:pointer;flex:0 0 auto";
      // min-level
      const sel = levelSelect(ev.minLevel); sel.disabled = !ev.enabled;
      // test
      const testBtn = document.createElement("button"); testBtn.className = "btn btn-ghost btn-sm"; testBtn.textContent = t("settings.notifTest"); testBtn.style.cssText = "font-size:11px;padding:2px 8px;flex:0 0 auto";
      toggle.onchange = async () => { sel.disabled = !toggle.checked; await put(ev.key, { enabled: toggle.checked, minLevel: sel.value }); ev.enabled = toggle.checked; };
      sel.onchange = async () => { await put(ev.key, { enabled: toggle.checked, minLevel: sel.value }); };
      testBtn.onclick = async () => {
        testBtn.disabled = true;
        try {
          const res = await fetch("/api/notification-rules/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ eventKey: ev.key }) });
          const d = await res.json().catch(() => ({}));
          testBtn.textContent = d.wouldNotify ? "✓" : t("settings.notifMuted");
          window.dispatchEvent(new CustomEvent("xorcism:notifications-refresh"));
          setTimeout(() => { testBtn.textContent = t("settings.notifTest"); testBtn.disabled = false; }, 1600);
        } catch { testBtn.disabled = false; }
      };
      const right = document.createElement("div"); right.style.cssText = "display:flex;align-items:center;gap:6px;flex:0 0 auto";
      right.appendChild(sel); right.appendChild(testBtn); right.appendChild(toggle);
      r.appendChild(main); r.appendChild(right);
      list.appendChild(r);
    }
  }

  const footer = document.createElement("div");
  footer.style.cssText = "display:flex;justify-content:flex-end";
  const closeBtn = document.createElement("button");
  closeBtn.className = "btn btn-ghost btn-sm";
  closeBtn.textContent = t("modal.close") || "Fermer";
  closeBtn.onclick = () => bg.remove();
  footer.appendChild(closeBtn);
  card.appendChild(footer);

  list.innerHTML = `<div style="padding:12px;color:var(--text-dim);font-size:12px">…</div>`;
  fetch("/api/notification-rules").then((r) => r.json()).then((d) => render(d.events || [])).catch(() => { list.innerHTML = `<div style="padding:12px;color:var(--danger);font-size:12px">${t("common.error") || "Error"}</div>`; });

  bg.appendChild(card);
  document.body.appendChild(bg);
}

// Passkey manager (list / add / removal) in a modal window.
function openPasskeyManager(): void {
  const bg = document.createElement("div");
  bg.style.cssText =
    "position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:2000";
  const card = document.createElement("div");
  card.style.cssText =
    "background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:18px;width:460px;max-width:94vw";
  card.innerHTML =
    `<div style="font-size:15px;font-weight:600;color:var(--text);margin-bottom:4px">🔑 ${t("passkey.manage")}</div>` +
    `<div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${t("passkey.hint")}</div>`;
  const list = document.createElement("div");
  list.style.cssText = "max-height:46vh;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg);margin-bottom:12px";
  card.appendChild(list);
  const err = document.createElement("div");
  err.style.cssText = "color:var(--danger);font-size:12px;min-height:16px;margin-bottom:8px";
  card.appendChild(err);

  const footer = document.createElement("div");
  footer.style.cssText = "display:flex;gap:8px;justify-content:flex-end";
  const addBtn = document.createElement("button");
  addBtn.className = "btn btn-primary btn-sm";
  addBtn.textContent = t("passkey.add");
  const closeBtn = document.createElement("button");
  closeBtn.className = "btn btn-ghost btn-sm";
  closeBtn.textContent = t("modal.close") || "Fermer";
  closeBtn.onclick = () => bg.remove();
  footer.appendChild(addBtn);
  footer.appendChild(closeBtn);
  card.appendChild(footer);

  async function refresh(): Promise<void> {
    list.innerHTML = `<div style="padding:10px;color:var(--text-dim);font-size:12px">…</div>`;
    let items: PasskeyInfo[] = [];
    try { items = await listPasskeys(); } catch { /* ignore */ }
    list.innerHTML = "";
    if (!items.length) {
      list.innerHTML = `<div style="padding:10px;color:var(--text-dim);font-size:12px">${t("passkey.none")}</div>`;
      return;
    }
    for (const k of items) {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;align-items:center;gap:8px;padding:8px 10px;border-bottom:1px solid #1e2236";
      const info = document.createElement("div");
      info.style.cssText = "flex:1;min-width:0";
      const nm = document.createElement("div");
      nm.textContent = k.Name || "Clé d'accès";
      nm.style.cssText = "font-size:13px;color:var(--text)";
      const meta = document.createElement("div");
      meta.textContent = `${t("passkey.created")}: ${k.CreatedDate || "?"}` +
        (k.LastUsedDate ? ` · ${t("passkey.lastUsed")}: ${k.LastUsedDate}` : "");
      meta.style.cssText = "font-size:11px;color:var(--text-dim)";
      info.appendChild(nm); info.appendChild(meta);
      const rm = document.createElement("button");
      rm.className = "btn btn-ghost btn-sm";
      rm.textContent = "✕";
      rm.title = t("passkey.remove");
      rm.onclick = async () => {
        if (!confirm(t("passkey.confirmRemove"))) return;
        try { await deletePasskey(k.CredentialID); await refresh(); }
        catch { err.textContent = "Échec de la suppression."; }
      };
      row.appendChild(info); row.appendChild(rm);
      list.appendChild(row);
    }
  }

  addBtn.onclick = async () => {
    err.textContent = "";
    const name = prompt(t("passkey.namePrompt"), t("dialog.passkeyDefault"));
    if (name === null) return;
    addBtn.disabled = true;
    try { await registerPasskey(name.trim() || "Clé d'accès"); await refresh(); }
    catch (e) { err.textContent = (e as Error).message || "Échec de l'enregistrement."; }
    finally { addBtn.disabled = false; }
  };

  bg.appendChild(card);
  document.body.appendChild(bg);
  void refresh();
}

document.addEventListener("DOMContentLoaded", async () => {
  let me: any = null;
  try {
    const r = await fetch("/api/auth/me");
    if (r.ok) me = await r.json();
  } catch {
    /* ignore */
  }
  if (!me) {
    location.href = "/login";
    return;
  }
  if (me.mustChangePassword) {
    location.href = "/login";
    return;
  }

  const bar = document.querySelector(".topbar");
  if (!bar) return;

  // The language selector lives in Settings: marks the bar and removes any
  // selector already mounted by initLanguageSelector (depending on the script order).
  bar.setAttribute("data-lang-external", "1");
  bar.querySelectorAll(".lang-select").forEach((el) => el.remove());

  // Ensures a spacer to push the elements to the right
  if (!bar.querySelector(".spacer")) {
    const sp = document.createElement("span");
    sp.className = "spacer";
    bar.appendChild(sp);
  }

  const wrap = document.createElement("span");
  wrap.style.cssText = "display:flex;align-items:center;gap:12px;margin-left:12px";

  if (me.isAdmin) {
    const admin = document.createElement("a");
    admin.href = "/admin";
    admin.textContent = t("nav.admin");
    wrap.appendChild(admin);
  }

  // Current tenant (multi-tenant)
  if (me.tenantName) {
    const tn = document.createElement("span");
    tn.style.cssText =
      "font-size:11px;background:#1e3a5f;color:#bfdbfe;border-radius:10px;padding:2px 9px";
    tn.textContent = `🏢 ${me.tenantName}`;
    if (me.isSuperAdmin) tn.title = t("admin.superAdmin");
    wrap.appendChild(tn);
  }

  // Settings: display (language), security (PIN, passkeys)…
  const settingsBtn = document.createElement("button");
  settingsBtn.className = "btn btn-ghost btn-sm";
  settingsBtn.textContent = `⚙️ ${t("nav.settings")}`;
  settingsBtn.title = t("nav.settings");
  settingsBtn.onclick = () => openSettings(me);
  wrap.appendChild(settingsBtn);

  const logout = document.createElement("button");
  logout.className = "btn btn-ghost btn-sm";
  logout.textContent = t("nav.logout");
  logout.onclick = async () => {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    location.href = "/login";
  };
  wrap.appendChild(logout);

  bar.appendChild(wrap);
});
