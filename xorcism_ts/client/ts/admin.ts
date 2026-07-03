/**
 * admin.ts — Administration page: roles, granular permissions
 * (pages / databases / tables / fields), users, audit log.
 */

import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}
function toast(msg: string, type: "ok" | "err" = "ok"): void {
  const t = $("toast");
  t.textContent = msg;
  t.className = type === "err" ? "toast-err" : "toast-ok";
  (t as HTMLElement).style.opacity = "1";
  setTimeout(() => ((t as HTMLElement).style.opacity = "0"), 2600);
}
async function jget(url: string): Promise<any> {
  const r = await fetch(url);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}
async function jpost(url: string, body: unknown): Promise<any> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
async function jdelete(url: string): Promise<any> {
  const r = await fetch(url, { method: "DELETE" });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
function escHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}
function fmtDay(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "—" : d.toISOString().slice(0, 10);
}

interface Crud { c: boolean; r: boolean; u: boolean; d: boolean }
type Role = { RoleID: number; RoleName: string; RoleDescription?: string };

type Tenant = {
  TenantID: number;
  TenantName: string;
  IsSystem: number;
  IsActive: number;
  userCount?: number;
};

let roles: Role[] = [];
let currentRoleId = 0;
let isSuperAdmin = false;
let tenants: Tenant[] = [];
let resources: { pages: { path: string; label: string; group?: string }[]; databases: { db: string; tables: string[] }[] } = {
  pages: [],
  databases: [],
};
// permMap key = `${type}:${key}` → Crud
const permMap = new Map<string, Crud>();

function getPerm(type: string, key: string): Crud {
  return permMap.get(`${type}:${key}`) ?? { c: false, r: false, u: false, d: false };
}

async function savePerm(type: string, key: string, crud: Crud): Promise<void> {
  permMap.set(`${type}:${key}`, crud);
  try {
    await jpost(`/api/admin/permissions/${currentRoleId}`, {
      resourceType: type,
      resourceKey: key,
      c: crud.c,
      r: crud.r,
      u: crud.u,
      d: crud.d,
    });
  } catch (e) {
    toast(t("toast.error") + " " + e, "err");
  }
}

// Builds a permissions row (CRUD checkboxes or R only)
function permRow(
  label: string,
  type: string,
  key: string,
  cls: string,
  opts: { which: ("c" | "r" | "u" | "d")[]; toggle?: () => void; toggled?: boolean }
): HTMLElement {
  const row = document.createElement("div");
  row.className = "perm-row " + cls;

  if (opts.toggle) {
    const tg = document.createElement("button");
    tg.className = "toggle";
    tg.textContent = opts.toggled ? "▾" : "▸";
    tg.onclick = opts.toggle;
    row.appendChild(tg);
  } else {
    const sp = document.createElement("span");
    sp.className = "toggle";
    row.appendChild(sp);
  }

  // XID = authentication / identities database (accounts, sessions, rights): very
  // sensitive access → label in red + confirmation when granting a right.
  const danger = key === "XID" || key.startsWith("XID.");
  const lbl = document.createElement("span");
  lbl.className = "lbl";
  lbl.textContent = danger ? "⚠ " + label : label;
  lbl.title = danger ? `${key} ${t("tip.authDb")}` : key;
  if (danger) { lbl.style.color = "var(--danger)"; lbl.style.fontWeight = "600"; row.classList.add("perm-danger"); }
  row.appendChild(lbl);

  const cur = getPerm(type, key);
  (["c", "r", "u", "d"] as const).forEach((k) => {
    const cell = document.createElement("label");
    if (!opts.which.includes(k)) {
      cell.style.visibility = "hidden";
    } else {
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = (cur as any)[k];
      cb.onchange = () => {
        // XID: confirmation before GRANTING a right (checking) — not on removal.
        if (danger && cb.checked && !window.confirm(t("dialog.xidWarn"))) {
          cb.checked = false;
          return;
        }
        const c = getPerm(type, key);
        (c as any)[k] = cb.checked;
        savePerm(type, key, { ...c });
      };
      cell.appendChild(cb);
      cell.appendChild(document.createTextNode(k.toUpperCase()));
    }
    row.appendChild(cell);
  });
  return row;
}

const PAGE_GROUP_LABEL: Record<string, string> = {
  core: "Core", asset: "Asset-Based", exposure: "Vulnerability & Exposure", threat: "Threat",
  risk: "Risk-Based", compliance: "Compliance", operations: "Response & Operations", platform: "Platform",
};
function renderPages(): void {
  const host = $("perm-pages");
  host.innerHTML = "";
  // group the feature pages by approach (collapsible) — there are ~70, so a flat list is unusable.
  const groups: Record<string, { path: string; label: string }[]> = {};
  const order: string[] = [];
  resources.pages.forEach((p) => { const g = p.group || "core"; if (!groups[g]) { groups[g] = []; order.push(g); } groups[g].push(p); });
  for (const g of order) {
    const header = document.createElement("div");
    header.className = "perm-row lvl-db";
    header.style.cursor = "pointer"; header.style.fontWeight = "700";
    header.innerHTML = `<span class="toggle">&#9656;</span> ${PAGE_GROUP_LABEL[g] || g} <span style="color:#64748b;font-weight:400">(${groups[g].length})</span>`;
    let open = false; let box: HTMLElement | null = null;
    header.addEventListener("click", () => {
      open = !open;
      if (open) { box = document.createElement("div"); groups[g].forEach((p) => box!.appendChild(permRow(`${p.label}  (${p.path})`, "page", p.path, "lvl-table", { which: ["r"] }))); header.after(box); }
      else if (box) { box.remove(); box = null; }
      (header.querySelector(".toggle") as HTMLElement).innerHTML = open ? "&#9662;" : "&#9656;";
    });
    host.appendChild(header);
  }
}

function renderData(): void {
  const host = $("perm-data");
  host.innerHTML = "";
  resources.databases.forEach((d) => {
    let tablesOpen = false;
    let tablesBox: HTMLElement | null = null;

    const dbRow = permRow(d.db, "database", d.db, "lvl-db", {
      which: ["c", "r", "u", "d"],
      toggled: false,
      toggle: () => {
        tablesOpen = !tablesOpen;
        if (tablesOpen) {
          tablesBox = document.createElement("div");
          d.tables.forEach((t) => renderTableRow(tablesBox!, d.db, t));
          dbRow.after(tablesBox);
        } else if (tablesBox) {
          tablesBox.remove();
          tablesBox = null;
        }
        (dbRow.querySelector(".toggle") as HTMLElement).textContent = tablesOpen ? "▾" : "▸";
      },
    });
    host.appendChild(dbRow);
  });
}

function renderTableRow(host: HTMLElement, db: string, table: string): void {
  let fieldsOpen = false;
  let fieldsBox: HTMLElement | null = null;
  const key = `${db}.${table}`;

  const row = permRow(table, "table", key, "lvl-table", {
    which: ["c", "r", "u", "d"],
    toggle: async () => {
      fieldsOpen = !fieldsOpen;
      if (fieldsOpen) {
        fieldsBox = document.createElement("div");
        row.after(fieldsBox);
        try {
          const fields: string[] = await jget(
            `/api/admin/fields?db=${encodeURIComponent(db)}&table=${encodeURIComponent(table)}`
          );
          fields.forEach((f) =>
            fieldsBox!.appendChild(
              permRow(f, "field", `${db}.${table}.${f}`, "lvl-field", { which: ["c", "r", "u", "d"] })
            )
          );
        } catch (e) {
          toast(t("toast.errFields") + " " + e, "err");
        }
      } else if (fieldsBox) {
        fieldsBox.remove();
        fieldsBox = null;
      }
      (row.querySelector(".toggle") as HTMLElement).textContent = fieldsOpen ? "▾" : "▸";
    },
  });
  host.appendChild(row);
}

async function selectRole(roleId: number): Promise<void> {
  currentRoleId = roleId;
  permMap.clear();
  try {
    const perms: any[] = await jget(`/api/admin/permissions/${roleId}`);
    perms.forEach((p) =>
      permMap.set(`${p.ResourceType}:${p.ResourceKey}`, {
        c: !!p.CanCreate,
        r: !!p.CanRead,
        u: !!p.CanUpdate,
        d: !!p.CanDelete,
      })
    );
  } catch (e) {
    toast(t("toast.errPermissions") + " " + e, "err");
  }
  renderPages();
  renderData();
}

// Fills the roles multiselect of the "new user" form
function populateRoleOptions(): void {
  const nu = $("nu-roles") as HTMLSelectElement;
  nu.innerHTML = "";
  roles.forEach((r) => {
    const o = document.createElement("option");
    o.value = String(r.RoleID);
    o.textContent = r.RoleName;
    nu.appendChild(o);
  });
}

// Loads the roles list (without the permissions editor — tenant-admin usage)
async function loadRolesList(): Promise<void> {
  roles = await jget("/api/admin/roles");
  populateRoleOptions();
}

// Super-admin: roles + permissions editor
async function loadRoles(): Promise<void> {
  roles = await jget("/api/admin/roles");
  const sel = $("role-select") as HTMLSelectElement;
  sel.innerHTML = "";
  roles.forEach((r) => {
    const o = document.createElement("option");
    o.value = String(r.RoleID);
    o.textContent = r.RoleName;
    sel.appendChild(o);
  });
  populateRoleOptions();
  if (roles.length) await selectRole(Number(sel.value || roles[0].RoleID));
}

// ── Tenants (super-admin) ──────────────────────────────────────────────────────
async function loadTenants(): Promise<void> {
  tenants = await jget("/api/admin/tenants");
  renderTenantsTable();

  // "tenant" filter of the users list
  const filt = $("user-tenant-filter") as HTMLSelectElement;
  const prev = filt.value;
  filt.innerHTML = `<option value="">${t("admin.allTenants")}</option>`;
  tenants.forEach((tn) => {
    const o = document.createElement("option");
    o.value = String(tn.TenantID);
    o.textContent = tn.TenantName;
    filt.appendChild(o);
  });
  filt.value = prev;

  // "tenant" selector of the creation form
  const nu = $("nu-tenant") as HTMLSelectElement;
  nu.innerHTML = "";
  tenants
    .filter((tn) => tn.IsActive)
    .forEach((tn) => {
      const o = document.createElement("option");
      o.value = String(tn.TenantID);
      o.textContent = tn.TenantName;
      nu.appendChild(o);
    });
}

function renderTenantsTable(): void {
  const tb = $("tenants-tbody");
  tb.innerHTML = "";
  tenants.forEach((tn) => {
    const tr = document.createElement("tr");
    const sysPill = tn.IsSystem ? ` <span class="pill">${t("admin.system")}</span>` : "";
    tr.innerHTML = `<td>${tn.TenantName}${sysPill}</td><td>${tn.userCount ?? ""}</td>`;

    const tdStatus = document.createElement("td");
    tdStatus.innerHTML = tn.IsActive
      ? `<span class="pill" style="background:#14532d;color:#86efac">${t("admin.active")}</span>`
      : `<span class="pill" style="background:#7f1d1d;color:#fecaca">${t("admin.inactive")}</span>`;
    tr.appendChild(tdStatus);

    const tdAct = document.createElement("td");
    if (!tn.IsSystem) {
      const b = document.createElement("button");
      b.className = "btn btn-ghost btn-sm";
      b.textContent = tn.IsActive ? t("admin.disable") : t("admin.enable");
      b.onclick = async () => {
        try {
          await jpost(`/api/admin/tenants/${tn.TenantID}/active`, { active: !tn.IsActive });
          await loadTenants();
        } catch (e) {
          toast(t("toast.error") + " " + e, "err");
        }
      };
      tdAct.appendChild(b);
    }
    tr.appendChild(tdAct);
    tb.appendChild(tr);
  });
}

// ── Agent enrollment keys (managed XOR_ENROLL_KEYs) ────────────────────
async function loadEnrollKeys(): Promise<void> {
  // (Re)populate the optional tenant-scope selector from the loaded tenants.
  const sel = $("enroll-tenant") as HTMLSelectElement;
  const prev = sel.value;
  sel.innerHTML = `<option value="">${t("admin.enrollAnyTenant")}</option>`;
  tenants.filter((tn) => tn.IsActive).forEach((tn) => {
    const o = document.createElement("option");
    o.value = String(tn.TenantID);
    o.textContent = tn.TenantName;
    sel.appendChild(o);
  });
  sel.value = prev;
  const data = await jget("/api/admin/enroll-keys");
  renderEnrollKeys(data);
}

function renderEnrollKeys(data: { keys: any[]; envKeySet: boolean; activeCount: number }): void {
  const note = $("enroll-env-note");
  const envTxt = data.envKeySet ? t("admin.enrollEnvSet") : t("admin.enrollEnvUnset");
  note.textContent = `${envTxt} · ${data.activeCount} ${t("admin.enrollActive")}`;

  const tb = $("enroll-keys-tbody");
  tb.innerHTML = "";
  if (!data.keys.length) {
    tb.innerHTML = `<tr><td colspan="8" style="color:var(--text-dim)">${t("admin.enrollNone")}</td></tr>`;
    return;
  }
  data.keys.forEach((k) => {
    const tr = document.createElement("tr");
    const revoked = !!k.Revoked;
    const expired = !!k.expired;
    const pill = revoked
      ? `<span class="pill" style="background:#7f1d1d;color:#fecaca">${t("admin.enrollStRevoked")}</span>`
      : expired
        ? `<span class="pill" style="background:#78350f;color:#fed7aa">${t("admin.enrollStExpired")}</span>`
        : `<span class="pill" style="background:#14532d;color:#86efac">${t("admin.enrollStActive")}</span>`;
    const used = `${k.UseCount || 0}${k.LastUsedDate ? ` <span style="color:var(--text-dim)">(${fmtDay(k.LastUsedDate)})</span>` : ""}`;
    tr.innerHTML =
      `<td>${escHtml(k.Label)}</td>` +
      `<td><code>${escHtml(k.Prefix)}</code></td>` +
      `<td>${k.tenantName ? escHtml(k.tenantName) : `<span style="color:var(--text-dim)">—</span>`}</td>` +
      `<td>${fmtDay(k.CreatedDate)}</td>` +
      `<td>${k.ExpiresDate ? fmtDay(k.ExpiresDate) : "∞"}</td>` +
      `<td>${used}</td>` +
      `<td>${pill}</td>`;
    const tdAct = document.createElement("td");
    if (!revoked) {
      const b = document.createElement("button");
      b.className = "btn btn-ghost btn-sm";
      b.textContent = t("admin.enrollRevoke");
      b.onclick = async () => {
        if (!confirm(t("admin.enrollRevokeConfirm"))) return;
        try {
          await jdelete(`/api/admin/enroll-keys/${k.EnrollKeyID}`);
          await loadEnrollKeys();
          toast(t("admin.enrollRevoked"));
        } catch (e) {
          toast(t("toast.error") + " " + e, "err");
        }
      };
      tdAct.appendChild(b);
    }
    tr.appendChild(tdAct);
    tb.appendChild(tr);
  });
}

// ── Users ─────────────────────────────────────────────────────────────
async function loadUsers(): Promise<void> {
  let url = "/api/admin/users";
  if (isSuperAdmin) {
    const f = ($("user-tenant-filter") as HTMLSelectElement).value;
    if (f) url += "?tenantId=" + encodeURIComponent(f);
  }
  const users: any[] = await jget(url);
  const tb = $("users-tbody");
  tb.innerHTML = "";
  users.forEach((u) => {
    const tr = document.createElement("tr");

    const rolesSel = document.createElement("select");
    rolesSel.multiple = true;
    rolesSel.style.cssText = "height:48px;min-width:120px";
    roles.forEach((r) => {
      const o = document.createElement("option");
      o.value = String(r.RoleID);
      o.textContent = r.RoleName;
      o.selected = (u.roles || []).includes(r.RoleName);
      rolesSel.appendChild(o);
    });

    tr.innerHTML = `<td>${u.Email}</td><td>${u.DisplayName ?? ""}</td>`;
    if (isSuperAdmin) {
      const tdT = document.createElement("td");
      tdT.textContent =
        (u.TenantName as string) ??
        tenants.find((x) => x.TenantID === u.TenantID)?.TenantName ??
        "";
      tr.appendChild(tdT);
    }
    const tdRoles = document.createElement("td");
    tdRoles.appendChild(rolesSel);
    const okRoles = document.createElement("button");
    okRoles.className = "btn btn-ghost btn-sm";
    okRoles.textContent = "✓";
    okRoles.title = t("tip.saveRoles");
    okRoles.onclick = async () => {
      const roleIds = Array.from(rolesSel.selectedOptions).map((o) => Number(o.value));
      try {
        await jpost(`/api/admin/users/${u.UserID}/roles`, { roleIds });
        toast(t("toast.rolesUpdated"));
      } catch (e) {
        toast(t("toast.error") + " " + e, "err");
      }
    };
    tdRoles.appendChild(okRoles);
    tr.appendChild(tdRoles);

    const tdStatus = document.createElement("td");
    tdStatus.innerHTML = u.IsLockedOut
      ? '<span class="pill" style="background:#7f1d1d;color:#fecaca">Verrouillé</span>'
      : '<span class="pill" style="background:#14532d;color:#86efac">Actif</span>';
    if (u.MustChangePassword) tdStatus.innerHTML += '<span class="pill">chg. mdp</span>';
    tr.appendChild(tdStatus);

    const tdAct = document.createElement("td");
    const lockBtn = document.createElement("button");
    lockBtn.className = "btn btn-ghost btn-sm";
    lockBtn.textContent = u.IsLockedOut ? "Déverrouiller" : "Verrouiller";
    lockBtn.onclick = async () => {
      await jpost(`/api/admin/users/${u.UserID}/lock`, { locked: !u.IsLockedOut });
      loadUsers();
    };
    const pwBtn = document.createElement("button");
    pwBtn.className = "btn btn-ghost btn-sm";
    pwBtn.textContent = "Réinit. mdp";
    pwBtn.onclick = async () => {
      const np = prompt(t("dialog.tempPwPrompt"));
      if (!np) return;
      try {
        await jpost(`/api/admin/users/${u.UserID}/reset-password`, { password: np });
        toast(t("toast.passwordReset"));
      } catch (e) {
        toast(t("toast.error") + " " + e, "err");
      }
    };
    tdAct.appendChild(lockBtn);
    tdAct.appendChild(document.createTextNode(" "));
    tdAct.appendChild(pwBtn);
    tr.appendChild(tdAct);

    tb.appendChild(tr);
  });
}

async function loadAudit(): Promise<void> {
  const rows: any[] = await jget("/api/admin/audit?limit=200");
  const tb = $("audit-tbody");
  tb.innerHTML = "";
  rows.forEach((a) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${a.Timestamp ?? ""}</td><td>${a.Email ?? a.UserID ?? ""}</td>` +
      `<td>${a.Action ?? ""}</td><td>${a.ResourceKey ?? ""}</td>` +
      `<td>${a.Detail ?? ""}</td><td>${a.IP ?? ""}</td>`;
    tb.appendChild(tr);
  });
}

// ── Init ─────────────────────────────────────────────────────────────────────
// ── Menu access control (per group/card → allowed NICE profiles) ──
function maEsc(s: string): string { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string)); }
async function loadLandingAccess(): Promise<void> {
  const host = document.getElementById("menuaccess-body"); if (!host) return;
  let data: any;
  try { data = await jget("/api/admin/landing-access"); } catch { host.textContent = ""; return; }
  const profiles: string[] = data.profiles || [];
  const restr = new Map<string, string[]>();
  for (const r of data.restrictions || []) restr.set(r.itemType + ":" + r.itemKey, r.profiles || []);
  const byGroup: Record<string, any[]> = {};
  for (const c of (data.cards || [])) (byGroup[c.group] ||= []).push(c);
  const chips = (type: string, key: string): string => {
    const sel = new Set(restr.get(type + ":" + key) || []);
    return `<div class="ma-chips">` + profiles.map((p) => `<label class="ma-chip${sel.has(p) ? " on" : ""}"><input type="checkbox" data-type="${type}" data-key="${maEsc(key)}" value="${maEsc(p)}" ${sel.has(p) ? "checked" : ""}>${maEsc(p)}</label>`).join("") + `</div>`;
  };
  let html = "";
  for (const g of (data.groups || [])) {
    html += `<div class="ma-group"><div class="ma-grouphead"><b>${maEsc(g.label)}</b> <span style="color:#64748b;font-size:11px">${maEsc(g.id)}</span>${chips("group", g.id)}</div>`;
    for (const c of (byGroup[g.id] || [])) html += `<div class="ma-card"><span class="ma-cardlabel">${maEsc(c.label)}</span><span class="ma-href">${maEsc(c.href)}</span>${chips("card", c.href)}</div>`;
    html += `</div>`;
  }
  host.innerHTML = html;
  host.querySelectorAll<HTMLInputElement>('input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener("change", async () => {
      const type = cb.dataset.type!, key = cb.dataset.key!;
      const checked = [...host.querySelectorAll<HTMLInputElement>(`input[data-type="${type}"][data-key="${(window as any).CSS?.escape ? CSS.escape(key) : key}"]:checked`)].map((x) => x.value);
      cb.closest(".ma-chip")?.classList.toggle("on", cb.checked);
      try {
        const r = await fetch("/api/admin/landing-access", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ itemType: type, itemKey: key, profiles: checked }) });
        if (!r.ok) throw new Error(String(r.status));
        toast(t("admin.saved") || "Saved");
      } catch { toast(t("toast.errSave") || "Failed", "err"); cb.checked = !cb.checked; cb.closest(".ma-chip")?.classList.toggle("on", cb.checked); }
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  initI18n();
  try {
    const who = await jget("/api/admin/whoami");
    isSuperAdmin = !!who.isSuperAdmin;
    const badge = $("tenant-badge");
    badge.textContent = isSuperAdmin
      ? `${t("admin.superAdmin")}${who.tenantName ? " — " + who.tenantName : ""}`
      : who.tenantName || "";

    if (isSuperAdmin) {
      document.body.classList.add("is-super");
      resources = await jget("/api/admin/resources");
      await loadTenants();
      await loadEnrollKeys();
      await loadRoles();
    } else {
      // Tenant admin: no permissions editor nor tenant management
      await loadRolesList();
    }
    await loadUsers();
    await loadAudit();
    await loadLandingAccess();
  } catch (e) {
    toast(t("toast.errInit") + " " + e, "err");
  }

  ($("role-select") as HTMLSelectElement).onchange = (e) =>
    selectRole(Number((e.target as HTMLSelectElement).value));

  // "tenant" filter (super-admin)
  ($("user-tenant-filter") as HTMLSelectElement).onchange = () => loadUsers();

  // Creation of a tenant (super-admin)
  $("btn-add-tenant").onclick = async () => {
    const name = ($("new-tenant") as HTMLInputElement).value.trim();
    if (!name) return;
    try {
      await jpost("/api/admin/tenants", { name });
      ($("new-tenant") as HTMLInputElement).value = "";
      await loadTenants();
      toast(t("admin.tenantCreated"));
    } catch (e) {
      toast(t("toast.error") + " " + e, "err");
    }
  };

  // Create a managed agent enrollment key (super-admin)
  $("btn-add-enroll-key").onclick = async () => {
    const label = ($("enroll-label") as HTMLInputElement).value.trim();
    if (!label) return void toast(t("admin.enrollNeedLabel"), "err");
    const tenantId = ($("enroll-tenant") as HTMLSelectElement).value || null;
    const expiryRaw = ($("enroll-expiry") as HTMLInputElement).value.trim();
    const expiresInDays = expiryRaw ? Number(expiryRaw) : null;
    const btn = $("btn-add-enroll-key") as HTMLButtonElement;
    btn.disabled = true;
    try {
      const r = await jpost("/api/admin/enroll-keys", { label, tenantId, expiresInDays });
      const box = $("enroll-new-key");
      box.style.display = "block";
      box.innerHTML = `${escHtml(t("admin.enrollNewKeyMsg"))}<br><code style="font-size:13px;word-break:break-all;user-select:all">${escHtml(r.key)}</code>`;
      ($("enroll-label") as HTMLInputElement).value = "";
      ($("enroll-expiry") as HTMLInputElement).value = "";
      await loadEnrollKeys();
      toast(t("admin.enrollCreated"));
    } catch (e) {
      toast(t("toast.error") + " " + e, "err");
    } finally {
      btn.disabled = false;
    }
  };

  $("btn-backup").onclick = async () => {
    const btn = $("btn-backup") as HTMLButtonElement;
    const out = $("backup-result");
    btn.disabled = true;
    out.textContent = t("admin.backupRunning");
    try {
      const r = await jpost("/api/admin/backup", {});
      const totalMb = (r.files.reduce((a: number, f: any) => a + f.bytes, 0) / 1048576).toFixed(1);
      out.innerHTML = `✅ ${r.files.length} ${t("admin.backupDone")} (${totalMb} MB)<br><span style="color:var(--text-dim)">${r.dir}</span>`;
    } catch (e) {
      out.textContent = "❌ " + e;
    } finally {
      btn.disabled = false;
    }
  };

  $("btn-correlate").onclick = async () => {
    const btn = $("btn-correlate") as HTMLButtonElement;
    const out = $("correlate-result");
    btn.disabled = true;
    out.textContent = t("admin.correlateRunning");
    try {
      const r = await jpost("/api/admin/correlate-cve", {});
      out.innerHTML = `✅ ${r.links} ${t("admin.correlateLinks")} — ${r.assetsMatched} ${t("admin.correlateAssets")}, ${r.cvesMatched} CVE<br><span style="color:var(--text-dim)">${r.assetCpes} CPE actifs × ${r.cveCpes} CPE affectées</span>`;
    } catch (e) {
      out.textContent = "❌ " + e;
    } finally {
      btn.disabled = false;
    }
  };

  $("btn-notify-all").onclick = async () => {
    const btn = $("btn-notify-all") as HTMLButtonElement;
    const out = $("notify-result");
    const title = ($("notify-title") as HTMLInputElement).value.trim();
    if (!title) { out.textContent = "❌ " + (t("admin.notifyTitleReq") || "Titre requis"); return; }
    const message = ($("notify-message") as HTMLTextAreaElement).value.trim();
    const level = ($("notify-level") as HTMLSelectElement).value;
    if (!confirm(t("admin.notifyConfirm") || "Envoyer cette notification à tous les utilisateurs ?")) return;
    btn.disabled = true;
    out.textContent = "…";
    try {
      const r = await jpost("/api/notifications", { title, message: message || undefined, level, target: "all" });
      out.textContent = `✅ ${r.created} ${t("admin.notifySent") || "notification(s) envoyée(s)"}`;
      ($("notify-title") as HTMLInputElement).value = "";
      ($("notify-message") as HTMLTextAreaElement).value = "";
    } catch (e) {
      out.textContent = "❌ " + e;
    } finally {
      btn.disabled = false;
    }
  };

  $("btn-add-role").onclick = async () => {
    const name = ($("new-role") as HTMLInputElement).value.trim();
    if (!name) return;
    try {
      await jpost("/api/admin/roles", { name });
      ($("new-role") as HTMLInputElement).value = "";
      await loadRoles();
      toast(t("toast.roleCreated"));
    } catch (e) {
      toast(t("toast.error") + " " + e, "err");
    }
  };

  $("btn-add-user").onclick = async () => {
    const email = ($("nu-email") as HTMLInputElement).value.trim();
    const displayName = ($("nu-name") as HTMLInputElement).value.trim();
    const password = ($("nu-pw") as HTMLInputElement).value;
    const roleIds = Array.from(($("nu-roles") as HTMLSelectElement).selectedOptions).map((o) =>
      Number(o.value)
    );
    const body: Record<string, unknown> = { email, displayName, password, roleIds };
    if (isSuperAdmin) {
      const tnVal = ($("nu-tenant") as HTMLSelectElement).value;
      if (tnVal) body.tenantId = Number(tnVal);
    }
    try {
      await jpost("/api/admin/users", body);
      ($("nu-email") as HTMLInputElement).value = "";
      ($("nu-name") as HTMLInputElement).value = "";
      ($("nu-pw") as HTMLInputElement).value = "";
      await loadUsers();
      toast(t("toast.userCreated"));
    } catch (e) {
      toast(t("toast.error") + " " + e, "err");
    }
  };

  $("btn-refresh-audit").onclick = loadAudit;
});
