/**
 * bia.ts — Business Impact Analysis page (TypeScript client)
 */

import { biaApi, BiaAudit, BiaEntry } from "./api";
import { mkRichText } from "./rte";
import { initI18n, t } from "./i18n";

// ── Constants ─────────────────────────────────────────────────────────────────

const CRIT_OPTS = ["Critical", "High", "Medium", "Low", "N/A"];
const RISK_OPTS = ["Critical", "High", "Medium", "Low", "N/A"];
const IMP_OPTS = ["Majeur", "Significatif", "Modere", "Mineur", "Negligeable", "N/A"];
const ASSET_TYPES = ["Systeme", "Application", "Donnees", "Reseau", "Infrastructure", "Process", "Personnel", "Autre"];

// ── State ─────────────────────────────────────────────────────────────────────

let currentAuditId: number | null = null;
let entries: BiaEntry[] = [];

// ── Helpers ───────────────────────────────────────────────────────────────────

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function toast(msg: string, type: "ok" | "err" = "ok"): void {
  const t = $("toast");
  t.textContent = msg;
  t.className = type === "err" ? "toast-err" : "toast-ok";
  (t as HTMLElement).style.opacity = "1";
  setTimeout(() => ((t as HTMLElement).style.opacity = "0"), 2800);
}

function mkSelect(opts: string[], val?: string): HTMLSelectElement {
  const s = document.createElement("select");
  opts.forEach((o) => {
    const opt = document.createElement("option");
    opt.value = o;
    opt.textContent = o;
    if (o === val) opt.selected = true;
    s.appendChild(opt);
  });
  return s;
}

function mkInput(val?: string, placeholder?: string): HTMLInputElement {
  const i = document.createElement("input");
  i.value = val ?? "";
  i.placeholder = placeholder ?? "";
  return i;
}

// AssetName combobox: <input> linked to a shared <datalist> of distinct ASSET
// names (free input allowed). The datalist is created once and fed
// by loadAssetNames().
const ASSET_NAME_LIST_ID = "bia-asset-names";
let assetNameOptions: string[] = [];

function ensureAssetNameDatalist(): HTMLDataListElement {
  let dl = document.getElementById(ASSET_NAME_LIST_ID) as HTMLDataListElement | null;
  if (!dl) {
    dl = document.createElement("datalist");
    dl.id = ASSET_NAME_LIST_ID;
    document.body.appendChild(dl);
  }
  dl.innerHTML = "";
  assetNameOptions.forEach((n) => {
    const o = document.createElement("option");
    o.value = n;
    dl!.appendChild(o);
  });
  return dl;
}

async function loadAssetNames(): Promise<void> {
  try {
    assetNameOptions = await biaApi.assetNames();
  } catch {
    assetNameOptions = [];
  }
  ensureAssetNameDatalist();
}

function mkAssetNameInput(val?: string, placeholder?: string): HTMLInputElement {
  const i = mkInput(val, placeholder);
  i.setAttribute("list", ASSET_NAME_LIST_ID);
  i.autocomplete = "off";
  return i;
}

// Auditor combobox: the #a-auditor input linked to a shared <datalist> of distinct PERSON
// full names (free input still allowed). Mirrors the AssetName datalist above.
const PERSON_NAME_LIST_ID = "bia-person-names";
let personNameOptions: string[] = [];

function ensurePersonNameDatalist(): HTMLDataListElement {
  let dl = document.getElementById(PERSON_NAME_LIST_ID) as HTMLDataListElement | null;
  if (!dl) {
    dl = document.createElement("datalist");
    dl.id = PERSON_NAME_LIST_ID;
    document.body.appendChild(dl);
  }
  dl.innerHTML = "";
  personNameOptions.forEach((n) => {
    const o = document.createElement("option");
    o.value = n;
    dl!.appendChild(o);
  });
  return dl;
}

async function loadPersonNames(): Promise<void> {
  try {
    personNameOptions = await biaApi.personNames();
  } catch {
    personNameOptions = [];
  }
  ensurePersonNameDatalist();
  const aud = document.getElementById("a-auditor") as HTMLInputElement | null;
  if (aud) { aud.setAttribute("list", PERSON_NAME_LIST_ID); aud.autocomplete = "off"; }
}

function mkTextarea(val?: string, placeholder?: string): HTMLTextAreaElement {
  const t = document.createElement("textarea");
  t.value = val ?? "";
  t.placeholder = placeholder ?? "";
  t.rows = 2;
  return t;
}


// ── Audits ────────────────────────────────────────────────────────────────────

async function loadAudits(): Promise<void> {
  const audits = await biaApi.getAudits();
  const el = $("audit-list");
  el.innerHTML = "";

  if (!audits.length) {
    el.innerHTML = `<div class="empty">Aucun audit BIA. Cliquez sur "+ Nouvel audit".</div>`;
    return;
  }

  audits.forEach((a) => {
    const div = document.createElement("div");
    div.className = "audit-item" + (a.BIAAuditID === currentAuditId ? " active" : "");
    div.onclick = () => selectAudit(a);

    const statusCls =
      a.BIAAuditStatus === "Final"
        ? "badge-final"
        : a.BIAAuditStatus === "In Progress"
        ? "badge-progress"
        : "badge-draft";

    div.innerHTML = `
      <div class="meta">
        <div class="name">${a.BIAAuditName || "(sans nom)"}</div>
        <div class="sub">${a.BIAAuditDate ?? ""} &bull; ${a.Auditor ?? ""} &bull; ${a.BIAAuditScope ?? ""}</div>
      </div>
      <span class="badge ${statusCls}">${a.BIAAuditStatus ?? "Draft"}</span>
    `;

    const btnDel = document.createElement("button");
    btnDel.className = "btn btn-danger btn-sm";
    btnDel.textContent = "✕";
    btnDel.onclick = (e) => {
      e.stopPropagation();
      deleteAudit(a.BIAAuditID!);
    };
    div.appendChild(btnDel);
    el.appendChild(div);
  });
}

async function selectAudit(a: BiaAudit): Promise<void> {
  currentAuditId = a.BIAAuditID!;
  $("entry-section").style.display = "";
  $("entry-title").textContent = `BIA : ${a.BIAAuditName}`;
  await loadAudits();
  await loadEntries();
}

async function deleteAudit(id: number): Promise<void> {
  if (!confirm(t("dialog.deleteAudit"))) return;
  await biaApi.deleteAudit(id);
  if (currentAuditId === id) {
    currentAuditId = null;
    $("entry-section").style.display = "none";
  }
  toast(t("toast.auditDeleted"), "ok");
  loadAudits();
}

async function updateAuditStatus(status: string): Promise<void> {
  if (!currentAuditId) return;
  await biaApi.updateAuditStatus(currentAuditId, status);
  toast(t("toast.status") + " " + status, "ok");
  loadAudits();
}

function openNewAuditModal(): void {
  $("audit-modal").classList.add("open");
  ($("a-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
}

function closeModal(): void {
  $("audit-modal").classList.remove("open");
}

async function createAudit(): Promise<void> {
  const name = ($("a-name") as HTMLInputElement).value.trim();
  if (!name) { toast(t("toast.nameRequired"), "err"); return; }

  const data: BiaAudit = {
    BIAAuditName: name,
    BIAAuditDescription: ($("a-desc") as HTMLTextAreaElement).value,
    BIAAuditScope: ($("a-scope") as HTMLInputElement).value,
    BIAAuditDate: ($("a-date") as HTMLInputElement).value,
    Auditor: ($("a-auditor") as HTMLInputElement).value,
  };

  const res = await biaApi.createAudit(data);
  closeModal();
  toast(t("toast.auditCreated"), "ok");
  await loadAudits();
  selectAudit({ ...data, BIAAuditID: res.id });
}

// ── Entries ───────────────────────────────────────────────────────────────────

async function loadEntries(): Promise<void> {
  if (!currentAuditId) return;
  entries = await biaApi.getEntries(currentAuditId);
  renderTable();
}

function renderTable(): void {
  const tbody = $("bia-tbody");
  tbody.innerHTML = "";

  const filterCrit = ($("filter-crit") as HTMLSelectElement).value;
  const visible = filterCrit
    ? entries.filter((e) => e.CriticalityLevel === filterCrit)
    : entries;

  visible.forEach((e) => tbody.appendChild(buildRow(e)));
  $("statusbar").textContent = `${visible.length} ligne(s) / ${entries.length} total`;
}

type Field = {
  key: keyof BiaEntry;
  el: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
  cls?: string;
  mount?: HTMLElement; // visual element to display instead of `el` (e.g. rich editor)
};

function buildRow(e: BiaEntry): HTMLTableRowElement {
  const tr = document.createElement("tr");
  if (e.BIAEntryID) tr.dataset.id = String(e.BIAEntryID);

  const descRte = mkRichText(e.AssetDescription, "Desc.");

  const fields: Field[] = [
    { key: "AssetName",          el: mkAssetNameInput(e.AssetName, "Nom asset"), cls: "col-name" },
    { key: "AssetDescription",   el: descRte.hidden, mount: descRte.mount,      cls: "col-desc" },
    { key: "AssetType",          el: mkSelect(ASSET_TYPES, e.AssetType),        cls: "col-type" },
    { key: "CriticalityLevel",   el: mkSelect(CRIT_OPTS, e.CriticalityLevel),   cls: "col-crit" },
    { key: "OwnerName",          el: mkInput(e.OwnerName, "Proprietaire"),       cls: "col-owner" },
    { key: "RiskDescription",    el: mkTextarea(e.RiskDescription, "Risque"),   cls: "col-risk" },
    { key: "RiskLevel",          el: mkSelect(RISK_OPTS, e.RiskLevel),          cls: "col-rlvl" },
    { key: "ImpactFinancial",    el: mkSelect(IMP_OPTS, e.ImpactFinancial),     cls: "col-imp" },
    { key: "ImpactOperational",  el: mkSelect(IMP_OPTS, e.ImpactOperational),   cls: "col-imp" },
    { key: "ImpactLegal",        el: mkSelect(IMP_OPTS, e.ImpactLegal),         cls: "col-imp" },
    { key: "ImpactReputational", el: mkSelect(IMP_OPTS, e.ImpactReputational),  cls: "col-imp" },
    { key: "MTD",                el: mkInput(e.MTD, "ex: 4h"),                  cls: "col-mtd" },
    { key: "RTO",                el: mkInput(e.RTO, "ex: 2h"),                  cls: "col-mtd" },
    { key: "RPO",                el: mkInput(e.RPO, "ex: 1h"),                  cls: "col-mtd" },
    { key: "Notes",              el: mkTextarea(e.Notes, "Notes"),              cls: "col-notes" },
  ];

  fields.forEach((f) => {
    const td = document.createElement("td");
    if (f.cls) td.className = f.cls;
    td.appendChild(f.el); // always present (hidden if rich editor) for reading .value
    if (f.mount) td.appendChild(f.mount);
    tr.appendChild(td);
  });

  // Actions
  const tdAct = document.createElement("td");
  tdAct.className = "actions";

  const btnSave = document.createElement("button");
  btnSave.className = "btn btn-primary btn-sm";
  btnSave.textContent = "OK";
  btnSave.onclick = () => saveRow(tr, fields, e.BIAEntryID);

  const btnDel = document.createElement("button");
  btnDel.className = "btn btn-danger btn-sm";
  btnDel.textContent = "X";

  btnDel.onclick = () => deleteEntry(e.BIAEntryID, tr);

  tdAct.appendChild(btnSave);
  tdAct.appendChild(document.createElement("br"));
  tdAct.appendChild(btnDel);
  tr.appendChild(tdAct);

  return tr;
}

function collectRow(fields: Field[]): Partial<BiaEntry> {
  const obj: Partial<BiaEntry> = {};
  fields.forEach((f) => {
    (obj as Record<string, string>)[f.key] = f.el.value;
  });
  return obj;
}

async function saveRow(tr: HTMLTableRowElement, fields: Field[], existingId?: number): Promise<void> {
  const data = collectRow(fields) as BiaEntry;
  data.BIAAuditID = currentAuditId!;

  if (!data.AssetName) { toast(t("toast.assetNameRequired"), "err"); return; }

  if (existingId) {
    await biaApi.updateEntry(existingId, data);
    const idx = entries.findIndex((e) => e.BIAEntryID === existingId);
    if (idx >= 0) entries[idx] = { ...entries[idx], ...data };
    toast(t("toast.rowUpdated"), "ok");
  } else {
    const res = await biaApi.createEntry(data);
    data.BIAEntryID = res.id;
    entries.push(data);
    tr.dataset.id = String(res.id);
    // Re-wire buttons with real id
    const btns = tr.querySelectorAll<HTMLButtonElement>("button");
    btns[0].onclick = () => saveRow(tr, fields, res.id);
    btns[1].onclick = () => deleteEntry(res.id, tr);
    toast(t("toast.rowSaved"), "ok");
  }
  $("statusbar").textContent = `${entries.length} ligne(s)`;
}

async function deleteEntry(id: number | undefined, tr: HTMLTableRowElement): Promise<void> {
  if (!id) { tr.remove(); return; }
  if (!confirm(t("dialog.deleteLine"))) return;
  await biaApi.deleteEntry(id);
  entries = entries.filter((e) => e.BIAEntryID !== id);
  tr.remove();
  $("statusbar").textContent = `${entries.length} ligne(s)`;
  toast(t("toast.rowDeleted"), "ok");
}

function addRow(): void {
  const e: BiaEntry = {
    BIAAuditID: currentAuditId!,
    AssetType: "Systeme",
    CriticalityLevel: "Medium",
    RiskLevel: "Medium",
    ImpactFinancial: "N/A",
    ImpactOperational: "N/A",
    ImpactLegal: "N/A",
    ImpactReputational: "N/A",
  };
  const tr = buildRow(e);
  $("bia-tbody").appendChild(tr);
  (tr.querySelector("input") as HTMLInputElement)?.focus();
}

// ── Export ────────────────────────────────────────────────────────────────────

function gatherData(): string[][] {
  const headers = [
    "Nom asset", "Description", "Type", "Criticite", "Owner",
    "Risque", "Niv. risque", "Impact Fin.", "Impact Op.", "Impact Legal",
    "Impact Reput.", "MTD", "RTO", "RPO", "Notes",
  ];
  // HTML → plain text (for the rich description), harmless on simple fields
  const htmlToText = (s: string): string => {
    if (!/<[a-z/][\s\S]*>/i.test(s)) return s;
    const d = document.createElement("div");
    d.innerHTML = s;
    return (d.textContent || "").trim();
  };

  const rows = $("bia-tbody").querySelectorAll<HTMLTableRowElement>("tr");
  const data: string[][] = [headers];
  rows.forEach((tr) => {
    const cells = tr.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
      "input,select,textarea"
    );
    // Excludes the color pickers of the rich editor's toolbar
    const values = Array.from(cells)
      .filter((c) => !(c instanceof HTMLInputElement && c.type === "color"))
      .map((c) => htmlToText(c.value));
    data.push(values);
  });
  return data;
}

function exportCSV(): void {
  const data = gatherData();
  const csv = data
    .map((r) => r.map((v) => `"${v.replace(/"/g, '""')}"`).join(","))
    .join("\r\n");
  const bom = "﻿";
  const blob = new Blob([bom + csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `BIA_${currentAuditId ?? "export"}_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
}

function exportExcel(): void {
  const data = gatherData();
  const XLSX = (window as unknown as { XLSX: typeof import("xlsx") }).XLSX;
  const ws = XLSX.utils.aoa_to_sheet(data);
  ws["!cols"] = data[0].map(() => ({ wch: 22 }));
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "BIA");
  XLSX.writeFile(wb, `BIA_${currentAuditId ?? "export"}_${new Date().toISOString().slice(0, 10)}.xlsx`);
}

// ── Wire & init ───────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("btn-new-audit").onclick = openNewAuditModal;
  $("btn-create-audit").onclick = createAudit;
  $("btn-cancel-modal").onclick = closeModal;
  $("btn-add-row").onclick = addRow;
  $("btn-add-row-bottom").onclick = addRow;
  $("btn-csv").onclick = exportCSV;
  $("btn-excel").onclick = exportExcel;
  $("btn-depgraph").onclick = () => { if (currentAuditId) window.open(`/bia-graph?audit=${currentAuditId}`, "_blank", "noopener"); };
  $("btn-finalize").onclick = () => updateAuditStatus("Final");
  $("filter-crit").onchange = renderTable;

  loadAssetNames();
  loadPersonNames();
  loadAudits();
});
