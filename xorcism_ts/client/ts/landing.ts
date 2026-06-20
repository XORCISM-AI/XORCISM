/**
 * landing.ts — Fusion-center main menu grouped into "approaches" (asset / exposure / threat /
 * risk / compliance / operations / platform). Drag-to-reorder the domain cards WITHIN their
 * approach. The order is saved per-user via the prefs API (key "landing-order" =
 * { [groupId]: hrefs[] }), so it persists across sessions/devices and degrades gracefully
 * (new cards or new groups fall back to their HTML position).
 */
import { t } from "./i18n";

const PREF_KEY = "landing-order";
type OrderMap = Record<string, string[]>;

const grids = (): HTMLElement[] => [...document.querySelectorAll<HTMLElement>(".domain-grid")];
const cardsIn = (grid: Element): HTMLAnchorElement[] => [...grid.querySelectorAll<HTMLAnchorElement>(".domain-card")];
const hrefOf = (c: HTMLAnchorElement): string => c.getAttribute("href") || "";
const groupOf = (grid: Element): string =>
  (grid as HTMLElement).dataset.group || (grid.closest<HTMLElement>(".approach")?.dataset.group ?? "");

/** Snapshot the current order of every approach grid. */
function currentMap(): OrderMap {
  const m: OrderMap = {};
  for (const g of grids()) m[groupOf(g)] = cardsIn(g).map(hrefOf);
  return m;
}
async function loadOrder(): Promise<OrderMap | null> {
  try {
    const r = await fetch(`/api/prefs/${PREF_KEY}`); if (!r.ok) return null;
    const d = await r.json(); const v = d.value;
    // Current format is an object map; tolerate (and ignore) the old flat-array format.
    return v && typeof v === "object" && !Array.isArray(v) ? (v as OrderMap) : null;
  } catch { return null; }
}
async function saveOrder(map: OrderMap): Promise<void> {
  try {
    await fetch(`/api/prefs/${PREF_KEY}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: map }) });
  } catch { /* offline */ }
}
function applyOrder(map: OrderMap): void {
  for (const grid of grids()) {
    const order = map[groupOf(grid)]; if (!Array.isArray(order)) continue;
    const list = cardsIn(grid); const byHref = new Map(list.map((c) => [hrefOf(c), c]));
    const seen = new Set<string>();
    for (const h of order) { const c = byHref.get(h); if (c) { grid.appendChild(c); seen.add(h); } } // saved order first
    for (const c of list) if (!seen.has(hrefOf(c))) grid.appendChild(c);                              // new cards keep their tail position
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  if (!grids().length) return;
  const btn = document.getElementById("landing-reorder");
  const reset = document.getElementById("landing-reset");
  const label = document.getElementById("lr-label");
  if (!btn) return;

  const saved = await loadOrder();
  if (saved) applyOrder(saved);

  let editing = false; let dragged: HTMLAnchorElement | null = null; let dragGrid: Element | null = null;
  const setEditing = (on: boolean): void => {
    editing = on;
    for (const g of grids()) { g.classList.toggle("reordering", on); cardsIn(g).forEach((c) => { c.draggable = on; }); }
    if (reset) reset.style.display = on ? "" : "none";
    if (label) label.textContent = on ? t("landing.reorderDone") : t("landing.reorder");
  };

  btn.addEventListener("click", () => setEditing(!editing));
  reset?.addEventListener("click", async () => { await saveOrder({}); location.reload(); });

  // Document-level drag handlers cover every approach grid; reordering is constrained to the
  // grid the drag started in, so a card never leaves its approach.
  document.addEventListener("dragstart", (e) => {
    const c = (e.target as HTMLElement).closest<HTMLAnchorElement>(".domain-card");
    if (!editing || !c) return;
    dragged = c; dragGrid = c.closest(".domain-grid"); c.classList.add("dragging");
    try { (e as DragEvent).dataTransfer!.effectAllowed = "move"; } catch { /* */ }
  });
  document.addEventListener("dragend", () => {
    if (!dragged) return;
    dragged.classList.remove("dragging"); dragged = null; dragGrid = null;
    void saveOrder(currentMap());
  });
  document.addEventListener("dragover", (e) => {
    if (!editing || !dragged || !dragGrid) return;
    const target = (e.target as HTMLElement).closest<HTMLAnchorElement>(".domain-card");
    if (!target || target === dragged) return;
    if (target.closest(".domain-grid") !== dragGrid) return;   // stay within the same approach
    e.preventDefault();
    const r = target.getBoundingClientRect();
    const before = ((e as DragEvent).clientX - r.left) < r.width / 2; // left half → insert before, else after
    dragGrid.insertBefore(dragged, before ? target : target.nextSibling);
  });
  // while editing, a card click must NOT navigate
  document.addEventListener("click", (e) => {
    if (editing && (e.target as HTMLElement).closest(".domain-card")) e.preventDefault();
  }, true);
});
