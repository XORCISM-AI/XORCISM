/**
 * tools.ts — the Tool Catalogue (/tools) with GitHub-style stars.
 * Browse/search/filter/sort XORCISM's TOOL catalogue and star tools; data from /api/tools,
 * toggling via POST /api/tools/:id/star. Star counts are global; the filled star = you starred it.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Tool { id: number; name: string; description: string | null; category: string | null; url: string | null; starCount: number; starred: boolean; }
interface Catalogue {
  tools: Tool[]; categories: { category: string; count: number }[]; total: number;
  summary: { tools: number; starred: number; categories: number };
}

const PAGE = 60;
const state = { q: "", category: "", sort: "stars", starred: false, offset: 0, total: 0, loaded: 0 };
let myStars = 0;

function card(t: Tool): string {
  const isHttp = !!t.url && /^https?:\/\//i.test(t.url);
  const href = isHttp ? esc(t.url!) : `/?db=XORCISM&table=TOOL&filterCol=ToolID&filterVal=${t.id}`;
  const tgt = isHttp ? ' target="_blank" rel="noopener noreferrer"' : "";
  return `<div class="tool" data-id="${t.id}">
    <div class="top"><div style="flex:1">
      <div class="nm"><a href="${href}"${tgt}>${esc(t.name)}</a></div>
      ${t.category ? `<div class="cat">${esc(t.category)}</div>` : ""}
    </div></div>
    ${t.description ? `<div class="desc">${esc(t.description)}</div>` : '<div class="desc muted">No description.</div>'}
    <div class="foot">
      <span class="star${t.starred ? " on" : ""}" data-id="${t.id}" role="button" tabindex="0" title="${t.starred ? "Unstar" : "Star"} this tool">
        <span class="ic">${t.starred ? "★" : "☆"}</span><span class="ct">${t.starCount}</span></span>
      ${isHttp ? `<a class="ext" href="${esc(t.url!)}" target="_blank" rel="noopener noreferrer">repo ↗</a>` : ""}
    </div>
  </div>`;
}

function statCards(s: Catalogue["summary"]): string {
  const c = (lbl: string, val: string, color?: string) =>
    `<div class="tc-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div></div>`;
  return `<div class="tc-cards">
    ${c("Tools in catalogue", String(s.tools))}
    ${c("★ Your stars", String(s.starred), s.starred ? "#f5c518" : undefined)}
    ${c("Categories", String(s.categories))}
  </div>`;
}

function catPills(cats: Catalogue["categories"]): string {
  const pill = (cat: string, label: string, count: string) =>
    `<span class="tc-cat${state.category === cat ? " on" : ""}" data-cat="${esc(cat)}">${esc(label)}${count ? `<span class="n">${count}</span>` : ""}</span>`;
  return `<div class="tc-cats">${pill("", "All", "")}${cats.map((c) => pill(c.category, c.category, String(c.count))).join("")}</div>`;
}

function skeleton(): void {
  $("tc-body").innerHTML = `<div id="tc-stats"></div>
    <div class="tc-bar">
      <input type="search" id="tc-q" placeholder="Search tools by name or description…" autocomplete="off">
      <select id="tc-sort">
        <option value="stars">Most starred</option>
        <option value="name">Name (A–Z)</option>
        <option value="recent">Newest</option>
      </select>
      <span class="tc-toggle" id="tc-starred"><span class="ic">★</span> Starred only</span>
    </div>
    <div id="tc-cats"></div>
    <div class="tc-grid" id="tc-grid"></div>
    <div class="tc-more" id="tc-more"></div>`;

  const q = $("tc-q") as HTMLInputElement;
  q.value = state.q;
  ($("tc-sort") as HTMLSelectElement).value = state.sort;
  $("tc-starred").classList.toggle("on", state.starred);
  let deb: number | undefined;
  q.addEventListener("input", () => { window.clearTimeout(deb); deb = window.setTimeout(() => { state.q = q.value.trim(); load(true); }, 300); });
  ($("tc-sort") as HTMLSelectElement).addEventListener("change", (e) => { state.sort = (e.target as HTMLSelectElement).value; load(true); });
  $("tc-starred").addEventListener("click", () => { state.starred = !state.starred; $("tc-starred").classList.toggle("on", state.starred); load(true); });
  $("tc-cats").addEventListener("click", (e) => {
    const el = (e.target as HTMLElement).closest<HTMLElement>(".tc-cat"); if (!el) return;
    state.category = el.dataset.cat || ""; load(true);
  });
  // star clicks (event-delegated on the grid)
  const onStar = (e: Event) => {
    const el = (e.target as HTMLElement).closest<HTMLElement>(".star"); if (!el) return;
    void toggleStar(Number(el.dataset.id), el);
  };
  $("tc-grid").addEventListener("click", onStar);
  $("tc-grid").addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter" || (e as KeyboardEvent).key === " ") onStar(e); });
}

async function toggleStar(id: number, el: HTMLElement): Promise<void> {
  // optimistic flip
  const wasOn = el.classList.contains("on");
  el.classList.toggle("on", !wasOn);
  (el.querySelector(".ic") as HTMLElement).textContent = !wasOn ? "★" : "☆";
  const ct = el.querySelector(".ct") as HTMLElement;
  ct.textContent = String(Math.max(0, Number(ct.textContent) + (wasOn ? -1 : 1)));
  try {
    const r = await fetch(`/api/tools/${id}/star`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    // reconcile with the authoritative server state
    el.classList.toggle("on", !!d.starred);
    (el.querySelector(".ic") as HTMLElement).textContent = d.starred ? "★" : "☆";
    ct.textContent = String(d.starCount);
    myStars += d.starred ? 1 : -1;
    const ys = document.querySelector("#tc-stats .tc-card:nth-child(2) .val") as HTMLElement | null;
    if (ys) { ys.textContent = String(Math.max(0, myStars)); ys.style.color = myStars > 0 ? "#f5c518" : ""; }
    if (state.starred && !d.starred) el.closest(".tool")?.remove(); // dropped out of the "starred only" view
  } catch {
    // revert on failure
    el.classList.toggle("on", wasOn);
    (el.querySelector(".ic") as HTMLElement).textContent = wasOn ? "★" : "☆";
    ct.textContent = String(Math.max(0, Number(ct.textContent) + (wasOn ? 1 : -1)));
  }
}

async function load(reset: boolean): Promise<void> {
  if (reset) state.offset = 0;
  const params = new URLSearchParams({ sort: state.sort, limit: String(PAGE), offset: String(state.offset) });
  if (state.q) params.set("q", state.q);
  if (state.category) params.set("category", state.category);
  if (state.starred) params.set("starred", "1");
  let d: Catalogue;
  try { const r = await fetch("/api/tools?" + params.toString()); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("tc-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }

  if (!document.getElementById("tc-grid")) skeleton();
  myStars = d.summary.starred;
  $("tc-stats").innerHTML = statCards(d.summary);
  if (reset) $("tc-cats").innerHTML = catPills(d.categories);
  state.total = d.total;

  const grid = $("tc-grid");
  const html = d.tools.map(card).join("");
  if (reset) grid.innerHTML = d.tools.length ? html : `<div class="muted" style="padding:24px;grid-column:1/-1;text-align:center">No tools match${state.starred ? " — you haven't starred any yet" : ""}.</div>`;
  else grid.insertAdjacentHTML("beforeend", html);
  state.loaded = reset ? d.tools.length : state.loaded + d.tools.length;
  state.offset += d.tools.length;

  $("tc-more").innerHTML = state.loaded < state.total
    ? `<button id="tc-loadmore">Load more (${state.loaded} of ${state.total})</button>` : "";
  const lm = document.getElementById("tc-loadmore");
  if (lm) lm.addEventListener("click", () => { (lm as HTMLButtonElement).disabled = true; void load(false); });
}

document.addEventListener("DOMContentLoaded", () => {
  const sp = new URLSearchParams(location.search);
  if (sp.get("category")) state.category = sp.get("category")!;
  if (sp.get("q")) state.q = sp.get("q")!;
  if (sp.get("sort") && ["stars", "name", "recent"].includes(sp.get("sort")!)) state.sort = sp.get("sort")!;
  if (sp.get("starred") === "1") state.starred = true;
  void load(true);
});
