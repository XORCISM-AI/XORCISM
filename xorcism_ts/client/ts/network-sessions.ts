/** network-sessions.ts — NetFlow cartography around ASSET (/network-sessions). Reads /api/network-sessions. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const stCls = (s: string): string => (/establish/i.test(s) ? "st-established" : /reject|block|deny|drop/i.test(s) ? "st-rejected" : "st-other");
function bytes(n: number): string { if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB"; if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB"; if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB"; return n + " B"; }

function load(): void {
  fetch("/api/network-sessions").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    if (!d.sessions.length && !d.services.length) {
      $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No network-flow data yet.<br>
        Run the <a href="/connectors?connector=obserae" style="color:#a5b4fc">Obserae</a> connector with a NetFlow/IPFIX cartography + sessions export to populate discovered assets, services and sessions.</div>`;
      return;
    }
    const cards = [
      card("Assets seen", String(s.assets), "with flows/services"),
      card("Services", String(s.services), `${s.serviceInstances} on assets`, "#60a5fa"),
      card("Sessions", String(s.sessions), bytes(s.totalBytes) + " total"),
      card("External inbound", String(s.externalInbound), "from the Internet", s.externalInbound ? "#fbbf24" : "#4ade80"),
      card("Rejected", String(s.rejected), "blocked/denied flows", s.rejected ? "#f87171" : "#4ade80"),
    ].join("");

    const maxFlows = Math.max(1, ...d.services.map((x: any) => x.flows));
    const svc = d.services.map((x: any) => `<div class="row"><span class="nm2"><span class="proto">${esc(x.protocol)}/${x.port}</span> ${esc(x.service || "—")}</span><div class="bar"><i style="width:${(x.flows / maxFlows) * 100}%"></i></div><span style="min-width:80px;text-align:right" class="muted">${x.assets} host${x.assets > 1 ? "s" : ""} · ${x.flows} flows</span></div>`).join("");
    const maxB = Math.max(1, ...d.talkers.map((x: any) => x.bytes));
    const talk = d.talkers.map((x: any) => `<div class="row"><span class="nm2"><b style="color:#e2e8f0">${esc(x.name)}</b></span><div class="bar"><i style="width:${(x.bytes / maxB) * 100}%"></i></div><span style="min-width:90px;text-align:right" class="muted">${bytes(x.bytes)} · ${x.sessions} sess.</span></div>`).join("");

    const sess = d.sessions.length
      ? `<table class="t"><thead><tr><th>Source</th><th>Destination</th><th>Proto</th><th>Service</th><th>Bytes</th><th>State</th><th>Last seen</th></tr></thead><tbody>${d.sessions.map((x: any) => `<tr>
          <td><span class="mono">${esc(x.src)}</span>${x.external ? ` <span class="ext">EXT</span>` : ""}${x.srcAsset ? `<div class="muted" style="font-size:11px">${esc(x.srcAsset)}</div>` : ""}${x.srcPort ? `<span class="muted" style="font-size:10px"> :${x.srcPort}</span>` : ""}</td>
          <td><span class="mono">${esc(x.dst)}</span>${x.dstAsset ? `<div class="muted" style="font-size:11px">${esc(x.dstAsset)}</div>` : ""}${x.dstPort ? `<span class="muted" style="font-size:10px"> :${x.dstPort}</span>` : ""}</td>
          <td><span class="proto">${esc(x.protocol)}</span></td><td>${esc(x.service || "—")}</td><td>${bytes(x.bytes)}</td>
          <td><span class="st ${stCls(x.state)}">${esc(x.state || "—")}</span></td><td class="muted" style="font-size:11px">${esc(x.lastSeen)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">No sessions.</div>`;
    const disc = d.assets.length
      ? `<table class="t"><thead><tr><th>Asset</th><th>Services</th><th>Sessions</th><th>Traffic</th></tr></thead><tbody>${d.assets.slice(0, 40).map((a: any) => `<tr><td><a class="nm" style="color:#a5b4fc" href="/?db=XORCISM&table=ASSET&filterCol=AssetID&filterVal=${a.id}">${esc(a.name)}</a></td><td>${a.services}</td><td>${a.sessions}</td><td>${bytes(a.bytes)}</td></tr>`).join("")}</tbody></table>`
      : "<div class='muted'>—</div>";

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="grid2">
        <div class="panel"><div class="sec" style="margin-top:0">Exposed services / ports</div>${svc || "<div class='muted'>No services.</div>"}</div>
        <div class="panel"><div class="sec" style="margin-top:0">Top talkers (by traffic)</div>${talk || "<div class='muted'>—</div>"}</div>
      </div>
      <div class="sec">Sessions (${d.sessions.length})</div>${sess}
      <div class="sec">Discovered assets (${d.assets.length})</div>${disc}`;
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
document.addEventListener("DOMContentLoaded", load);
