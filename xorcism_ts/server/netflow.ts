/**
 * netflow.ts — Network flow (NetFlow/IPFIX) observability around ASSET: discovery, monitoring and
 * SOC investigation. Reads the ASSETSERVICE (asset↔service: protocol/port) and NETWORKSESSION
 * (reconstructed flows: src↔dst, bytes/packets, state) tables fed by the obserae connector, and
 * derives the cartography view — discovered assets, exposed services/ports, top talkers, the session
 * list, and suspicious flows (external inbound, rejected). Seeds a small demo cartography.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

function cols(t: string): Set<string> { try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); } }
function has(t: string): boolean { try { return !!getDb("XORCISM").prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; } }
const isPrivate = (ip: string): boolean => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(String(ip || ""));
function tw(tenant: number | null, col = "TenantID"): string { return tenant != null ? `WHERE (${col} = ${tenant} OR ${col} IS NULL)` : ""; }

export function netflowInventory(tenant: number | null): any {
  const db = getDb("XORCISM");
  if (!has("NETWORKSESSION") && !has("ASSETSERVICE")) return { assets: [], services: [], sessions: [], talkers: [], summary: { assets: 0, services: 0, sessions: 0 } };
  const assetName = new Map<number, string>();
  try { for (const a of db.prepare("SELECT AssetID, AssetName FROM ASSET").all() as any[]) assetName.set(Number(a.AssetID), String(a.AssetName || `#${a.AssetID}`)); } catch { /* */ }

  // services (ASSET ↔ SERVICE)
  const svcRows = has("ASSETSERVICE") ? (db.prepare(`SELECT * FROM ASSETSERVICE ${tw(tenant)} ORDER BY FlowCount DESC`).all() as any[]) : [];
  const svcByAsset = new Map<number, number>();
  const portAgg = new Map<string, { service: string; protocol: string; port: number; assets: number; flows: number }>();
  for (const s of svcRows) {
    svcByAsset.set(Number(s.AssetID), (svcByAsset.get(Number(s.AssetID)) || 0) + 1);
    const k = `${s.Protocol}/${s.Port}`;
    const p = portAgg.get(k) || { service: String(s.ServiceName || ""), protocol: String(s.Protocol || ""), port: Number(s.Port || 0), assets: 0, flows: 0 };
    p.assets++; p.flows += Number(s.FlowCount || 0); if (!p.service && s.ServiceName) p.service = String(s.ServiceName); portAgg.set(k, p);
  }
  const services = [...portAgg.values()].sort((a, b) => b.flows - a.flows).slice(0, 40);

  // sessions
  const sessRows = has("NETWORKSESSION") ? (db.prepare(`SELECT * FROM NETWORKSESSION ${tw(tenant)} ORDER BY NetworkSessionID DESC`).all() as any[]) : [];
  const bytesByAsset = new Map<number, number>(); const sessByAsset = new Map<number, number>();
  let totalBytes = 0, extInbound = 0, rejected = 0;
  const sessions = sessRows.map((s) => {
    const b = Number(s.Bytes || 0); totalBytes += b;
    for (const aid of [s.SrcAssetID, s.DstAssetID]) if (aid != null) { bytesByAsset.set(Number(aid), (bytesByAsset.get(Number(aid)) || 0) + b); sessByAsset.set(Number(aid), (sessByAsset.get(Number(aid)) || 0) + 1); }
    const srcExt = !isPrivate(String(s.SrcIP)), state = String(s.State || "");
    if (srcExt && isPrivate(String(s.DstIP))) extInbound++;
    if (/reject|block|denied|drop/i.test(state)) rejected++;
    return { id: Number(s.NetworkSessionID), src: String(s.SrcIP || ""), srcAsset: s.SrcAssetID != null ? assetName.get(Number(s.SrcAssetID)) : null, dst: String(s.DstIP || ""), dstAsset: s.DstAssetID != null ? assetName.get(Number(s.DstAssetID)) : null,
      protocol: String(s.Protocol || ""), srcPort: s.SrcPort != null ? Number(s.SrcPort) : null, dstPort: s.DstPort != null ? Number(s.DstPort) : null, service: String(s.ServiceName || ""),
      bytes: b, packets: Number(s.Packets || 0), flows: Number(s.Flows || 0), state, direction: String(s.Direction || ""), external: srcExt,
      lastSeen: s.LastSeen ? String(s.LastSeen).slice(0, 16).replace("T", " ") : "" };
  });

  // discovered assets (have a service or a session)
  const aids = new Set<number>([...svcByAsset.keys(), ...sessByAsset.keys()]);
  const assets = [...aids].map((id) => ({ id, name: assetName.get(id) || `#${id}`, services: svcByAsset.get(id) || 0, sessions: sessByAsset.get(id) || 0, bytes: bytesByAsset.get(id) || 0 }))
    .sort((a, b) => b.bytes - a.bytes).slice(0, 60);
  const talkers = [...bytesByAsset.entries()].map(([id, bytes]) => ({ id, name: assetName.get(id) || `#${id}`, bytes, sessions: sessByAsset.get(id) || 0 })).sort((a, b) => b.bytes - a.bytes).slice(0, 12);

  return {
    assets, services, sessions: sessions.slice(0, 200), talkers,
    summary: { assets: aids.size, services: portAgg.size, serviceInstances: svcRows.length, sessions: sessRows.length,
      totalBytes, gb: Math.round((totalBytes / 1e9) * 100) / 100, externalInbound: extInbound, rejected, uniquePorts: portAgg.size },
  };
}

// ── seed (demo cartography mirroring connectors/obserae/sample.yaml) ──────────────
export function seedNetflow(tenant: number): { assets: number; services: number; sessions: number } {
  const db = getDb("XORCISM");
  if (!has("NETWORKSESSION")) return { assets: 0, services: 0, sessions: 0 };
  if ((db.prepare("SELECT COUNT(*) n FROM NETWORKSESSION").get() as { n: number }).n) return { assets: 0, services: 0, sessions: 0 };
  const now = new Date().toISOString();
  const cache = new Map<string, number>();
  const ensureAsset = (name: string, hostname?: string, os?: string): number => {
    if (cache.has(name)) return cache.get(name)!;
    const ex = db.prepare("SELECT AssetID FROM ASSET WHERE AssetName = ? LIMIT 1").get(name) as { AssetID: number } | undefined;
    if (ex) { cache.set(name, ex.AssetID); return ex.AssetID; }
    const r = db.prepare("INSERT INTO ASSET (AssetName, hostname, OSName, CreatedDate) VALUES (?,?,?,?)").run(name.slice(0, 200), hostname ?? null, os ?? null, now);
    const id = Number(r.lastInsertRowid); cache.set(name, id); return id;
  };
  const hosts: [string, string, string, string][] = [["web-prod-01", "10.0.0.21", "web-prod-01.corp", "Linux"], ["db-prod-01", "10.0.0.22", "db-prod-01.corp", "Linux"], ["app-prod-01", "10.0.0.30", "", "Linux"]];
  for (const [n, ip, hn, os] of hosts) { const aid = ensureAsset(n, hn, os); cache.set(ip, aid); }
  let na = cache.size;
  const svc: [string, string, number, string, number][] = [["10.0.0.21", "tcp", 443, "https", 412], ["10.0.0.21", "tcp", 22, "ssh", 8], ["10.0.0.22", "tcp", 5432, "postgresql", 96], ["10.0.0.30", "tcp", 8080, "http-app", 210]];
  let ns = 0;
  const insSvc = db.prepare("INSERT INTO ASSETSERVICE (AssetID, Protocol, Port, ServiceName, FlowCount, FirstSeen, LastSeen, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)");
  for (const [ip, proto, port, name, flows] of svc) { const aid = ensureAsset(ip); try { insSvc.run(aid, proto, port, name, flows, now, now, "Obserae", tenant, now); ns++; } catch { /* unique */ } }
  const sess: [string, string, string, number, number, string, number, number, number, string][] = [
    ["203.0.113.5", "10.0.0.21", "tcp", 51514, 443, "https", 184320, 220, 3, "established"],
    ["10.0.0.30", "10.0.0.22", "tcp", 40122, 5432, "postgresql", 982144, 1450, 22, "established"],
    ["10.0.0.21", "10.0.0.30", "tcp", 33990, 8080, "http-app", 451000, 690, 14, "established"],
    ["198.51.100.9", "10.0.0.21", "tcp", 44210, 22, "ssh", 8400, 60, 5, "rejected"],
  ];
  let nse = 0;
  const insS = db.prepare("INSERT INTO NETWORKSESSION (SessionGUID, SrcAssetID, DstAssetID, SrcIP, DstIP, Protocol, SrcPort, DstPort, ServiceName, Bytes, Packets, Flows, State, Direction, FirstSeen, LastSeen, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
  for (const [src, dst, proto, sp, dp, name, bytes, pkts, flows, state] of sess) {
    insS.run(randomUUID(), ensureAsset(src), ensureAsset(dst), src, dst, proto, sp, dp, name, bytes, pkts, flows, state, isPrivate(src) ? "internal" : "inbound", now, now, "Obserae", tenant, now); nse++;
  }
  return { assets: na, services: ns, sessions: nse };
}
