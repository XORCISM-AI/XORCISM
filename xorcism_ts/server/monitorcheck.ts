/**
 * monitorcheck.ts — the live Asset-Monitoring prober. Periodically probes the enabled
 * MONITORINGCHECK monitors that are due (per their IntervalSeconds) and records the result:
 *   • http  — HTTP(S) request, up if 2xx/3xx (warning if slow / 4xx), down on error/timeout/5xx
 *   • tcp   — TCP connect to host:port
 *   • dns   — DNS resolution of the host
 *   • ssl   — TLS connect, reads the certificate expiry (sets SSLExpiryDate / SSLIssuer)
 *   • ping  — OS `ping` (1 packet), or TCP reachability when a port is given
 *   • server— skipped (those come from the agent / CheckCle connector)
 * Each result goes through updateMonitorStatus (status + up↔down incident lifecycle), plus a rolling
 * uptime % (EMA) and SSL expiry. Stdlib only (http/https/net/tls/dns/child_process); no new deps.
 * Opt-out with XOR_MONITOR=0. No-op when there are no enabled monitors (zero outbound traffic).
 */
import http from "http";
import https from "https";
import net from "net";
import tls from "tls";
import { lookup as dnsLookup } from "dns";
import { execFile } from "child_process";
import { getDb } from "./db";
import { updateMonitorStatus } from "./monitoring";

const PROBE_TIMEOUT = 10_000;
const MIN_INTERVAL = 30; // seconds
const CONCURRENCY = 8;
const SLOW_MS = 2_000;

interface Probe { status: "up" | "down" | "warning"; rt: number | null; sslExpiry?: string | null; sslIssuer?: string | null; msg?: string }

function hostPort(target: string, defPort: number): { host: string; port: number } {
  let t = String(target || "").trim();
  const m = /^[a-z]+:\/\//i.exec(t);
  if (m) { try { const u = new URL(t); return { host: u.hostname, port: Number(u.port) || (u.protocol === "https:" ? 443 : 80) }; } catch { /* fall through */ } }
  t = t.replace(/^[a-z]+:\/\//i, "").split("/")[0];
  const [h, p] = t.split(":");
  return { host: h, port: p ? Number(p) : defPort };
}

function probeHttp(target: string): Promise<Probe> {
  return new Promise((resolve) => {
    let url: URL;
    try { url = new URL(/^https?:\/\//i.test(target) ? target : "http://" + target); } catch { return resolve({ status: "down", rt: null, msg: "bad url" }); }
    const lib = url.protocol === "https:" ? https : http;
    const t0 = Date.now();
    const req = lib.request(url, { method: "GET", timeout: PROBE_TIMEOUT, rejectUnauthorized: false, headers: { "User-Agent": "XORCISM-Monitor" } }, (res) => {
      const rt = Date.now() - t0; res.resume();
      const code = res.statusCode || 0;
      const status = code >= 200 && code < 400 ? (rt > SLOW_MS ? "warning" : "up") : (code >= 400 && code < 500 ? "warning" : "down");
      resolve({ status, rt, msg: `HTTP ${code}` });
    });
    req.on("timeout", () => { req.destroy(); resolve({ status: "down", rt: Date.now() - t0, msg: "timeout" }); });
    req.on("error", (e) => resolve({ status: "down", rt: Date.now() - t0, msg: String((e as Error).message) }));
    req.end();
  });
}

function probeTcp(target: string): Promise<Probe> {
  return new Promise((resolve) => {
    const { host, port } = hostPort(target, 80);
    if (!host || !port) return resolve({ status: "down", rt: null, msg: "bad host:port" });
    const t0 = Date.now();
    const sock = net.connect({ host, port, timeout: PROBE_TIMEOUT });
    sock.on("connect", () => { const rt = Date.now() - t0; sock.destroy(); resolve({ status: rt > SLOW_MS ? "warning" : "up", rt }); });
    sock.on("timeout", () => { sock.destroy(); resolve({ status: "down", rt: Date.now() - t0, msg: "timeout" }); });
    sock.on("error", (e) => resolve({ status: "down", rt: Date.now() - t0, msg: String((e as Error).message) }));
  });
}

function probeDns(target: string): Promise<Probe> {
  return new Promise((resolve) => {
    const host = hostPort(target, 0).host;
    if (!host) return resolve({ status: "down", rt: null, msg: "no host" });
    const t0 = Date.now();
    const timer = setTimeout(() => resolve({ status: "down", rt: Date.now() - t0, msg: "timeout" }), PROBE_TIMEOUT);
    dnsLookup(host, (err, addr) => { clearTimeout(timer); resolve(err ? { status: "down", rt: Date.now() - t0, msg: String(err.message) } : { status: "up", rt: Date.now() - t0, msg: String(addr) }); });
  });
}

function probeSsl(target: string): Promise<Probe> {
  return new Promise((resolve) => {
    const { host, port } = hostPort(target, 443);
    if (!host) return resolve({ status: "down", rt: null, msg: "no host" });
    const t0 = Date.now();
    const sock = tls.connect({ host, port, servername: host, timeout: PROBE_TIMEOUT, rejectUnauthorized: false }, () => {
      const rt = Date.now() - t0;
      const cert = sock.getPeerCertificate();
      sock.destroy();
      if (!cert || !cert.valid_to) return resolve({ status: "warning", rt, msg: "no certificate" });
      const exp = new Date(cert.valid_to);
      const days = Math.floor((exp.getTime() - Date.now()) / 86_400_000);
      const rawIssuer = (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null;
      const issuer = rawIssuer == null ? null : String(Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer);
      resolve({ status: days < 0 ? "down" : days <= 14 ? "warning" : "up", rt, sslExpiry: exp.toISOString().slice(0, 10), sslIssuer: issuer, msg: `expires in ${days}d` });
    });
    sock.on("timeout", () => { sock.destroy(); resolve({ status: "down", rt: Date.now() - t0, msg: "timeout" }); });
    sock.on("error", (e) => resolve({ status: "down", rt: Date.now() - t0, msg: String((e as Error).message) }));
  });
}

function probePing(target: string): Promise<Probe> {
  const { host, port } = hostPort(target, 0);
  if (port) return probeTcp(target); // a port was given → TCP reachability is the honest "ping"
  if (!host) return Promise.resolve({ status: "down", rt: null, msg: "no host" });
  const args = process.platform === "win32" ? ["-n", "1", "-w", "5000", host] : ["-c", "1", "-W", "5", host];
  const t0 = Date.now();
  return new Promise((resolve) => {
    execFile("ping", args, { timeout: PROBE_TIMEOUT, windowsHide: true }, (err, stdout) => {
      const rt = Date.now() - t0;
      if (err) return resolve({ status: "down", rt, msg: "no reply" });
      const m = /time[=<]\s*([\d.]+)\s*ms/i.exec(String(stdout));
      resolve({ status: "up", rt: m ? Math.round(Number(m[1])) : rt });
    });
  });
}

function probe(type: string, target: string): Promise<Probe | null> {
  switch ((type || "http").toLowerCase()) {
    case "http": return probeHttp(target);
    case "tcp": return probeTcp(target);
    case "dns": return probeDns(target);
    case "ssl": return probeSsl(target);
    case "ping": return probePing(target);
    default: return Promise.resolve(null); // "server" etc. → agent/connector-driven
  }
}

/** Minimal 5-field cron matcher (min hour day-of-month month day-of-week). Supports *, lists, ranges, steps. */
function cronField(spec: string, value: number, min: number, max: number): boolean {
  for (const part of spec.split(",")) {
    let [range, stepStr] = part.split("/");
    const step = stepStr ? Number(stepStr) : 1;
    let lo = min; let hi = max;
    if (range !== "*") {
      const m = range.split("-");
      lo = Number(m[0]); hi = m[1] !== undefined ? Number(m[1]) : (stepStr ? max : lo);
    }
    if (Number.isNaN(lo) || Number.isNaN(hi) || step < 1) continue;
    for (let v = lo; v <= hi; v += step) if (((v - min) % (max - min + 1) + (max - min + 1)) % (max - min + 1) + min === value) return true;
  }
  return false;
}
function cronMatches(expr: string, d: Date): boolean {
  const f = expr.trim().split(/\s+/);
  if (f.length !== 5) return false;
  const dow = d.getDay(); // 0=Sun
  return cronField(f[0], d.getMinutes(), 0, 59) && cronField(f[1], d.getHours(), 0, 23) &&
         cronField(f[2], d.getDate(), 1, 31) && cronField(f[3], d.getMonth() + 1, 1, 12) &&
         (cronField(f[4], dow, 0, 6) || cronField(f[4], dow === 0 ? 7 : dow, 0, 7));
}

interface Due { CheckID: number; CheckType: string; Target: string; UptimePercent: number | null; IntervalSeconds: number | null; CronExpression: string | null; LastCheckedAt: string | null }

function dueMonitors(): Due[] {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='MONITORINGCHECK'").get()) return [];
  const hasCron = new Set((db.prepare(`PRAGMA table_info("MONITORINGCHECK")`).all() as { name: string }[]).map((c) => c.name)).has("CronExpression");
  const cronSel = hasCron ? "CronExpression" : "NULL CronExpression";
  const rows = db.prepare(
    `SELECT CheckID, CheckType, Target, UptimePercent, IntervalSeconds, ${cronSel}, LastCheckedAt
     FROM MONITORINGCHECK WHERE (Enabled IS NULL OR Enabled = 1) AND Target IS NOT NULL AND TRIM(Target) <> ''
       AND LOWER(COALESCE(CheckType,'http')) <> 'server'`
  ).all() as Due[];
  const now = Date.now();
  const nowDate = new Date();
  return rows.filter((r) => {
    const last = r.LastCheckedAt ? Date.parse(String(r.LastCheckedAt)) : 0;
    const cron = (r.CronExpression || "").trim();
    if (cron) {
      // Cron-scheduled: due when the current minute matches and we haven't already checked this minute.
      return cronMatches(cron, nowDate) && (!last || Number.isNaN(last) || now - last >= 55_000);
    }
    const iv = Math.max(MIN_INTERVAL, Number(r.IntervalSeconds) || 300) * 1000;
    return !last || Number.isNaN(last) || now - last >= iv;
  });
}

/** Probe all due monitors (bounded concurrency) and record results. Returns how many were checked. */
export async function runMonitorChecks(limit = 200): Promise<number> {
  const due = dueMonitors().slice(0, limit);
  if (!due.length) return 0;
  const db = getDb("XORCISM");
  let i = 0;
  const worker = async (): Promise<void> => {
    while (i < due.length) {
      const m = due[i++];
      try {
        const r = await probe(m.CheckType, m.Target);
        if (!r) continue;
        updateMonitorStatus(m.CheckID, r.status, r.rt, null); // status + incident lifecycle
        // rolling uptime (EMA, available = not down) + SSL expiry/issuer.
        const avail = r.status === "down" ? 0 : 100;
        const up = m.UptimePercent == null ? avail : Math.round((m.UptimePercent * 0.9 + avail * 0.1) * 100) / 100;
        const sets: string[] = ["UptimePercent = ?"]; const args: unknown[] = [up];
        if (r.sslExpiry) { sets.push("SSLExpiryDate = ?"); args.push(r.sslExpiry); }
        if (r.sslIssuer) { sets.push("SSLIssuer = ?"); args.push(r.sslIssuer); }
        args.push(m.CheckID);
        db.prepare(`UPDATE MONITORINGCHECK SET ${sets.join(", ")} WHERE CheckID = ?`).run(...args);
      } catch { /* one bad monitor must not stop the run */ }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, due.length) }, worker));
  return due.length;
}

let timer: NodeJS.Timeout | null = null;
export function startMonitorChecker(): void {
  if (timer || process.env.XOR_MONITOR === "0") return;
  // Tick every 30 s; each monitor is actually probed only when its own interval has elapsed.
  timer = setInterval(() => {
    runMonitorChecks().then((n) => { if (n) console.log(`[monitor] probed ${n} due monitor(s)`); })
      .catch((e) => console.warn(`[monitor] tick: ${(e as Error).message}`));
  }, 30_000);
  if (typeof timer.unref === "function") timer.unref();
  console.log("[monitor] live monitor checker started (30s tick; XOR_MONITOR=0 to disable)");
}
