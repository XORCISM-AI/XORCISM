/**
 * endpointquery.ts — Tanium-style real-time endpoint querying ("Interact").
 *
 * Ask a question of the whole XOR agent fleet and get answers back in seconds, aggregated into
 * an answer grid (distinct value × number of endpoints) — Tanium's signature capability, built on
 * the existing pull-based agent tasking (XAGENTJOB kind="query", claimed at the next check-in) and
 * the XOR agent's local sensors. Questions + per-endpoint answers live in XAGENT.
 *
 *   askQuestion()  → one XAGENTJOB(kind=query) per ONLINE agent
 *   agent          → runs the sensor, POSTs answers to /api/agent/query
 *   questionResults() → groups answers into the answer grid (Tanium "Saved Question" view)
 */
import { getAgentDb, listAgents, createAgentJob } from "./agents";
import { allocId } from "./db";
import { randomUUID } from "crypto";

const nowSql = (): string => new Date().toISOString().replace("T", " ").slice(0, 19);

/** The sensor catalogue — the named questions the fleet can answer. `list` sensors return many
 *  values per endpoint (e.g. processes); single sensors return one value per endpoint. */
export interface Sensor { id: string; name: string; category: string; description: string; list: boolean; unit?: string }
export const SENSORS: Sensor[] = [
  { id: "os-version", name: "Operating System", category: "System", description: "OS name + version of each endpoint.", list: false },
  { id: "ip-address", name: "IP Address", category: "Network", description: "Primary IPv4 address.", list: false },
  { id: "last-reboot", name: "Last Reboot", category: "System", description: "Days since last boot (uptime bucket).", list: false },
  { id: "cpu-percent", name: "CPU Usage", category: "Performance", description: "Current CPU utilization bucket.", list: false, unit: "%" },
  { id: "memory-percent", name: "Memory Usage", category: "Performance", description: "Current memory utilization bucket.", list: false, unit: "%" },
  { id: "disk-free-gb", name: "Free Disk Space", category: "Performance", description: "Free space on the system drive (bucket).", list: false, unit: "GB" },
  { id: "domain-joined", name: "Domain / Workgroup", category: "System", description: "AD domain or workgroup membership.", list: false },
  { id: "agent-version", name: "XOR Agent Version", category: "Inventory", description: "Version of the XOR agent running.", list: false },
  { id: "running-processes", name: "Running Processes", category: "Investigate", description: "Process names currently running (filterable).", list: true },
  { id: "installed-apps", name: "Installed Applications", category: "Inventory", description: "Installed application names.", list: true },
  { id: "listening-ports", name: "Listening Ports", category: "Network", description: "TCP ports in LISTEN state.", list: true },
  { id: "logged-in-users", name: "Logged-in Users", category: "Investigate", description: "Interactive user sessions.", list: true },
  { id: "local-admins", name: "Local Administrators", category: "Identity", description: "Members of the local Administrators group.", list: true },
  { id: "running-services", name: "Running Services", category: "System", description: "Services in the running state.", list: true },
];
export const sensorById = (id: string): Sensor | undefined => SENSORS.find((s) => s.id === id);

export function ensureEndpointQueryTables(): void {
  let db; try { db = getAgentDb(); } catch { return; }
  db.exec(`
    CREATE TABLE IF NOT EXISTS ENDPOINTQUESTION (
      QuestionID INTEGER PRIMARY KEY, QuestionGUID TEXT, SensorID TEXT, SensorName TEXT, Text TEXT,
      Filter TEXT, AskedByUserID INTEGER, AskedByName TEXT, TargetCount INTEGER, Status TEXT,
      AskedAt TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS ENDPOINTANSWER (
      AnswerID INTEGER PRIMARY KEY, QuestionID INTEGER, Agent TEXT, Value TEXT, CreatedAt TEXT);
    CREATE INDEX IF NOT EXISTS ix_epanswer_q ON ENDPOINTANSWER(QuestionID);
    CREATE INDEX IF NOT EXISTS ix_epquestion_tenant ON ENDPOINTQUESTION(TenantID);
  `);
}

const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

/** Ask a question of the online fleet: records the question + queues a query job per online agent. */
export function askQuestion(sensorId: string, opts: { filter?: string; userId?: number | null; userName?: string }, tenant: number | null): { questionId: number; targeted: number; sensor: string } | null {
  ensureEndpointQueryTables();
  const sensor = sensorById(sensorId);
  if (!sensor) return null;
  const db = getAgentDb();
  const online = listAgents().filter((a) => String((a as { status?: string }).status || "").toLowerCase() === "online");
  const id = allocId(db, "ENDPOINTQUESTION", "QuestionID");
  const text = `Get ${sensor.name}${opts.filter ? ` containing "${opts.filter}"` : ""} from all machines`;
  db.prepare(`INSERT INTO ENDPOINTQUESTION (QuestionID, QuestionGUID, SensorID, SensorName, Text, Filter, AskedByUserID, AskedByName, TargetCount, Status, AskedAt, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), sensor.id, sensor.name, text, opts.filter || null, opts.userId ?? null, opts.userName || null, online.length, online.length ? "asking" : "no-targets", nowSql(), tenant);
  // queue a pull-based query job for each online agent (answered at the next check-in)
  for (const a of online) {
    try { createAgentJob(a.name, "query", { questionId: id, sensorId: sensor.id, filter: opts.filter || null }, opts.userId ?? null); } catch { /* */ }
  }
  return { questionId: id, targeted: online.length, sensor: sensor.name };
}

/** Record one endpoint's answers to a question (called by the agent result endpoint). */
export function recordAnswers(agent: string, questionId: number, values: string[]): { stored: number } {
  ensureEndpointQueryTables();
  const db = getAgentDb();
  const q = db.prepare("SELECT QuestionID FROM ENDPOINTQUESTION WHERE QuestionID=?").get(questionId);
  if (!q) return { stored: 0 };
  const vals = (Array.isArray(values) ? values : [String(values)]).map((v) => String(v ?? "").slice(0, 400)).filter((v) => v !== "");
  // replace any prior answers from this agent for this question (latest wins)
  db.prepare("DELETE FROM ENDPOINTANSWER WHERE QuestionID=? AND Agent=?").run(questionId, agent);
  let aid = allocId(db, "ENDPOINTANSWER", "AnswerID");
  const ins = db.prepare("INSERT INTO ENDPOINTANSWER (AnswerID, QuestionID, Agent, Value, CreatedAt) VALUES (?,?,?,?,?)");
  const tx = db.transaction(() => { for (const v of (vals.length ? vals : ["(none)"])) ins.run(aid++, questionId, agent, v, nowSql()); });
  tx();
  // mark complete when all targets have answered
  const target = num((db.prepare("SELECT TargetCount FROM ENDPOINTQUESTION WHERE QuestionID=?").get(questionId) as { TargetCount: number }).TargetCount);
  const answered = num((db.prepare("SELECT COUNT(DISTINCT Agent) n FROM ENDPOINTANSWER WHERE QuestionID=?").get(questionId) as { n: number }).n);
  db.prepare("UPDATE ENDPOINTQUESTION SET Status=? WHERE QuestionID=?").run(answered >= target && target > 0 ? "complete" : "asking", questionId);
  return { stored: vals.length };
}

/** The answer grid for a question: distinct value × number of endpoints (Tanium "Saved Question"). */
export function questionResults(questionId: number, tenant: number | null): any {
  ensureEndpointQueryTables();
  const db = getAgentDb();
  const q = db.prepare("SELECT * FROM ENDPOINTQUESTION WHERE QuestionID=?").get(questionId) as any;
  if (!q) return null;
  if (tenant != null && q.TenantID != null && Number(q.TenantID) !== tenant) return null;
  const rows = db.prepare("SELECT Value, COUNT(DISTINCT Agent) n FROM ENDPOINTANSWER WHERE QuestionID=? GROUP BY Value ORDER BY n DESC, Value").all(questionId) as { Value: string; n: number }[];
  const answered = num((db.prepare("SELECT COUNT(DISTINCT Agent) n FROM ENDPOINTANSWER WHERE QuestionID=?").get(questionId) as { n: number }).n);
  const target = num(q.TargetCount);
  const maxN = rows.reduce((m, r) => Math.max(m, num(r.n)), 0) || 1;
  return {
    id: questionId, text: String(q.Text), sensor: String(q.SensorName), filter: q.Filter || null, status: String(q.Status),
    askedBy: q.AskedByName || null, askedAt: String(q.AskedAt || ""), target, answered, pct: target ? Math.round((answered / target) * 100) : 0,
    grid: rows.map((r) => ({ value: String(r.Value), endpoints: num(r.n), bar: Math.round((num(r.n) / maxN) * 100) })),
  };
}

export function recentQuestions(tenant: number | null, limit = 25): any[] {
  ensureEndpointQueryTables();
  const tw = tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  return (getAgentDb().prepare(`SELECT QuestionID, SensorName, Text, Filter, TargetCount, Status, AskedByName, AskedAt FROM ENDPOINTQUESTION ${tw} ORDER BY QuestionID DESC LIMIT ${limit}`).all() as any[])
    .map((q) => {
      const answered = num((getAgentDb().prepare("SELECT COUNT(DISTINCT Agent) n FROM ENDPOINTANSWER WHERE QuestionID=?").get(q.QuestionID) as { n: number }).n);
      return { id: num(q.QuestionID), sensor: String(q.SensorName), text: String(q.Text), filter: q.Filter || null, target: num(q.TargetCount), answered, status: String(q.Status), askedBy: q.AskedByName || null, askedAt: String(q.AskedAt || "") };
    });
}

export function endpointQueryDashboard(tenant: number | null): any {
  ensureEndpointQueryTables();
  let agents: any[] = [];
  try { agents = listAgents(); } catch { /* */ }
  const online = agents.filter((a) => String(a.status || "").toLowerCase() === "online").length;
  return {
    fleet: { total: agents.length, online, offline: agents.length - online },
    sensors: SENSORS, categories: [...new Set(SENSORS.map((s) => s.category))],
    questions: recentQuestions(tenant),
  };
}

/** Demo seed: a few answered questions with realistic aggregated answers, so the answer grid is
 *  populated without a live agent fleet. Synthetic endpoint hostnames; demo only. */
export function seedEndpointQueryDemo(tenant: number): { questions: number } {
  ensureEndpointQueryTables();
  const db = getAgentDb();
  if (num((db.prepare("SELECT COUNT(*) n FROM ENDPOINTQUESTION WHERE TenantID=?").get(tenant) as { n: number }).n) > 0) return { questions: 0 };
  const hosts = Array.from({ length: 18 }, (_, i) => `EP-${String(i + 1).padStart(3, "0")}`);
  const mk = (sensorId: string, filter: string | null, text: string, perHost: (h: string, i: number) => string[]): void => {
    const s = sensorById(sensorId)!;
    const qid = allocId(db, "ENDPOINTQUESTION", "QuestionID");
    db.prepare("INSERT INTO ENDPOINTQUESTION (QuestionID, QuestionGUID, SensorID, SensorName, Text, Filter, AskedByName, TargetCount, Status, AskedAt, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
      .run(qid, randomUUID(), s.id, s.name, text, filter, "demo", hosts.length, "complete", nowSql(), tenant);
    let aid = allocId(db, "ENDPOINTANSWER", "AnswerID");
    const ins = db.prepare("INSERT INTO ENDPOINTANSWER (AnswerID, QuestionID, Agent, Value, CreatedAt) VALUES (?,?,?,?,?)");
    hosts.forEach((h, i) => { for (const v of perHost(h, i)) ins.run(aid++, qid, h, v, nowSql()); });
  };
  const os = ["Windows 11 Pro 23H2", "Windows 11 Pro 23H2", "Windows 11 Pro 23H2", "Windows 10 Pro 22H2", "Windows 10 Pro 22H2", "Ubuntu 22.04 LTS", "Ubuntu 22.04 LTS", "macOS 14 Sonoma", "Windows Server 2022"];
  mk("os-version", null, "Get Operating System from all machines", (h, i) => [os[i % os.length]]);
  mk("running-processes", "chrome", "Get Running Processes containing \"chrome\" from all machines", (h, i) => i % 3 === 0 ? ["chrome.exe"] : i % 3 === 1 ? ["chrome.exe", "chrome.exe"] : ["(none)"]);
  mk("listening-ports", null, "Get Listening Ports from all machines", (h, i) => i % 2 ? ["445", "139", "3389"] : ["445", "139", "22"]);
  mk("disk-free-gb", null, "Get Free Disk Space from all machines", (h, i) => [["< 10 GB", "10–50 GB", "50–100 GB", "> 100 GB"][i % 4]]);
  mk("local-admins", null, "Get Local Administrators from all machines", (h, i) => i % 5 === 0 ? ["Administrator", "BUILTIN\\Domain Admins", "svc-backup"] : ["Administrator", "BUILTIN\\Domain Admins"]);
  return { questions: 5 };
}
