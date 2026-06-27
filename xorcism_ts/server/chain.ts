/**
 * chain.ts — Pentest tool-chaining orchestrator ("attack playbooks").
 *
 * Mimics a full engagement by chaining connectors: seed a target, run a tool
 * (e.g. nmap), parse its normalized result into *facts* (open ports / services /
 * detected tech / vulns), then fire rules that auto-launch the right next tool
 * (web scanner on 80/443, WPScan when WordPress is seen, …), recursively, until
 * no rule matches. Findings are rolled up onto the engagement (AUDITFINDING).
 *
 * A run is a state machine advanced by a server-side ticker (startChainEngine):
 *   step pending → (launch) → running → (result) → done → (rules) → child steps…
 *
 * Two execution backends per run:
 *   - "simulate" (default): the engine synthesizes a realistic, clearly-labelled
 *     normalized result from the target — NO real scanning, works without a worker.
 *     Use it to design/validate playbooks and demo the engine safely.
 *   - "live": creates real XJOB jobs (queued) executed by the Python runner against
 *     in-scope targets only (ROE re-enforced worker-side). Requires the pentest
 *     capability. The runner persists result_json (see runner.process_job) so the
 *     orchestrator can read the facts back.
 *
 * Tables (XORCISM.db): XCHAINPLAYBOOK, XCHAINRUN, XCHAINSTEP. Tenant scope is
 * inherited from the parent engagement (XCOMPLIANCE.AUDIT) and mirrored on the run.
 */
import fs from "fs";
import path from "path";
import { randomUUID, createHash } from "crypto";
import { getDb } from "./db";
import { createJob, getJob, upsertEngagementByName } from "./jobs";
import { createFinding, getEngagementAssets, ScopeAsset } from "./engagements";

const CONNECTORS_DIR = path.resolve(__dirname, "../../../connectors");

// ── Playbook model ────────────────────────────────────────────────────────────
export interface ChainRule {
  id: string;
  /** Match condition against the producing step's facts. */
  when: { service?: string; ports?: number[]; tech?: string; hasVuln?: boolean; hasHosts?: boolean; hasEmails?: boolean };
  run: string;                       // connector id to launch
  /** url/host/same derive one target from the parent; host-each fans out one step per discovered host. */
  targetFrom: "url" | "host" | "same" | "host-each";
  label: string;
}
export interface PlaybookDef {
  seed: string[];                    // connector(s) run on the seed target
  rules: ChainRule[];
  maxDepth: number;
  maxSteps: number;
}

/** The shipped default playbook — the user's canonical example, end to end. */
export const DEFAULT_PLAYBOOK: PlaybookDef = {
  seed: ["nmap"],
  maxDepth: 4,
  maxSteps: 60,
  rules: [
    { id: "web-fingerprint", when: { service: "https?|http-proxy|http-alt|ssl/http", ports: [80, 443, 8080, 8443, 8000, 8888] }, run: "whatweb", targetFrom: "url", label: "HTTP service open → fingerprint (WhatWeb)" },
    { id: "web-content", when: { service: "https?|http-proxy|http-alt|ssl/http", ports: [80, 443, 8080, 8443, 8000, 8888] }, run: "dirsearch", targetFrom: "url", label: "Web server → dirsearch content discovery (hidden dirs/files)" },
    { id: "web-params", when: { service: "https?|http-proxy|http-alt|ssl/http", ports: [80, 443, 8080, 8443, 8000, 8888] }, run: "arjun", targetFrom: "url", label: "Web server → Arjun HTTP parameter discovery (hidden params → injection/IDOR surface)" },
    { id: "web-nikto", when: { service: "https?|http-proxy|http-alt|ssl/http", ports: [80, 443, 8080, 8443, 8000, 8888] }, run: "nikto", targetFrom: "url", label: "Web server → Nikto vulnerability scan" },
    { id: "web-nuclei", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "nuclei", targetFrom: "url", label: "Web server → Nuclei templates" },
    { id: "web-artemis", when: { service: "https?|http-proxy|http-alt|ssl/http", ports: [80, 443, 8080, 8443, 8000, 8888] }, run: "artemis", targetFrom: "url", label: "Web server → Artemis modular scan (CERT-PL: exposed VCS, outdated CMS, misconfig)" },
    { id: "web-burpwn", when: { service: "https?|http-proxy|http-alt|ssl/http", ports: [80, 443, 8080, 8443, 8000, 8888] }, run: "burpwn", targetFrom: "url", label: "Web server → burpwn proxy capture (endpoints, auth surfaces, sensitive params)" },
    { id: "wordpress", when: { tech: "wordpress" }, run: "wpscan", targetFrom: "url", label: "WordPress detected → WPScan" },
    { id: "wordpress-wpprobe", when: { tech: "wordpress" }, run: "wpprobe", targetFrom: "url", label: "WordPress detected → WPProbe (plugin/theme CVEs)" },
    { id: "graphql", when: { tech: "graphql" }, run: "graphql-cop", targetFrom: "url", label: "GraphQL endpoint detected → GraphQL Cop (introspection / DoS / CSRF / info-leak)" },
    { id: "tls", when: { ports: [443, 8443] }, run: "sslyze", targetFrom: "host", label: "TLS endpoint → sslyze (cert/cipher audit)" },
    { id: "openvas", when: { service: ".*" }, run: "openvas", targetFrom: "host", label: "Open service found → OpenVAS / Greenbone host vulnerability scan (NVT/CVE)" },
    { id: "ai-deep-analysis", when: { hasVuln: true }, run: "cybersentinel-ai", targetFrom: "host", label: "Vulnerability found → CyberSentinel AI deep analysis (33-tool orchestration + AI triage + MITRE ATT&CK mapping)" },
  ],
};

// Sensitive (non-web) services nmap may surface → synthesized findings.
const SENSITIVE: Record<number, { name: string; sev: string }> = {
  21: { name: "FTP", sev: "Low" }, 23: { name: "Telnet (cleartext)", sev: "Medium" },
  22: { name: "SSH", sev: "Info" }, 3389: { name: "RDP", sev: "Medium" },
  3306: { name: "MySQL", sev: "High" }, 5432: { name: "PostgreSQL", sev: "High" },
  1433: { name: "MS SQL Server", sev: "High" }, 27017: { name: "MongoDB", sev: "High" },
  6379: { name: "Redis", sev: "High" }, 9200: { name: "Elasticsearch", sev: "High" },
  445: { name: "SMB", sev: "Medium" }, 25: { name: "SMTP", sev: "Info" },
};

// ── Facts ─────────────────────────────────────────────────────────────────────
export interface Facts {
  services: { port: number; proto: string; name: string; product?: string; version?: string; cpe?: string }[];
  tech: string[];
  vulns: { ref: string; severity: string; name?: string }[];
  hosts: string[];
  emails: string[];
  leaks: { ref: string; severity: string; name?: string }[];
}

function now(): string { return new Date().toISOString().replace("T", " ").slice(0, 19); }

/** Pull facts out of a connector's normalized result (runner contract). */
export function extractFacts(result: any): Facts {
  const f: Facts = { services: [], tech: [], vulns: [], hosts: [], emails: [], leaks: [] };
  if (!result || typeof result !== "object") return f;
  for (const e of result.emails || []) if (e) f.emails.push(String(e).toLowerCase());
  for (const l of result.leaks || []) { if (!l || !l.ref) continue; f.leaks.push({ ref: String(l.ref), severity: String(l.severity || "Medium"), name: l.name || undefined }); }
  for (const s of result.services || []) {
    const port = Number(s.port);
    if (!Number.isFinite(port)) continue;
    f.services.push({ port, proto: String(s.protocol || s.proto || "tcp"), name: String(s.name || "").toLowerCase(), product: s.product || undefined, version: s.version || undefined, cpe: s.cpe || undefined });
  }
  const tech = new Set<string>();
  for (const c of result.cpes || []) techFromCpe(String(c)).forEach((t) => tech.add(t));
  for (const s of f.services) { if (s.cpe) techFromCpe(s.cpe).forEach((t) => tech.add(t)); if (s.product) tech.add(String(s.product).toLowerCase()); }
  for (const t of result.tech || result.technologies || []) tech.add(String(t).toLowerCase());
  f.tech = [...tech];
  for (const v of result.vulns || []) {
    if (!v || !v.ref) continue;
    f.vulns.push({ ref: String(v.ref), severity: String(v.severity || sevOfRef(String(v.ref))), name: v.name || undefined });
  }
  for (const a of result.assets || []) { const h = a.hostname || a.ip; if (h) f.hosts.push(String(h)); }
  for (const h of result.hosts || []) f.hosts.push(String(h));
  return f;
}

/** cpe:/a:wordpress:wordpress:5.2 → ["wordpress"]; cpe:2.3:a:apache:http_server → ["apache","http_server"]. */
function techFromCpe(cpe: string): string[] {
  const out: string[] = [];
  // strip "cpe:" / "cpe:2.3:" / "cpe:/" prefixes and the part letter (a/o/h), for both
  // CPE 2.2 URIs ("cpe:/a:vendor:product:…") and 2.3 FS ("cpe:2.3:a:vendor:product:…").
  const m = cpe.replace(/^cpe:(2\.3:)?\/?/i, "").replace(/^[aoh]:/i, "").split(":").filter(Boolean);
  for (const p of m.slice(0, 2)) { const v = p.toLowerCase(); if (v && v !== "*" && v !== "-") out.push(v); }
  return out;
}
function sevOfRef(ref: string): string { return /^CVE-/i.test(ref) ? "High" : "Medium"; }

// ── Rule evaluation ───────────────────────────────────────────────────────────
function ruleMatches(rule: ChainRule, f: Facts): boolean {
  const w = rule.when;
  let needed = 0, met = 0;
  if (w.service) { needed++; const re = new RegExp(`^(${w.service})$`, "i"); if (f.services.some((s) => re.test(s.name))) met++; }
  if (w.ports && w.ports.length) { needed++; if (f.services.some((s) => w.ports!.includes(s.port))) met++; }
  if (w.tech) { needed++; const re = new RegExp(w.tech, "i"); if (f.tech.some((t) => re.test(t))) met++; }
  if (w.hasVuln) { needed++; if (f.vulns.length) met++; }
  if (w.hasHosts) { needed++; if (f.hosts.length) met++; }
  if (w.hasEmails) { needed++; if (f.emails.length) met++; }
  if (!needed) return false;
  // service/ports are OR'd (either proves "web"); tech/hasVuln are required when present.
  if (w.service && w.ports) {
    const re = new RegExp(`^(${w.service})$`, "i");
    const web = f.services.some((s) => re.test(s.name) || w.ports!.includes(s.port));
    if (!web) return false;
    if (w.tech) { const tre = new RegExp(w.tech, "i"); return f.tech.some((t) => tre.test(t)); }
    return true;
  }
  return met === needed;
}

// ── Target derivation ─────────────────────────────────────────────────────────
export function hostOf(target: string): string {
  let t = String(target || "").trim();
  if (/^https?:\/\//i.test(t)) { try { return new URL(t).hostname; } catch { /* */ } }
  t = t.replace(/^[a-z]+:\/\//i, "").split("/")[0];
  // strip :port unless it's part of an IPv6 literal in brackets
  if (!t.startsWith("[")) t = t.split(":")[0];
  return t;
}
function webTargetFor(host: string, f: Facts): string {
  const tls = f.services.find((s) => [443, 8443].includes(s.port) || /https|ssl\/http/i.test(s.name));
  if (tls) return tls.port === 443 ? `https://${host}` : `https://${host}:${tls.port}`;
  const http = f.services.find((s) => [80, 8080, 8000, 8888].includes(s.port) || /^https?$/i.test(s.name));
  if (http) return http.port === 80 ? `http://${host}` : `http://${host}:${http.port}`;
  return `https://${host}`;
}
function deriveTarget(rule: ChainRule, parentTarget: string, f: Facts): string {
  const host = hostOf(parentTarget);
  if (rule.targetFrom === "host") return host;
  if (rule.targetFrom === "same") return parentTarget;
  return webTargetFor(host, f);
}

// ── Manifest presence (a rule's connector must exist on disk) ─────────────────
const manifestCache = new Map<string, boolean>();
function connectorExists(id: string): boolean {
  if (manifestCache.has(id)) return manifestCache.get(id)!;
  const ok = /^[a-z0-9_-]+$/i.test(id) && fs.existsSync(path.join(CONNECTORS_DIR, id, "connector.json"));
  manifestCache.set(id, ok);
  return ok;
}
function targetParamName(id: string): string | null {
  try {
    const m = JSON.parse(fs.readFileSync(path.join(CONNECTORS_DIR, id, "connector.json"), "utf-8"));
    const params = m.parameters || [];
    // prefer a properly-typed target/url param (the worker enforces ROE scope on those)
    const typed = params.find((x: any) => x.type === "target" || x.type === "url");
    if (typed) return typed.name;
    // fall back to a well-known param name (OSINT connectors often type their target as "string")
    const named = params.find((x: any) => ["target", "domain", "host", "url", "ip", "query"].includes(String(x.name).toLowerCase()));
    return named ? named.name : null;
  } catch { return null; }
}

// ── Schema ────────────────────────────────────────────────────────────────────
let ensured = false;
export function ensureChainTables(): void {
  if (ensured) return;
  const db = getDb("XORCISM");
  db.exec(`
    CREATE TABLE IF NOT EXISTS XCHAINPLAYBOOK(
      PlaybookID INTEGER PRIMARY KEY, PlaybookGUID TEXT, Name TEXT, Description TEXT,
      Definition TEXT, Builtin INTEGER DEFAULT 0, TenantID INTEGER, CreatedDate TEXT, CreatedBy INTEGER);
    CREATE TABLE IF NOT EXISTS XCHAINRUN(
      ChainRunID INTEGER PRIMARY KEY, ChainRunGUID TEXT, AuditID INTEGER, PlaybookID INTEGER,
      PlaybookName TEXT, Name TEXT, SeedTarget TEXT, SeedKind TEXT, Mode TEXT,
      Status TEXT DEFAULT 'running', TenantID INTEGER, CreatedDate TEXT, CreatedBy INTEGER,
      FinishedDate TEXT, StepsTotal INTEGER DEFAULT 0, FindingsTotal INTEGER DEFAULT 0,
      BackingEngagementID INTEGER);
    CREATE TABLE IF NOT EXISTS XCHAINSTEP(
      ChainStepID INTEGER PRIMARY KEY, ChainRunID INTEGER, ParentStepID INTEGER, Depth INTEGER,
      Connector TEXT, Target TEXT, RuleID TEXT, RuleLabel TEXT, JobID INTEGER,
      Status TEXT DEFAULT 'pending', FactsJSON TEXT, Summary TEXT, CreatedDate TEXT, FinishedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_chainrun_audit ON XCHAINRUN(AuditID);
    CREATE INDEX IF NOT EXISTS ix_chainstep_run ON XCHAINSTEP(ChainRunID);`);
  // migration: AssetsTotal — hosts a run auto-discovered into the inventory (OSINT chains).
  try {
    const c = new Set((db.prepare('PRAGMA table_info("XCHAINRUN")').all() as { name: string }[]).map((r) => r.name));
    if (!c.has("AssetsTotal")) db.exec('ALTER TABLE "XCHAINRUN" ADD COLUMN AssetsTotal INTEGER DEFAULT 0');
  } catch { /* ignore */ }
  seedBuiltinPlaybooks(db);
  ensured = true;
}

function seedBuiltinPlaybooks(db: ReturnType<typeof getDb>): void {
  const have = new Set((db.prepare("SELECT Name FROM XCHAINPLAYBOOK WHERE Builtin=1").all() as { Name: string }[]).map((r) => r.Name));
  const builtins: { name: string; description: string; def: PlaybookDef }[] = [
    { name: "Full external pentest", description: "Port/service discovery (nmap) → web fingerprint & scanners on HTTP(S) (Nikto, Nuclei, Artemis) → WPScan on WordPress → TLS audit → OpenVAS/Greenbone host vulnerability scan → CyberSentinel AI deep analysis when a vulnerability is found. Findings roll up to the engagement.", def: DEFAULT_PLAYBOOK },
    { name: "Web app assessment", description: "Fingerprint (WhatWeb) → Nikto + Nuclei + Artemis (CERT-PL) → WPScan + WPProbe when WordPress is detected → GraphQL Cop when a GraphQL endpoint is detected → CyberSentinel AI deep analysis on any web vulnerability. Seed a URL.", def: { seed: ["whatweb", "nikto", "nuclei", "artemis"], maxDepth: 3, maxSteps: 40, rules: [{ id: "wordpress", when: { tech: "wordpress" }, run: "wpscan", targetFrom: "url", label: "WordPress detected → WPScan" }, { id: "wordpress-wpprobe", when: { tech: "wordpress" }, run: "wpprobe", targetFrom: "url", label: "WordPress detected → WPProbe (plugin/theme CVEs)" }, { id: "graphql", when: { tech: "graphql" }, run: "graphql-cop", targetFrom: "url", label: "GraphQL endpoint detected → GraphQL Cop (introspection / DoS / CSRF / info-leak)" }, { id: "ai-web", when: { hasVuln: true }, run: "cybersentinel-ai", targetFrom: "url", label: "Web vulnerability → CyberSentinel AI deep analysis (AI triage + MITRE ATT&CK mapping)" }] } },
    { name: "GraphQL API assessment", description: "Audit a GraphQL endpoint with GraphQL Cop (introspection, GraphiQL/Playground exposure, alias/field/directive/circular-query & batch DoS, GET/POST CSRF, tracing info-leak) → CyberSentinel AI deep analysis on any finding. Seed the GraphQL endpoint URL (e.g. https://app/graphql).", def: { seed: ["graphql-cop"], maxDepth: 2, maxSteps: 8, rules: [{ id: "ai-graphql", when: { hasVuln: true }, run: "cybersentinel-ai", targetFrom: "url", label: "GraphQL issue found → CyberSentinel AI deep analysis (AI triage + MITRE ATT&CK mapping)" }] } },
    { name: "AI agent assessment", description: "Verify an AI/agentic system before deployment with Praxen (behaviour vs declared Worker Remit: policy divergence, credential exposure, missing controls, capability drift, hidden prompts, compound attack paths — mapped to OWASP LLM Top 10 2025 / Agentic AI 2026) → CyberSentinel AI deep analysis on any finding. Findings roll up to the engagement and feed the LLM red-team / AI-BAS module. Seed the agent workspace (a Praxen JSON report).", def: { seed: ["praxen"], maxDepth: 2, maxSteps: 8, rules: [{ id: "ai-agent-triage", when: { hasVuln: true }, run: "cybersentinel-ai", targetFrom: "same", label: "Agent finding → CyberSentinel AI deep analysis (AI triage + MITRE ATT&CK / ATLAS mapping)" }] } },
    { name: "Autonomous AI pentest (Strix)", description: "Run Strix — an autonomous AI hacking agent — against a web app, API or codebase. Strix's AI agents dynamically test and exploit the target like real pentesters and validate each finding with a proof-of-concept (IDOR/auth bypass, SQL/NoSQL/command injection, SSRF/XXE/deserialization, XSS, business-logic, JWT/session, misconfig). Validated findings → ASSET + VULNERABILITY → CyberSentinel AI deep analysis (AI triage + MITRE ATT&CK mapping). Seed the target (a Strix findings JSON / run).", def: { seed: ["strix"], maxDepth: 2, maxSteps: 8, rules: [{ id: "strix-triage", when: { hasVuln: true }, run: "cybersentinel-ai", targetFrom: "same", label: "Strix finding → CyberSentinel AI deep analysis (AI triage + MITRE ATT&CK mapping)" }] } },
    { name: "Digital Risk Protection sweep (NADAR-CTI)", description: "Outside-in Digital Risk Protection: NADAR-CTI sweeps 8 OSINT sources for the organization's external exposure — discovered subdomains & exposed hosts → ASSET, Shodan CVEs / LeakIX misconfig / exposed admin panels → VULNERABILITY, and ransomware-group mentions / credential leaks / breaches → CTI (XTHREAT, ATT&CK-tagged). The newly discovered external hosts are then port/service-scanned with nmap to confirm the live attack surface, and any exposed vulnerability is escalated to CyberSentinel AI for deep triage + MITRE ATT&CK mapping. Seed the org/domain (a NADAR JSON export for offline runs).", def: {
      seed: ["nadar-cti"], maxDepth: 3, maxSteps: 40, rules: [
        { id: "drp-portscan", when: { hasHosts: true }, run: "nmap", targetFrom: "host-each", label: "Exposed subdomain/host discovered → nmap port & service scan (confirm live attack surface)" },
        { id: "drp-triage", when: { hasVuln: true }, run: "cybersentinel-ai", targetFrom: "host", label: "Exposed vulnerability (Shodan CVE / misconfig) → CyberSentinel AI deep analysis (AI triage + MITRE ATT&CK mapping)" },
      ] } },
    { name: "AI-driven full assessment (CyberSentinel AI)", description: "Run CyberSentinel AI (by 3sk1nt4n) directly against a target as the primary engine: its agentic core orchestrates 33 tools (Nmap, Nuclei, Nikto, SQLMap, Shodan, VirusTotal…) in an isolated Kali sandbox, a local LLM (Ollama) triages the real scan results and correlates threat intel, and findings are mapped to MITRE ATT&CK in a Neo4j graph. The scanned host/URL → ASSET, open services → components, each finding (CVE + severity, ATT&CK-tagged) → VULNERABILITY — feeding the exposure, attack-path and threat-informed-defense pipelines. Live mode: seed a host/URL (set api_base to the CyberSentinel FastAPI backend). Offline mode: seed a CyberSentinel results JSON export.", def: { seed: ["cybersentinel-ai"], maxDepth: 1, maxSteps: 4, rules: [] } },
    { name: "Web recon (subdomains)", description: "Subdomain discovery — passive (subfinder) + active brute-force/resolve (puredns) → probe each host with httpx → fingerprint & scan the live web hosts (WhatWeb, Nikto) → WPScan on WordPress. Seed a domain.", def: {
      seed: ["subfinder", "puredns"], maxDepth: 5, maxSteps: 60, rules: [
        { id: "probe", when: { hasHosts: true }, run: "httpx", targetFrom: "host-each", label: "Subdomains found → probe with httpx" },
        { id: "web-fingerprint", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "whatweb", targetFrom: "url", label: "Live web host → fingerprint (WhatWeb)" },
        { id: "web-nikto", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "nikto", targetFrom: "url", label: "Live web host → Nikto scan" },
        { id: "wordpress", when: { tech: "wordpress" }, run: "wpscan", targetFrom: "url", label: "WordPress detected → WPScan" },
      ] } },
    { name: "DNS brute-force recon (puredns)", description: "Active subdomain brute-force with puredns (massdns + wildcard filtering + trusted-resolver validation) → probe each resolved host with httpx → fingerprint & scan the live web hosts (WhatWeb, Nikto) → WPScan on WordPress. Seed a domain; provide a wordlist on the worker for live runs.", def: {
      seed: ["puredns"], maxDepth: 5, maxSteps: 60, rules: [
        { id: "probe", when: { hasHosts: true }, run: "httpx", targetFrom: "host-each", label: "Resolved subdomains → probe with httpx" },
        { id: "web-fingerprint", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "whatweb", targetFrom: "url", label: "Live web host → fingerprint (WhatWeb)" },
        { id: "web-nikto", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "nikto", targetFrom: "url", label: "Live web host → Nikto scan" },
        { id: "wordpress", when: { tech: "wordpress" }, run: "wpscan", targetFrom: "url", label: "WordPress detected → WPScan" },
      ] } },
    { name: "Network recon only", description: "Single nmap sweep — no follow-on tools. Safe baseline.", def: { seed: ["nmap"], maxDepth: 1, maxSteps: 4, rules: [] } },
    { name: "External exploitation (Metasploit)", description: "nmap discovery → web fingerprint/scan → Metasploit auxiliary scanners on the open services → attempt exploitation with Metasploit of any vulnerability found. Seed an IP/host.", def: {
      seed: ["nmap"], maxDepth: 4, maxSteps: 50, rules: [
        { id: "web-fingerprint", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "whatweb", targetFrom: "url", label: "HTTP service → fingerprint (WhatWeb)" },
        { id: "web-nikto", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "nikto", targetFrom: "url", label: "Web server → Nikto scan" },
        { id: "openvas", when: { service: ".*" }, run: "openvas", targetFrom: "host", label: "Open services → OpenVAS / Greenbone vulnerability scan (NVT/CVE)" },
        { id: "msf-aux", when: { service: ".*" }, run: "metasploit-scan", targetFrom: "host", label: "Open services → Metasploit auxiliary scanners" },
        { id: "msf-exploit", when: { hasVuln: true }, run: "metasploit", targetFrom: "host", label: "Vulnerability found → attempt exploitation (Metasploit)" },
      ] } },
    { name: "Internal AD / SMB sweep (Metasploit)", description: "nmap → on SMB (445/139): Metasploit SMB auxiliary scanners + CrackMapExec → exploit SMB vulnerabilities (e.g. MS17-010) with Metasploit. Seed an internal IP or CIDR.", def: {
      seed: ["nmap"], maxDepth: 4, maxSteps: 60, rules: [
        { id: "smb-msf", when: { ports: [445, 139] }, run: "metasploit-scan", targetFrom: "host", label: "SMB open → Metasploit SMB auxiliary (ms17-010…)" },
        { id: "smb-cme", when: { ports: [445] }, run: "crackmapexec", targetFrom: "host", label: "SMB open → CrackMapExec (signing, sessions)" },
        { id: "smb-exploit", when: { hasVuln: true }, run: "metasploit", targetFrom: "host", label: "SMB vulnerability → exploit (Metasploit)" },
      ] } },
    { name: "TLS/SSL hardening audit", description: "nmap → on 443/8443: sslyze + testssl.sh (protocols, ciphers, certificate). Non-intrusive. Seed an IP/host.", def: {
      seed: ["nmap"], maxDepth: 2, maxSteps: 20, rules: [
        { id: "tls-sslyze", when: { ports: [443, 8443] }, run: "sslyze", targetFrom: "host", label: "TLS endpoint → sslyze" },
        { id: "tls-testssl", when: { ports: [443, 8443] }, run: "testssl-sh", targetFrom: "host", label: "TLS endpoint → testssl.sh" },
      ] } },
    { name: "External recon → attack surface (OSINT)", description: "Seed a DOMAIN. Passive recon first (subfinder, theHarvester) → probe each host (httpx) and check exposure (Shodan) → breach check the emails (HIBP) → fingerprint & scan the live web hosts → WPScan. In Live mode, discovered hosts auto-populate the asset inventory.", def: {
      seed: ["subfinder", "theharvester"], maxDepth: 6, maxSteps: 90, rules: [
        { id: "probe", when: { hasHosts: true }, run: "httpx", targetFrom: "host-each", label: "Subdomains found → probe (httpx)" },
        { id: "exposure", when: { hasHosts: true }, run: "shodan", targetFrom: "host-each", label: "Subdomains found → exposure (Shodan, passive)" },
        { id: "breach", when: { hasEmails: true }, run: "have-i-been-pwned", targetFrom: "host", label: "Emails found → breach check (HIBP)" },
        { id: "web-fingerprint", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "whatweb", targetFrom: "url", label: "Live web host → fingerprint (WhatWeb)" },
        { id: "web-nikto", when: { service: "https?|http-proxy|ssl/http", ports: [80, 443, 8080, 8443] }, run: "nikto", targetFrom: "url", label: "Live web host → Nikto scan" },
        { id: "wordpress", when: { tech: "wordpress" }, run: "wpscan", targetFrom: "url", label: "WordPress detected → WPScan" },
      ] } },
  ];
  for (const b of builtins) {
    if (have.has(b.name)) {
      // Keep code authoritative for built-ins: refresh the shipped definition/description
      // so newly-added steps (e.g. the CyberSentinel AI deep-analysis rule) propagate on boot.
      // Users customise by cloning to a non-builtin playbook, so this never clobbers their work.
      db.prepare("UPDATE XCHAINPLAYBOOK SET Description=?, Definition=? WHERE Name=? AND Builtin=1")
        .run(b.description, JSON.stringify(b.def), b.name);
      continue;
    }
    db.prepare(
      `INSERT INTO XCHAINPLAYBOOK (PlaybookID, PlaybookGUID, Name, Description, Definition, Builtin, CreatedDate)
       VALUES ((SELECT COALESCE(MAX(PlaybookID),0)+1 FROM XCHAINPLAYBOOK), ?, ?, ?, ?, 1, ?)`
    ).run(randomUUID(), b.name, b.description, JSON.stringify(b.def), now());
  }
}

// ── Playbooks (read) ──────────────────────────────────────────────────────────
export interface Playbook { PlaybookID: number; Name: string; Description: string; Definition: string; Builtin: number; }
export function listPlaybooks(tenant: number | null): Playbook[] {
  ensureChainTables();
  const db = getDb("XORCISM");
  const where = tenant != null ? "WHERE Builtin=1 OR TenantID=? OR TenantID IS NULL" : "";
  const args = tenant != null ? [tenant] : [];
  return db.prepare(`SELECT PlaybookID, Name, Description, Definition, Builtin FROM XCHAINPLAYBOOK ${where} ORDER BY Builtin DESC, Name`).all(...args) as Playbook[];
}
export function getPlaybook(id: number): Playbook | undefined {
  ensureChainTables();
  return getDb("XORCISM").prepare("SELECT PlaybookID, Name, Description, Definition, Builtin FROM XCHAINPLAYBOOK WHERE PlaybookID=?").get(id) as Playbook | undefined;
}
function parseDef(p: Playbook): PlaybookDef {
  try { const d = JSON.parse(p.Definition); if (d && Array.isArray(d.seed)) return { seed: d.seed, rules: d.rules || [], maxDepth: d.maxDepth || 4, maxSteps: d.maxSteps || 60 }; } catch { /* */ }
  return DEFAULT_PLAYBOOK;
}

// ── Import / export (portable JSON) ───────────────────────────────────────────
const SCHEMA = "xorcism.attack-chain/v1";
const CONN_RE = /^[a-z0-9_-]{1,64}$/i;

function validRe(s: string): boolean { if (s.length > 200) return false; try { new RegExp(s); return true; } catch { return false; } }

/** Validate + clamp an untrusted definition (import). Returns null if unusable. */
function sanitizeDef(raw: any): PlaybookDef | null {
  if (!raw || typeof raw !== "object") return null;
  const seed = (Array.isArray(raw.seed) ? raw.seed : []).filter((s: any) => typeof s === "string" && CONN_RE.test(s)).slice(0, 10);
  if (!seed.length) return null;
  const rules: ChainRule[] = [];
  for (const r of (Array.isArray(raw.rules) ? raw.rules : [])) {
    if (!r || typeof r !== "object" || typeof r.run !== "string" || !CONN_RE.test(r.run)) continue;
    const tf = ["url", "host", "same", "host-each"].includes(r.targetFrom) ? r.targetFrom : "url";
    const w = r.when && typeof r.when === "object" ? r.when : {};
    const when: ChainRule["when"] = {};
    if (typeof w.service === "string" && validRe(w.service)) when.service = w.service.slice(0, 200);
    if (Array.isArray(w.ports)) { const ps = w.ports.map(Number).filter((n: number) => Number.isInteger(n) && n > 0 && n < 65536).slice(0, 50); if (ps.length) when.ports = ps; }
    if (typeof w.tech === "string" && validRe(w.tech)) when.tech = w.tech.slice(0, 200);
    if (w.hasVuln === true) when.hasVuln = true;
    if (w.hasHosts === true) when.hasHosts = true;
    if (!when.service && !when.ports && !when.tech && !when.hasVuln && !when.hasHosts) continue; // a rule with no condition would never fire
    rules.push({ id: (typeof r.id === "string" ? r.id : `r${rules.length}`).slice(0, 64), when, run: r.run, targetFrom: tf, label: (typeof r.label === "string" ? r.label : r.run).slice(0, 200) });
    if (rules.length >= 40) break;
  }
  return { seed, rules, maxDepth: Math.min(8, Math.max(1, Number(raw.maxDepth) || 4)), maxSteps: Math.min(200, Math.max(1, Number(raw.maxSteps) || 60)) };
}

export function exportPlaybook(id: number): any | null {
  const p = getPlaybook(id); if (!p) return null;
  return { schema: SCHEMA, name: p.Name, description: p.Description, builtin: !!p.Builtin, definition: parseDef(p) };
}
export function exportPlaybooks(tenant: number | null): any {
  return { schema: `${SCHEMA}+bundle`, exportedAt: now(), count: 0, playbooks: listPlaybooks(tenant).map((p) => ({ name: p.Name, description: p.Description, builtin: !!p.Builtin, definition: parseDef(p) })) };
}

/** Import one or more playbooks (single object, array, or {playbooks:[…]}). Always non-builtin. */
export function importPlaybooks(payload: any, tenant: number | null, userId: number): { imported: number; skipped: number; names: string[] } {
  ensureChainTables();
  const list = Array.isArray(payload?.playbooks) ? payload.playbooks : Array.isArray(payload) ? payload : [payload];
  const db = getDb("XORCISM");
  let imported = 0, skipped = 0; const names: string[] = [];
  for (const item of list.slice(0, 200)) {
    if (!item || typeof item !== "object") { skipped++; continue; }
    const def = sanitizeDef(item.definition || item.def || item);
    if (!def) { skipped++; continue; }
    let name = ((typeof item.name === "string" && item.name.trim()) ? item.name.trim() : "Imported playbook").slice(0, 120);
    if (db.prepare("SELECT 1 FROM XCHAINPLAYBOOK WHERE Name=? AND Builtin=1").get(name)) name = `${name} (imported)`;
    const desc = (typeof item.description === "string" ? item.description : "").slice(0, 2000);
    const ex = db.prepare("SELECT PlaybookID FROM XCHAINPLAYBOOK WHERE Name=? AND Builtin=0 AND TenantID IS ?").get(name, tenant) as { PlaybookID: number } | undefined;
    if (ex) db.prepare("UPDATE XCHAINPLAYBOOK SET Description=?, Definition=? WHERE PlaybookID=?").run(desc, JSON.stringify(def), ex.PlaybookID);
    else db.prepare(
      `INSERT INTO XCHAINPLAYBOOK (PlaybookID, PlaybookGUID, Name, Description, Definition, Builtin, TenantID, CreatedDate, CreatedBy)
       VALUES ((SELECT COALESCE(MAX(PlaybookID),0)+1 FROM XCHAINPLAYBOOK), ?, ?, ?, ?, 0, ?, ?, ?)`
    ).run(randomUUID(), name, desc, JSON.stringify(def), tenant, now(), userId);
    imported++; names.push(name);
  }
  return { imported, skipped, names };
}

/** Delete a non-builtin playbook (tenant-guarded). Builtins are protected. */
export function deletePlaybook(id: number, tenant: number | null): boolean {
  const db = getDb("XORCISM");
  const p = db.prepare("SELECT Builtin, TenantID FROM XCHAINPLAYBOOK WHERE PlaybookID=?").get(id) as { Builtin: number; TenantID: number | null } | undefined;
  if (!p || p.Builtin) return false;
  if (tenant != null && p.TenantID != null && p.TenantID !== tenant) return false;
  db.prepare("DELETE FROM XCHAINPLAYBOOK WHERE PlaybookID=?").run(id);
  return true;
}

// ── Runs ──────────────────────────────────────────────────────────────────────
export interface ChainRun {
  ChainRunID: number; AuditID: number; PlaybookID: number; PlaybookName: string; Name: string;
  SeedTarget: string; SeedKind: string; Mode: string; Status: string; CreatedDate: string;
  FinishedDate: string | null; StepsTotal: number; FindingsTotal: number; AssetsTotal?: number; TenantID?: number | null;
}
export interface ChainStep {
  ChainStepID: number; ChainRunID: number; ParentStepID: number | null; Depth: number;
  Connector: string; Target: string; RuleID: string | null; RuleLabel: string | null;
  JobID: number | null; Status: string; FactsJSON: string | null; Summary: string | null;
  CreatedDate: string; FinishedDate: string | null;
}

export function listRuns(auditId: number): ChainRun[] {
  ensureChainTables();
  return getDb("XORCISM").prepare(
    `SELECT ChainRunID, AuditID, PlaybookID, PlaybookName, Name, SeedTarget, SeedKind, Mode, Status,
            CreatedDate, FinishedDate, StepsTotal, FindingsTotal, AssetsTotal
     FROM XCHAINRUN WHERE AuditID=? ORDER BY ChainRunID DESC`
  ).all(auditId) as ChainRun[];
}
export function getRun(runId: number): ChainRun | undefined {
  ensureChainTables();
  return getDb("XORCISM").prepare(
    `SELECT ChainRunID, AuditID, PlaybookID, PlaybookName, Name, SeedTarget, SeedKind, Mode, Status,
            CreatedDate, FinishedDate, StepsTotal, FindingsTotal, AssetsTotal, TenantID
     FROM XCHAINRUN WHERE ChainRunID=?`
  ).get(runId) as ChainRun | undefined;
}
export function getRunSteps(runId: number): ChainStep[] {
  ensureChainTables();
  return getDb("XORCISM").prepare(
    `SELECT ChainStepID, ChainRunID, ParentStepID, Depth, Connector, Target, RuleID, RuleLabel,
            JobID, Status, FactsJSON, Summary, CreatedDate, FinishedDate
     FROM XCHAINSTEP WHERE ChainRunID=? ORDER BY ChainStepID`
  ).all(runId) as ChainStep[];
}

function addStep(db: ReturnType<typeof getDb>, runId: number, parentId: number | null, depth: number, connector: string, target: string, ruleId: string | null, ruleLabel: string | null): number {
  db.prepare(
    `INSERT INTO XCHAINSTEP (ChainStepID, ChainRunID, ParentStepID, Depth, Connector, Target, RuleID, RuleLabel, Status, CreatedDate)
     VALUES ((SELECT COALESCE(MAX(ChainStepID),0)+1 FROM XCHAINSTEP), ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`
  ).run(runId, parentId, depth, connector, target, ruleId, ruleLabel, now());
  return (db.prepare("SELECT MAX(ChainStepID) m FROM XCHAINSTEP WHERE ChainRunID=?").get(runId) as { m: number }).m;
}

/** Create a run + its seed step(s). Returns the run id. */
export function createRun(o: {
  auditId: number; tenant: number | null; playbookId: number; seedTarget: string; seedKind: string;
  mode: "simulate" | "live"; name?: string; userId: number;
}): { runId: number; error?: string } {
  ensureChainTables();
  const db = getDb("XORCISM");
  const pb = getPlaybook(o.playbookId);
  if (!pb) return { runId: 0, error: "playbook not found" };
  const def = parseDef(pb);
  const seedConns = def.seed.filter(connectorExists);
  if (!seedConns.length) return { runId: 0, error: "no runnable seed connector for this playbook" };

  let backingId: number | null = null;
  if (o.mode === "live") {
    backingId = upsertEngagementByName(`Chain: ${pb.Name} → ${o.seedTarget} (audit ${o.auditId})`, [hostOf(o.seedTarget)], "Tool-chaining run", o.userId);
  }
  const guid = randomUUID();
  db.prepare(
    `INSERT INTO XCHAINRUN (ChainRunID, ChainRunGUID, AuditID, PlaybookID, PlaybookName, Name, SeedTarget,
        SeedKind, Mode, Status, TenantID, CreatedDate, CreatedBy, BackingEngagementID)
     VALUES ((SELECT COALESCE(MAX(ChainRunID),0)+1 FROM XCHAINRUN), ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)`
  ).run(guid, o.auditId, o.playbookId, pb.Name, o.name || `${pb.Name} · ${o.seedTarget}`, o.seedTarget, o.seedKind, o.mode, o.tenant, now(), o.userId, backingId);
  const runId = (db.prepare("SELECT MAX(ChainRunID) m FROM XCHAINRUN WHERE ChainRunGUID=?").get(guid) as { m: number }).m;
  for (const c of seedConns) addStep(db, runId, null, 0, c, o.seedTarget, "seed", "Seed");
  db.prepare("UPDATE XCHAINRUN SET StepsTotal=(SELECT COUNT(*) FROM XCHAINSTEP WHERE ChainRunID=?) WHERE ChainRunID=?").run(runId, runId);
  // Kick the engine immediately so the UI shows progress without waiting a full tick.
  setTimeout(() => { try { advanceRun(runId); } catch { /* ticker will retry */ } }, 50);
  return { runId };
}

export function stopRun(runId: number): void {
  const db = getDb("XORCISM");
  db.prepare("UPDATE XCHAINRUN SET Status='stopped', FinishedDate=? WHERE ChainRunID=? AND Status='running'").run(now(), runId);
  db.prepare("UPDATE XCHAINSTEP SET Status='skipped' WHERE ChainRunID=? AND Status IN ('pending')").run(runId);
}

// ── Engine ────────────────────────────────────────────────────────────────────
function summarize(connector: string, f: Facts): string {
  if (f.services.length) {
    const top = f.services.slice(0, 8).map((s) => `${s.port}/${s.name || s.proto}`).join(", ");
    return `${f.services.length} open: ${top}${f.services.length > 8 ? "…" : ""}`;
  }
  if (f.leaks.length) return `${f.leaks.length} leak/breach finding(s)`;
  if (f.vulns.length) return `${f.vulns.length} issue(s)` + (f.tech.length ? ` · ${f.tech.slice(0, 4).join(", ")}` : "");
  if (f.tech.length) return `tech: ${f.tech.slice(0, 6).join(", ")}`;
  if (f.hosts.length > 1 || f.emails.length) {
    const parts: string[] = [];
    if (f.hosts.length > 1) parts.push(`${f.hosts.length} hosts`);
    if (f.emails.length) parts.push(`${f.emails.length} emails`);
    return parts.join(" · ") + (f.hosts.length > 1 ? `: ${f.hosts.slice(0, 3).join(", ")}${f.hosts.length > 3 ? "…" : ""}` : "");
  }
  return "no actionable result";
}

/** Map a discovered host to an in-scope engagement asset (best-effort). */
function assetForHost(assets: ScopeAsset[], host: string): number | null {
  const h = host.toLowerCase();
  for (const a of assets) {
    for (const v of [a.ipaddressIPv4, a.ipaddressIPv6, a.fqdn, a.hostname]) if (v && String(v).toLowerCase() === h) return a.AssetID;
    if (a.websiteurl && hostOf(String(a.websiteurl)).toLowerCase() === h) return a.AssetID;
  }
  return null;
}

/** Roll up a step's facts into engagement findings (deduped by name within the run). */
function rollupFindings(run: ChainRun, step: ChainStep, f: Facts): number {
  const db = getDb("XCOMPLIANCE");
  const existing = new Set((db.prepare("SELECT FindingName FROM AUDITFINDING WHERE AuditID=?").all(run.AuditID) as { FindingName: string }[]).map((r) => r.FindingName));
  const assets = getEngagementAssets(run.AuditID);
  const host = hostOf(step.Target);
  const aid = assetForHost(assets, host);
  const tag = run.Mode === "simulate" ? " (simulated)" : "";
  let made = 0;
  const make = (name: string, severity: string, description: string) => {
    if (existing.has(name)) return; existing.add(name);
    createFinding(run.AuditID, { name, severity, status: "Open", source: `chain:${step.Connector}`, description: description + tag, assetIds: aid ? [aid] : [] });
    made++;
  };
  for (const v of f.vulns) make(`${v.ref}${v.name ? " — " + v.name : ""} on ${host}`, v.severity, `Reported by ${step.Connector} during the attack chain on ${step.Target}.`);
  for (const l of f.leaks) make(`${l.name || l.ref} (${host})`, l.severity, `OSINT/breach exposure reported by ${step.Connector} for ${step.Target}.`);
  if (step.Connector === "nmap") for (const s of f.services) { const m = SENSITIVE[s.port]; if (m) make(`${m.name} exposed (${s.port}/${s.proto}) on ${host}`, m.sev, `Service ${m.name} reachable on ${host}:${s.port}${s.product ? ` (${s.product} ${s.version || ""})` : ""}.`); }
  // XCHAINRUN lives in XORCISM (db above is the XCOMPLIANCE handle for findings).
  if (made) getDb("XORCISM").prepare("UPDATE XCHAINRUN SET FindingsTotal=FindingsTotal+? WHERE ChainRunID=?").run(made, run.ChainRunID);
  return made;
}

/** Apply the playbook rules to a finished step's facts → enqueue child steps. */
function applyRules(run: ChainRun, step: ChainStep, f: Facts): void {
  const pb = getPlaybook(run.PlaybookID); if (!pb) return;
  const def = parseDef(pb);
  if (step.Depth + 1 > def.maxDepth) return;
  const db = getDb("XORCISM");
  const steps = getRunSteps(run.ChainRunID);
  if (steps.length >= def.maxSteps) return;
  const seen = new Set(steps.map((s) => `${s.Connector}|${s.Target}`));
  for (const rule of def.rules) {
    if (!ruleMatches(rule, f)) continue;
    if (!connectorExists(rule.run)) continue;
    // host-each fans out one step per discovered host (capped); others derive a single target.
    const targets = rule.targetFrom === "host-each"
      ? [...new Set(f.hosts.map((h) => hostOf(h)).filter(Boolean))].slice(0, 25)
      : [deriveTarget(rule, step.Target, f)];
    for (const target of targets) {
      const key = `${rule.run}|${target}`;
      if (seen.has(key)) continue;
      seen.add(key);
      addStep(db, run.ChainRunID, step.ChainStepID, step.Depth + 1, rule.run, target, rule.id, rule.label);
      if (seen.size >= def.maxSteps) break;
    }
    if (seen.size >= def.maxSteps) break;
  }
  db.prepare("UPDATE XCHAINRUN SET StepsTotal=(SELECT COUNT(*) FROM XCHAINSTEP WHERE ChainRunID=?) WHERE ChainRunID=?").run(run.ChainRunID, run.ChainRunID);
}

/**
 * Auto-inventory: LIVE OSINT/recon discovery promotes discovered hosts to ASSETs
 * (idempotent by name) and links them to the engagement scope. Simulate mode never
 * writes to the inventory. Returns the number of NEW assets created.
 */
function promoteHostsToAssets(run: ChainRun, step: ChainStep, f: Facts): number {
  if (run.Mode !== "live") return 0;
  const xo = getDb("XORCISM");
  const cols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((r) => r.name));
  // discovered subdomains (f.hosts) + the step's own target host
  const hosts = [...new Set([...f.hosts, hostOf(step.Target)].map((h) => hostOf(String(h || ""))).filter(Boolean))].slice(0, 50);
  const stepHost = hostOf(step.Target);
  const web = f.services.find((s) => /^https?$/.test(s.name) || [80, 443, 8080, 8443].includes(s.port));
  const tenant = (run as { TenantID?: number | null }).TenantID ?? null;
  let made = 0;
  for (const h of hosts) {
    let aid: number;
    const ex = xo.prepare("SELECT AssetID FROM ASSET WHERE AssetName=?").get(h) as { AssetID: number } | undefined;
    if (ex) aid = ex.AssetID;
    else {
      const fields = ["AssetID", "AssetName", "AssetDescription", "CreatedDate"];
      const place = ["(SELECT COALESCE(MAX(AssetID),0)+1 FROM ASSET)", "?", "?", "?"];
      const vals: unknown[] = [h, `Discovered via OSINT chain (${run.PlaybookName})`, now()];
      if (cols.has("TenantID")) { fields.push("TenantID"); place.push("?"); vals.push(tenant); }
      if (web && h === stepHost && cols.has("websiteurl")) { fields.push("websiteurl"); place.push("?"); vals.push((web.port === 443 ? "https://" : "http://") + h); }
      xo.prepare(`INSERT INTO ASSET (${fields.join(",")}) VALUES (${place.join(",")})`).run(...vals);
      aid = (xo.prepare("SELECT MAX(AssetID) m FROM ASSET WHERE AssetName=?").get(h) as { m: number }).m;
      made++;
    }
    try {
      if (!xo.prepare("SELECT 1 FROM ASSETAUDIT WHERE AssetID=? AND AuditID=?").get(aid, run.AuditID)) {
        xo.prepare(`INSERT INTO ASSETAUDIT (AssetAuditID, AssetAuditGUID, AssetID, AuditID, Date, ValidFrom)
          VALUES ((SELECT COALESCE(MAX(AssetAuditID),0)+1 FROM ASSETAUDIT), ?, ?, ?, ?, ?)`).run(randomUUID(), aid, run.AuditID, now(), now());
      }
    } catch { /* link table variant */ }
  }
  if (made) xo.prepare("UPDATE XCHAINRUN SET AssetsTotal=COALESCE(AssetsTotal,0)+? WHERE ChainRunID=?").run(made, run.ChainRunID);
  return made;
}

function completeStep(run: ChainRun, step: ChainStep, result: any): void {
  const db = getDb("XORCISM");
  const f = extractFacts(result);
  db.prepare("UPDATE XCHAINSTEP SET Status='done', FactsJSON=?, Summary=?, FinishedDate=? WHERE ChainStepID=?")
    .run(JSON.stringify(f).slice(0, 200000), summarize(step.Connector, f), now(), step.ChainStepID);
  rollupFindings(run, step, f);
  promoteHostsToAssets(run, step, f);
  applyRules(run, { ...step, Status: "done" }, f);
}

/** Launch a step: simulate (synthesize result) or live (queue an XJOB). */
function launchStep(run: ChainRun, step: ChainStep): void {
  const db = getDb("XORCISM");
  if (run.Mode === "simulate") {
    const result = simulateResult(step.Connector, step.Target);
    completeStep(run, step, result);
    return;
  }
  // live: create a real job (ROE enforced by the worker via BackingEngagementID)
  const tp = targetParamName(step.Connector);
  const backing = (getRun(run.ChainRunID) as any)?.BackingEngagementID ?? null;
  if (!tp) { db.prepare("UPDATE XCHAINSTEP SET Status='error', Summary=?, FinishedDate=? WHERE ChainStepID=?").run("connector has no target parameter", now(), step.ChainStepID); return; }
  const jobId = createJob(step.Connector, { [tp]: step.Target }, step.Target, run.AuditID, backing, null);
  db.prepare("UPDATE XCHAINSTEP SET Status='running', JobID=? WHERE ChainStepID=?").run(jobId, step.ChainStepID);
}

/** Poll a live step's backing job and complete/fail the step when it settles. */
function pollLiveStep(run: ChainRun, step: ChainStep): void {
  if (!step.JobID) return;
  const job = getJob(step.JobID);
  const db = getDb("XORCISM");
  if (!job) { db.prepare("UPDATE XCHAINSTEP SET Status='error', Summary=?, FinishedDate=? WHERE ChainStepID=?").run("job vanished", now(), step.ChainStepID); return; }
  if (["done", "collected", "importing"].includes(job.status)) {
    let result: any = {};
    try { result = JSON.parse(job.result_json || "{}"); } catch { /* */ }
    completeStep(run, step, result);
  } else if (["failed", "error"].includes(job.status)) {
    db.prepare("UPDATE XCHAINSTEP SET Status='error', Summary=?, FinishedDate=? WHERE ChainStepID=?").run((job.error || "tool failed").slice(0, 300), now(), step.ChainStepID);
  }
  // queued/running → keep waiting
}

/** Advance a single run by one step of work. Safe to call repeatedly. */
export function advanceRun(runId: number): void {
  const run = getRun(runId);
  if (!run || run.Status !== "running") return;
  const db = getDb("XORCISM");
  const steps = getRunSteps(runId);
  for (const s of steps) {
    if (s.Status === "pending") launchStep(run, s);
    else if (s.Status === "running") pollLiveStep(run, s);
  }
  const after = getRunSteps(runId);
  const busy = after.some((s) => s.Status === "pending" || s.Status === "running");
  if (!busy) {
    db.prepare("UPDATE XCHAINRUN SET Status='done', FinishedDate=?, StepsTotal=? WHERE ChainRunID=? AND Status='running'").run(now(), after.length, runId);
  }
}

let timer: NodeJS.Timeout | null = null;
let ticking = false;
/** Server-side ticker: advances every active chain run. Booted from index.ts. */
export function startChainEngine(): void {
  if (timer) return;
  ensureChainTables();
  timer = setInterval(() => {
    if (ticking) return;
    ticking = true;
    try {
      const runs = getDb("XORCISM").prepare("SELECT ChainRunID FROM XCHAINRUN WHERE Status='running'").all() as { ChainRunID: number }[];
      for (const r of runs) { try { advanceRun(r.ChainRunID); } catch { /* keep the loop alive */ } }
    } finally { ticking = false; }
  }, 1500);
  timer.unref?.();
}

// ── Simulator (safe, deterministic, clearly-labelled — NO real scanning) ──────
// 31-bit positive hash → signed `>>` and `%` downstream stay non-negative (no undefined picks).
function h32(s: string): number { return parseInt(createHash("sha256").update(s).digest("hex").slice(0, 8), 16) & 0x7fffffff; }
function pick<T>(arr: T[], seed: number): T { return arr[seed % arr.length]; }

/**
 * Produce a plausible normalized result for (connector, target) without touching
 * any host. Deterministic from the target so a run is reproducible. Web ports are
 * biased to appear so the chain demonstrably fans out into web tooling.
 */
export function simulateResult(connector: string, target: string): any {
  const host = hostOf(target);
  const seed = h32(host + "|" + connector);
  if (connector === "nmap") {
    const services: any[] = [
      { asset: host, port: 22, protocol: "tcp", state: "open", name: "ssh", product: "OpenSSH", version: pick(["7.4", "8.2p1", "9.0"], seed) },
      { asset: host, port: 80, protocol: "tcp", state: "open", name: "http", product: pick(["Apache httpd", "nginx", "Microsoft IIS"], seed), version: pick(["2.4.41", "1.18.0", "10.0"], seed >> 2) },
      { asset: host, port: 443, protocol: "tcp", state: "open", name: "https", product: pick(["Apache httpd", "nginx"], seed >> 1), version: pick(["2.4.41", "1.18.0"], seed >> 3) },
    ];
    const extras = [3306, 3389, 21, 8080, 6379, 445, 5432];
    const n = seed % extras.length;
    for (let i = 0; i < n && i < 3; i++) {
      const p = extras[(seed >> (i + 1)) % extras.length];
      const nm: Record<number, string> = { 3306: "mysql", 3389: "ms-wbt-server", 21: "ftp", 8080: "http-proxy", 6379: "redis", 445: "microsoft-ds", 5432: "postgresql" };
      if (!services.some((s) => s.port === p)) services.push({ asset: host, port: p, protocol: "tcp", state: "open", name: nm[p] || "unknown" });
    }
    const cpes = services.filter((s) => s.product).map((s) => `cpe:/a:${String(s.product).split(" ")[0].toLowerCase()}:${String(s.product).split(" ").pop()!.toLowerCase()}:${s.version}`);
    return { assets: [{ ip: host, hostname: host, os: pick(["Linux 5.x", "Windows Server 2019", "Ubuntu 20.04"], seed) }], services, cpes: [...new Set(cpes)], vulns: [] };
  }
  if (["subfinder", "amass", "sublist3r", "puredns"].includes(connector)) {
    // puredns brute-forces a large wordlist (active) → simulate a wider set than passive enum
    const labels = ["www", "api", "dev", "staging", "mail", "vpn", "shop", "blog", "admin", "test", "git", "jenkins", "portal", "internal"];
    const apex = host.replace(/^www\./, "");
    const n = connector === "puredns" ? 5 + (seed % 4) : 3 + (seed % 3); // puredns 5–8, others 3–5
    const hosts = new Set<string>();
    for (let i = 0; i < n; i++) hosts.add(`${labels[(seed >> i) % labels.length]}.${apex}`);
    const list = [...hosts];
    return { assets: list.map((h) => ({ hostname: h, ip: h })), hosts: list, services: [], cpes: [], vulns: [] };
  }
  if (connector === "theharvester") {
    const labels = ["www", "mail", "portal", "vpn", "remote", "dev", "api"];
    const apex = host.replace(/^www\./, "");
    const hosts = [...new Set(Array.from({ length: 2 + (seed % 3) }, (_, i) => `${labels[(seed >> i) % labels.length]}.${apex}`))];
    const names = ["admin", "info", "jdoe", "contact", "support", "hr", "sales"];
    const emails = [...new Set(Array.from({ length: 2 + (seed % 4) }, (_, i) => `${names[(seed >> i) % names.length]}@${apex}`))];
    return { assets: hosts.map((hn) => ({ hostname: hn, ip: hn })), hosts, emails, services: [], cpes: [], vulns: [] };
  }
  if (["shodan", "censys", "fofa", "netlas"].includes(connector)) {
    // passive exposure: report exposed services + tech WITHOUT touching the host
    const cat: [number, string][] = [[443, "https"], [80, "http"], [22, "ssh"]];
    const services = cat.slice(0, 2 + (seed % 2)).map(([p, n]) => ({ asset: host, port: p, protocol: "tcp", state: "open", name: n, product: pick(["nginx", "Apache httpd", "OpenSSH"], seed) }));
    const isWp = seed % 3 === 0;
    return { assets: [{ hostname: host, ip: host }], services, tech: isWp ? ["wordpress"] : [], cpes: isWp ? ["cpe:/a:wordpress:wordpress:6.1"] : [], vulns: [] };
  }
  if (["have-i-been-pwned", "holehe", "hudson-rock", "dehashed"].includes(connector)) {
    const breaches = pick([["LinkedIn (2021)", "Collection #1"], ["Dropbox (2016)", "Adobe (2013)"], ["Facebook (2019)"]], seed);
    const leaks = breaches.map((bn, i) => ({ asset: host, ref: `HIBP-${i}`, severity: "Medium", name: `Account present in breach: ${bn}` }));
    if (seed % 2 === 0) leaks.push({ asset: host, ref: "HIBP-CREDS", severity: "High", name: "Plaintext credential pair exposed in a public paste" });
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: [], leaks };
  }
  if (connector === "httpx") {
    if (seed % 4 === 0) return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: [] }; // 25% not a live web host
    const isWp = seed % 3 === 0;
    return {
      assets: [{ hostname: host, ip: host }],
      services: [{ asset: host, port: 443, protocol: "tcp", state: "open", name: "https", product: pick(["nginx", "Apache httpd", "cloudflare"], seed) }],
      tech: isWp ? ["wordpress"] : [], cpes: isWp ? ["cpe:/a:wordpress:wordpress:6.1"] : [], vulns: [],
    };
  }
  if (connector === "whatweb") {
    const isWp = seed % 2 === 0;
    const stack = pick([["Apache", "PHP"], ["nginx", "PHP"], ["IIS", "ASP.NET"]], seed);
    const tech = [...stack.map((s) => s.toLowerCase()), ...(isWp ? ["wordpress"] : [])];
    const cpes = isWp ? ["cpe:/a:wordpress:wordpress:6.1"] : [];
    return { assets: [{ hostname: host, ip: host }], services: [{ asset: host, port: /https/i.test(target) ? 443 : 80, protocol: "tcp", name: "http", product: stack[0] }], tech, cpes, vulns: [] };
  }
  if (connector === "nikto") {
    const v: any[] = [
      { asset: host, ref: "NIKTO-XFO", severity: "Low", name: "Missing X-Frame-Options header" },
      { asset: host, ref: "NIKTO-BANNER", severity: "Info", name: "Server banner discloses software version" },
    ];
    if (seed % 3 === 0) v.push({ asset: host, ref: "CVE-2021-41773", severity: "High", name: "Apache 2.4.49 path traversal" });
    if (seed % 5 === 0) v.push({ asset: host, ref: "NIKTO-DIRIDX", severity: "Medium", name: "Directory indexing enabled on /backup/" });
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: v };
  }
  if (connector === "nuclei") {
    const v: any[] = [{ asset: host, ref: "NUCLEI-TECH", severity: "Info", name: "Technology detection" }];
    if (seed % 2 === 0) v.push({ asset: host, ref: "CVE-2017-5638", severity: "Critical", name: "Apache Struts RCE (S2-045)" });
    if (seed % 4 === 0) v.push({ asset: host, ref: "NUCLEI-GITEXP", severity: "Medium", name: "Exposed .git directory" });
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: v };
  }
  if (connector === "wpscan") {
    const plugin = pick(["contact-form-7", "elementor", "woocommerce", "wpforms"], seed);
    return {
      assets: [{ hostname: host, ip: host }], tech: ["wordpress"], cpes: ["cpe:/a:wordpress:wordpress:6.1"], services: [],
      vulns: [
        { asset: host, ref: "WPVDB-CORE", severity: "Medium", name: "WordPress core 6.1 — known issues, update available" },
        { asset: host, ref: pick(["CVE-2023-2745", "CVE-2022-1903", "CVE-2023-4634"], seed), severity: "High", name: `Vulnerable plugin: ${plugin}` },
      ],
    };
  }
  if (connector === "sslyze" || connector === "testssl-sh") {
    const v: any[] = [];
    if (seed % 2 === 0) v.push({ asset: host, ref: "TLS-WEAKCIPHER", severity: "Medium", name: "Weak cipher suites enabled (TLS 1.0/1.1)" });
    if (seed % 3 === 0) v.push({ asset: host, ref: "TLS-EXPIRING", severity: "Low", name: "Certificate expires in < 30 days" });
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: v };
  }
  if (connector === "metasploit-scan") {
    // auxiliary scanners — may surface a critical SMB/RDP RCE
    const v: any[] = [];
    if (seed % 2 === 0) v.push({ asset: host, ref: "CVE-2017-0144", severity: "Critical", name: "MS17-010 EternalBlue (SMB RCE) — auxiliary/scanner/smb/smb_ms17_010" });
    else v.push({ asset: host, ref: "MSF-SMBVER", severity: "Info", name: "SMB version / host information disclosed" });
    if (seed % 3 === 0) v.push({ asset: host, ref: "CVE-2019-0708", severity: "Critical", name: "BlueKeep RDP (CVE-2019-0708) likely vulnerable" });
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: v };
  }
  if (connector === "metasploit") {
    // exploitation attempt — deterministic ~50% success
    if (seed % 2 === 0) return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: [{ asset: host, ref: "MSF-SESSION", severity: "Critical", name: "Exploitation successful — Meterpreter session opened (exploit/windows/smb/ms17_010_eternalblue)" }] };
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: [] }; // target not exploitable / no session
  }
  if (connector === "crackmapexec" || connector === "netexec") {
    const v: any[] = [{ asset: host, ref: "CME-SMBSIGN", severity: "Medium", name: "SMB signing not required" }];
    if (seed % 4 === 0) v.push({ asset: host, ref: "CME-NULLSESS", severity: "Medium", name: "Null session / anonymous SMB access allowed" });
    return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: v };
  }
  // unknown connector → no actionable facts
  return { assets: [{ hostname: host, ip: host }], services: [], cpes: [], vulns: [] };
}
