/**
 * cvematch.ts — Continuous CVE → ASSET matching ("New CVEs for ASSET"), precision-tuned.
 *
 * Links newly-imported CVEs to the assets whose *technologies* they affect. An asset's technologies
 * come from two CURATED inventories — its CPE inventory (CPEFORASSET → CPE vendor/product) and its
 * software products (ASSETPRODUCT → PRODUCT.ProductName / ProductVendor / CPE) — plus, as a weak
 * fallback only, its free-text tech tags (ASSETTAG.Tag).
 *
 * The hard problem is FALSE POSITIVES: CVE titles are just the CVE id (VULName == VULReferentialID)
 * so the only text signal is the long VULDescription prose, and matching a generic tag like "email"
 * (in ~4,900 descriptions) or a bare vendor/OS token ("apple", "windows", "microsoft") against that
 * prose links an asset to thousands of irrelevant CVEs. To fix this, matches are CONFIDENCE-TIERED and
 * only links at/above a threshold (default Medium) are auto-created; the trusted signals are the
 * CURATED product & CPE inventories, NOT free tags:
 *
 *   High   — precise CPE link: the CVE's affected CPE (VULNERABILITYFORCPE) shares a CPE *identity*
 *            (part:vendor:product, via cpeCanon — the two DBs do NOT share a CPE integer id, and the
 *            asset side is CPE 2.2 while the CVE side is CPE 2.3, so the match is by canonical name)
 *            with a CPE of the asset — from CPEFORASSET *or* a linked PRODUCT's CPE. Also High: a
 *            vendor+product *pair* both word-matched in the CVE text (from a CPE or a PRODUCT
 *            vendor+name) — a strong, specific co-occurrence.
 *   Medium — a *specific product* word/phrase matched in the CVE text: a non-generic token from the
 *            asset's CPE products, or an ASSETPRODUCT → PRODUCT.ProductName (a curated name, matched
 *            as its full phrase or a specific single token — never a generic sub-word).
 *   Low    — any ASSETTAG token (free text). Tags are the weakest signal — a generic tag like "email"
 *            must never link a mail asset to random CVEs — so they are deliberately kept BELOW the
 *            auto-link threshold: recorded but NOT auto-linked by default (run with minConfidence=low
 *            to include them).
 *   (dropped) — generic categories / protocols / OS / vendor names (email, web, dns, vpn, firewall,
 *            windows, apple, microsoft, …) and bare CPE/product vendor tokens never match on their own.
 *
 * Every auto-created link records MatchConfidence / MatchSource / MatchedToken on ASSETVULNERABILITY
 * so users can audit and triage (and bulk-flag FalsePositive). Idempotent; watermark-bounded.
 */
import { getDb, notifyUsers } from "./db";
import { emitLoopEvent } from "./croc";
import * as xid from "./xid";

// Generic technology categories / protocols / OS / vendors that occur in too much CVE prose to be a
// reliable per-asset signal on their own. Applied to standalone CPE-product tokens AND to tags
// (NOT to CPE vendor+product pairs, where the product narrows the vendor). Lowercase, "_"→" ".
const BLOCKLIST = new Set<string>([
  "", "*", "-", "n/a", "and", "the", "for", "with", "all", "none", "other", "misc", "general",
  // generic software/role words
  "app", "application", "web", "www", "site", "website", "api", "rest", "soap", "graphql", "sdk", "cli", "gui", "ui",
  "data", "core", "base", "common", "main", "default", "server", "client", "service", "services", "daemon", "agent",
  "system", "systems", "tool", "tools", "toolkit", "suite", "platform", "software", "hardware", "firmware", "device",
  "appliance", "module", "plugin", "addon", "extension", "library", "lib", "framework", "runtime", "middleware",
  "engine", "manager", "management", "console", "portal", "dashboard", "admin", "panel", "controller", "node", "host",
  "cluster", "container", "image", "package", "registry", "repo", "repository", "endpoint", "workstation", "desktop",
  "laptop", "mobile", "tablet", "phone", "printer", "scanner", "camera", "sensor", "gateway", "proxy", "cache",
  "queue", "broker", "bus", "stream", "pipeline", "function", "lambda", "worker", "job", "task", "cron", "scheduler",
  "test", "dev", "prod", "staging", "demo", "sample", "example", "lab", "sandbox",
  // generic product-name qualifiers (never a specific product on their own — guards single-word names)
  "security", "update", "updates", "standard", "professional", "enterprise", "premium", "essentials",
  "edition", "redistributable", "redist", "component", "components", "assistant", "utility", "utilities",
  // categories / protocols
  "email", "mail", "webmail", "smtp", "imap", "pop3", "exchange", "messaging", "chat", "im", "sms", "voice", "voip",
  "sip", "pbx", "telephony", "video", "conference", "meeting", "collaboration", "calendar", "contacts", "directory",
  "web", "http", "https", "html", "css", "js", "json", "xml", "yaml", "dns", "dhcp", "ntp", "snmp", "ldap", "kerberos",
  "radius", "saml", "oidc", "vpn", "ssh", "ftp", "sftp", "tftp", "ftps", "tls", "ssl", "ipsec", "smb", "cifs", "nfs",
  "rdp", "vnc", "telnet", "rpc", "soap", "mqtt", "amqp", "kafka",
  "database", "db", "datastore", "sql", "nosql", "rdbms", "warehouse", "datalake", "storage", "nas", "san", "backup",
  "restore", "archive", "filesystem", "fs", "disk", "volume",
  "network", "networking", "lan", "wan", "vlan", "subnet", "wifi", "wireless", "bluetooth", "router", "switch",
  "modem", "firewall", "waf", "ids", "ips", "siem", "edr", "xdr", "ndr", "soar", "antivirus", "av", "dlp", "casb",
  "cloud", "saas", "paas", "iaas", "faas", "serverless", "vm", "vmware", "hypervisor", "virtualization", "iot", "ot",
  "ics", "scada", "plc", "hmi",
  "auth", "authentication", "authz", "authorization", "sso", "mfa", "2fa", "otp", "totp", "login", "logon", "session",
  "credential", "credentials", "password", "passwd", "secret", "token", "key", "cert", "certificate", "pki",
  "crm", "erp", "hr", "hrm", "finance", "accounting", "billing", "payroll", "payment", "payments", "pos", "ecommerce",
  "shop", "cart", "checkout", "cms", "blog", "forum", "wiki", "lms", "itsm", "ticketing", "helpdesk",
  "monitor", "monitoring", "metrics", "logging", "logs", "log", "telemetry", "analytics", "reporting", "report",
  "file", "files", "folder", "document", "documents", "docs", "spreadsheet", "pdf", "office", "image", "images",
  "media", "audio", "photo", "photos", "music", "game", "games",
  // OS / vendors (too broad alone; vendors still used via CPE pairs)
  "windows", "win", "linux", "unix", "macos", "osx", "mac", "ios", "ipados", "android", "chromeos", "ubuntu", "debian",
  "redhat", "rhel", "centos", "fedora", "suse", "opensuse", "solaris", "aix", "hpux", "freebsd", "openbsd", "netbsd",
  "microsoft", "apple", "google", "amazon", "aws", "azure", "gcp", "oracle", "ibm", "cisco", "juniper", "hp", "hpe",
  "dell", "lenovo", "intel", "amd", "nvidia", "qualcomm", "broadcom", "samsung", "huawei", "xiaomi", "sony", "lg",
  "adobe", "sap", "salesforce", "atlassian", "vmware", "citrix", "fortinet", "paloalto", "checkpoint", "sophos",
  "mcafee", "symantec", "trellix", "kaspersky", "trendmicro", "crowdstrike", "sentinelone", "zscaler", "okta",
]);

// Short (3–4 char) tokens that ARE specific products (so a tag of this name links at Medium).
const KNOWN_SHORT_PRODUCTS = new Set<string>([
  "php", "git", "vim", "tar", "zip", "gzip", "bzip2", "curl", "wget", "sudo", "bash", "zsh", "ksh", "tcsh", "perl",
  "ruby", "rust", "nodejs", "deno", "bun", "java", "dotnet", "exim", "bind", "ntpd", "lighttpd", "haproxy",
  "varnish", "memcached", "redis", "mysql", "psql", "sqlite", "jira", "grafana", "kibana", "consul", "vault", "nomad",
  "envoy", "istio", "helm", "kubectl", "containerd", "runc", "podman", "qemu", "xen", "kvm", "glibc", "musl", "zlib",
  "expat", "pcre", "libxml2", "libxslt", "openssl", "libssh", "krb5", "samba", "squid", "nginx", "httpd", "tomcat",
  "jetty", "struts", "spring", "log4j", "log4net", "jackson", "drupal", "joomla", "moodle", "magento", "wordpress",
  "gitlab", "github", "jenkins", "ansible", "terraform", "vault", "minio", "rabbitmq", "mongodb", "mariadb", "postgres",
  "postgresql", "elasticsearch", "opensearch", "splunk", "zabbix", "nagios", "snort", "suricata", "wireshark", "nmap",
]);

const CONF_LABEL: Record<number, string> = { 3: "High", 2: "Medium", 1: "Low" };

function escapeRe(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function normToken(t: string): string { return String(t || "").replace(/_/g, " ").trim().toLowerCase(); }
function nowTs(): string { return new Date().toISOString().slice(0, 19).replace("T", " "); }
function confFromName(s: string | undefined): number { return s === "high" ? 3 : s === "low" ? 1 : 2; }

/** Vendor + product tokens from a CPE 2.3 (cpe:2.3:a:vendor:product:…) or 2.2 (cpe:/a:vendor:product:…) name. */
function cpeTokens(cpeName: string): [string, string] {
  const n = String(cpeName || "");
  if (n.startsWith("cpe:2.3:")) { const p = n.split(":"); return [normToken(p[3]), normToken(p[4])]; }
  const p = n.replace(/^cpe:\/?/i, "").split(":"); return [normToken(p[1]), normToken(p[2])];
}

/**
 * Canonical CPE identity "part:vendor:product" from a 2.2 OR 2.3 CPE name, or null if unusable.
 * CRITICAL: the two databases do NOT share a CPE integer id space — XORCISM.CPE.CPEID is an integer
 * surrogate (its CPE URI lives in CPE.CPEName, in **2.2** form) whereas
 * XVULNERABILITY.VULNERABILITYFORCPE.CPEID is a **2.3** CPE URI STRING. A precise asset↔CVE CPE match
 * must therefore compare CPE *identities* (this key), never the ids. Version is intentionally dropped:
 * NVD affected-CPE rows are usually version-wildcarded, so product-identity match = "the CVE affects a
 * product the asset runs".
 */
function cpeCanon(cpeName: string): string | null {
  const s = String(cpeName || "").toLowerCase();
  if (!s.startsWith("cpe:")) return null;
  const part = s.startsWith("cpe:2.3:") ? (s.split(":")[2] || "a") : ((/^cpe:\/?([aoh])/.exec(s) || [])[1] || "a");
  const [vendor, product] = cpeTokens(cpeName);
  if (!vendor || !product || vendor === "*" || product === "*") return null;
  return `${part}:${vendor}:${product}`;
}

// Distinguishing brand/vendor/OS tokens (a subset of BLOCKLIST): a phrase containing one is NOT
// "purely generic" — "microsoft office" is a specific product, "web server" is not.
const BRANDS = new Set<string>([
  "microsoft", "apple", "google", "amazon", "aws", "azure", "oracle", "ibm", "cisco", "juniper",
  "adobe", "sap", "vmware", "citrix", "mozilla", "dell", "hp", "hpe", "lenovo", "intel", "amd",
  "nvidia", "samsung", "huawei", "sony", "symantec", "mcafee", "kaspersky", "canonical", "redhat",
  "fortinet", "sophos", "atlassian", "salesforce", "windows", "linux", "ubuntu", "debian", "android",
  "macos", "ios", "solaris", "freebsd", "unix",
]);
// Common English words that are also product/CPE names but far too generic as a BARE single token
// (e.g. "access" matches "unauthorized access" in a huge share of CVE prose). Rejected as standalone
// keywords/pairs, but still allowed inside a multi-word phrase ("microsoft access") that disambiguates.
const AMBIGUOUS_WORDS = new Set<string>([
  "access", "reader", "viewer", "player", "studio", "central", "express", "connect", "bridge",
  "insight", "insights", "discovery", "commerce", "contact", "partner", "protect",
]);
/** True iff every non-version word of a phrase is BLOCKLISTed AND none is a distinguishing brand. */
function allGeneric(phrase: string): boolean {
  const ws = phrase.split(/\s+/).filter(Boolean).filter((w) => !/^v?\d+(\.\d+)*$/.test(w));
  return ws.length > 0 && ws.every((w) => BLOCKLIST.has(w)) && !ws.some((w) => BRANDS.has(w));
}

/**
 * Precise keyword(s) from a CURATED PRODUCT.ProductName. Precision-first (this feeds auto-linking):
 *  - a single-token name → that token, iff specific (len ≥ 5, or a known short product) and not generic;
 *  - a multi-word name → the FULL phrase (+ a version-stripped variant, dropping trailing "8"/"2019"/
 *    "v3"/"11.0" tokens) — NEVER individual generic sub-words (so "Kaspersky Endpoint Security" links on
 *    the phrase, not on the bare word "security").
 */
function productNameKeywords(name: string): string[] {
  const n = normToken(name);
  if (!n) return [];
  const words = n.split(/\s+/).filter(Boolean);
  const out = new Set<string>();
  if (words.length === 1) {
    const w = words[0];
    if ((w.length >= 5 || KNOWN_SHORT_PRODUCTS.has(w)) && !BLOCKLIST.has(w) && !AMBIGUOUS_WORDS.has(w)) out.add(w);
  } else {
    if (n.length >= 4 && !BLOCKLIST.has(n) && !allGeneric(n)) out.add(n);
    const stripped = words.filter((w) => !/^v?\d+(\.\d+)*$/.test(w)).join(" ");
    if (stripped && stripped !== n && stripped.length >= 4 && !BLOCKLIST.has(stripped) && !allGeneric(stripped)) out.add(stripped);
  }
  return [...out];
}

export interface AssetTech {
  assetId: number; name: string; tenantId: number | null;
  cpeKeys: Set<string>;                     // canonical CPE identities (part:vendor:product), from cpeCanon()
  pairs: { vendor: string; product: string; rxV: RegExp; rxP: RegExp }[];
  specific: string[]; weak: string[];
  sourceOf: Map<string, string>;            // token → "cpe-keyword" | "product" | "tag"
  rxSpecific: RegExp | null; rxWeak: RegExp | null;
}

/** Build the per-asset technology index, classifying tokens by precision. */
export function buildAssetTechIndex(tenant: number | null): AssetTech[] {
  const db = getDb("XORCISM");
  const tw = tenant != null ? `WHERE COALESCE(TenantID, ${tenant}) = ${tenant}` : "";
  const assets = db.prepare(`SELECT AssetID id, AssetName name, TenantID t FROM ASSET ${tw}`).all() as { id: number; name: string | null; t: number | null }[];
  type Acc = { name: string | null; t: number | null; cpe: Set<string>; pairs: Map<string, { vendor: string; product: string }>; src: Map<string, string> };
  const byAsset = new Map<number, Acc>();
  for (const a of assets) byAsset.set(a.id, { name: a.name, t: a.t, cpe: new Set(), pairs: new Map(), src: new Map() });

  // CPE inventory → canonical CPE identity (for precise CVE match) + product tokens (standalone, if
  // specific) + vendor+product pairs (always, if product is specific). Match by CPE *name*, not id.
  for (const r of db.prepare(`SELECT ca.AssetID aid, c.CPEName name FROM CPEFORASSET ca JOIN CPE c ON c.CPEID = ca.CPEID`).all() as { aid: number; name: string }[]) {
    const e = byAsset.get(r.aid); if (!e) continue;
    const canon = cpeCanon(r.name); if (canon) e.cpe.add(canon);
    const [vendor, product] = cpeTokens(r.name);
    if (product && product.length >= 3 && !BLOCKLIST.has(product) && !AMBIGUOUS_WORDS.has(product)) {
      if (!e.src.has(product)) e.src.set(product, "cpe-keyword");   // CPE products are trusted (curated inventory)
      if (vendor && vendor.length >= 3) e.pairs.set(`${vendor}|${product}`, { vendor, product });
    }
  }

  // Software products (ASSETPRODUCT → PRODUCT): a CURATED inventory — the most reliable per-asset
  // signal after a precise CPE. Contributes: the product's CPE identity (PRODUCT.CPEName, or its
  // CPEID resolved to CPE.CPEName → the asset's CPE key set, so a product linked to the asset yields a
  // precise CPE↔CVE match, High); a vendor+product pair (High) and product token(s) from that CPE
  // name (like the CPE inventory); and the curated PRODUCT.ProductName as a specific keyword (Medium)
  // — matched precisely (full phrase / specific token), never a generic sub-word.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETPRODUCT'").get()
    && db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='PRODUCT'").get()) {
    const prodRows = db.prepare(
      `SELECT ap.AssetID aid, p.ProductName name, p.ProductVendor vendor,
              COALESCE(NULLIF(TRIM(p.CPEName), ''), pc.CPEName) cpeName
         FROM ASSETPRODUCT ap JOIN PRODUCT p ON p.ProductID = ap.ProductID
         LEFT JOIN CPE pc ON pc.CPEID = p.CPEID`
    ).all() as { aid: number; name: string | null; vendor: string | null; cpeName: string | null }[];
    for (const r of prodRows) {
      const e = byAsset.get(r.aid); if (!e) continue;
      // Product's CPE identity → the asset's CPE key set (precise CPE↔CVE match, High) + same token
      // treatment as the CPE inventory (pair High + product keyword Medium).
      if (r.cpeName) {
        const canon = cpeCanon(r.cpeName); if (canon) e.cpe.add(canon);
        const [cv, cp] = cpeTokens(r.cpeName);
        if (cp && cp.length >= 3 && !BLOCKLIST.has(cp) && !AMBIGUOUS_WORDS.has(cp)) {
          if (!e.src.has(cp)) e.src.set(cp, "product");
          if (cv && cv.length >= 3) e.pairs.set(`${cv}|${cp}`, { vendor: cv, product: cp });
        }
      }
      // Product NAME → specific keyword(s), precise (phrase / specific token, no generic sub-words).
      const pvendor = normToken(r.vendor || "");
      for (const kw of productNameKeywords(r.name || "")) {
        if (!e.src.has(kw)) e.src.set(kw, "product");
        // Vendor + the (already-specific) product name → a strong (High) co-occurrence pair. Like the
        // CPE pairs, the vendor is NOT blocklisted (the specific product narrows a broad vendor).
        if (pvendor && pvendor.length >= 3 && !kw.includes(pvendor)) {
          e.pairs.set(`${pvendor}|${kw}`, { vendor: pvendor, product: kw });
        }
      }
    }
  }

  // Tech tags → WEAK fallback only (Low tier; not auto-linked at the default Medium threshold).
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETTAG'").get()) {
    for (const r of db.prepare(`SELECT AssetID aid, Tag tag FROM ASSETTAG WHERE Tag IS NOT NULL`).all() as { aid: number; tag: string }[]) {
      const e = byAsset.get(r.aid); if (!e) continue;
      const n = normToken(r.tag);
      if (n.length >= 3 && !BLOCKLIST.has(n) && !e.src.has(n)) e.src.set(n, "tag");
    }
  }

  const out: AssetTech[] = [];
  for (const [id, e] of byAsset) {
    const specific: string[] = []; const weak: string[] = [];
    for (const [tok, source] of e.src) {
      // CURATED inventories (CPE + PRODUCT) are specific (Medium, auto-link); free tags are weak (Low).
      const isSpec = source === "cpe-keyword" || source === "product";
      (isSpec ? specific : weak).push(tok);
    }
    // Interior spaces in a phrase token match any whitespace run (double space, newline) — a curated
    // product name should still match line-wrapped / oddly-spaced CVE prose.
    const esc = (t: string): string => escapeRe(t).replace(/ /g, "\\s+");
    const rx = (toks: string[]): RegExp | null => toks.length ? new RegExp("\\b(" + toks.map(esc).join("|") + ")\\b", "i") : null;
    const wb = (t: string): RegExp => new RegExp("\\b" + esc(t) + "\\b", "i");
    const tech: AssetTech = {
      assetId: id, name: e.name || `#${id}`, tenantId: e.t ?? null, cpeKeys: e.cpe,
      pairs: [...e.pairs.values()].map((p) => ({ ...p, rxV: wb(p.vendor), rxP: wb(p.product) })),
      specific, weak, sourceOf: e.src, rxSpecific: rx(specific), rxWeak: rx(weak),
    };
    if (tech.cpeKeys.size || tech.pairs.length || tech.rxSpecific || tech.rxWeak) out.push(tech);
  }
  return out;
}

/** Score one CVE against one asset → the best {confidence (3/2/1), source, token}, or null. */
function scoreMatch(a: AssetTech, hay: string, cpes: Set<string> | undefined): { conf: number; source: string; token: string } | null {
  // High — precise CPE link: the asset and the CVE share a CPE identity (part:vendor:product).
  if (cpes && cpes.size) { const c = [...a.cpeKeys].find((x) => cpes.has(x)); if (c != null) return { conf: 3, source: "cpe", token: c.slice(0, 100) }; }
  // High — CPE vendor+product pair both present.
  for (const p of a.pairs) {
    if (p.rxP.test(hay) && p.rxV.test(hay)) return { conf: 3, source: "cpe-pair", token: `${p.vendor}+${p.product}` };
  }
  // Medium — a specific product token. Collapse whitespace runs in the matched text so the source
  // lookup hits the canonical token key (the phrase regex may have matched varied spacing/newlines).
  if (a.rxSpecific) { const m = a.rxSpecific.exec(hay); if (m) { const tok = m[1].toLowerCase().replace(/\s+/g, " ").trim(); return { conf: 2, source: a.sourceOf.get(tok) || "cpe-keyword", token: tok }; } }
  // Low — a short ambiguous tag token.
  if (a.rxWeak) { const m = a.rxWeak.exec(hay); if (m) return { conf: 1, source: "tag", token: m[1].toLowerCase().replace(/\s+/g, " ").trim() }; }
  return null;
}

// ── watermark (CVEMATCHCURSOR, single row id=1) ───────────────────────────────────
export function ensureCveMatchTables(): void {
  let db; try { db = getDb("XORCISM"); } catch { return; }
  db.exec(`CREATE TABLE IF NOT EXISTS CVEMATCHCURSOR (id INTEGER PRIMARY KEY, lastVulnerabilityID INTEGER, lastRunAt TEXT, lastNewLinks INTEGER);`);
  if (!db.prepare("SELECT 1 FROM CVEMATCHCURSOR WHERE id=1").get()) {
    let maxId = 0;
    try { maxId = (getDb("XVULNERABILITY").prepare("SELECT COALESCE(MAX(VulnerabilityID),0) m FROM VULNERABILITY").get() as { m: number }).m; } catch { /* xvuln absent */ }
    db.prepare("INSERT INTO CVEMATCHCURSOR (id, lastVulnerabilityID, lastRunAt, lastNewLinks) VALUES (1, ?, NULL, 0)").run(maxId);
  }
}
function getWatermark(): number {
  try { return (getDb("XORCISM").prepare("SELECT lastVulnerabilityID v FROM CVEMATCHCURSOR WHERE id=1").get() as { v: number } | undefined)?.v ?? 0; } catch { return 0; }
}
function setWatermark(maxId: number, newLinks: number): void {
  try { getDb("XORCISM").prepare("UPDATE CVEMATCHCURSOR SET lastVulnerabilityID=?, lastRunAt=?, lastNewLinks=? WHERE id=1").run(maxId, nowTs(), newLinks); } catch { /* ignore */ }
}

function colset(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

// ── recipients: users with read access to XORCISM.ASSET in the tenant ──────────────
function assetReaders(tenant: number | null): number[] {
  const out: number[] = [];
  try {
    for (const u of xid.listUsers(tenant) as Record<string, unknown>[]) {
      if (u.IsLockedOut) continue;
      const uid = Number(u.UserID);
      if (!Number.isInteger(uid) || uid <= 0) continue;
      if (xid.isAdmin(uid)) { out.push(uid); continue; }
      const perms = xid.getEffectivePermissions(uid);
      if (perms.get("database:XORCISM")?.CanRead || perms.get("table:XORCISM.ASSET")?.CanRead) out.push(uid);
    }
  } catch { /* RBAC unavailable */ }
  return out;
}

export interface MatchResult { cvesScanned: number; newLinks: number; assetsAffected: number; assetsNotified: number; maxVulnId: number; mode: string; minConfidence: string; byConfidence: Record<string, number>; }

/**
 * Match CVEs to assets and create the links + notifications.
 *  - default (no since/days): delta since the watermark (import hook & periodic job).
 *  - { days }: rescan CVEs modified within the last N days (on-demand "rematch").
 *  - { minConfidence }: "high" | "medium" (default) | "low" — the lowest tier that auto-links.
 */
export function matchCves(opts: { tenant?: number | null; sinceVulnId?: number; days?: number; limit?: number; notify?: boolean; minConfidence?: string } = {}): MatchResult {
  const tenant = opts.tenant ?? null;
  const notify = opts.notify !== false;
  const limit = Math.min(opts.limit ?? 50_000, 200_000);
  const minConf = confFromName(opts.minConfidence);
  const usingWatermark = opts.sinceVulnId == null && opts.days == null;
  const since = opts.sinceVulnId ?? (usingWatermark ? getWatermark() : 0);
  const mode = usingWatermark ? "delta" : (opts.days != null ? `${opts.days}d` : `since#${since}`);

  const index = buildAssetTechIndex(tenant);
  const empty: MatchResult = { cvesScanned: 0, newLinks: 0, assetsAffected: 0, assetsNotified: 0, maxVulnId: since, mode, minConfidence: CONF_LABEL[minConf], byConfidence: {} };
  if (!index.length) return empty;

  const xo = getDb("XORCISM"); const xv = getDb("XVULNERABILITY");
  let rows: { id: number; ref: string; descr: string | null; short: string | null }[];
  if (opts.days != null) {
    rows = xv.prepare(
      `SELECT VulnerabilityID id, VULReferentialID ref, VULDescription descr, VULShortName short FROM VULNERABILITY
       WHERE VULReferentialID LIKE 'CVE-%' AND COALESCE(VULModifiedDate, VULPublishedDate, CreatedDate) >= date('now', ?)
       ORDER BY VulnerabilityID LIMIT ?`).all(`-${Math.max(1, Math.round(opts.days))} days`, limit) as typeof rows;
  } else {
    rows = xv.prepare(
      `SELECT VulnerabilityID id, VULReferentialID ref, VULDescription descr, VULShortName short FROM VULNERABILITY
       WHERE VulnerabilityID > ? AND VULReferentialID LIKE 'CVE-%' ORDER BY VulnerabilityID LIMIT ?`).all(since, limit) as typeof rows;
  }
  if (!rows.length) { if (usingWatermark) setWatermark(since, 0); return empty; }

  // Precise CPE links for the candidate CVEs. VULNERABILITYFORCPE.CPEID holds the affected CPE as a
  // 2.3 URI STRING (NOT an integer id) → normalize to the same canonical identity as the asset side.
  const cveCpe = new Map<number, Set<string>>();
  try {
    if (xv.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='VULNERABILITYFORCPE'").get()) {
      const ids = rows.map((r) => r.id);
      for (let i = 0; i < ids.length; i += 800) {
        const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
        for (const r of xv.prepare(`SELECT VulnerabilityID v, CPEID c FROM VULNERABILITYFORCPE WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { v: number; c: string }[]) {
          const canon = cpeCanon(String(r.c)); if (!canon) continue;
          (cveCpe.get(r.v) ?? cveCpe.set(r.v, new Set()).get(r.v)!).add(canon);
        }
      }
    }
  } catch { /* table absent / different shape */ }

  // Column-aware insert (match provenance columns are added by ensureAssetColumns).
  const avc = colset("XORCISM", "ASSETVULNERABILITY");
  const baseCols = ["AssetID", "VulnerabilityID", "CreatedDate", "TenantID", "Status"];
  const provCols = ["MatchConfidence", "MatchSource", "MatchedToken"].filter((c) => avc.has(c));
  const insCols = [...baseCols.filter((c) => avc.has(c)), ...provCols];
  const insAv = xo.prepare(`INSERT INTO ASSETVULNERABILITY (${insCols.map((c) => `"${c}"`).join(",")}) VALUES (${insCols.map(() => "?").join(",")})`);
  const existsAv = xo.prepare("SELECT 1 FROM ASSETVULNERABILITY WHERE AssetID=? AND VulnerabilityID=?");

  const perAsset = new Map<number, { count: number; name: string; tenant: number | null }>();
  const byConfidence: Record<string, number> = {};
  let maxId = since; const now = nowTs();

  const tx = xo.transaction(() => {
    for (const cve of rows) {
      if (cve.id > maxId) maxId = cve.id;
      const hay = `${cve.descr || ""} ${cve.short || ""}`;
      const cpes = cveCpe.get(cve.id);
      for (const a of index) {
        const m = scoreMatch(a, hay, cpes);
        if (!m || m.conf < minConf) continue;
        if (existsAv.get(a.assetId, cve.id)) continue;
        const vals: Record<string, unknown> = {
          AssetID: a.assetId, VulnerabilityID: cve.id, CreatedDate: now, TenantID: a.tenantId, Status: "Open",
          MatchConfidence: CONF_LABEL[m.conf], MatchSource: m.source, MatchedToken: m.token.slice(0, 100),
        };
        insAv.run(...insCols.map((c) => vals[c]));
        const e = perAsset.get(a.assetId) ?? { count: 0, name: a.name, tenant: a.tenantId };
        e.count++; perAsset.set(a.assetId, e);
        byConfidence[CONF_LABEL[m.conf]] = (byConfidence[CONF_LABEL[m.conf]] || 0) + 1;
      }
    }
  });
  tx();

  let newLinks = 0; for (const e of perAsset.values()) newLinks += e.count;
  let assetsNotified = 0;
  if (notify) {
    for (const [aid, e] of perAsset) {
      const recips = assetReaders(e.tenant);
      if (!recips.length) continue;
      notifyUsers(recips, {
        title: `New CVEs for ${e.name}`,
        message: `${e.count} new CVE${e.count > 1 ? "s" : ""} matched this asset's technologies (CPE / products).`,
        level: "warning", source: "cve-match",
        link: `/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=AssetID&filterVal=${aid}`,
        tenantId: e.tenant,
      });
      assetsNotified++;
    }
  }
  if (usingWatermark) setWatermark(maxId, newLinks);
  if (newLinks > 0) {
    try {
      emitLoopEvent({
        type: "exposure.new_cve", source: "cve-match",
        summary: `${newLinks} new CVE link${newLinks > 1 ? "s" : ""} across ${perAsset.size} asset${perAsset.size > 1 ? "s" : ""} (≥${CONF_LABEL[minConf]})`,
        severity: newLinks >= 25 ? "high" : "medium", direction: "croc->soc", tenant,
      });
    } catch { /* never break matching */ }
  }
  return { cvesScanned: rows.length, newLinks, assetsAffected: perAsset.size, assetsNotified, maxVulnId: maxId, mode, minConfidence: CONF_LABEL[minConf], byConfidence };
}

export interface RescoreResult { scanned: number; flagged: number; kept: number; }

/**
 * Re-score the EXISTING keyword-matched backlog and flag the weak ones as FalsePositive (reversible).
 * Targets only legacy auto-match links — ToolID IS NULL (scanners set a ToolID) and no MatchSource yet —
 * so scanner-found and manually-added links are left alone. Links whose asset technology no longer
 * supports them at ≥ minConfidence get FalsePositive=1 + MatchSource='cve-match:rescored'; the rest get
 * their confidence recorded. Opt-in (the on-demand rematch with ?rescore=1).
 */
export function rescoreLegacyMatches(tenant: number | null, minConfidence?: string, limit = 50_000): RescoreResult {
  const minConf = confFromName(minConfidence);
  const xo = getDb("XORCISM"); const xv = getDb("XVULNERABILITY");
  const avc = colset("XORCISM", "ASSETVULNERABILITY");
  if (!avc.has("FalsePositive") || !avc.has("MatchSource")) return { scanned: 0, flagged: 0, kept: 0 };
  const index = new Map<number, AssetTech>();
  for (const a of buildAssetTechIndex(tenant)) index.set(a.assetId, a);

  const tw = tenant != null && avc.has("TenantID") ? `AND (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const toolClause = avc.has("ToolID") ? "AND ToolID IS NULL" : "";
  const links = xo.prepare(
    `SELECT AssetVulnerabilityID id, AssetID aid, VulnerabilityID vid FROM ASSETVULNERABILITY
     WHERE VulnerabilityID IS NOT NULL AND COALESCE(FalsePositive,0)=0 AND MatchSource IS NULL ${toolClause} ${tw}
     LIMIT ${Math.min(limit, 200_000)}`
  ).all() as { id: number; aid: number; vid: number }[];
  if (!links.length) return { scanned: 0, flagged: 0, kept: 0 };

  // Fetch CVE text + CPE for the distinct vulns involved.
  const vids = [...new Set(links.map((l) => l.vid))];
  const cveText = new Map<number, string>(); const cveCpe = new Map<number, Set<string>>();
  for (let i = 0; i < vids.length; i += 800) {
    const chunk = vids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
    for (const r of xv.prepare(`SELECT VulnerabilityID v, VULDescription d, VULShortName s FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { v: number; d: string | null; s: string | null }[])
      cveText.set(Number(r.v), `${r.d || ""} ${r.s || ""}`);
    try {
      for (const r of xv.prepare(`SELECT VulnerabilityID v, CPEID c FROM VULNERABILITYFORCPE WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { v: number; c: string }[]) {
        const canon = cpeCanon(String(r.c)); if (!canon) continue;
        (cveCpe.get(r.v) ?? cveCpe.set(r.v, new Set()).get(r.v)!).add(canon);
      }
    } catch { /* table absent */ }
  }

  const flag = xo.prepare(`UPDATE ASSETVULNERABILITY SET FalsePositive=1, MatchSource='cve-match:rescored', MatchConfidence=? WHERE AssetVulnerabilityID=?`);
  const keep = xo.prepare(`UPDATE ASSETVULNERABILITY SET MatchSource='cve-match:rescored', MatchConfidence=? WHERE AssetVulnerabilityID=?`);
  let flagged = 0, kept = 0;
  const tx = xo.transaction(() => {
    for (const l of links) {
      const hay = cveText.get(l.vid);
      if (hay == null) continue;                   // CVE text missing → can't evaluate → leave as-is
      const a = index.get(l.aid);
      // No tech signal at all (e.g. an asset with only generic tags like "email") → nothing can support
      // a keyword link → it's a false positive of the old loose matcher.
      const m = a ? scoreMatch(a, hay, cveCpe.get(l.vid)) : null;
      if (!m || m.conf < minConf) { flag.run(m ? CONF_LABEL[m.conf] : "Low", l.id); flagged++; }
      else { keep.run(CONF_LABEL[m.conf], l.id); kept++; }
    }
  });
  tx();
  return { scanned: links.length, flagged, kept };
}

// ── periodic matcher (hourly) ──────────────────────────────────────────────────────
let _timer: NodeJS.Timeout | null = null;
export function startCveMatcher(): void {
  if (_timer || process.env.XOR_CVE_MATCH === "0") return;
  _timer = setInterval(() => {
    try {
      const r = matchCves({ tenant: null });
      if (r.newLinks) console.log(`[cvematch] periodic: ${r.newLinks} new link(s) → ${r.assetsNotified} asset(s) notified (scanned ${r.cvesScanned} CVEs, ${r.mode}, ≥${r.minConfidence})`);
    } catch (e) { console.warn(`[cvematch] periodic tick: ${(e as Error).message}`); }
  }, 60 * 60 * 1000);
  if (typeof _timer.unref === "function") _timer.unref();
  console.log("[cvematch] periodic CVE→asset matcher started (hourly; XOR_CVE_MATCH=0 to disable)");
}
