/**
 * index.ts — XORCISM Express server (with XID authentication + RBAC)
 */

import "express-async-errors";
import express, { Request, Response, NextFunction } from "express";
import path from "path";
import explorerRouter from "./routes/explorer";
import biaRouter from "./routes/bia";
import authRouter from "./routes/auth";
import oidcRouter from "./routes/oidc";
import adminRouter from "./routes/admin";
import connectorsRouter from "./routes/connectors";
import workerApiRouter from "./routes/worker_api";
import vaultRouter from "./routes/vault";
import { agentTokenRouter, agentAdminRouter } from "./routes/agent";
import { getAgentDb } from "./agents";
import feedbackRouter from "./routes/feedback";
import prefsRouter from "./routes/prefs";
import notificationsRouter from "./routes/notifications";
import ocilRouter from "./routes/ocil";
import osvRouter from "./routes/osv";
import pentestRouter from "./routes/pentest";
import { ensurePentestColumns } from "./engagements";
import { ensureChainTables, startChainEngine } from "./chain";
import screenshotRouter from "./routes/screenshot";
import circlRouter from "./routes/circl";
import exploitdbRouter from "./routes/exploitdb";
import fusionRouter from "./routes/fusion";
import attackPathRouter from "./routes/attackpath";
import purpleTeamRouter from "./routes/purpleteam";
import ransomwareRouter from "./routes/ransomware";
import assuranceRouter from "./routes/assurance";
import slaRouter from "./routes/sla";
import { ensureSlaColumns } from "./sla";
import pirRouter from "./routes/pir";
import identitiesRouter from "./routes/identities";
import assetsRouter from "./routes/assets";
import incidentsRouter from "./routes/incidents";
import complianceRouter from "./routes/compliance";
import policiesRouter from "./routes/policies";
import configurationRouter from "./routes/configuration";
import crisisRouter from "./routes/crisis";
import tidRouter from "./routes/tid";
import v1Router from "./routes/v1";
import apikeysRouter from "./routes/apikeys";
import webhooksRouter from "./routes/webhooks";
import { apiKeyAuth } from "./apikey";
import ctiRouter from "./routes/cti";
import driftRouter from "./routes/drift";
import contentRouter from "./routes/content";
import { ensureDriftTable } from "./drift";
import aiRouter from "./routes/ai";
import uploadRouter, { UPLOAD_DIR } from "./routes/upload";
import threatReportRouter from "./routes/threatreport";
import sigmaRouter from "./routes/sigma";
import epssRouter from "./routes/epss";
import huntingRouter from "./routes/hunting";
import threatFeedsRouter from "./routes/threatfeeds";
import { antibot } from "./antibot";
import { getJobDb } from "./jobs";
import { startScheduler } from "./scheduler";
import { startThreatFeedPoller } from "./feeds";
import { startRiskScoreLoop } from "./riskscore";
import {
  loadUser,
  requireAuthGate,
  requireAdmin,
  requirePageApi,
  userCanPage,
  seedAdmin,
} from "./auth";
import { purgeExpiredSessions } from "./xid";
import { ensureSchemaDbs, seedData, ensureTenantColumns, ensureThreatModelTables, ensureComplianceDb, ensureTicketDb, ensureThreatTables, ensureIncidentTables, ensureOpenctiColumns, ensureEmulationTables, ensureGrcColumns, ensureBugBountyTables, ensureEbiosTables, ensureAssetColumns, ensureIdentityTables, ensureOvalScanTables, ensureVulnerabilityColumns } from "./db";
import { tr } from "./i18n";

const PORT = Number(process.env.PORT) || 9292;
const app = express();
app.disable("x-powered-by");

// ── Security headers (OWASP Secure Headers Project) ────────────────────────
app.use((req: Request, res: Response, next: NextFunction) => {
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  // Disables unused browser APIs (OWASP: reduced attack surface)
  res.setHeader(
    "Permissions-Policy",
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"
  );
  // Cross-origin isolation (anti-XS-Leaks / Spectre)
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // HSTS: only on HTTPS (ignored by browsers over cleartext anyway)
  if (secure) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      // CDNs used: Chart.js (jsdelivr) and SheetJS (sheetjs.com); inline required by the pages
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.sheetjs.com",
      "style-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
      "object-src 'none'",
      "frame-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      ...(secure ? ["upgrade-insecure-requests"] : []),
    ].join("; ")
  );
  next();
});

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json({ limit: "25mb" })); // large JSON imports
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(antibot); // anti-bot / anti-scraping (rate + UA + bursts)
app.use(loadUser); // populates req.user from the session cookie

// Static resources (public — needed by the login page)
app.use("/js", express.static(path.join(__dirname, "../../dist/client/js")));
app.use("/css", express.static(path.join(__dirname, "../../client/css")));
app.use(
  "/vendor/xlsx.full.min.js",
  express.static(path.join(__dirname, "../../node_modules/xlsx/dist/xlsx.full.min.js"))
);

// Authentication routes (public login; the others check req.user)
app.use("/api/auth", authRouter);
app.use("/api/auth", oidcRouter); // OAuth/OIDC (public login + callback)

// Remote workers + XOR agents API: authenticated by TOKEN (no session) → before the gate
app.use("/api", workerApiRouter);
app.use("/api", agentTokenRouter);

// API-key auth: populates req.user from Authorization: Bearer xor_… / X-API-Key
// when there's no session, so the REST API works for programmatic clients.
app.use(apiKeyAuth);

// ── Authentication gate (everything else requires a session) ─────────────────
app.use(requireAuthGate);

// ── Protected APIs ──────────────────────────────────────────────────────────────
app.use("/api/admin", requireAdmin, adminRouter);
app.use("/api/bia", requirePageApi("/bia"), biaRouter);
app.use("/api", vaultRouter); // encryption vault (each route checks admin)
app.use("/api", agentAdminRouter); // XOR agents (list, events, launch a scan)
app.use("/api", feedbackRouter); // user feedback (ratings / improvements)
app.use("/api", prefsRouter); // user preferences (CTI feeds, display…)
app.use("/api", notificationsRouter); // notifications (header bell + browser)
app.use("/api", ocilRouter); // OCIL 2.0 import/export of XCOMPLIANCE questionnaires
app.use("/api", osvRouter); // OSV.dev integration (lookup + VULNERABILITY import)
app.use("/api", pentestRouter); // Pentest mode: bulk scan of assets
app.use("/api", screenshotRouter); // URL screenshot (ASSET websiteurl → AssetImage)
app.use("/api", circlRouter); // CIRCL vulnerability-lookup (KEV search + import)
app.use("/api", exploitdbRouter); // Exploit-DB search (local SearchSploit index) + CVE→exploit lookup
app.use("/api", fusionRouter); // exploitability & relevance fusion score + prioritized exposure worklist
app.use("/api", attackPathRouter); // attack-path & choke-point graph (reachability entry→crown-jewel)
app.use("/api", purpleTeamRouter); // purple-team: chain ATT&CK detection coverage (Sigma) + rule generation
app.use("/api", ransomwareRouter); // ransomware-to-$ scenario simulator (BIA/FAIR impact + D3FEND controls)
app.use("/api", assuranceRouter); // continuously-proven compliance (control assurance from live telemetry)
app.use("/api", slaRouter); // incident SLA view: incidents measured against asset-defined resolution SLAs
app.use("/api", pirRouter); // Priority Intelligence Requirements coverage register
app.use("/api", identitiesRouter); // IAM: identity inventory (human + non-human) + governance findings
app.use("/api", assetsRouter); // Asset Management: asset inventory + governance worklist
app.use("/api", incidentsRouter); // Incident Management: incident inventory + governance worklist
app.use("/api", complianceRouter); // Compliance Management: audit inventory + findings/policy worklist
app.use("/api", policiesRouter); // Policy & Document Management: policy lifecycle + document register worklist
app.use("/api", configurationRouter); // Configuration Management: OVAL secure-config content library + verification worklist
app.use("/api", crisisRouter); // Crisis Management: tabletop-exercise readiness + scenario library + improvement worklist
app.use("/api", tidRouter); // Threat-Informed Defense: ATT&CK technique coverage (adversary use vs detect/mitigate/test)
app.use("/api/v1", v1Router); // public REST API v1 (API-key auth, read-only, tenant-scoped)
app.use("/api", apikeysRouter); // manage your own API keys (session-authenticated)
app.use("/api", webhooksRouter); // manage outbound webhooks (session-authenticated)
app.use("/api", ctiRouter); // "CTI that acts": intel cross-referenced with inventory + auto-ticket
app.use("/api", driftRouter); // attack-surface drift (snapshot + diff)
app.use("/api", contentRouter); // content hub exports (OpenVEX, Sigma bundle)
app.use("/api", aiRouter); // local AI (Ollama): "Ask the threat model" + OCIL suggestion
app.use("/api", uploadRouter); // file upload (evidence, etc.)
app.use("/api", threatReportRouter); // THREATREPORT PDF ingestion → IOC / THREATACTOR
app.use("/api", sigmaRouter); // Sigma rule → SPL / KQL / EQL conversion
app.use("/api", epssRouter); // FIRST.org EPSS lookup (VULNERABILITY form)
app.use("/api", huntingRouter); // Threat Hunting domain (HUNT/IOC/XTHREAT + AI hunt assistant)
app.use("/api", threatFeedsRouter); // curated CTI RSS feeds (THREATFEED) + server-side fetch/parse
app.use("/api", connectorsRouter);
app.use("/api", explorerRouter);

// Uploaded files — served only to authenticated users (after the gate).
// Images/PDF inline (preview); everything else forced to download to neutralize
// execution of malicious HTML/SVG served from our origin.
const INLINE_OK = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"]);
app.use(
  "/uploads",
  express.static(UPLOAD_DIR, {
    setHeaders: (res, filePath) => {
      const ext = path.extname(filePath).toLowerCase();
      res.setHeader("Content-Disposition", INLINE_OK.has(ext) ? "inline" : "attachment");
      res.setHeader("X-Content-Type-Options", "nosniff");
    },
  })
);

// ── Pages HTML ──────────────────────────────────────────────────────────────────
const CLIENT_DIR = path.join(__dirname, "../../client");

// Page access guard (page-level RBAC; Admin = full access)
function pageGuard(pagePath: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (userCanPage(req.user, pagePath)) return next();
    res.status(403).send(tr(req, "page.deniedHtml"));
  };
}

app.get("/login", (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "login.html"));
});
app.get("/register", (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "register.html")));
app.get("/forgot", (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "forgot.html")));
app.get("/reset", (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "reset.html")));
app.get("/feedback", pageGuard("/"), (_req: Request, res: Response) => res.sendFile(path.join(CLIENT_DIR, "feedback.html")));

app.get("/", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "index.html"));
});

app.get("/bia", pageGuard("/bia"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "bia.html"));
});

app.get("/bia-graph", pageGuard("/bia"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "bia-graph.html"));
});
app.get("/dashboard", pageGuard("/dashboard"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "dashboard.html"));
});

app.get("/threat-feeds", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-feeds.html"));
});

app.get("/attack", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack.html"));
});
app.get("/kill-chain", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "kill-chain.html"));
});
app.get("/d3fend", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "d3fend.html"));
});
app.get("/ask", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ask.html"));
});
app.get("/a3m", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "a3m.html"));
});
app.get("/hunting", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "hunting.html"));
});
app.get("/tprm", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "tprm.html"));
});
app.get("/ebios", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ebios.html"));
});
app.get("/stix-graph", pageGuard("/stix-graph"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "stix-graph.html"));
});
app.get("/attack-surface", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack-surface.html"));
});
app.get("/pentest", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pentest.html"));
});
app.get("/pentest/report", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pentest-report.html"));
});
app.get("/pentest/chain", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "chain.html"));
});
app.get("/exploitdb", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "exploitdb.html"));
});
app.get("/exposure", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "exposure.html"));
});
app.get("/attack-path", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack-path.html"));
});
app.get("/purple-team", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "purple-team.html"));
});
app.get("/ransomware", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "ransomware.html"));
});
app.get("/assurance", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "assurance.html"));
});
app.get("/incident-sla", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "incident-sla.html"));
});
app.get("/pir", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "pir.html"));
});
app.get("/identities", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "identities.html"));
});
app.get("/asset-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "asset-management.html"));
});
app.get("/incident-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "incident-management.html"));
});
app.get("/compliance-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "compliance-management.html"));
});
app.get("/crisis-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "crisis-management.html"));
});
app.get("/policy-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "policy-management.html"));
});
app.get("/configuration-management", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "configuration-management.html"));
});
app.get("/threat-informed-defense", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-informed-defense.html"));
});
app.get("/oval-scan", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "oval-scan.html"));
});
app.get("/api-docs", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "api-docs.html"));
});
app.get("/api-keys", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "api-keys.html"));
});
app.get("/webhooks", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "webhooks.html"));
});
app.get("/cti-watch", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "cti-watch.html"));
});
app.get("/drift", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "drift.html"));
});
app.get("/content", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "content.html"));
});

app.get("/vault", requireAdmin, (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "vault.html"));
});

app.get("/connectors", pageGuard("/connectors"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "connectors.html"));
});

app.get("/admin", requireAdmin, (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "admin.html"));
});

// ── Error handling ───────────────────────────────────────────────────────────
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: err.message });
});

// ── Startup ────────────────────────────────────────────────────────────────────
ensureSchemaDbs(); // creates the "schema" databases (XORCISM, XVULNERABILITY, XATTACK, XMALWARE, XINCIDENT, XTHREAT, XOVAL, XWINDOWS) if missing
seedAdmin();
ensureComplianceDb(); // creates the XCOMPLIANCE.db database (AUDIT, AUDITFINDING, AUDITREPORT)
ensurePentestColumns(); // links AUDITFINDING to its engagement (AUDIT type=Pentest) — must run after ensureComplianceDb
ensureChainTables(); // tool-chaining playbooks: XCHAINPLAYBOOK / XCHAINRUN / XCHAINSTEP (+ seeds builtins)
ensureDriftTable(); // attack-surface drift snapshots (XSURFACESNAPSHOT)
ensureTicketDb(); // creates the XTICKET.db database (TICKET, TICKETCOMMENT, TICKETCATEGORY, TICKETATTACHMENT)
getAgentDb(); // creates the XAGENT.db database (XOR agents, events, IOC) if needed
ensureThreatModelTables(); // creates the THREATMODEL* tables (XORCISM.db) if needed
ensureThreatTables(); // creates the XTHREAT tables (IOC…) if needed
ensureIncidentTables(); // creates the XINCIDENT.ALERT table if needed
ensureOpenctiColumns(); // adapts the XTHREAT tables to OpenCTI properties (Confidence/TLP/Sighting…)
ensureEmulationTables(); // adversary emulation / validation (BAS) module: EMULATION*/ATOMICTEST
ensureAssetColumns(); // adds ASSET.BusinessValue (and future core ASSET fields) if missing
ensureIdentityTables(); // IAM registry: XORCISM.IDENTITY + IDENTITYPERSON (human + non-human identities)
ensureOvalScanTables(); // OVAL scan results: extend XOVAL.OVALRESULTS into per-asset verdicts + seed result enum
ensureSlaColumns(); // ASSET.SLAResponseHours/SLAResolutionHours + INCIDENT.Duration (SLA breach view)
ensureVulnerabilityColumns(); // adds VULNERABILITY.EPSS (Exploit Prediction Scoring System) if missing
ensureGrcColumns(); // advanced GRC: CRQ/FAIR (risk register), findings workflow, policy lifecycle
ensureBugBountyTables(); // Bug Bounty program management (XVULNERABILITY): BUGBOUNTY*
ensureEbiosTables(); // EBIOS Risk Manager (ANSSI) in XCOMPLIANCE: reuses RISKASSESSMENT/RISKSCENARIO + EBIOS* tables
ensureTenantColumns(); // adds TenantID to the operational tables (best-effort)
getJobDb(); // creates the job-queue schema (XJOB.db) if needed
seedData(); // pre-inserts reference data (e.g. VOCABULARY "XORCISM") — idempotent
startScheduler(); // fires the connectors' scheduled tasks (XSCHEDULE)
startThreatFeedPoller(); // periodically turns CTI RSS feed items into THREATREPORT entries
startRiskScoreLoop(); // recomputes ASSET.RiskScore every 30 s
startChainEngine(); // advances active tool-chaining runs (pentest playbooks)
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

app.listen(PORT, () => {
  console.log(`\n  XORCISM TypeScript Server (auth XID activée)`);
  console.log(`  http://localhost:${PORT}/login\n`);
});
