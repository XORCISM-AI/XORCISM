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
import screenshotRouter from "./routes/screenshot";
import circlRouter from "./routes/circl";
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
import { ensureSchemaDbs, seedData, ensureTenantColumns, ensureThreatModelTables, ensureComplianceDb, ensureTicketDb, ensureThreatTables, ensureIncidentTables, ensureOpenctiColumns, ensureEmulationTables, ensureGrcColumns, ensureBugBountyTables, ensureEbiosTables, ensureAssetColumns, ensureVulnerabilityColumns } from "./db";
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

app.get("/dashboard", pageGuard("/dashboard"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "dashboard.html"));
});

app.get("/threat-feeds", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "threat-feeds.html"));
});

app.get("/attack", pageGuard("/"), (_req: Request, res: Response) => {
  res.sendFile(path.join(CLIENT_DIR, "attack.html"));
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
ensureTicketDb(); // creates the XTICKET.db database (TICKET, TICKETCOMMENT, TICKETCATEGORY, TICKETATTACHMENT)
getAgentDb(); // creates the XAGENT.db database (XOR agents, events, IOC) if needed
ensureThreatModelTables(); // creates the THREATMODEL* tables (XORCISM.db) if needed
ensureThreatTables(); // creates the XTHREAT tables (IOC…) if needed
ensureIncidentTables(); // creates the XINCIDENT.ALERT table if needed
ensureOpenctiColumns(); // adapts the XTHREAT tables to OpenCTI properties (Confidence/TLP/Sighting…)
ensureEmulationTables(); // adversary emulation / validation (BAS) module: EMULATION*/ATOMICTEST
ensureAssetColumns(); // adds ASSET.BusinessValue (and future core ASSET fields) if missing
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
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

app.listen(PORT, () => {
  console.log(`\n  XORCISM TypeScript Server (auth XID activée)`);
  console.log(`  http://localhost:${PORT}/login\n`);
});
