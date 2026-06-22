// esbuild.config.js — bundles client TypeScript to dist/client/
const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");

const watch = process.argv.includes("--watch");

const entryPoints = [
  "client/ts/app.ts",
  "client/ts/landing.ts",
  "client/ts/bia.ts",
  "client/ts/bia-graph.ts",
  "client/ts/dashboard.ts",
  "client/ts/login.ts",
  "client/ts/register.ts",
  "client/ts/forgot.ts",
  "client/ts/reset.ts",
  "client/ts/admin.ts",
  "client/ts/session-ui.ts",
  "client/ts/stix-graph.ts",
  "client/ts/attack-surface.ts",
  "client/ts/pentest-page.ts",
  "client/ts/pentest-report.ts",
  "client/ts/connectors.ts",
  "client/ts/attack.ts",
  "client/ts/kill-chain.ts",
  "client/ts/chain.ts",
  "client/ts/exploitdb.ts",
  "client/ts/exposure.ts",
  "client/ts/attack-path.ts",
  "client/ts/purple-team.ts",
  "client/ts/ransomware.ts",
  "client/ts/assurance.ts",
  "client/ts/sla.ts",
  "client/ts/pir.ts",
  "client/ts/identities.ts",
  "client/ts/asset-management.ts",
  "client/ts/incident-management.ts",
  "client/ts/compliance-management.ts",
  "client/ts/policy-management.ts",
  "client/ts/configuration-management.ts",
  "client/ts/crisis-management.ts",
  "client/ts/fair-mam.ts",
  "client/ts/risk-register.ts",
  "client/ts/pqcmm.ts",
  "client/ts/sca.ts",
  "client/ts/tools.ts",
  "client/ts/threat-model.ts",
  "client/ts/threat-informed-defense.ts",
  "client/ts/oval-scan.ts",
  "client/ts/api-keys.ts",
  "client/ts/api-docs.ts",
  "client/ts/webhooks.ts",
  "client/ts/cti-watch.ts",
  "client/ts/drift.ts",
  "client/ts/content.ts",
  "client/ts/d3fend.ts",
  "client/ts/ask.ts",
  "client/ts/a3m.ts",
  "client/ts/tprm.ts",
  "client/ts/ebios.ts",
  "client/ts/nist-800-30.ts",
  "client/ts/ot-security.ts",
  "client/ts/patch-management.ts",
  "client/ts/asset-monitoring.ts",
  "client/ts/control-management.ts",
  "client/ts/trust-center.ts",
  "client/ts/trust-public.ts",
  "client/ts/investment-advisor.ts",
  "client/ts/bug-bounty.ts",
  "client/ts/vulnerability-management.ts",
  "client/ts/org-chart.ts",
  "client/ts/attack-tree.ts",
  "client/ts/cloud-security.ts",
  "client/ts/security-awareness.ts",
  "client/ts/malware-scan.ts",
  "client/ts/compliance-journeys.ts",
  "client/ts/osint-graph.ts",
  "client/ts/hunting.ts",
];

const ctx = esbuild.context({
  entryPoints,
  bundle: true,
  outdir: "dist/client/js",
  platform: "browser",
  target: ["es2020"],
  sourcemap: true,
  minify: false,
  charset: "utf8", // keeps UTF-8 in the output (instead of escaping \uXXXX) — multilingual i18n
  logLevel: "info",
}).then(async (ctx) => {
  if (watch) {
    await ctx.watch();
    console.log("[esbuild] watching for changes...");
  } else {
    await ctx.rebuild();
    await ctx.dispose();
    console.log("[esbuild] build complete");
  }
}).catch(() => process.exit(1));
