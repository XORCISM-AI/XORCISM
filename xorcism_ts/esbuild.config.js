// esbuild.config.js — bundles client TypeScript to dist/client/
const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");

const watch = process.argv.includes("--watch");

const entryPoints = [
  "client/ts/app.ts",
  "client/ts/bia.ts",
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
  "client/ts/d3fend.ts",
  "client/ts/ask.ts",
  "client/ts/a3m.ts",
  "client/ts/tprm.ts",
  "client/ts/ebios.ts",
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
