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
  "client/ts/easm.ts",
  "client/ts/frameworks.ts",
  "client/ts/ai-guardrails.ts",
  "client/ts/incident-management.ts",
  "client/ts/compliance-management.ts",
  "client/ts/policy-management.ts",
  "client/ts/configuration-management.ts",
  "client/ts/crisis-management.ts",
  "client/ts/crisis-exercise.ts",
  "client/ts/fair-mam.ts",
  "client/ts/fair-tef.ts",
  "client/ts/devsecops.ts",
  "client/ts/risk-register.ts",
  "client/ts/pqcmm.ts",
  "client/ts/csf-maturity.ts",
  "client/ts/cbom.ts",
  "client/ts/ai-sbom.ts",
  "client/ts/trace.ts",
  "client/ts/tlpt.ts",
  "client/ts/agent-firewall.ts",
  "client/ts/sprs.ts",
  "client/ts/exposure-remediation.ts",
  "client/ts/essential-eight.ts",
  "client/ts/adversary-opportunity.ts",
  "client/ts/insurance-readiness.ts",
  "client/ts/sca.ts",
  "client/ts/tools.ts",
  "client/ts/threat-model.ts",
  "client/ts/threat-informed-defense.ts",
  "client/ts/oval-scan.ts",
  "client/ts/oval-editor.ts",
  "client/ts/api-keys.ts",
  "client/ts/api-docs.ts",
  "client/ts/webhooks.ts",
  "client/ts/cti-watch.ts",
  "client/ts/threat-feeds.ts",
  "client/ts/drift.ts",
  "client/ts/content.ts",
  "client/ts/d3fend.ts",
  "client/ts/ask.ts",
  "client/ts/a3m.ts",
  "client/ts/mitigant.ts",
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
  "client/ts/questionnaire-journeys.ts",
  "client/ts/zero-trust.ts",
  "client/ts/authz-governance.ts",
  "client/ts/cra-compliance.ts",
  "client/ts/ai-control-library.ts",
  "client/ts/itdr.ts",
  "client/ts/identity-governance.ts",
  "client/ts/soc.ts",
  "client/ts/soc-cmm.ts",
  "client/ts/cert-ops.ts",
  "client/ts/governance.ts",
  "client/ts/ai-threat-advisor.ts",
  "client/ts/workforce.ts",
  "client/ts/team-ops.ts",
  "client/ts/voc.ts",
  "client/ts/vm-report.ts",
  "client/ts/board-report.ts",
  "client/ts/privacy.ts",
  "client/ts/soar.ts",
  "client/ts/endpoint-query.ts",
  "client/ts/ctem.ts",
  "client/ts/cti-expert.ts",
  "client/ts/threat-copilot.ts",
  "client/ts/crq.ts",
  "client/ts/vuln-assessment.ts",
  "client/ts/wifi-pentest.ts",
  "client/ts/reg-calendar.ts",
  "client/ts/ai-systems.ts",
  "client/ts/knowledge-graph.ts",
  "client/ts/mssp.ts",
  "client/ts/croc-orchestrator.ts",
  "client/ts/siem.ts",
  "client/ts/ai-redteam.ts",
  "client/ts/ai-detection.ts",
  "client/ts/llm-pentest.ts",
  "client/ts/ai-skills.ts",
  "client/ts/reg-incident-reporting.ts",
  "client/ts/slsa.ts",
  "client/ts/chatops.ts",
  "client/ts/croc.ts",
  "client/ts/cyber-risk-hunting.ts",
  "client/ts/agents.ts",
  "client/ts/network-sessions.ts",
  "client/ts/osint-graph.ts",
  "client/ts/hunting.ts",
  "client/ts/questionnaire-assistant.ts",
];

const shared = {
  bundle: true,
  outdir: "dist/client/js",
  platform: "browser",
  target: ["es2020"],
  sourcemap: true,
  // Minify in production. Set XOR_NO_MINIFY=1 for readable bundles when debugging the client.
  minify: process.env.XOR_NO_MINIFY !== "1",
  legalComments: "none",
  charset: "utf8", // keeps UTF-8 in the output (instead of escaping \uXXXX) — multilingual i18n
  logLevel: "info",
};

// The multilingual i18n dictionary (i18n.ts, ~700 KB of string data) is imported by 100+ page bundles.
// Inlining it into every bundle made each page ship ~600 KB of duplicated strings (and it shipped TWICE
// per page: in session-ui.js AND the page bundle). This plugin rewrites every `import … from "./i18n"`
// in the page bundles to read from a single global (window.XORI18N), so the dictionary is built ONCE as
// /js/i18n.js, downloaded once, and cached across every page. Page bundles drop to a fraction of their
// size and navigation becomes near-instant. The page <script> tags load /js/i18n.js first. Keeps classic
// (IIFE) script output — no ESM/module-type change needed.
const i18nGlobalPlugin = {
  name: "i18n-global",
  setup(build) {
    build.onResolve({ filter: /^\.\/i18n$/ }, () => ({ path: "i18n-global", namespace: "i18n-global" }));
    build.onLoad({ filter: /.*/, namespace: "i18n-global" }, () => ({
      loader: "js",
      contents:
        "const M = globalThis.XORI18N;\n" +
        "export const SUPPORTED = M.SUPPORTED, getLang = M.getLang, lang = M.lang, t = M.t,\n" +
        "  setLang = M.setLang, applyTranslations = M.applyTranslations,\n" +
        "  createLanguageSelect = M.createLanguageSelect, initLanguageSelector = M.initLanguageSelector,\n" +
        "  initI18n = M.initI18n;\n",
    }));
  },
};

// Pre-compress the built bundles once (brotli + gzip) so the server can serve the precompressed bytes
// directly — smaller than on-the-fly gzip (brotli-11) and removes the per-request compression CPU from
// the synchronous hot path. The server falls back to live compression for anything not precompressed.
function precompress() {
  const zlib = require("zlib");
  const dir = path.join(__dirname, "dist/client/js");
  let n = 0;
  for (const f of fs.readdirSync(dir)) {
    if (!/\.(js|css)$/.test(f)) continue;
    const buf = fs.readFileSync(path.join(dir, f));
    fs.writeFileSync(path.join(dir, f + ".gz"), zlib.gzipSync(buf, { level: 9 }));
    fs.writeFileSync(path.join(dir, f + ".br"),
      zlib.brotliCompressSync(buf, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 } }));
    n++;
  }
  console.log(`[esbuild] pre-compressed ${n} bundles (.gz + .br)`);
}

Promise.all([
  // 1) the shared i18n dictionary → window.XORI18N (one file, cached across all pages)
  esbuild.context({ ...shared, entryPoints: ["client/ts/i18n.ts"], globalName: "XORI18N" }),
  // 2) all page bundles, with i18n externalised to that global
  esbuild.context({ ...shared, entryPoints, plugins: [i18nGlobalPlugin] }),
]).then(async (ctxs) => {
  if (watch) {
    await Promise.all(ctxs.map((c) => c.watch()));
    console.log("[esbuild] watching for changes...");
  } else {
    await Promise.all(ctxs.map((c) => c.rebuild()));
    await Promise.all(ctxs.map((c) => c.dispose()));
    precompress();
    console.log("[esbuild] build complete");
  }
}).catch((e) => { console.error(e); process.exit(1); });
