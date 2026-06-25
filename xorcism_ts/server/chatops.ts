/**
 * chatops.ts — two-way ChatOps: query XORCISM and act on it from Slack / Teams.
 *
 * The inbound counterpart to teams.ts (outbound). A command dispatcher answers natural-ish commands
 * (posture / digest / exposures / obligations / queue / approve N / dismiss N / ai) by reusing the
 * existing modules, and a Slack-signature verifier secures the webhook. Read-only by default; the
 * approve/dismiss actions on the agentic orchestrator queue require CHATOPS_ALLOW_ACTIONS=1.
 */
import crypto from "crypto";
import { boardReport } from "./boardreport";
import { generateDigest } from "./crocdigest";
import { topExposures } from "./fusion";
import { regCalendar } from "./regobligations";
import { orchestratorDashboard, decideAction } from "./orchestrator";
import { aiSystemDashboard } from "./aisystems";

export interface ChatContext { tenant: number | null; userId: number | null; canAct: boolean }
export interface ChatReply { text: string; queue?: { id: number; title: string; severity: string }[] }

const safe = <T>(fn: () => T, dflt: T): T => { try { return fn(); } catch { return dflt; } };
const HELP = [
  "*XORCISM ChatOps* — commands:",
  "• `posture` — enterprise posture score & trend",
  "• `digest` — today's CROC standup (priorities)",
  "• `exposures` — top prioritised exposures",
  "• `obligations` — overdue / imminent regulatory deadlines",
  "• `ai` — AI governance gaps",
  "• `queue` — the agentic orchestrator's approval queue",
  "• `approve <id>` / `dismiss <id>` — decide a proposed action",
].join("\n");

export function dispatchCommand(raw: string, ctx: ChatContext): ChatReply {
  const text = (raw || "").trim();
  const [cmd, ...rest] = text.split(/\s+/);
  const arg = rest.join(" ");
  switch ((cmd || "help").toLowerCase()) {
    case "help": case "": case "?":
      return { text: HELP };

    case "posture": case "score": {
      const r = safe(() => boardReport(ctx.tenant), null as any);
      if (!r) return { text: "Posture unavailable." };
      return { text: `*Posture ${r.posture.score}/100 (${r.posture.grade})* — ${r.posture.verdict}. Enterprise risk ${r.posture.enterpriseRisk}; trend *${r.trend.direction}*. ${r.criticalAssets.atRisk}/${r.criticalAssets.total} crown jewels at risk.` };
    }
    case "digest": case "standup": {
      const d = safe(() => generateDigest(ctx.tenant), null as any);
      if (!d) return { text: "Digest unavailable." };
      const pr = (d.priorities || []).slice(0, 4).map((p: any) => `${p.rank}. ${p.action}`).join("\n");
      return { text: `*${d.headline}.*\n${pr || "Nothing urgent."}` };
    }
    case "exposures": case "top": {
      const r = safe(() => topExposures(ctx.tenant, 5).results, [] as any[]);
      if (!r.length) return { text: "No open exposures. :tada:" };
      return { text: "*Top exposures:*\n" + r.map((x: any) => `• ${x.ref || x.cve || x.name || x.asset || "?"} — score ${Math.round(x.score ?? 0)}${x.kev ? " · KEV" : ""}`).join("\n") };
    }
    case "obligations": case "deadlines": case "reg": {
      const c = safe(() => regCalendar(ctx.tenant), null as any);
      if (!c) return { text: "Calendar unavailable." };
      const soon = (c.obligations || []).filter((o: any) => ["Overdue", "Due soon"].includes(o.effectiveStatus)).slice(0, 5);
      return { text: `*Regulatory: ${c.summary.overdue} overdue · ${c.summary.dueSoon} due ≤30d.*\n` + (soon.map((o: any) => `• ${o.effectiveStatus === "Overdue" ? ":red_circle:" : ":large_yellow_circle:"} ${o.regulation} ${o.reference} — ${o.title}${o.dueDate ? ` (${o.dueDate})` : ""}`).join("\n") || "Nothing imminent.") };
    }
    case "ai": case "ai-risk": {
      const d = safe(() => aiSystemDashboard(ctx.tenant), null as any);
      if (!d) return { text: "AI inventory unavailable." };
      const w = (d.worklist || []).slice(0, 4).map((s: any) => `• ${s.name} (${s.riskTier}) — ${s.gaps[0] || "review"}`).join("\n");
      return { text: `*AI governance:* ${d.summary.highRisk} high-risk, ${d.summary.ungoverned} ungoverned.\n${w || "All governed."}` };
    }
    case "queue": case "actions": {
      const o = safe(() => orchestratorDashboard(ctx.tenant), null as any);
      if (!o) return { text: "Orchestrator unavailable." };
      const q = (o.queue || []).slice(0, 5);
      if (!q.length) return { text: "Approval queue is clear. :white_check_mark:" };
      return {
        text: `*Orchestrator queue (${o.summary.proposed}):*\n` + q.map((a: any) => `• #${a.id} [${a.severity}] ${a.title} — _${a.recommendedAction}_`).join("\n") + (ctx.canAct ? "\nReply `approve <id>` or `dismiss <id>`." : "\n_(read-only — set CHATOPS_ALLOW_ACTIONS=1 to act)_"),
        queue: q.map((a: any) => ({ id: a.id, title: a.title, severity: a.severity })),
      };
    }
    case "approve": case "dismiss": {
      if (!ctx.canAct) return { text: ":lock: Acting from chat is disabled (set `CHATOPS_ALLOW_ACTIONS=1`)." };
      const id = Number(arg);
      if (!Number.isInteger(id)) return { text: `Usage: \`${cmd} <id>\` (see \`queue\`).` };
      const decision = cmd.toLowerCase() === "approve" ? "approved" : "dismissed";
      const ok = safe(() => decideAction(id, ctx.tenant, decision as "approved" | "dismissed", ctx.userId), false);
      return { text: ok ? `:white_check_mark: Action #${id} *${decision}*.` : `Action #${id} not found or already decided.` };
    }
    default:
      return { text: `Unknown command \`${cmd}\`. Try \`help\`.` };
  }
}

/** Verify a Slack request signature (v0 HMAC-SHA256 over `v0:timestamp:body`). */
export function verifySlackSignature(rawBody: Buffer | string, timestamp: string, signature: string, secret: string): boolean {
  if (!secret || !signature || !timestamp) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false; // replay window: 5 min
  const body = typeof rawBody === "string" ? rawBody : (rawBody?.toString("utf8") ?? "");
  const hmac = crypto.createHmac("sha256", secret).update(`v0:${timestamp}:${body}`).digest("hex");
  const expected = `v0=${hmac}`;
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature)); } catch { return false; }
}

/** Verify a Teams outgoing-webhook HMAC (base64 HMAC-SHA256 over the raw body, 'HMAC ' prefix). */
export function verifyTeamsHmac(rawBody: Buffer | string, authHeader: string, secretB64: string): boolean {
  if (!secretB64 || !authHeader) return false;
  try {
    const key = Buffer.from(secretB64, "base64");
    const body = typeof rawBody === "string" ? Buffer.from(rawBody, "utf8") : rawBody;
    const digest = "HMAC " + crypto.createHmac("sha256", key).update(body).digest("base64");
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(authHeader));
  } catch { return false; }
}
