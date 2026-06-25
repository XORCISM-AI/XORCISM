/** chatops.ts (routes) — two-way ChatOps.
 *  • POST /api/chatops/command   — session-authed (the in-app console + generic integrations)
 *  • POST /api/chatops/slack/command + /slack/interactive — Slack (verified by signing secret)
 *  • POST /api/chatops/teams      — Teams outgoing webhook (verified by HMAC secret)
 *  Read-only unless CHATOPS_ALLOW_ACTIONS=1 (approve/dismiss on the orchestrator queue). */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { dispatchCommand, verifySlackSignature, verifyTeamsHmac, type ChatContext, type ChatReply } from "../chatops";
import { decideAction } from "../orchestrator";

const router = Router();
const rawOf = (req: Request): Buffer | string => (req as Request & { rawBody?: Buffer }).rawBody ?? "";
const chatTenant = (): number | null => { const v = (process.env.CHATOPS_TENANT || "").trim(); return /^-?\d+$/.test(v) ? Number(v) : null; };
const chatCanAct = (): boolean => process.env.CHATOPS_ALLOW_ACTIONS === "1";

// ── In-app console / generic JSON integration (session-authed) ──
router.post("/chatops/command", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const ctx: ChatContext = {
    tenant: req.user.isSuperAdmin ? null : (req.user.tenantId ?? null),
    userId: req.user.UserID ?? null,
    canAct: userCan(req.user, "update", "XINCIDENT", "INCIDENT"),
  };
  const text = String((req.body as { text?: unknown })?.text ?? "");
  try { res.json(dispatchCommand(text, ctx)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── Slack slash command (application/x-www-form-urlencoded, signed) ──
function slackVerify(req: Request, res: Response): boolean {
  const secret = process.env.SLACK_SIGNING_SECRET || "";
  if (!secret) { res.status(503).json({ error: "Slack not configured (SLACK_SIGNING_SECRET)." }); return false; }
  const ok = verifySlackSignature(rawOf(req), String(req.header("x-slack-request-timestamp") || ""), String(req.header("x-slack-signature") || ""), secret);
  if (!ok) { res.status(401).send("invalid signature"); return false; }
  return true;
}
function slackPayload(reply: ChatReply): unknown {
  const blocks: unknown[] = [{ type: "section", text: { type: "mrkdwn", text: reply.text } }];
  for (const a of reply.queue || []) {
    blocks.push({
      type: "actions", block_id: `act_${a.id}`,
      elements: [
        { type: "button", action_id: `approve_${a.id}`, style: "primary", text: { type: "plain_text", text: `✓ Approve #${a.id}` }, value: String(a.id) },
        { type: "button", action_id: `dismiss_${a.id}`, text: { type: "plain_text", text: `✕ Dismiss #${a.id}` }, value: String(a.id) },
      ],
    });
  }
  return { response_type: "ephemeral", text: reply.text, blocks };
}

router.post("/chatops/slack/command", (req: Request, res: Response) => {
  if (!slackVerify(req, res)) return;
  const text = String((req.body as { text?: unknown })?.text ?? "");
  const reply = dispatchCommand(text, { tenant: chatTenant(), userId: null, canAct: chatCanAct() });
  res.json(slackPayload(reply));
});

router.post("/chatops/slack/interactive", (req: Request, res: Response) => {
  if (!slackVerify(req, res)) return;
  let payload: any = {};
  try { payload = JSON.parse(String((req.body as { payload?: unknown })?.payload ?? "{}")); } catch { /* */ }
  const action = (payload.actions && payload.actions[0]) || {};
  const m = /^(approve|dismiss)_(\d+)$/.exec(String(action.action_id || ""));
  if (!m) return void res.json({ text: "No action." });
  if (!chatCanAct()) return void res.json({ replace_original: false, text: ":lock: Acting from chat is disabled (CHATOPS_ALLOW_ACTIONS=1)." });
  const ok = decideAction(Number(m[2]), chatTenant(), m[1] === "approve" ? "approved" : "dismissed", null);
  res.json({ replace_original: false, text: ok ? `:white_check_mark: Action #${m[2]} *${m[1] === "approve" ? "approved" : "dismissed"}* by ${payload.user?.username || "chat"}.` : `Action #${m[2]} not found or already decided.` });
});

// ── Teams outgoing webhook (signed with the shared HMAC secret) ──
router.post("/chatops/teams", (req: Request, res: Response) => {
  const secret = process.env.TEAMS_OUTGOING_SECRET || "";
  if (!secret) return void res.status(503).json({ type: "message", text: "Teams not configured (TEAMS_OUTGOING_SECRET)." });
  if (!verifyTeamsHmac(rawOf(req), String(req.header("authorization") || ""), secret)) return void res.status(401).json({ type: "message", text: "invalid signature" });
  const text = String((req.body as { text?: unknown })?.text ?? "").replace(/<at>.*?<\/at>/g, "").trim();
  const reply = dispatchCommand(text, { tenant: chatTenant(), userId: null, canAct: chatCanAct() });
  res.json({ type: "message", text: reply.text });
});

export default router;
