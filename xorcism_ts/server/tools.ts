/**
 * tools.ts — the TOOL catalogue with GitHub-style stars.
 *
 * The catalogue is a global reference set (tenant-owned tools + the shared, TenantID-NULL
 * seed/imports), browsable, searchable, category-filterable and sortable. Each user can
 * "star" a tool (XORCISM.TOOLSTAR, one row per user+tool); a tool's star count is the total
 * across ALL users (global, like GitHub). `starred` is whether the current user starred it.
 */
import { getDb } from "./db";

export interface ToolRow {
  id: number; name: string; description: string | null; category: string | null;
  url: string | null; starCount: number; starred: boolean;
}
export interface ToolCatalogue {
  tools: ToolRow[];
  categories: { category: string; count: number }[];
  total: number;
  summary: { tools: number; starred: number; categories: number };
}

export type ToolSort = "stars" | "name" | "recent";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

// Catalogue visibility: the shared catalogue (TenantID NULL) + the caller's own tenant rows.
// Super-admin (tenant === null) sees everything.
function visibility(tenant: number | null): { clause: string; args: Record<string, unknown> } {
  if (tenant == null) return { clause: "1=1", args: {} };
  return { clause: "(t.TenantID = @tenant OR t.TenantID IS NULL)", args: { tenant } };
}

export function toolCatalogue(
  userId: number, tenant: number | null,
  opts: { q?: string; category?: string; sort?: ToolSort; starred?: boolean; limit?: number; offset?: number } = {},
): ToolCatalogue {
  const empty: ToolCatalogue = { tools: [], categories: [], total: 0, summary: { tools: 0, starred: 0, categories: 0 } };
  let db; try { db = getDb("XORCISM"); } catch { return empty; }
  if (!has(db, "TOOL")) return empty;
  const starOk = has(db, "TOOLSTAR");
  const vis = visibility(tenant);
  const limit = Math.min(Math.max(Number(opts.limit) || 60, 1), 300);
  const offset = Math.max(Number(opts.offset) || 0, 0);

  const where: string[] = [vis.clause];
  const args: Record<string, unknown> = { ...vis.args, uid: userId, limit, offset };
  const q = String(opts.q || "").trim();
  if (q) { where.push("(t.ToolName LIKE @q OR t.ToolDescription LIKE @q)"); args.q = `%${q}%`; }
  if (opts.category) { where.push("t.Category = @cat"); args.cat = opts.category; }
  if (opts.starred && starOk) where.push("EXISTS (SELECT 1 FROM TOOLSTAR s WHERE s.ToolID = t.ToolID AND s.UserID = @uid)");
  const whereSql = "WHERE " + where.join(" AND ");

  const starCountExpr = starOk ? "(SELECT COUNT(*) FROM TOOLSTAR s WHERE s.ToolID = t.ToolID)" : "0";
  const starredExpr = starOk ? "(SELECT COUNT(*) FROM TOOLSTAR s WHERE s.ToolID = t.ToolID AND s.UserID = @uid)" : "0";
  const order = opts.sort === "name" ? "t.ToolName COLLATE NOCASE ASC"
    : opts.sort === "recent" ? "t.ToolID DESC"
    : `${starCountExpr} DESC, t.ToolName COLLATE NOCASE ASC`;

  const rows = db.prepare(
    `SELECT t.ToolID AS id, t.ToolName AS name, t.ToolDescription AS description,
            t.Category AS category, t.ToolURL AS url,
            ${starCountExpr} AS starCount, ${starredExpr} AS starred
     FROM TOOL t ${whereSql} ORDER BY ${order} LIMIT @limit OFFSET @offset`,
  ).all(args) as any[];

  const total = (db.prepare(`SELECT COUNT(*) AS c FROM TOOL t ${whereSql}`).get(args) as { c: number }).c;

  // Category pills + summary are over the full visible catalogue (stable navigation).
  const cats = db.prepare(
    `SELECT COALESCE(t.Category,'Uncategorized') AS category, COUNT(*) AS count
     FROM TOOL t WHERE ${vis.clause} GROUP BY t.Category ORDER BY count DESC, category COLLATE NOCASE`,
  ).all(vis.args) as { category: string; count: number }[];
  const totalTools = (db.prepare(`SELECT COUNT(*) AS c FROM TOOL t WHERE ${vis.clause}`).get(vis.args) as { c: number }).c;
  const myStars = starOk
    ? (db.prepare(`SELECT COUNT(*) AS c FROM TOOLSTAR s JOIN TOOL t ON t.ToolID = s.ToolID WHERE s.UserID = @uid AND ${vis.clause}`)
        .get({ ...vis.args, uid: userId }) as { c: number }).c
    : 0;

  return {
    tools: rows.map((r) => ({
      id: r.id, name: r.name, description: r.description, category: r.category, url: r.url,
      starCount: Number(r.starCount) || 0, starred: Number(r.starred) > 0,
    })),
    categories: cats,
    total,
    summary: { tools: totalTools, starred: myStars, categories: cats.length },
  };
}

/** Toggle a star for (userId, toolId). Returns the new state + the tool's global star count. */
export function toggleStar(userId: number, toolId: number, tenant: number | null): { starred: boolean; starCount: number } {
  const db = getDb("XORCISM");
  const vis = visibility(tenant);
  const exists = db.prepare(`SELECT 1 FROM TOOL t WHERE t.ToolID = @id AND ${vis.clause}`).get({ ...vis.args, id: toolId });
  if (!exists) throw new Error("tool not found");
  const star = db.prepare("SELECT StarID FROM TOOLSTAR WHERE UserID = ? AND ToolID = ?").get(userId, toolId) as { StarID: number } | undefined;
  if (star) {
    db.prepare("DELETE FROM TOOLSTAR WHERE StarID = ?").run(star.StarID);
  } else {
    db.prepare("INSERT INTO TOOLSTAR (ToolID, UserID, CreatedDate) VALUES (?,?,?)").run(toolId, userId, new Date().toISOString());
  }
  const starCount = (db.prepare("SELECT COUNT(*) AS c FROM TOOLSTAR WHERE ToolID = ?").get(toolId) as { c: number }).c;
  return { starred: !star, starCount };
}
