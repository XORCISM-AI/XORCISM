/**
 * sigma.ts — Sigma rule parsing + conversion to SPL (Splunk), KQL (Sentinel/Kusto)
 * and EQL (Elastic).
 *
 * Covers the common Sigma detection grammar: named selections (maps / lists of
 * maps / keyword lists), field value modifiers (contains, startswith, endswith,
 * all, re, lt/lte/gt/gte), list values (OR), and the `condition` expression
 * (and / or / not / parentheses, plus `1 of x*`, `all of x*`, `1 of them`,
 * `all of them`). Field names are emitted as-is (a "no-pipeline" conversion) —
 * for production field mappings/taxonomy use a pySigma backend pipeline.
 */
import yaml from "js-yaml";

export interface SigmaRule {
  title?: string;
  id?: string;
  description?: string;
  status?: string;
  level?: string;
  author?: string;
  references?: string[];
  tags?: string[];
  logsource?: { product?: string; service?: string; category?: string };
  detection?: Record<string, unknown>;
}

export type Target = "spl" | "kql" | "eql";

export type Cond =
  | { op: "match"; field: string; mods: string[]; values: unknown[] }
  | { op: "keyword"; values: string[] }
  | { op: "and" | "or"; items: Cond[] }
  | { op: "not"; item: Cond }
  | { op: "true" };

export function parseSigma(text: string): SigmaRule {
  const doc = yaml.load(text) as Record<string, unknown> | undefined;
  if (!doc || typeof doc !== "object") throw new Error("Invalid Sigma YAML (expected a mapping).");
  if (!doc.detection || typeof doc.detection !== "object") throw new Error("Sigma rule has no 'detection' block.");
  return doc as SigmaRule;
}

/** ATT&CK technique ids (Txxxx) from Sigma `tags` (e.g. attack.t1059.001). */
export function attackTagsOf(rule: SigmaRule): string[] {
  const out = new Set<string>();
  for (const tag of rule.tags || []) {
    const m = /attack\.(t\d{4}(?:\.\d{3})?)/i.exec(String(tag));
    if (m) out.add(m[1].toUpperCase());
  }
  return [...out];
}

// ── detection → condition AST ─────────────────────────────────────────────────
function selectionToCond(sel: unknown): Cond {
  if (Array.isArray(sel)) {
    if (sel.every((x) => x === null || typeof x !== "object")) {
      return { op: "keyword", values: sel.map((x) => String(x)) };
    }
    return { op: "or", items: sel.map(selectionToCond) };
  }
  if (sel && typeof sel === "object") {
    const items: Cond[] = [];
    for (const [key, val] of Object.entries(sel as Record<string, unknown>)) {
      const [field, ...mods] = key.split("|");
      items.push({ op: "match", field, mods, values: Array.isArray(val) ? val : [val] });
    }
    return items.length === 1 ? items[0] : { op: "and", items };
  }
  return { op: "keyword", values: [String(sel)] };
}

function flatten(op: "and" | "or", a: Cond, b: Cond): Cond[] {
  const out: Cond[] = [];
  for (const c of [a, b]) {
    if (c.op === op) out.push(...c.items);
    else out.push(c);
  }
  return out;
}

function resolveCondition(condition: string, selections: Record<string, Cond>): Cond {
  const names = Object.keys(selections);
  const tokens = condition.replace(/[()]/g, (m) => ` ${m} `).split(/\s+/).filter(Boolean);
  let i = 0;
  const peek = (): string | undefined => tokens[i];
  const eat = (): string => tokens[i++];
  const sel = (n: string): Cond => selections[n] ?? { op: "true" };

  const ofExpr = (quantifier: string): Cond => {
    eat(); // 'of'
    const target = eat() || "them";
    let sels: Cond[];
    if (target === "them") sels = names.map(sel);
    else if (target.endsWith("*")) sels = names.filter((n) => n.startsWith(target.slice(0, -1))).map(sel);
    else sels = [sel(target)];
    if (!sels.length) return { op: "true" };
    return { op: quantifier === "all" ? "and" : "or", items: sels };
  };

  const primary = (): Cond => {
    const tk = peek();
    if (tk === "(") { eat(); const e = orExpr(); if (peek() === ")") eat(); return e; }
    if (tk === "not") { eat(); return { op: "not", item: primary() }; }
    if (tk === "all" || tk === "any" || (tk && /^\d+$/.test(tk))) {
      const q = eat();
      if (peek() === "of") return ofExpr(q);
      return sel(q);
    }
    return sel(eat());
  };
  const andExpr = (): Cond => {
    let left = primary();
    while (peek() === "and") { eat(); left = { op: "and", items: flatten("and", left, primary()) }; }
    return left;
  };
  const orExpr = (): Cond => {
    let left = andExpr();
    while (peek() === "or") { eat(); left = { op: "or", items: flatten("or", left, andExpr()) }; }
    return left;
  };
  return orExpr();
}

export function buildCond(rule: SigmaRule): Cond {
  const det = rule.detection || {};
  const selections: Record<string, Cond> = {};
  for (const [k, v] of Object.entries(det)) if (k !== "condition") selections[k] = selectionToCond(v);
  const condStr = String((det as Record<string, unknown>).condition ?? "").trim();
  if (!condStr) {
    const items = Object.values(selections);
    return items.length ? (items.length === 1 ? items[0] : { op: "and", items }) : { op: "true" };
  }
  return resolveCondition(condStr, selections);
}

// ── Rendering per target ──────────────────────────────────────────────────────
function esc(v: unknown, q = '"'): string {
  return String(v).split(q).join("\\" + q);
}
function wildcardToRe(v: string): string {
  return v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*").replace(/\\\?/g, ".");
}

function matchSpl(c: Extract<Cond, { op: "match" }>): string {
  const parts = c.values.map((val) => {
    if (val === null) return `NOT ${c.field}=*`;
    const v = esc(val);
    if (c.mods.includes("contains")) return `${c.field}="*${v}*"`;
    if (c.mods.includes("startswith")) return `${c.field}="${v}*"`;
    if (c.mods.includes("endswith")) return `${c.field}="*${v}"`;
    if (c.mods.includes("re")) return `${c.field}="${v}"`; // best-effort (Splunk regex is a pipe command)
    if (c.mods.includes("gt")) return `${c.field}>${val}`;
    if (c.mods.includes("gte")) return `${c.field}>=${val}`;
    if (c.mods.includes("lt")) return `${c.field}<${val}`;
    if (c.mods.includes("lte")) return `${c.field}<=${val}`;
    return `${c.field}="${v}"`;
  });
  const join = c.mods.includes("all") ? " " : " OR ";
  return parts.length > 1 ? `(${parts.join(join)})` : parts[0];
}
function matchKql(c: Extract<Cond, { op: "match" }>): string {
  const parts = c.values.map((val) => {
    if (val === null) return `isempty(${c.field})`;
    const v = esc(val);
    if (c.mods.includes("contains")) return `${c.field} contains "${v}"`;
    if (c.mods.includes("startswith")) return `${c.field} startswith "${v}"`;
    if (c.mods.includes("endswith")) return `${c.field} endswith "${v}"`;
    if (c.mods.includes("re")) return `${c.field} matches regex "${v}"`;
    if (c.mods.includes("gt")) return `${c.field} > ${val}`;
    if (c.mods.includes("gte")) return `${c.field} >= ${val}`;
    if (c.mods.includes("lt")) return `${c.field} < ${val}`;
    if (c.mods.includes("lte")) return `${c.field} <= ${val}`;
    return typeof val === "number" ? `${c.field} == ${val}` : `${c.field} =~ "${v}"`;
  });
  const join = c.mods.includes("all") ? " and " : " or ";
  return parts.length > 1 ? `(${parts.join(join)})` : parts[0];
}
function matchEql(c: Extract<Cond, { op: "match" }>): string {
  const parts = c.values.map((val) => {
    if (val === null) return `${c.field} == null`;
    const v = esc(val);
    if (c.mods.includes("contains")) return `${c.field} like~ "*${v}*"`;
    if (c.mods.includes("startswith")) return `${c.field} like~ "${v}*"`;
    if (c.mods.includes("endswith")) return `${c.field} like~ "*${v}"`;
    if (c.mods.includes("re")) return `${c.field} regex~ "${v}"`;
    if (c.mods.includes("gt")) return `${c.field} > ${val}`;
    if (c.mods.includes("gte")) return `${c.field} >= ${val}`;
    if (c.mods.includes("lt")) return `${c.field} < ${val}`;
    if (c.mods.includes("lte")) return `${c.field} <= ${val}`;
    return typeof val === "number" ? `${c.field} == ${val}` : `${c.field} == "${v}"`;
  });
  const join = c.mods.includes("all") ? " and " : " or ";
  return parts.length > 1 ? `(${parts.join(join)})` : parts[0];
}

function render(c: Cond, t: Target): string {
  const AND = t === "spl" ? " " : " and ";
  const OR = t === "spl" ? " OR " : " or ";
  const NOT = t === "spl" ? "NOT " : "not ";
  switch (c.op) {
    case "true": return "*";
    case "and": return c.items.map((x) => render(x, t)).filter((s) => s && s !== "*").join(AND) || "*";
    case "or": return "(" + c.items.map((x) => render(x, t)).join(OR) + ")";
    case "not": {
      const inner = render(c.item, t);
      return t === "spl" ? `NOT ${inner}` : `${NOT}(${inner})`;
    }
    case "keyword":
      return c.values.length
        ? "(" + c.values.map((v) => (t === "spl" ? `"*${esc(v)}*"` : t === "kql" ? `* contains "${esc(v)}"` : `_raw : "*${esc(v)}*"`)).join(OR) + ")"
        : "*";
    case "match":
      return t === "spl" ? matchSpl(c) : t === "kql" ? matchKql(c) : matchEql(c);
  }
}

/** Convert a parsed Sigma rule to one backend query. */
export function convertRule(rule: SigmaRule, target: Target): string {
  const cond = buildCond(rule);
  const body = render(cond, target);
  const ls = rule.logsource || {};
  const lsName = ls.category || ls.service || ls.product || "events";
  if (target === "kql") {
    // table mapping is environment-specific; emit a generic where over the logsource.
    return `${capitalize(lsName)}\n| where ${body}`;
  }
  if (target === "eql") {
    const cat = ls.category || "any";
    return `${cat} where ${body}`;
  }
  // SPL
  const src = ls.service ? `source="${ls.service}" ` : ls.product ? `index="${ls.product}" ` : "";
  return `${src}${body}`.trim();
}

function capitalize(s: string): string {
  return s.replace(/[^A-Za-z0-9]/g, "").replace(/^./, (c) => c.toUpperCase()) || "Events";
}

/** Convert Sigma YAML text to all three backends + metadata. Throws on invalid YAML. */
export function convertSigma(text: string): {
  title: string; level: string; status: string; logsource: string;
  attackTags: string[]; spl: string; kql: string; eql: string;
} {
  const rule = parseSigma(text);
  const ls = rule.logsource || {};
  return {
    title: rule.title || "",
    level: rule.level || "",
    status: rule.status || "",
    logsource: [ls.product, ls.category, ls.service].filter(Boolean).join("/"),
    attackTags: attackTagsOf(rule),
    spl: convertRule(rule, "spl"),
    kql: convertRule(rule, "kql"),
    eql: convertRule(rule, "eql"),
  };
}
