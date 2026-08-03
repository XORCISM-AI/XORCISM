/**
 * aicrosswalk.ts — AI Governance Crosswalk cockpit (/ai-governance-crosswalk).
 *
 * Renders the Crosswalk Matrix from *The Enterprise AI Governance Crosswalk* (Akhawat, 2026): one row per
 * governance capability, columns mapping EU AI Act (legal obligation), NIST AI RMF (reasoning), ISO/IEC
 * 42001 (management system) and Singapore's Model AI Governance Frameworks (complementary guidance), each
 * with required evidence, owning role and priority. Adds per-tenant capability status tracking + coverage
 * analytics, the EU application timeline (post-Digital-Omnibus), the AI Governance Navigator and the
 * 90-day roadmap.
 *
 * Per-tenant status lives in AICROSSWALKSTATUS (XORCISM). The matrix itself is the curated dataset in
 * data/aiCrosswalk.ts. Complements the [[ai-control-library]] (reusable controls) — this is the
 * instrument-crosswalk view. RBAC: XCOMPLIANCE.AUDIT.
 */
import { getDb } from "./db";
import { CROSSWALK_ROWS, CROSSWALK_DOMAINS, CROSSWALK_INSTRUMENTS, CrosswalkRow, Priority,
  EU_TIMELINE, NAVIGATOR_QUESTIONS, ROADMAP_PHASES } from "./data/aiCrosswalk";

export const CROSSWALK_STATUSES = ["not-started", "in-progress", "met", "na"] as const;
export type CrosswalkStatus = (typeof CROSSWALK_STATUSES)[number];

const now = (): string => new Date().toISOString();

// ── Living columns: resolve a capability's instrument refs to the actual imported CONTROL rows ──────
/** The VOCABULARY name(s) backing each instrument column (populated by the framework importers). */
const INSTRUMENT_VOCABS: Record<string, string[]> = {
  eu: ["EU AI Act"],
  nist: ["NIST AI RMF 1.0"],
  iso: ["ISO42001"],
  sg: [
    "Singapore Model AI Governance Framework (2020)",
    "Singapore Model AI Governance Framework for GenAI (2024)",
    "Singapore Model AI Governance Framework for Agentic AI (2026)",
    "OECD AI Principles (2019, updated 2024)",
  ],
};
const SG_PREFIX: Record<string, string> = { "2020": "SG20", GenAI: "SGGEN", Agentic: "SGAGT", OECD: "OECD" };
const MAPPING_SOURCE = "AI-Gov-Crosswalk 2026"; // CONTROLMAPPING.Source — idempotency key for the sync

interface Ctl { id: number; cis: string | null; iso: string | null; name: string; vocab: string }

/** Load (and cache per call) all CONTROL rows of the vocabularies backing an instrument column. */
function loadInstrumentControls(cache: Map<string, Ctl[]>, key: string): Ctl[] {
  if (cache.has(key)) return cache.get(key)!;
  const db = getDb("XORCISM");
  const out: Ctl[] = [];
  for (const vname of INSTRUMENT_VOCABS[key] || []) {
    const v = db.prepare("SELECT VocabularyID FROM VOCABULARY WHERE VocabularyName=?").get(vname) as { VocabularyID: number } | undefined;
    if (!v) continue;
    const rows = db.prepare("SELECT ControlID id, CIS cis, ISO iso, ControlName name FROM CONTROL WHERE VocabularyID=?").all(v.VocabularyID) as Ctl[];
    for (const r of rows) out.push({ ...r, vocab: vname });
  }
  cache.set(key, out);
  return out;
}

/** Best-effort resolve a capability's instrument reference string to matching CONTROL rows. */
function resolveRef(cache: Map<string, Ctl[]>, key: string, ref: string): Ctl[] {
  const ctls = loadInstrumentControls(cache, key);
  const picks = new Map<number, Ctl>();
  const add = (c: Ctl): void => { if (!picks.has(c.id)) picks.set(c.id, c); };
  if (key === "eu") {
    for (const m of ref.matchAll(/Art\.?\s*(\d+)/g)) { const a = `Art. ${m[1]}`; for (const c of ctls) if (c.cis === a) add(c); }
  } else if (key === "nist") {
    for (const m of ref.matchAll(/(GOVERN|MAP|MEASURE|MANAGE)\s*(\d+)(?:\.(\d+))?/g)) {
      const fam = `${m[1]} ${m[2]}`, exact = m[3] ? `${fam}.${m[3]}` : null;
      for (const c of ctls) { if (!c.cis) continue; if (exact ? c.cis === exact : (c.cis === fam || c.cis.startsWith(fam + "."))) add(c); }
    }
  } else if (key === "iso") {
    for (const m of ref.matchAll(/A\.\d+(?:\.\d+)*/g)) { const tk = m[0]; for (const c of ctls) { const v = c.iso || c.cis; if (v && (v === tk || v.startsWith(tk + "."))) add(c); } }
  } else if (key === "sg") {
    for (const seg of ref.split(";")) {
      const pm = seg.match(/\b(2020|GenAI|Agentic|OECD)\b/); if (!pm) continue;
      const p = SG_PREFIX[pm[1]];
      const nums = [...seg.matchAll(/\((\d+(?:\.\d+)?(?:\s*,\s*\d+(?:\.\d+)?)*)\)/g)].flatMap((m) => m[1].split(",").map((x) => x.trim()));
      for (const n of nums) { const cis = `${p}.${n}`; for (const c of ctls) { if (c.cis && (c.cis === cis || c.cis.startsWith(cis + "."))) add(c); } }
    }
  }
  return [...picks.values()];
}

export interface RefLink { count: number; items: { id: number; ref: string | null; name: string }[] }
function pack(list: Ctl[]): RefLink { return { count: list.length, items: list.slice(0, 6).map((c) => ({ id: c.id, ref: c.cis || c.iso, name: c.name })) }; }

export function ensureCrosswalkTables(): void {
  const db = getDb("XORCISM");
  db.exec(`
    CREATE TABLE IF NOT EXISTS AICROSSWALKSTATUS (
      StatusID INTEGER PRIMARY KEY AUTOINCREMENT,
      CapID TEXT NOT NULL, Status TEXT, EvidenceRef TEXT, Owner TEXT, Notes TEXT,
      TenantID INTEGER, UpdatedDate TEXT,
      UNIQUE (CapID, TenantID));
    CREATE INDEX IF NOT EXISTS ix_aicrosswalk_tenant ON AICROSSWALKSTATUS(TenantID);`);
}

interface StatusRow { Status: string | null; EvidenceRef: string | null; Owner: string | null; Notes: string | null; UpdatedDate: string | null }

function statusMap(tenant: number | null): Record<string, StatusRow> {
  const db = getDb("XORCISM");
  const where = tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  const rows = db.prepare(`SELECT CapID, Status, EvidenceRef, Owner, Notes, UpdatedDate FROM AICROSSWALKSTATUS ${where}`)
    .all(...(tenant != null ? [tenant] : [])) as (StatusRow & { CapID: string })[];
  const m: Record<string, StatusRow> = {};
  for (const r of rows) m[r.CapID] = r; // tenant row (or global) wins; last write per CapID
  return m;
}

export interface CrosswalkCapability extends CrosswalkRow {
  status: CrosswalkStatus; evidenceRef: string | null; ownerOverride: string | null; notes: string | null; updatedDate: string | null;
  links?: { eu: RefLink; nist: RefLink; iso: RefLink; sg: RefLink }; // resolved to imported CONTROL rows (living columns)
}

/** The full crosswalk matrix for a tenant: capabilities (with status), grouped by domain, + analytics. */
export function crosswalkMatrix(tenant: number | null): {
  instruments: typeof CROSSWALK_INSTRUMENTS;
  domains: { domain: string; rows: CrosswalkCapability[]; met: number; total: number }[];
  capabilities: CrosswalkCapability[];
  summary: ReturnType<typeof crosswalkSummary>;
  timeline: typeof EU_TIMELINE; navigator: string[]; roadmap: typeof ROADMAP_PHASES;
} {
  ensureCrosswalkTables();
  const sm = statusMap(tenant);
  const cache = new Map<string, Ctl[]>();
  const capabilities: CrosswalkCapability[] = CROSSWALK_ROWS.map((r) => {
    const s = sm[r.id];
    const st = (s?.Status && (CROSSWALK_STATUSES as readonly string[]).includes(s.Status) ? s.Status : "not-started") as CrosswalkStatus;
    return {
      ...r, status: st, evidenceRef: s?.EvidenceRef ?? null, ownerOverride: s?.Owner ?? null, notes: s?.Notes ?? null, updatedDate: s?.UpdatedDate ?? null,
      links: {
        eu: pack(resolveRef(cache, "eu", r.eu)), nist: pack(resolveRef(cache, "nist", r.nist)),
        iso: pack(resolveRef(cache, "iso", r.iso)), sg: pack(resolveRef(cache, "sg", r.sg)),
      },
    };
  });
  const domains = CROSSWALK_DOMAINS.map((domain) => {
    const rows = capabilities.filter((c) => c.domain === domain);
    const assessable = rows.filter((c) => c.status !== "na");
    return { domain, rows, met: rows.filter((c) => c.status === "met").length, total: assessable.length };
  }).filter((d) => d.rows.length);
  return { instruments: CROSSWALK_INSTRUMENTS, domains, capabilities, summary: crosswalkSummary(capabilities),
    timeline: EU_TIMELINE, navigator: NAVIGATOR_QUESTIONS, roadmap: ROADMAP_PHASES };
}

/** Coverage analytics: overall %, per-instrument, per-priority, per-domain, status counts. */
export function crosswalkSummary(caps: CrosswalkCapability[]) {
  const assessable = caps.filter((c) => c.status !== "na");
  const met = assessable.filter((c) => c.status === "met").length;
  const statusCounts: Record<string, number> = { "not-started": 0, "in-progress": 0, met: 0, na: 0 };
  for (const c of caps) statusCounts[c.status]++;

  // Per-instrument coverage: of capabilities that reference the instrument, share that are met.
  const perInstrument = CROSSWALK_INSTRUMENTS.map((inst) => {
    const refs = assessable.filter((c) => String((c as unknown as Record<string, string>)[inst.key] || "").trim() !== "");
    const m = refs.filter((c) => c.status === "met").length;
    return { key: inst.key, label: inst.label, met: m, total: refs.length, pct: refs.length ? Math.round((m / refs.length) * 100) : 0 };
  });

  const priorities: Priority[] = ["P1", "P2", "P3"];
  const perPriority = priorities.map((p) => {
    const rows = assessable.filter((c) => c.priority === p);
    const m = rows.filter((c) => c.status === "met").length;
    return { priority: p, met: m, total: rows.length, pct: rows.length ? Math.round((m / rows.length) * 100) : 0 };
  });

  return {
    totalCapabilities: caps.length,
    assessable: assessable.length,
    met,
    coveragePct: assessable.length ? Math.round((met / assessable.length) * 100) : 0,
    statusCounts, perInstrument, perPriority,
    p1Open: assessable.filter((c) => c.priority === "P1" && c.status !== "met").length,
  };
}

/** Upsert one capability's status for a tenant. */
export function setCrosswalkStatus(tenant: number | null, capId: string,
  patch: { status?: string; evidenceRef?: string; owner?: string; notes?: string }): CrosswalkCapability {
  ensureCrosswalkTables();
  if (!CROSSWALK_ROWS.some((r) => r.id === capId)) throw new Error(`unknown capability ${capId}`);
  if (patch.status && !(CROSSWALK_STATUSES as readonly string[]).includes(patch.status)) throw new Error(`invalid status ${patch.status}`);
  const db = getDb("XORCISM");
  const t = tenant ?? null;
  const existing = db.prepare("SELECT StatusID FROM AICROSSWALKSTATUS WHERE CapID=? AND (TenantID IS ?)").get(capId, t) as { StatusID: number } | undefined;
  if (existing) {
    const sets: string[] = []; const vals: unknown[] = [];
    if (patch.status !== undefined) { sets.push("Status=?"); vals.push(patch.status); }
    if (patch.evidenceRef !== undefined) { sets.push("EvidenceRef=?"); vals.push(patch.evidenceRef || null); }
    if (patch.owner !== undefined) { sets.push("Owner=?"); vals.push(patch.owner || null); }
    if (patch.notes !== undefined) { sets.push("Notes=?"); vals.push(patch.notes || null); }
    sets.push("UpdatedDate=?"); vals.push(now());
    vals.push(existing.StatusID);
    db.prepare(`UPDATE AICROSSWALKSTATUS SET ${sets.join(", ")} WHERE StatusID=?`).run(...vals);
  } else {
    db.prepare("INSERT INTO AICROSSWALKSTATUS (CapID, Status, EvidenceRef, Owner, Notes, TenantID, UpdatedDate) VALUES (?,?,?,?,?,?,?)")
      .run(capId, patch.status || "not-started", patch.evidenceRef || null, patch.owner || null, patch.notes || null, t, now());
  }
  const cap = crosswalkMatrix(tenant).capabilities.find((c) => c.id === capId)!;
  return cap;
}

/** Markdown export of the crosswalk matrix (auditor / board handout). */
export function crosswalkMarkdown(tenant: number | null): string {
  const m = crosswalkMatrix(tenant);
  const L: string[] = [];
  L.push("# AI Governance Crosswalk\n");
  L.push(`Coverage: **${m.summary.coveragePct}%** (${m.summary.met}/${m.summary.assessable} capabilities met) — P1 open: ${m.summary.p1Open}\n`);
  L.push("| Domain | Capability | EU AI Act | NIST AI RMF | ISO/IEC 42001 | Singapore | Evidence | Owner | Priority | Status |");
  L.push("|---|---|---|---|---|---|---|---|---|---|");
  for (const c of m.capabilities) {
    L.push(`| ${c.domain} | ${c.capability} | ${c.eu} | ${c.nist} | ${c.iso} | ${c.sg} | ${c.evidence} | ${c.ownerOverride || c.owner} | ${c.priority} | ${c.status} |`);
  }
  L.push("\n## EU AI Act timeline (post Digital Omnibus)\n");
  for (const t of m.timeline) L.push(`- **${t.date}** — ${t.item} (${t.status})`);
  return L.join("\n");
}

/**
 * Persist the crosswalk as CONTROLMAPPING rows: for every capability, anchor on the resolved Singapore /
 * OECD control(s) and write a mapping to each resolved EU AI Act / NIST AI RMF / ISO 42001 control. This
 * makes Singapore a first-class node in the framework-crosswalk graph (like the PCI↔CSF crosswalk).
 * Idempotent by Source. Requires the framework importers to have been run. Returns row counts.
 */
export function syncCrosswalkMappings(): { mapped: number; capabilities: number; anchored: number } {
  ensureCrosswalkTables();
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CONTROLMAPPING'").get()) throw new Error("CONTROLMAPPING table missing");
  const cache = new Map<string, Ctl[]>();
  const label: Record<string, string> = { eu: "EU AI Act", nist: "NIST AI RMF", iso: "ISO/IEC 42001" };
  db.prepare("DELETE FROM CONTROLMAPPING WHERE Source=?").run(MAPPING_SOURCE);
  let next = (((db.prepare("SELECT COALESCE(MAX(MappingID),0) m FROM CONTROLMAPPING").get() as { m: number }).m) || 0) + 1;
  const ins = db.prepare("INSERT INTO CONTROLMAPPING (MappingID,MappingGUID,ControlID,Framework,ExternalID,ExternalName,Relationship,Source,CreatedDate) VALUES (?,?,?,?,?,?,?,?,?)");
  const ts = now();
  let mapped = 0, anchored = 0;
  const tx = db.transaction(() => {
    for (const cap of CROSSWALK_ROWS) {
      const sg = resolveRef(cache, "sg", cap.sg).slice(0, 5);
      if (!sg.length) continue;
      anchored++;
      for (const key of ["eu", "nist", "iso"] as const) {
        const targets = resolveRef(cache, key, cap[key]).slice(0, 5);
        for (const s of sg) for (const tgt of targets) {
          ins.run(next++, `cwmap-${cap.id}-${s.id}-${key}-${tgt.id}`, s.id, label[key], tgt.cis || tgt.iso, (tgt.name || "").slice(0, 300), "crosswalk", MAPPING_SOURCE, ts);
          mapped++;
        }
      }
    }
  });
  tx();
  return { mapped, capabilities: CROSSWALK_ROWS.length, anchored };
}
