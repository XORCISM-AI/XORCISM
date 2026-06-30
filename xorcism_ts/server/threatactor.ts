/**
 * threatactor.ts — Threat-actor profiling + the Diamond Model of Intrusion Analysis.
 *
 * Builds an intel-grade profile on top of the legacy XTHREAT.THREATACTOR table (extended by
 * ensureThreatActorProfile() in db.ts with STIX threat-actor vocabularies + the four Diamond
 * Model vertices). The Diamond Model (Caltagirone, Pendergast & Betz, 2013) structures every
 * intrusion around four core features connected by edges:
 *
 *        Adversary  (who)
 *         /      \
 *   Capability — Infrastructure        ← technology meta-feature (horizontal axis)
 *         \      /
 *         Victim  (target)             ← socio-political meta-feature (vertical axis)
 *
 * Capabilities are resolved from ATT&CK technique ids (AttackTags) + malware/tools (MalwareTags);
 * infrastructure from curated IOCs (THREATACTORINFRA); victims from target sectors / regions and
 * the incidents the actor is linked to (THREATACTORFORINCIDENT). Tenant-scoped (NULL = global).
 */
import { getDb } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const s = (v: unknown): string => (v == null ? "" : String(v));
const tw = (tenant: number | null): string => (tenant != null ? "(TenantID = ? OR TenantID IS NULL)" : "1=1");
const ta = (tenant: number | null): number[] => (tenant != null ? [tenant] : []);

/** STIX 2.1 threat-actor open vocabularies, surfaced in the profile-builder dropdowns. */
export const STIX_VOCAB = {
  actorTypes: ["nation-state", "crime-syndicate", "criminal", "hacker", "hacktivist", "insider-accidental",
    "insider-disgruntled", "competitor", "terrorist", "activist", "spy", "sensationalist", "unknown"],
  sophistication: ["none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic"],
  resourceLevel: ["individual", "club", "contest", "team", "organization", "government"],
  motivations: ["accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
    "personal-gain", "personal-satisfaction", "revenge", "unpredictable", "espionage", "financial", "destruction"],
};

export interface ActorRow { [k: string]: any }

/** Resolve ATT&CK technique ids ("T1566", "T1059.001") → {id, name} (best-effort; degrades to id only). */
export function resolveCapabilities(attackTags: string): { id: string; name: string }[] {
  const ids = (attackTags || "").split(/[,\s;]+/).map((x) => x.trim().toUpperCase()).filter((x) => /^T\d/.test(x));
  if (!ids.length) return [];
  const xa = getDb("XATTACK");
  const out: { id: string; name: string }[] = [];
  const stmt = has(xa, "ATTACKTECHNIQUE") ? xa.prepare("SELECT AttackTechniqueName n FROM ATTACKTECHNIQUE WHERE TechniqueID = ? LIMIT 1") : null;
  for (const id of ids) {
    let name = "";
    const numMatch = id.replace(/^T/, "").match(/^\d+/);
    if (stmt && numMatch) { try { const r = stmt.get(Number(numMatch[0])) as { n?: string } | undefined; name = s(r?.n); } catch { /* tolerate */ } }
    out.push({ id, name });
  }
  return out;
}

/** Summary list of all profiled actors for the current tenant. */
export function listActors(tenant: number | null): { actors: ActorRow[]; summary: any } {
  const xt = getDb("XTHREAT");
  if (!has(xt, "THREATACTOR")) return { actors: [], summary: { total: 0 } };
  const rows = xt.prepare(
    `SELECT ThreatActorID id, ThreatActorName name, Aliases, ActorTypes, Motivation, Sophistication, ResourceLevel,
       country, TargetSectors, TargetRegions, AttackTags, MalwareTags, InfrastructureNotes,
       DiamondAdversary, DiamondCapability, DiamondInfrastructure, DiamondVictim, FirstSeen, LastSeen, Confidence, Active
     FROM THREATACTOR WHERE ${tw(tenant)} AND ThreatActorName IS NOT NULL AND ThreatActorName != ''
     ORDER BY (Active IS 0), LastSeen DESC, ThreatActorID DESC`).all(...ta(tenant)) as ActorRow[];
  const techCount = (t: string): number => (t || "").split(/[,\s;]+/).filter((x) => /^T\d/i.test(x.trim())).length;
  const actors: ActorRow[] = rows.map((r) => ({ ...r, capabilityCount: techCount(r.AttackTags), diamondComplete: diamondCompleteness(r) }));
  const summary = {
    total: actors.length,
    nationState: actors.filter((a) => /nation-state|spy/i.test(a.ActorTypes || "")).length,
    advanced: actors.filter((a) => /advanced|expert|innovator|strategic/i.test(a.Sophistication || "")).length,
    profiled: actors.filter((a) => a.diamondComplete >= 4).length,
    avgCapabilities: actors.length ? Math.round(actors.reduce((n, a) => n + a.capabilityCount, 0) / actors.length) : 0,
  };
  return { actors, summary };
}

/** How many of the 4 Diamond vertices are populated (curated text OR derived data). */
function diamondCompleteness(r: ActorRow): number {
  let n = 0;
  if (s(r.DiamondAdversary) || s(r.ThreatActorName) || s(r.Aliases)) n++;
  if (s(r.DiamondCapability) || s(r.AttackTags) || s(r.MalwareTags)) n++;
  if (s(r.DiamondInfrastructure) || s(r.InfrastructureNotes)) n++;
  if (s(r.DiamondVictim) || s(r.TargetSectors) || s(r.TargetRegions)) n++;
  return n;
}

/** Full profile + the assembled Diamond Model for one actor. */
export function actorProfile(tenant: number | null, id: number): any {
  const xt = getDb("XTHREAT");
  if (!has(xt, "THREATACTOR")) return null;
  const a = xt.prepare(`SELECT * FROM THREATACTOR WHERE ThreatActorID = ? AND ${tw(tenant)}`).get(id, ...ta(tenant)) as ActorRow | undefined;
  if (!a) return null;

  const capabilities = resolveCapabilities(s(a.AttackTags));
  const malware = s(a.MalwareTags).split(/[,;]+/).map((x) => x.trim()).filter(Boolean);
  const infra = has(xt, "THREATACTORINFRA")
    ? xt.prepare("SELECT ActorInfraID id, IocType type, IocValue value, Role role, Confidence, FirstSeen, LastSeen FROM THREATACTORINFRA WHERE ThreatActorID = ? ORDER BY ActorInfraID DESC").all(id) as any[]
    : [];
  const sectors = s(a.TargetSectors).split(/[,;]+/).map((x) => x.trim()).filter(Boolean);
  const regions = s(a.TargetRegions).split(/[,;]+/).map((x) => x.trim()).filter(Boolean);

  // incidents this actor is linked to (the realised "victim" edge)
  let incidents: any[] = [];
  try {
    if (has(xt, "THREATACTORFORINCIDENT")) {
      const xi = getDb("XINCIDENT");
      const links = xt.prepare("SELECT IncidentID FROM THREATACTORFORINCIDENT WHERE ThreatActorID = ? AND IncidentID IS NOT NULL").all(id) as { IncidentID: number }[];
      const ids = links.map((l) => l.IncidentID).filter((x) => x != null);
      if (ids.length && has(xi, "INCIDENT")) {
        const ph = ids.map(() => "?").join(",");
        incidents = xi.prepare(`SELECT IncidentID id, IncidentName name, Severity, IncidentStatus status FROM INCIDENT WHERE IncidentID IN (${ph}) LIMIT 25`).all(...ids) as any[];
      }
    }
  } catch { /* tolerate */ }

  const diamond = {
    adversary: { label: s(a.ThreatActorName), text: s(a.DiamondAdversary), aliases: s(a.Aliases), types: s(a.ActorTypes), country: s(a.country), motivation: s(a.Motivation), sophistication: s(a.Sophistication), resourceLevel: s(a.ResourceLevel) },
    capability: { text: s(a.DiamondCapability), techniques: capabilities, malware, count: capabilities.length + malware.length },
    infrastructure: { text: s(a.DiamondInfrastructure) || s(a.InfrastructureNotes), iocs: infra, count: infra.length },
    victim: { text: s(a.DiamondVictim), sectors, regions, incidents, count: sectors.length + regions.length + incidents.length },
    meta: { sociopolitical: s(a.SociopoliticalMeta), technology: s(a.TechnologyMeta), confidence: s(a.Confidence), firstSeen: s(a.FirstSeen), lastSeen: s(a.LastSeen) },
    completeness: diamondCompleteness(a),
  };
  return { actor: a, diamond };
}

/** Create or update an actor profile. Returns the actor id. */
export function upsertActor(tenant: number | null, data: any): { id: number } {
  const xt = getDb("XTHREAT");
  const now = new Date().toISOString();
  const fields: Record<string, any> = {
    ThreatActorName: s(data.name).slice(0, 200), ThreatActorDescription: s(data.description).slice(0, 6000),
    Aliases: s(data.aliases), ActorTypes: s(data.actorTypes), Motivation: s(data.motivation),
    SecondaryMotivations: s(data.secondaryMotivations), Sophistication: s(data.sophistication),
    ResourceLevel: s(data.resourceLevel), country: s(data.country), FirstSeen: s(data.firstSeen),
    LastSeen: s(data.lastSeen), AttackTags: s(data.attackTags), MalwareTags: s(data.malwareTags),
    TargetSectors: s(data.targetSectors), TargetRegions: s(data.targetRegions),
    InfrastructureNotes: s(data.infrastructureNotes), Confidence: s(data.confidence),
    Active: data.active === false || data.active === 0 ? 0 : 1, UpdatedDate: now,
  };
  const id = Number(data.id) || 0;
  if (id > 0) {
    const sets = Object.keys(fields).map((k) => `${k} = ?`).join(", ");
    xt.prepare(`UPDATE THREATACTOR SET ${sets} WHERE ThreatActorID = ? AND ${tw(tenant)}`).run(...Object.values(fields), id, ...ta(tenant));
    return { id };
  }
  const nid = Number((xt.prepare("SELECT COALESCE(MAX(ThreatActorID),0)+1 n FROM THREATACTOR").get() as { n: number }).n);
  const keys = ["ThreatActorID", "ThreatActorGUID", "CreatedDate", "TenantID", ...Object.keys(fields)];
  const vals = [nid, (globalThis as any).crypto?.randomUUID?.() ?? String(nid), now, tenant, ...Object.values(fields)];
  xt.prepare(`INSERT INTO THREATACTOR (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...vals);
  return { id: nid };
}

/** Set the four Diamond Model vertices + the two meta-feature axes (curated narrative). */
export function setDiamond(tenant: number | null, id: number, d: any): { ok: boolean } {
  const xt = getDb("XTHREAT");
  const r = xt.prepare(
    `UPDATE THREATACTOR SET DiamondAdversary = ?, DiamondCapability = ?, DiamondInfrastructure = ?, DiamondVictim = ?,
       SociopoliticalMeta = ?, TechnologyMeta = ?, UpdatedDate = ? WHERE ThreatActorID = ? AND ${tw(tenant)}`)
    .run(s(d.adversary), s(d.capability), s(d.infrastructure), s(d.victim), s(d.sociopolitical), s(d.technology), new Date().toISOString(), id, ...ta(tenant));
  return { ok: r.changes > 0 };
}

/** Add a curated infrastructure IOC to the Diamond "Infrastructure" vertex. */
export function addInfra(tenant: number | null, actorId: number, ioc: any): { id: number } {
  const xt = getDb("XTHREAT");
  const nid = Number((xt.prepare("SELECT COALESCE(MAX(ActorInfraID),0)+1 n FROM THREATACTORINFRA").get() as { n: number }).n);
  xt.prepare(`INSERT INTO THREATACTORINFRA (ActorInfraID, ThreatActorID, IocType, IocValue, Role, FirstSeen, LastSeen, Confidence, Source, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(nid, actorId, s(ioc.type).slice(0, 40), s(ioc.value).slice(0, 400), s(ioc.role).slice(0, 60),
    s(ioc.firstSeen), s(ioc.lastSeen), s(ioc.confidence).slice(0, 20), s(ioc.source).slice(0, 120), new Date().toISOString(), tenant);
  return { id: nid };
}

export function removeInfra(tenant: number | null, infraId: number): { ok: boolean } {
  const xt = getDb("XTHREAT");
  const r = xt.prepare(`DELETE FROM THREATACTORINFRA WHERE ActorInfraID = ? AND ${tw(tenant)}`).run(infraId, ...ta(tenant));
  return { ok: r.changes > 0 };
}

export function deleteActor(tenant: number | null, id: number): { ok: boolean } {
  const xt = getDb("XTHREAT");
  const r = xt.prepare(`UPDATE THREATACTOR SET Active = 0, UpdatedDate = ? WHERE ThreatActorID = ? AND ${tw(tenant)}`).run(new Date().toISOString(), id, ...ta(tenant));
  return { ok: r.changes > 0 };
}

/** Seed one fully-profiled demo actor (idempotent by name+tenant) to showcase the Diamond Model. */
export function seedDemo(tenant: number): { created: number } {
  const xt = getDb("XTHREAT");
  if (!has(xt, "THREATACTOR")) return { created: 0 };
  const name = "DEMO — Tempest Kitten (APT-DEMO)";
  const exists = xt.prepare("SELECT ThreatActorID id FROM THREATACTOR WHERE ThreatActorName = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(name, tenant) as { id: number } | undefined;
  if (exists) return { created: 0 };
  const { id } = upsertActor(tenant, {
    name, description: "Demonstration state-aligned espionage actor used to showcase XORCISM threat-actor profiling and the Diamond Model.",
    aliases: "APT-DEMO, Tempest Kitten, TG-4242", actorTypes: "nation-state, spy", motivation: "espionage",
    secondaryMotivations: "organizational-gain", sophistication: "advanced", resourceLevel: "government",
    country: "—", firstSeen: "2021-03-01", lastSeen: new Date().toISOString().slice(0, 10),
    attackTags: "T1566, T1190, T1059, T1071, T1041, T1486", malwareTags: "DemoRAT, ShadowLoader, GhostTunnel",
    targetSectors: "Government, Defense, Energy, Telecommunications", targetRegions: "EMEA, APAC",
    infrastructureNotes: "Rotating VPS C2 + compromised edge devices; fast-flux domains.", confidence: "Medium",
  });
  setDiamond(tenant, id, {
    adversary: "State-aligned espionage group; persistent, well-resourced; operates in business hours of a single time zone.",
    capability: "Spear-phishing (T1566) for access, exploits internet-facing apps (T1190); living-off-the-land (T1059, T1071); custom RAT + loader; data exfil (T1041) and occasional destructive wiper (T1486).",
    infrastructure: "Tiered C2: throwaway VPS front nodes → bastion → operator. Fast-flux domains, compromised SOHO/edge routers as redirectors.",
    victim: "Government, defense industrial base, energy and telecom operators across EMEA & APAC; targets engineers and admins.",
    sociopolitical: "Adversary↔Victim: strategic intelligence collection aligned to state interests; long-dwell, low-noise.",
    technology: "Capability↔Infrastructure: modular RAT keyed to per-victim C2; TLS-blended beaconing over rotating domains.",
  });
  const infras = [
    { type: "domain", value: "cdn-sync-update[.]net", role: "C2 front", confidence: "High" },
    { type: "ipv4-addr", value: "203.0.113[.]66", role: "bastion", confidence: "Medium" },
    { type: "domain", value: "mail-gov-portal[.]org", role: "phishing", confidence: "High" },
    { type: "sha256", value: "e3b0c44298fc1c149afbf4c8996fb924…", role: "DemoRAT payload", confidence: "Medium" },
  ];
  for (const i of infras) addInfra(tenant, id, i);
  return { created: 1 };
}
