/**
 * Capabilities, principals, and quota accounting (spec §2).
 *
 * Capabilities are broker-stored grants referenced by opaque IDs — not
 * bearer tokens. Grant integrity derives from the writer-signed
 * CapabilityIssued envelope. An effective grant is the intersection of the
 * grant, every ancestor, the principal binding, claim status, policy, fence
 * configuration, and remaining quotas.
 */

import { WorldError } from "./errors.js";
import { isDecimal, MAX_COUNTER } from "./ids.js";
import { jcsBytes, type JsonValue, type JsonObject } from "./canon.js";
import { openAead } from "./crypto.js";
import type { Store } from "./store.js";

export const VERBS = [
  "state.read", "state.write", "object.export", "object.import", "net.fetch",
  "secret.use", "worker.start", "worker.stop", "audit.read", "branch.create",
  "snapshot.create", "admin.manage", "cap.delegate",
] as const;
export type Verb = (typeof VERBS)[number];

export const RESOURCE_KINDS = [
  "kv", "object", "export", "import", "network", "secret", "principal",
  "worker", "audit", "branch", "snapshot", "admin",
] as const;
export type ResourceKind = (typeof RESOURCE_KINDS)[number];

export interface ResourceSelector {
  kind: ResourceKind;
  match: "exact" | "prefix";
  value: string;
}

export interface Grant {
  id: string;
  world: string;
  claim: string;
  subject: string;
  parent: string | null;
  verbs: Verb[];
  resources: ResourceSelector[];
  not_before_tick: string;
  not_after_tick: string;
  depth: number;
  delegable: boolean;
  max_uses: string;
  max_bytes: string;
  issue_epoch: string;
}

export const MAX_DELEGATION_DEPTH = 4; // launch profile

const GRANT_FIELDS = new Set([
  "id", "world", "claim", "subject", "parent", "verbs", "resources",
  "not_before_tick", "not_after_tick", "depth", "delegable", "max_uses",
  "max_bytes", "issue_epoch",
]);

/** Validate a complete grant record (§2.3). */
export function validateGrant(g: unknown): Grant {
  if (typeof g !== "object" || g === null || Array.isArray(g)) {
    throw new WorldError("SCHEMA_VALIDATION", "Grant must be an object.");
  }
  const r = g as JsonObject;
  for (const k of Object.keys(r)) {
    if (!GRANT_FIELDS.has(k)) throw new WorldError("SCHEMA_VALIDATION", `Unknown grant field ${k}.`);
  }
  for (const k of ["id", "world", "claim", "subject", "not_before_tick", "not_after_tick", "max_uses", "max_bytes", "issue_epoch"]) {
    if (typeof r[k] !== "string") throw new WorldError("SCHEMA_VALIDATION", `Grant field ${k} must be a string.`);
  }
  for (const k of ["not_before_tick", "not_after_tick", "max_uses", "max_bytes", "issue_epoch"]) {
    if (!isDecimal(r[k])) throw new WorldError("SCHEMA_NUMBER_RANGE", `Grant field ${k} must be a decimal string.`);
  }
  if (BigInt(r["max_uses"] as string) > MAX_COUNTER || BigInt(r["max_bytes"] as string) > MAX_COUNTER) {
    throw new WorldError("COUNTER_EXHAUSTED", "Grant bound exceeds 2^63-1.");
  }
  if (r["parent"] !== null && typeof r["parent"] !== "string") {
    throw new WorldError("SCHEMA_VALIDATION", "Grant parent must be a string or null.");
  }
  if (!Array.isArray(r["verbs"]) || (r["verbs"] as JsonValue[]).length === 0) {
    throw new WorldError("SCHEMA_VALIDATION", "Grant verbs must be a nonempty array.");
  }
  for (const v of r["verbs"] as JsonValue[]) {
    if (typeof v !== "string" || !(VERBS as readonly string[]).includes(v)) {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown verb ${String(v)}.`);
    }
  }
  if (!Array.isArray(r["resources"])) {
    throw new WorldError("SCHEMA_VALIDATION", "Grant resources must be an array.");
  }
  for (const sel of r["resources"] as JsonValue[]) {
    validateSelector(sel);
  }
  if (typeof r["depth"] !== "number" || !Number.isSafeInteger(r["depth"]) || (r["depth"] as number) < 0) {
    throw new WorldError("SCHEMA_VALIDATION", "Grant depth must be a safe nonnegative integer.");
  }
  if (typeof r["delegable"] !== "boolean") {
    throw new WorldError("SCHEMA_VALIDATION", "Grant delegable must be boolean.");
  }
  return r as unknown as Grant;
}

export function validateSelector(sel: unknown): ResourceSelector {
  if (typeof sel !== "object" || sel === null || Array.isArray(sel)) {
    throw new WorldError("SCHEMA_VALIDATION", "Selector must be an object.");
  }
  const s = sel as JsonObject;
  for (const k of Object.keys(s)) {
    if (k !== "kind" && k !== "match" && k !== "value") {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown selector field ${k}.`);
    }
  }
  if (typeof s["kind"] !== "string" || !(RESOURCE_KINDS as readonly string[]).includes(s["kind"])) {
    throw new WorldError("SCHEMA_VALIDATION", `Unknown resource kind ${String(s["kind"])}.`);
  }
  if (s["match"] !== "exact" && s["match"] !== "prefix") {
    throw new WorldError("SCHEMA_VALIDATION", "Selector match must be exact or prefix.");
  }
  if (typeof s["value"] !== "string" || s["value"].length === 0) {
    throw new WorldError("SCHEMA_VALIDATION", "Selector value must be a nonempty string.");
  }
  return s as unknown as ResourceSelector;
}

/**
 * Normalize a kv key per §2.6: slash-separated ASCII segments; reject
 * percent-encoding, empty/dot segments, NUL, backslash, non-ASCII.
 */
export function normalizeKvKey(key: unknown): string {
  if (typeof key !== "string" || key.length === 0) {
    throw new WorldError("BAD_REQUEST", "kv key must be a nonempty string.");
  }
  if (key.includes("%") || key.includes("\\") || key.includes("\0")) {
    throw new WorldError("BAD_REQUEST", "kv key contains a forbidden byte or encoding.");
  }
  for (let i = 0; i < key.length; i++) {
    if (key.charCodeAt(i) > 0x7f || key.charCodeAt(i) < 0x20) {
      throw new WorldError("BAD_REQUEST", "kv key must be printable ASCII.");
    }
  }
  const segs = key.split("/");
  for (const s of segs) {
    if (s === "" || s === "." || s === "..") {
      throw new WorldError("BAD_REQUEST", `kv key has an empty or dot segment: ${key}.`);
    }
  }
  return key;
}

/**
 * Prefix match (§2.3/§2.5). Hierarchical kinds (`kv`, `audit`, `export`,
 * `import`, `network`) use segment-aware rules: prefix `orders/` matches
 * `orders/7` but not `orders2/7` or `orders`. Flat-identifier kinds
 * (`branch`, `worker`, `principal`, `object`, `snapshot`) use plain
 * string-prefix matching, so `trial` covers `trial1` and `mod` covers `mod1`.
 */
const SEGMENT_KINDS = new Set<ResourceKind>(["kv", "audit", "export", "import", "network"]);
export function selectorMatches(sel: ResourceSelector, kind: ResourceKind, value: string): boolean {
  if (sel.kind !== kind) return false;
  if (sel.match === "exact") return sel.value === value;
  const v = sel.value;
  if (!SEGMENT_KINDS.has(kind)) return value.startsWith(v);
  if (v.endsWith("/")) return value.startsWith(v) && value.length > v.length;
  return value === v || value.startsWith(v + "/");
}

/** Does the grant cover verb+resource? */
export function covers(grant: Grant, verb: Verb, resource: { kind: ResourceKind; value: string }): boolean {
  if (!grant.verbs.includes(verb)) return false;
  return grant.resources.some((s) => selectorMatches(s, resource.kind, resource.value));
}

export interface GrantRow {
  capability: string;
  claim: string;
  subject: string;
  parent: string | null;
  grant: Grant;
  generation: string;
  status: string;
}

export function loadGrant(store: Store, capability: string): GrantRow | undefined {
  const r = store.get<{ capability: string; claim: string; subject: string; parent: string | null; grant_enc: Uint8Array; generation: string; status: string }>(
    "SELECT capability,claim,subject,parent,grant_enc,generation,status FROM capabilities WHERE capability=?", capability);
  if (!r) return undefined;
  const plain = openAead(store.claimKey(r.claim), Buffer.from(r.grant_enc), Buffer.from(`grant/${r.claim}/${r.capability}`));
  const grant = validateGrant(JSON.parse(plain.toString("utf8")));
  return { capability: r.capability, claim: r.claim, subject: r.subject, parent: r.parent, grant, generation: r.generation, status: r.status };
}

/** Chain from leaf to root (§2.3: every non-root grant ends at an approved root). */
export function grantChain(store: Store, capability: string): GrantRow[] {
  const chain: GrantRow[] = [];
  let cur = loadGrant(store, capability);
  const seen = new Set<string>();
  while (cur) {
    if (seen.has(cur.capability)) throw new WorldError("CAP_WIDENING", "Grant ancestry has a cycle.");
    seen.add(cur.capability);
    chain.push(cur);
    if (cur.parent === null) {
      if (chain.length === 1) break; // administratively issued root
      break;
    }
    cur = loadGrant(store, cur.parent);
    if (!cur) throw new WorldError("CAP_REVOKED", "Grant parent is missing.");
  }
  if (chain[chain.length - 1]!.parent !== null) {
    throw new WorldError("CAP_REVOKED", "Grant chain does not end at a root.");
  }
  return chain;
}

/** Eligibility: computed, not persisted (§2.5). */
export function eligibility(grant: GrantRow, tick: string, usage: { uses: string; bytes: string }, needUses: bigint, needBytes: bigint): string {
  if (grant.status !== "ISSUED") return "ancestor-revoked";
  const g = grant.grant;
  if (BigInt(tick) < BigInt(g.not_before_tick)) return "not-yet-valid";
  if (BigInt(tick) >= BigInt(g.not_after_tick)) return "expired";
  const usesLeft = BigInt(g.max_uses) - BigInt(usage.uses);
  const bytesLeft = BigInt(g.max_bytes) - BigInt(usage.bytes);
  if (usesLeft < needUses || bytesLeft < needBytes) return "exhausted";
  return "valid";
}

export function principalStatus(store: Store, principal: string): { status: string; generation: string; type: string } | undefined {
  const r = store.get<{ status: string; generation: string; type: string }>(
    "SELECT status,generation,type FROM principals WHERE principal=?", principal);
  return r;
}

/**
 * Effective authority check for (cap, principal, verb, resource) at tick.
 * Returns the ordered ancestor closure on success; throws the first public
 * failure code per the §3.2 check order.
 */
export function effectiveAuthority(
  store: Store,
  capability: string,
  principal: string,
  verb: Verb,
  resource: { kind: ResourceKind; value: string },
  tick: string,
  need: { uses: bigint; bytes: bigint } = { uses: 1n, bytes: 0n },
): GrantRow[] {
  const leaf = loadGrant(store, capability);
  if (!leaf) throw new WorldError("NOT_FOUND", "Unknown or inaccessible capability.");
  // Claim scope is part of the grant; a caller cannot select another claim.
  const chain = grantChain(store, capability);
  // Subject binding: only the leaf grant's subject must equal the caller.
  if (leaf.subject !== principal) {
    throw new WorldError("NOT_FOUND", "Capability is not bound to this principal.");
  }
  const pr = principalStatus(store, principal);
  if (!pr) throw new WorldError("UNAUTHENTICATED", `Unknown principal ${principal}.`);
  if (pr.status !== "ENABLED") throw new WorldError("CAP_REVOKED", `Principal ${principal} is disabled.`);

  for (const row of chain) {
    if (row.status !== "ISSUED") {
      throw new WorldError("CAP_REVOKED", `Grant ${row.capability} is revoked.`);
    }
    const u = usageOf(store, row.capability);
    const e = eligibility(row, tick, u, need.uses, need.bytes);
    if (e === "not-yet-valid") throw new WorldError("CAP_EXPIRED", `Grant ${row.capability} is not yet valid.`);
    if (e === "expired") throw new WorldError("CAP_EXPIRED", `Grant ${row.capability} has expired.`);
    if (e === "exhausted") throw new WorldError("QUOTA_EXCEEDED", `Grant ${row.capability} is exhausted.`);
    // Ancestor subjects (the delegators) need only remain enabled.
    if (row !== chain[0]) {
      const anc = principalStatus(store, row.subject);
      if (!anc || anc.status !== "ENABLED") {
        throw new WorldError("CAP_REVOKED", `Delegator ${row.subject} is disabled.`);
      }
    }
  }
  // Verb and resource coverage on the leaf (ancestors were attenuation-checked at delegation).
  if (!covers(leaf.grant, verb, resource)) {
    // Confirm no ancestor would have covered it either; denial is opaque.
    throw new WorldError("FENCE_DENIED", `No grant covers ${verb} on ${resource.kind}:${resource.value}.`);
  }
  return chain;
}

// ---- usage accounting (§2.4, §7.3 reservations) ----

export function usageOf(store: Store, capability: string): { uses: string; bytes: string; heldUses: string; heldBytes: string } {
  const spent = store.get<{ u: string; b: string }>(
    `SELECT COALESCE(SUM(CASE WHEN dimension='uses' THEN CAST(spent AS INTEGER) ELSE 0 END),0) AS u,
            COALESCE(SUM(CASE WHEN dimension='bytes' THEN CAST(spent AS INTEGER) ELSE 0 END),0) AS b
     FROM reservations WHERE capability=?`, capability);
  const held = store.get<{ u: string; b: string }>(
    `SELECT COALESCE(SUM(CASE WHEN dimension='uses' AND state='HELD' THEN CAST(held AS INTEGER) ELSE 0 END),0) AS u,
            COALESCE(SUM(CASE WHEN dimension='bytes' AND state='HELD' THEN CAST(held AS INTEGER) ELSE 0 END),0) AS b
     FROM reservations WHERE capability=?`, capability);
  const u = (spent?.u ?? "0").toString(), b = (spent?.b ?? "0").toString();
  const hu = (held?.u ?? "0").toString(), hb = (held?.b ?? "0").toString();
  // Total consumed from the grant's ceiling: spent + held (a held reservation is not free).
  return {
    uses: (BigInt(u) + BigInt(hu)).toString(),
    bytes: (BigInt(b) + BigInt(hb)).toString(),
    heldUses: hu,
    heldBytes: hb,
  };
}

/**
 * Reserve `need` against every grant in the ancestor chain inside the
 * current transaction. The sum of simultaneous reservations can never
 * exceed any ancestor's remaining budget (TV-W-20).
 */
export function reserveChain(
  store: Store,
  crossing: string,
  chain: GrantRow[],
  need: { uses: bigint; bytes: bigint },
): void {
  for (const row of chain) {
    for (const [dimension, amount] of [["uses", need.uses], ["bytes", need.bytes]] as const) {
      const g = row.grant;
      const cap = dimension === "uses" ? BigInt(g.max_uses) : BigInt(g.max_bytes);
      const u = usageOf(store, row.capability);
      const used = dimension === "uses" ? BigInt(u.uses) : BigInt(u.bytes);
      if (used + amount > cap) {
        throw new WorldError("QUOTA_EXCEEDED", `Grant ${row.capability} ${dimension} budget exhausted.`);
      }
      store.run(
        "INSERT INTO reservations(crossing,capability,dimension,held,spent,state) VALUES(?,?,?,?, '0','HELD')",
        crossing, row.capability, dimension, amount.toString(),
      );
    }
  }
}

/** PREPARED cancellation: release all held reservations of the crossing. */
export function releaseReservations(store: Store, crossing: string): { uses: string; bytes: string } {
  const rows = store.all<{ dimension: string; held: string }>(
    "SELECT dimension,held FROM reservations WHERE crossing=? AND state='HELD'", crossing);
  let uses = 0n, bytes = 0n;
  for (const r of rows) {
    if (r.dimension === "uses") uses += BigInt(r.held);
    if (r.dimension === "bytes") bytes += BigInt(r.held);
  }
  store.run("UPDATE reservations SET state='RELEASED',held='0' WHERE crossing=? AND state='HELD'", crossing);
  return { uses: uses.toString(), bytes: bytes.toString() };
}

/**
 * Settle a crossing's reservations at definitive completion: actual usage
 * becomes spent, the released remainder is freed. Settled actual + released
 * remainder equals the original reservation exactly (§7.3).
 */
export function settleReservations(store: Store, crossing: string, actual: { uses: bigint; bytes: bigint }): void {
  const rows = store.all<{ capability: string; dimension: string; held: string; spent: string }>(
    "SELECT capability,dimension,held,spent FROM reservations WHERE crossing=? AND state='HELD'", crossing);
  for (const r of rows) {
    const act = r.dimension === "uses" ? actual.uses : actual.bytes;
    const held = BigInt(r.held);
    if (act > held) throw new WorldError("QUOTA_EXCEEDED", "Actual usage exceeds reservation.");
    const released = held - act;
    store.run("UPDATE reservations SET state='SETTLED',spent=?,held='0' WHERE crossing=? AND capability=? AND dimension=?",
      (BigInt(r.spent) + act).toString(), crossing, r.capability, r.dimension);
    void released;
  }
}

/**
 * Dispatch moves uses to spent while bytes remain HELD until settlement or
 * reconciliation (§7.3). UNKNOWN preserves HELD bytes and never refunds the
 * consumed dispatch use.
 */
export function markDispatched(store: Store, crossing: string): void {
  const rows = store.all<{ capability: string; dimension: string; held: string; spent: string }>(
    "SELECT capability,dimension,held,spent FROM reservations WHERE crossing=? AND state='HELD'", crossing);
  for (const r of rows) {
    if (r.dimension === "uses") {
      store.run("UPDATE reservations SET spent=?,held='0' WHERE crossing=? AND capability=? AND dimension=?",
        (BigInt(r.spent) + BigInt(r.held)).toString(), crossing, r.capability, r.dimension);
    }
    // bytes stay HELD
  }
}

// ---- delegation (§2.4) ----

/**
 * Attenuation check: child verbs ⊆ parent verbs, each child selector is
 * covered by a parent selector, validity window inside the parent's, maxima
 * no larger, depth exactly parent+1 and ≤ the launch-profile maximum.
 * Returns the list of violations; empty means admissible.
 */
export function attenuationViolations(parent: Grant, child: Grant, maxDepth = MAX_DELEGATION_DEPTH): { code: "CAP_WIDENING" | "CAP_DEPTH" | "CAP_EXPIRED"; msg: string }[] {
  const out: { code: "CAP_WIDENING" | "CAP_DEPTH" | "CAP_EXPIRED"; msg: string }[] = [];
  if (child.depth !== parent.depth + 1) {
    out.push({ code: "CAP_DEPTH", msg: `Child depth ${child.depth} is not parent depth ${parent.depth}+1.` });
  }
  if (child.depth > maxDepth) {
    out.push({ code: "CAP_DEPTH", msg: `Delegation depth exceeds ${maxDepth}.` });
  }
  for (const v of child.verbs) {
    if (!parent.verbs.includes(v)) out.push({ code: "CAP_WIDENING", msg: `Child verb ${v} not in parent.` });
  }
  for (const cs of child.resources) {
    const ok = parent.resources.some((ps) => coversSelector(ps, cs));
    if (!ok) out.push({ code: "CAP_WIDENING", msg: `Child selector ${cs.kind}:${cs.value} not covered by parent.` });
  }
  if (BigInt(child.not_before_tick) < BigInt(parent.not_before_tick)) {
    out.push({ code: "CAP_EXPIRED", msg: "Child starts before parent validity." });
  }
  if (BigInt(child.not_after_tick) > BigInt(parent.not_after_tick)) {
    out.push({ code: "CAP_EXPIRED", msg: "Child expiry exceeds parent expiry." });
  }
  if (BigInt(child.max_uses) > BigInt(parent.max_uses) || BigInt(child.max_bytes) > BigInt(parent.max_bytes)) {
    out.push({ code: "CAP_WIDENING", msg: "Child maxima exceed parent maxima." });
  }
  if (child.delegable && !parent.delegable) {
    out.push({ code: "CAP_WIDENING", msg: "Child re-enables delegation forbidden by ancestor." });
  }
  return out;
}

/**
 * Does parent selector `ps` cover child selector `cs`? Exact child under an
 * exact/prefix parent; a child prefix must stay inside the parent's prefix.
 */
export function coversSelector(ps: ResourceSelector, cs: ResourceSelector): boolean {
  if (ps.kind !== cs.kind) return false;
  if (ps.match === "exact") return cs.match === "exact" && ps.value === cs.value;
  // parent prefix covers child:
  if (cs.match === "exact") return selectorMatches(ps, cs.kind, cs.value);
  // both prefix: child's prefix subtree must be inside parent's.
  const pv = ps.value.endsWith("/") ? ps.value : ps.value + "/";
  const cv = cs.value.endsWith("/") ? cs.value : cs.value + "/";
  return cv.startsWith(pv) || cs.value === ps.value;
}
