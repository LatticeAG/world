/**
 * Fences (spec §3.1–3.2).
 *
 * A fence is a versioned policy object compiled to mandatory broker checks.
 * Multiple matching fences compose by intersection, explicit deny dominates
 * allow, and missing coverage denies. Checks are reported sorted by
 * (phase, fence_id, resource).
 */

import { WorldError } from "./errors.js";
import { isDecimal } from "./ids.js";
import { selectorMatches, type ResourceSelector, type ResourceKind, validateSelector } from "./capability.js";
import type { JsonObject, JsonValue } from "./canon.js";
import type { Store } from "./store.js";

export const FENCE_TYPES = [
  "claim-data", "filesystem", "network", "process", "resource",
  "secret", "governance", "temporal", "branch",
] as const;
export type FenceType = (typeof FENCE_TYPES)[number];

export interface Fence {
  id: string;
  type: FenceType;
  version: number;
  effect: "allow" | "deny";
  resources: ResourceSelector[];
  constraints?: {
    uses?: string; bytes?: string; cpu_ms?: string; memory_bytes?: string; pids?: string;
    profiles?: string[]; adapters?: string[]; peers?: string[]; schemas?: string[];
    timeout_ms?: number;
  };
}

const CONSTRAINT_KEYS = new Set(["uses", "bytes", "cpu_ms", "memory_bytes", "pids", "profiles", "adapters", "peers", "schemas", "timeout_ms"]);

/** Validate a fence record at configuration time (§3.1). */
export function validateFence(f: unknown): Fence {
  if (typeof f !== "object" || f === null || Array.isArray(f)) {
    throw new WorldError("SCHEMA_VALIDATION", "Fence must be an object.");
  }
  const r = f as JsonObject;
  for (const k of Object.keys(r)) {
    if (!["id", "type", "version", "effect", "resources", "constraints"].includes(k)) {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown fence field ${k}.`);
    }
  }
  if (typeof r["id"] !== "string" || typeof r["type"] !== "string" || !(FENCE_TYPES as readonly string[]).includes(r["type"])) {
    throw new WorldError("SCHEMA_VALIDATION", "Fence id/type invalid.");
  }
  if (typeof r["version"] !== "number" || !Number.isSafeInteger(r["version"]) || (r["version"] as number) < 1) {
    throw new WorldError("SCHEMA_VALIDATION", "Fence version must be a positive integer.");
  }
  if (r["effect"] !== "allow" && r["effect"] !== "deny") {
    throw new WorldError("SCHEMA_VALIDATION", "Fence effect must be allow or deny.");
  }
  if (!Array.isArray(r["resources"])) {
    throw new WorldError("SCHEMA_VALIDATION", "Fence resources must be an array.");
  }
  for (const s of r["resources"] as JsonValue[]) validateSelector(s);
  const c = r["constraints"] as JsonObject | undefined;
  if (c !== undefined) {
    if (typeof c !== "object" || c === null || Array.isArray(c)) {
      throw new WorldError("SCHEMA_VALIDATION", "Fence constraints must be an object.");
    }
    for (const k of Object.keys(c)) {
      if (!CONSTRAINT_KEYS.has(k)) throw new WorldError("SCHEMA_VALIDATION", `Unknown constraint key ${k}.`);
    }
    for (const k of ["uses", "bytes", "cpu_ms", "memory_bytes", "pids"]) {
      if (c[k] !== undefined && !isDecimal(c[k])) {
        throw new WorldError("SCHEMA_NUMBER_RANGE", `Constraint ${k} must be a decimal string.`);
      }
    }
    for (const k of ["profiles", "adapters", "peers", "schemas"]) {
      if (c[k] !== undefined && (!Array.isArray(c[k]) || !(c[k] as JsonValue[]).every((x) => typeof x === "string"))) {
        throw new WorldError("SCHEMA_VALIDATION", `Constraint ${k} must be a string array.`);
      }
    }
    if (c["timeout_ms"] !== undefined && (typeof c["timeout_ms"] !== "number" || !Number.isSafeInteger(c["timeout_ms"]))) {
      throw new WorldError("SCHEMA_VALIDATION", "Constraint timeout_ms must be an integer.");
    }
  }
  const fence = r as unknown as Fence;
  // §3.1 requirements on allow records.
  if (fence.effect === "allow") {
    const cj = fence.constraints ?? {};
    if (fence.type === "resource") {
      const finite = ["uses", "bytes"].some((k) => cj[k as keyof typeof cj] !== undefined)
        || ["cpu_ms", "memory_bytes", "pids"].some((k) => cj[k as keyof typeof cj] !== undefined);
      if (!finite) throw new WorldError("SCHEMA_VALIDATION", "Resource allow fence requires finite limits.");
    }
    if (fence.type === "process" && !(cj.profiles && cj.profiles.length > 0)) {
      throw new WorldError("SCHEMA_VALIDATION", "Process allow fence requires profiles.");
    }
    if (fence.type === "network" && !(cj.adapters && cj.adapters.length > 0)) {
      throw new WorldError("SCHEMA_VALIDATION", "Network allow fence requires certified adapters.");
    }
    if (fence.type === "claim-data" || fence.type === "secret") {
      const hasExport = fence.resources.some((s) => s.kind === "export" || s.kind === "import" || s.kind === "secret");
      if (hasExport && !(cj.peers && cj.schemas)) {
        if (fence.type === "claim-data" && fence.resources.some((s) => s.kind === "export" || s.kind === "import")) {
          throw new WorldError("SCHEMA_VALIDATION", "Data-export allow fence requires exact peer/schema constraints.");
        }
        if (fence.type === "secret") {
          throw new WorldError("SCHEMA_VALIDATION", "Secret allow fence requires exact peer/schema constraints.");
        }
      }
    }
  }
  return fence;
}

export function activeFences(store: Store, claim: string, types?: FenceType[]): Fence[] {
  const rows = store.all<{ id: string; version: number; fence_json: string }>(
    "SELECT id,version,fence_json FROM fences WHERE claim=? AND status='ACTIVE'", claim);
  const out: Fence[] = [];
  for (const r of rows) {
    const f = JSON.parse(r.fence_json) as Fence;
    if (!types || types.includes(f.type)) out.push(f);
  }
  return out;
}

export interface FenceCheck {
  fence: string;
  phase: string;
  resource: string;
  result: "PASS" | "DENY";
}

export interface FenceEval {
  result: "PASS" | "DENY";
  checks: FenceCheck[];
  /** First failing public code. */
  code?: "FENCE_DENIED" | "QUOTA_EXCEEDED";
  trace: string[];
}

/** Phase rank for the deterministic (phase,fence_id,resource) sort. */
const PHASE_RANK: Record<string, number> = {
  data: 10,
  network: 20,
  quota: 30,
  secret: 40,
  launch: 50,
  governance: 60,
};

function phaseFor(type: FenceType): string {
  switch (type) {
    case "claim-data": return "data";
    case "filesystem": return "data";
    case "network": return "network";
    case "resource": return "quota";
    case "secret": return "secret";
    case "process": return "launch";
    case "governance": return "governance";
    case "temporal": return "quota";
    case "branch": return "launch";
  }
}

/**
 * Ordered fence-type phases per action class — the concrete evaluation
 * order §3.2 step 5 requires. Reflects the real order the broker performs
 * the checks in.
 */
export function fencePhasesForAction(action: string): FenceType[] {
  switch (action) {
    case "kv.put": case "kv.get": return ["claim-data", "resource"];
    case "object.copy": return ["claim-data", "resource"];
    case "net.fetch": return ["network", "resource"];
    case "worker.start": case "worker.stop": return ["resource", "process"];
    case "secret.use": return ["secret", "resource"];
    case "branch.create": return ["branch", "resource"];
    default: return ["resource"];
  }
}

export interface CrossingResource {
  kind: ResourceKind;
  value: string;
  /** Bound fields used for constraint evaluation (max_cost, adapter, profile...). */
  cost?: { uses?: bigint; bytes?: bigint; cpu_ms?: bigint; memory_bytes?: bigint; pids?: bigint };
  adapter?: string;
  profile?: string;
  peer?: string;
  schema?: string;
}

/**
 * Evaluate all matching ACTIVE fences over the crossing's resources.
 * Deny dominates; every resource must be covered by an allow fence whose
 * constraints hold. Returns checks sorted by (phase, fence_id, resource).
 */
export function evalFences(store: Store, claim: string, action: string, resources: CrossingResource[]): FenceEval {
  const types = fencePhasesForAction(action);
  const fences = activeFences(store, claim, types);
  const checks: FenceCheck[] = [];
  const trace: string[] = [];

  for (const f of fences) {
    const matching = f.resources.filter((s) => resources.some((r) => selectorMatches(s, r.kind, r.value)));
    if (matching.length === 0) continue; // fence does not govern these resources
    for (const sel of matching) {
      const res = resources.find((r) => selectorMatches(sel, r.kind, r.value))!;
      const key = `${res.kind}:${res.value}`;
      if (f.effect === "deny") {
        checks.push({ fence: f.id, phase: phaseFor(f.type), resource: key, result: "DENY" });
        trace.push(`fence:${f.id}:deny`);
        return { result: "DENY", checks: sortChecks(checks), code: "FENCE_DENIED", trace };
      }
      // allow fence: check constraints
      const bad = constraintViolation(f, res);
      if (bad) {
        checks.push({ fence: f.id, phase: phaseFor(f.type), resource: key, result: "DENY" });
        trace.push(`fence:${f.id}:${bad}`);
        return { result: "DENY", checks: sortChecks(checks), code: bad === "quota" ? "QUOTA_EXCEEDED" : "FENCE_DENIED", trace };
      }
      checks.push({ fence: f.id, phase: phaseFor(f.type), resource: key, result: "PASS" });
      trace.push(`fence:${f.id}:PASS`);
    }
  }

  // Coverage: each resource of a governed kind needs at least one allow fence.
  for (const r of resources) {
    const typeForKind = types.find((t) => fences.some((f) => f.type === t && f.resources.some((s) => s.kind === r.kind)));
    if (!typeForKind) continue;
    const covered = fences.some((f) =>
      f.effect === "allow" && f.resources.some((s) => selectorMatches(s, r.kind, r.value)) &&
      !constraintViolation(f, r));
    if (!covered) {
      trace.push(`fence:<missing-coverage>:${r.kind}:${r.value}`);
      return { result: "DENY", checks: sortChecks(checks), code: "FENCE_DENIED", trace };
    }
  }
  return { result: "PASS", checks: sortChecks(checks), trace };
}

function sortChecks(checks: FenceCheck[]): FenceCheck[] {
  return checks.sort((a, b) => {
    const p = (PHASE_RANK[a.phase] ?? 99) - (PHASE_RANK[b.phase] ?? 99);
    if (p) return p;
    const f = a.fence.localeCompare(b.fence);
    if (f) return f;
    return a.resource.localeCompare(b.resource);
  });
}

/** Returns null if constraints hold, else a violation tag. */
function constraintViolation(f: Fence, r: CrossingResource): string | null {
  const c = f.constraints;
  if (!c) return null;
  if (r.cost) {
    for (const [dim, bound] of [["uses", c.uses], ["bytes", c.bytes], ["cpu_ms", c.cpu_ms], ["memory_bytes", c.memory_bytes], ["pids", c.pids]] as const) {
      const need = r.cost[dim as keyof typeof r.cost];
      if (bound !== undefined && need !== undefined && need > BigInt(bound)) return "quota";
    }
    if (c.timeout_ms !== undefined && r.cost.cpu_ms !== undefined && r.cost.cpu_ms > BigInt(c.timeout_ms)) return "quota";
  }
  if (c.adapters && r.adapter !== undefined && !c.adapters.includes(r.adapter)) return "adapter";
  if (c.profiles && r.profile !== undefined && !c.profiles.includes(r.profile)) return "profile";
  if (c.peers && r.peer !== undefined && !c.peers.includes(r.peer)) return "peer";
  if (c.schemas && r.schema !== undefined && !c.schemas.includes(r.schema)) return "schema";
  return null;
}
