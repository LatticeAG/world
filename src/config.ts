/**
 * Strict configuration, trust, and migration files (spec §6.7).
 *
 * No unknown keys, no interpolation, no environment overrides, no
 * unbounded limits. Paths must be absolute; trust pins world identity, an
 * external checkpoint, eligible keys, and a verification mode.
 */

import { WorldError } from "./errors.js";
import { isDecimal, isHash64 } from "./ids.js";
import type { JsonObject, JsonValue } from "./canon.js";

export interface WorldConfig {
  config_version: number;
  world: string;
  socket: string;
  storage_root: string;
  profile: string;
  policy: string;
  writer_key_handle: string;
  threshold: number;
  seats: string[];
  network_default: "deny" | "certified_adapters_only";
  limits: {
    claims: number; workers_per_claim: number; queue_per_claim: number;
    memory_bytes: string; cpu_ms: string; pids: number; event_bytes: number;
  };
  simulation: { ttl_ms: number; fuel: string; memory_bytes: string; timeout_ms: number };
  retention: { local_days: number; archive_destinations: string[]; automatic_prune: boolean };
  observability: { metrics_socket: string; include_payloads: boolean };
}

const LIMIT_KEYS = ["claims", "workers_per_claim", "queue_per_claim", "memory_bytes", "cpu_ms", "pids", "event_bytes"];
const SIM_KEYS = ["ttl_ms", "fuel", "memory_bytes", "timeout_ms"];
const RET_KEYS = ["local_days", "archive_destinations", "automatic_prune"];
const OBS_KEYS = ["metrics_socket", "include_payloads"];
const TOP_KEYS = ["config_version", "world", "socket", "storage_root", "profile", "policy", "writer_key_handle", "threshold", "seats", "network_default", "limits", "simulation", "retention", "observability"];

function noUnknown(o: JsonObject, allowed: string[], what: string): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) throw new WorldError("SCHEMA_VALIDATION", `${what} has unknown key ${k}.`);
  }
}

function req(o: JsonObject, k: string): JsonValue {
  const v = o[k];
  if (v === undefined) throw new WorldError("SCHEMA_VALIDATION", `Missing required key ${k}.`);
  return v;
}

function reqStr(o: JsonObject, k: string): string {
  const v = req(o, k);
  if (typeof v !== "string" || v.length === 0) throw new WorldError("SCHEMA_VALIDATION", `${k} must be a nonempty string.`);
  return v;
}

function reqInt(o: JsonObject, k: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const v = req(o, k);
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) {
    throw new WorldError("SCHEMA_NUMBER_RANGE", `${k} must be an integer in [${min},${max}].`);
  }
  return v;
}

function reqAbsPath(o: JsonObject, k: string): string {
  const v = reqStr(o, k);
  if (!v.startsWith("/")) throw new WorldError("SCHEMA_VALIDATION", `${k} must be an absolute path.`);
  return v;
}

/** Strictly validate world.json; throws SCHEMA_VALIDATION on any violation. */
export function parseWorldConfig(raw: unknown): WorldConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new WorldError("SCHEMA_VALIDATION", "Config must be an object.");
  }
  const c = raw as JsonObject;
  noUnknown(c, TOP_KEYS, "config");
  if (req(c, "config_version") !== 1) throw new WorldError("VERSION_UNSUPPORTED", "config_version must be 1.");
  const world = reqStr(c, "world");
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(world)) throw new WorldError("SCHEMA_VALIDATION", "Invalid world id.");
  const socket = reqAbsPath(c, "socket");
  const storageRoot = reqAbsPath(c, "storage_root");
  const profile = reqStr(c, "profile");
  if (profile !== "wasm-process-v1") {
    throw new WorldError("ENFORCER_UNCERTIFIED", `Profile ${profile} is not a certified launch profile.`);
  }
  const policy = reqStr(c, "policy");
  const keyHandle = reqStr(c, "writer_key_handle");
  const threshold = reqInt(c, "threshold", 1, 16);
  const seats = req(c, "seats");
  if (!Array.isArray(seats) || seats.length === 0 || !seats.every((s) => typeof s === "string")) {
    throw new WorldError("SCHEMA_VALIDATION", "seats must be a nonempty string array.");
  }
  if (threshold > seats.length) throw new WorldError("SCHEMA_VALIDATION", "threshold exceeds seat count.");
  const netDefault = reqStr(c, "network_default");
  if (netDefault !== "deny" && netDefault !== "certified_adapters_only") {
    throw new WorldError("SCHEMA_VALIDATION", "network_default must be deny or certified_adapters_only.");
  }
  const limits = req(c, "limits") as JsonObject;
  noUnknown(limits, LIMIT_KEYS, "limits");
  const limitsOut = {
    claims: reqInt(limits, "claims", 1, 100000),
    workers_per_claim: reqInt(limits, "workers_per_claim", 1, 1024),
    queue_per_claim: reqInt(limits, "queue_per_claim", 1, 1048576),
    memory_bytes: (() => { const v = reqStr(limits, "memory_bytes"); if (!isDecimal(v)) throw new WorldError("SCHEMA_NUMBER_RANGE", "limits.memory_bytes must be a decimal string."); return v; })(),
    cpu_ms: (() => { const v = reqStr(limits, "cpu_ms"); if (!isDecimal(v)) throw new WorldError("SCHEMA_NUMBER_RANGE", "limits.cpu_ms must be a decimal string."); return v; })(),
    pids: reqInt(limits, "pids", 1, 65536),
    event_bytes: reqInt(limits, "event_bytes", 1, 1048576),
  };
  const sim = req(c, "simulation") as JsonObject;
  noUnknown(sim, SIM_KEYS, "simulation");
  const simOut = {
    ttl_ms: reqInt(sim, "ttl_ms", 1, 3600000),
    fuel: (() => { const v = reqStr(sim, "fuel"); if (!isDecimal(v)) throw new WorldError("SCHEMA_NUMBER_RANGE", "simulation.fuel must be a decimal string."); return v; })(),
    memory_bytes: (() => { const v = reqStr(sim, "memory_bytes"); if (!isDecimal(v)) throw new WorldError("SCHEMA_NUMBER_RANGE", "simulation.memory_bytes must be a decimal string."); return v; })(),
    timeout_ms: reqInt(sim, "timeout_ms", 1, 600000),
  };
  const ret = req(c, "retention") as JsonObject;
  noUnknown(ret, RET_KEYS, "retention");
  const dests = req(ret, "archive_destinations");
  if (!Array.isArray(dests) || !dests.every((d) => typeof d === "string")) {
    throw new WorldError("SCHEMA_VALIDATION", "retention.archive_destinations must be a string array.");
  }
  const retOut = { local_days: reqInt(ret, "local_days", 0, 36500), archive_destinations: dests as string[], automatic_prune: Boolean(ret["automatic_prune"]) };
  const obs = req(c, "observability") as JsonObject;
  noUnknown(obs, OBS_KEYS, "observability");
  const obsOut = { metrics_socket: reqAbsPath(obs, "metrics_socket"), include_payloads: Boolean(obs["include_payloads"]) };
  return {
    config_version: 1, world, socket, storage_root: storageRoot, profile, policy,
    writer_key_handle: keyHandle, threshold, seats: seats as string[],
    network_default: netDefault, limits: limitsOut, simulation: simOut,
    retention: retOut, observability: obsOut,
  };
}

// ---- trust file ----

export interface TrustFile {
  trust_version: number;
  world: string;
  scope: { claim: string; branch: string };
  keys: { id: string; public_key: string; epoch: string; retired_range?: [string, string] }[];
  checkpoint: { minimum_seq: string; hash: string };
  mode: "INTEGRITY_ONLY" | "FULL_REPLAY";
}

const TRUST_KEYS = ["trust_version", "world", "scope", "keys", "checkpoint", "mode"];

export function parseTrustFile(raw: unknown): TrustFile {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new WorldError("SCHEMA_VALIDATION", "Trust file must be an object.");
  }
  const t = raw as JsonObject;
  noUnknown(t, TRUST_KEYS, "trust");
  if (req(t, "trust_version") !== 1) throw new WorldError("VERSION_UNSUPPORTED", "trust_version must be 1.");
  const world = reqStr(t, "world");
  const scope = req(t, "scope") as JsonObject;
  noUnknown(scope, ["claim", "branch"], "trust.scope");
  const keys = req(t, "keys");
  if (!Array.isArray(keys) || keys.length === 0) throw new WorldError("SCHEMA_VALIDATION", "trust.keys must be nonempty.");
  const parsedKeys = (keys as JsonValue[]).map((k) => {
    const kk = k as JsonObject;
    noUnknown(kk, ["id", "public_key", "epoch", "retired_range"], "trust.keys[]");
    const id = reqStr(kk, "id"), pub = reqStr(kk, "public_key"), epoch = reqStr(kk, "epoch");
    if (!isHash64(pub)) throw new WorldError("SCHEMA_VALIDATION", "trust key public_key must be 64 hex chars.");
    if (!isDecimal(epoch)) throw new WorldError("SCHEMA_NUMBER_RANGE", "trust key epoch must be decimal.");
    const rr = kk["retired_range"];
    let retired: [string, string] | undefined;
    if (rr !== undefined) {
      if (!Array.isArray(rr) || rr.length !== 2 || !isDecimal(rr[0]) || !isDecimal(rr[1])) {
        throw new WorldError("SCHEMA_VALIDATION", "retired_range must be [from,to] decimals.");
      }
      retired = [String(rr[0]), String(rr[1])];
    }
    return { id, public_key: pub, epoch, ...(retired ? { retired_range: retired } : {}) };
  });
  const cp = req(t, "checkpoint") as JsonObject;
  noUnknown(cp, ["minimum_seq", "hash"], "trust.checkpoint");
  if (!isDecimal(cp["minimum_seq"]) || !isHash64(cp["hash"])) {
    throw new WorldError("SCHEMA_VALIDATION", "checkpoint requires decimal minimum_seq and hash.");
  }
  const mode = reqStr(t, "mode");
  if (mode !== "INTEGRITY_ONLY" && mode !== "FULL_REPLAY") {
    throw new WorldError("SCHEMA_VALIDATION", "trust mode must be INTEGRITY_ONLY or FULL_REPLAY.");
  }
  return {
    trust_version: 1, world,
    scope: { claim: reqStr(scope, "claim"), branch: reqStr(scope, "branch") },
    keys: parsedKeys,
    checkpoint: { minimum_seq: String(cp["minimum_seq"]), hash: String(cp["hash"]) },
    mode,
  };
}

// ---- migration manifest ----

export interface MigrationManifest {
  migration_version: number;
  id: string;
  world: string;
  source_store: string;
  target_store: string;
  from_format: number;
  to_format: number;
  reader: string;
  writer: string;
  reducer: string;
  through_control_seq: string;
  retain_source: boolean;
  approval: string;
}

const MIG_KEYS = ["migration_version", "id", "world", "source_store", "target_store", "from_format", "to_format", "reader", "writer", "reducer", "through_control_seq", "retain_source", "approval"];

export function parseMigrationManifest(raw: unknown): MigrationManifest {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new WorldError("SCHEMA_VALIDATION", "Migration manifest must be an object.");
  }
  const m = raw as JsonObject;
  noUnknown(m, MIG_KEYS, "migration manifest");
  if (req(m, "migration_version") !== 1) throw new WorldError("VERSION_UNSUPPORTED", "migration_version must be 1.");
  for (const k of ["id", "world", "source_store", "target_store", "reader", "writer", "reducer", "approval"]) reqStr(m, k);
  if (typeof m["from_format"] !== "number" || typeof m["to_format"] !== "number") {
    throw new WorldError("SCHEMA_VALIDATION", "from_format/to_format must be integers.");
  }
  if (!isDecimal(m["through_control_seq"])) throw new WorldError("SCHEMA_NUMBER_RANGE", "through_control_seq must be decimal.");
  if (typeof m["retain_source"] !== "boolean") throw new WorldError("SCHEMA_VALIDATION", "retain_source must be boolean.");
  return m as unknown as MigrationManifest;
}
