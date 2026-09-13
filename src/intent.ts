/**
 * Canonical crossing intents (spec §0.2, §5.2).
 *
 * An intent names principal, source claim, destination, operation, exact
 * input, maximum resource cost, and dependency cut. This module validates
 * the closed action vocabulary and normalizes an intent to the verb and
 * resource list the authority/fence engines consume.
 */

import { WorldError } from "./errors.js";
import { isDecimal, assertId, isValidId } from "./ids.js";
import { intentDigestHex, sha256Hex } from "./crypto.js";
import { jcsBytes, type JsonObject, type JsonValue } from "./canon.js";
import { normalizeKvKey, type ResourceKind, type Verb } from "./capability.js";
import type { CrossingResource } from "./fences.js";

export const ACTIONS = ["kv.put", "kv.get", "object.copy", "net.fetch", "worker.start", "worker.stop"] as const;
export type Action = (typeof ACTIONS)[number];

export interface Intent {
  world: string;
  claim: string;
  branch: string;
  principal: string;
  cap: string;
  action: Action;
  args: JsonObject;
  max_cost: { uses: string; bytes: string; cpu_ms?: string; memory_bytes?: string; pids?: number };
  deadline_ms: string;
}

const INTENT_FIELDS = new Set(["world", "claim", "branch", "principal", "cap", "action", "args", "max_cost", "deadline_ms"]);

export function validateIntent(raw: unknown): Intent {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new WorldError("SCHEMA_VALIDATION", "Intent must be an object.");
  }
  const r = raw as JsonObject;
  for (const k of Object.keys(r)) {
    if (!INTENT_FIELDS.has(k)) throw new WorldError("SCHEMA_VALIDATION", `Unknown intent field ${k}.`);
  }
  for (const k of ["world", "claim", "branch", "principal", "cap", "action", "deadline_ms"]) {
    if (typeof r[k] !== "string") throw new WorldError("SCHEMA_VALIDATION", `Intent field ${k} must be a string.`);
  }
  if (!isValidId(r["claim"] as string) || !isValidId(r["branch"] as string)) {
    throw new WorldError("BAD_REQUEST", "Invalid claim/branch identifier.");
  }
  if (!(ACTIONS as readonly string[]).includes(r["action"] as string)) {
    throw new WorldError("SCHEMA_VALIDATION", `Unknown action ${String(r["action"])}.`);
  }
  if (typeof r["args"] !== "object" || r["args"] === null || Array.isArray(r["args"])) {
    throw new WorldError("SCHEMA_VALIDATION", "Intent args must be an object.");
  }
  const mc = r["max_cost"];
  if (typeof mc !== "object" || mc === null || Array.isArray(mc)) {
    throw new WorldError("SCHEMA_VALIDATION", "Intent max_cost must be an object.");
  }
  for (const k of Object.keys(mc as JsonObject)) {
    if (!["uses", "bytes", "cpu_ms", "memory_bytes", "pids"].includes(k)) {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown max_cost field ${k}.`);
    }
  }
  const m = mc as JsonObject;
  for (const k of ["uses", "bytes", "cpu_ms", "memory_bytes"]) {
    if (m[k] !== undefined && !isDecimal(m[k])) {
      throw new WorldError("SCHEMA_NUMBER_RANGE", `max_cost.${k} must be a decimal string.`);
    }
  }
  if (m["pids"] !== undefined && (typeof m["pids"] !== "number" || !Number.isSafeInteger(m["pids"]))) {
    throw new WorldError("SCHEMA_NUMBER_RANGE", "max_cost.pids must be a safe integer.");
  }
  if (!isDecimal(r["deadline_ms"])) {
    throw new WorldError("SCHEMA_NUMBER_RANGE", "deadline_ms must be a decimal string.");
  }
  if (m["uses"] === undefined || m["bytes"] === undefined) {
    throw new WorldError("SCHEMA_VALIDATION", "max_cost requires uses and bytes.");
  }
  const intent = r as unknown as Intent;
  validateArgs(intent);
  return intent;
}

function req(obj: JsonObject, k: string): JsonValue {
  const v = obj[k];
  if (v === undefined) throw new WorldError("SCHEMA_VALIDATION", `Missing arg ${k}.`);
  return v;
}

function reqStr(obj: JsonObject, k: string): string {
  const v = req(obj, k);
  if (typeof v !== "string") throw new WorldError("SCHEMA_VALIDATION", `Arg ${k} must be a string.`);
  return v;
}

function reqDec(obj: JsonObject, k: string): string {
  const v = reqStr(obj, k);
  if (!isDecimal(v)) throw new WorldError("SCHEMA_NUMBER_RANGE", `Arg ${k} must be a decimal string.`);
  return v;
}

/** Per-action argument validation under the closed §5.2 vocabulary. */
function validateArgs(i: Intent): void {
  const a = i.args;
  for (const k of Object.keys(a)) {
    if (!ARG_FIELDS[i.action].has(k)) {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown ${i.action} arg ${k}.`);
    }
  }
  switch (i.action) {
    case "kv.put": {
      normalizeKvKey(reqStr(a, "key"));
      req(a, "value");
      reqDec(a, "expected_rev");
      break;
    }
    case "kv.get": {
      normalizeKvKey(reqStr(a, "key"));
      break;
    }
    case "object.copy": {
      assertId(reqStr(a, "object"), "object");
      assertId(reqStr(a, "source"), "source claim");
      assertId(reqStr(a, "destination"), "destination claim");
      const cap = a["import_cap"];
      if (cap !== null && cap !== undefined && typeof cap !== "string") {
        throw new WorldError("SCHEMA_VALIDATION", "import_cap must be a string or null.");
      }
      break;
    }
    case "net.fetch": {
      assertId(reqStr(a, "adapter"), "adapter");
      const method = reqStr(a, "method");
      if (!/^[A-Z]{2,16}$/.test(method)) throw new WorldError("SCHEMA_VALIDATION", "method must be an uppercase token.");
      reqStr(a, "url");
      if (a["headers"] !== undefined && (typeof a["headers"] !== "object" || a["headers"] === null || Array.isArray(a["headers"]))) {
        throw new WorldError("SCHEMA_VALIDATION", "headers must be an object.");
      }
      reqDec(a, "max_response_bytes");
      reqDec(a, "deadline_ms");
      break;
    }
    case "worker.start": {
      assertId(reqStr(a, "module"), "module");
      reqStr(a, "profile");
      if (a["input_objects"] !== undefined && (!Array.isArray(a["input_objects"]) || !(a["input_objects"] as JsonValue[]).every((x) => typeof x === "string" && isValidId(x)))) {
        throw new WorldError("SCHEMA_VALIDATION", "input_objects must be object ids.");
      }
      reqDec(a, "cpu_ms");
      reqDec(a, "memory_bytes");
      const p = req(a, "pids");
      if (typeof p !== "number" || !Number.isSafeInteger(p) || p < 1) {
        throw new WorldError("SCHEMA_NUMBER_RANGE", "pids must be a safe positive integer.");
      }
      break;
    }
    case "worker.stop": {
      assertId(reqStr(a, "worker"), "worker");
      reqStr(a, "reason");
      break;
    }
  }
}

const ARG_FIELDS: Record<Action, Set<string>> = {
  "kv.put": new Set(["key", "value", "expected_rev"]),
  "kv.get": new Set(["key"]),
  "object.copy": new Set(["object", "source", "destination", "import_cap"]),
  "net.fetch": new Set(["adapter", "method", "url", "headers", "body_object", "max_response_bytes", "deadline_ms"]),
  "worker.start": new Set(["module", "profile", "input_objects", "cpu_ms", "memory_bytes", "pids"]),
  "worker.stop": new Set(["worker", "reason"]),
};

export function intentDigest(i: Intent): string {
  return intentDigestHex(i as unknown as JsonValue);
}

export interface NormalizedIntent {
  intent: Intent;
  digest: string;
  /** Leaf verb on the source claim. */
  verb: Verb;
  /** Source-claim resources the leaf grant must cover. */
  resources: CrossingResource[];
  /** External (dispatched) vs purely transactional. */
  external: boolean;
  /** Whether this action can only ever run on main. */
  effectful: boolean;
  cost: { uses: bigint; bytes: bigint; cpu_ms?: bigint; memory_bytes?: bigint; pids?: bigint };
}

/** Canonical byte count of a value for metered bytes (§5.2). */
export function meteredBytes(v: JsonValue): bigint {
  return BigInt(jcsBytes(v).byteLength);
}

export function normalizeIntent(raw: unknown): NormalizedIntent {
  const intent = validateIntent(raw);
  const digest = intentDigest(intent);
  const cost = {
    uses: BigInt(intent.max_cost.uses),
    bytes: BigInt(intent.max_cost.bytes),
    ...(intent.max_cost.cpu_ms !== undefined ? { cpu_ms: BigInt(intent.max_cost.cpu_ms) } : {}),
    ...(intent.max_cost.memory_bytes !== undefined ? { memory_bytes: BigInt(intent.max_cost.memory_bytes) } : {}),
    ...(intent.max_cost.pids !== undefined ? { pids: BigInt(intent.max_cost.pids) } : {}),
  };
  const a = intent.args;
  switch (intent.action) {
    case "kv.put": {
      const key = normalizeKvKey(a["key"]);
      const value = a["value"]!;
      return {
        intent, digest, verb: "state.write", external: false, effectful: true, cost,
        resources: [{ kind: "kv", value: key, cost }],
      };
    }
    case "kv.get": {
      const key = normalizeKvKey(a["key"]);
      return {
        intent, digest, verb: "state.read", external: false, effectful: false, cost,
        resources: [{ kind: "kv", value: key, cost }],
      };
    }
    case "object.copy": {
      const object = String(a["object"]);
      const dest = String(a["destination"]);
      const schema = String(a["schema"] ?? "json1");
      return {
        intent, digest, verb: "object.export", external: false, effectful: true, cost,
        resources: [
          { kind: "export", value: `${dest}/${object}/${schema}`, cost, peer: dest, schema },
          { kind: "object", value: object, cost },
        ],
      };
    }
    case "net.fetch": {
      const url = new URL(String(a["url"]));
      const port = url.port === "" ? "443" : url.port;
      const res: CrossingResource = {
        kind: "network",
        value: `${url.protocol.slice(0, -1)}/${url.hostname.toLowerCase()}/${port}/${String(a["adapter"])}`,
        cost, adapter: String(a["adapter"]),
      };
      return { intent, digest, verb: "net.fetch", external: true, effectful: true, cost, resources: [res] };
    }
    case "worker.start": {
      return {
        intent, digest, verb: "worker.start", external: true, effectful: true, cost,
        resources: [
          { kind: "worker", value: String(a["module"]), cost, profile: String(a["profile"]) },
        ],
      };
    }
    case "worker.stop": {
      return {
        intent, digest, verb: "worker.stop", external: false, effectful: true, cost,
        resources: [{ kind: "worker", value: String(a["worker"]), cost }],
      };
    }
  }
}
