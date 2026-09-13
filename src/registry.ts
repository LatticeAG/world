/**
 * Digest-pinned artifact registry (spec §1.6, §5.3, §10.3).
 *
 * Registries contain offline-installed, digest-pinned schemas and artifacts;
 * each is recorded as (name) -> {artifact_digest: H(J(bytes))} so two
 * implementations compare identical bytes. There is no runtime download.
 */

import { sha256Hex } from "./crypto.js";
import { jcsBytes, type JsonValue } from "./canon.js";
import { WorldError } from "./errors.js";

/** Registered event kinds at schema 1 (spec §1.5 + Appendix A). */
export const EVENT_KINDS_SCHEMA_1 = [
  "ClaimCreated",
  "ClaimStatusChanged",
  "PrincipalRegistered",
  "PrincipalDisabled",
  "CapabilityIssued",
  "CapabilityRevoked",
  "FenceConfigured",
  "PolicyActivated",
  "SimulationRecorded",
  "CrossingDenied",
  "CrossingPrepared",
  "CrossingDispatched",
  "CrossingCompleted",
  "CrossingFailed",
  "CrossingUnknown",
  "CrossingCancelled",
  "StatePatched",
  "ObjectImported",
  "ObservationRecorded",
  "WorkerStatusChanged",
  "BranchCreated",
  "BranchStatusChanged",
  "SnapshotCreated",
  "ArchiveCommitted",
  "PruneCommitted",
  "WriterStarted",
  "HostStatusChanged",
  "KeyRotated",
  "RecoveryAccepted",
  "MigrationStatusChanged",
  "AuditReleased",
  "ReceiptExported",
] as const;

export type EventKind = (typeof EVENT_KINDS_SCHEMA_1)[number];

export interface FieldSpec {
  type: "string" | "decimal" | "integer" | "boolean" | "object" | "array" | "hash" | "string|null" | "integer|null" | "array|null" | "hash|null" | "any";
  required: boolean;
  enum?: readonly string[];
  itemType?: FieldSpec["type"];
}

function isDecimalStr(v: unknown): boolean {
  return typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v);
}

function isHash(v: unknown): boolean {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function fieldOk(v: unknown, spec: FieldSpec): boolean {
  if (spec.type === "any") return true;
  if (v === null) return spec.type.endsWith("|null");
  const t = spec.type.replace("|null", "");
  switch (t) {
    case "string": return typeof v === "string";
    case "decimal": return isDecimalStr(v);
    case "integer": return typeof v === "number" && Number.isSafeInteger(v);
    case "boolean": return typeof v === "boolean";
    case "object": return typeof v === "object" && !Array.isArray(v);
    case "array": {
      if (!Array.isArray(v)) return false;
      if (spec.itemType) return v.every((e) => fieldOk(e, { type: spec.itemType!, required: true }));
      return true;
    }
    case "hash": return isHash(v);
    case "any": return true;
    default: return false;
  }
}

/**
 * Validate a payload object against a closed field spec: required fields
 * present and typed, unknown fields rejected (§1.2: unknown fields are
 * errors, not silently ignored).
 */
export function validatePayload(payload: unknown, fields: Record<string, FieldSpec>, kind: string): void {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new WorldError("SCHEMA_VALIDATION", `${kind} payload must be an object.`);
  }
  const p = payload as Record<string, unknown>;
  for (const k of Object.keys(p)) {
    if (!(k in fields)) {
      throw new WorldError("SCHEMA_VALIDATION", `${kind} payload has unknown field ${k}.`);
    }
  }
  for (const [k, spec] of Object.entries(fields)) {
    const v = p[k];
    if (v === undefined) {
      if (spec.required) throw new WorldError("SCHEMA_VALIDATION", `${kind} payload missing ${k}.`);
      continue;
    }
    if (!fieldOk(v, spec)) {
      throw new WorldError("SCHEMA_VALIDATION", `${kind} payload field ${k} has wrong type.`);
    }
    if (spec.enum && !(v === null) && !spec.enum.includes(v as string)) {
      throw new WorldError("SCHEMA_VALIDATION", `${kind} payload field ${k} not in closed enum.`);
    }
  }
}

const S = (type: FieldSpec["type"], required = true, extra?: Partial<FieldSpec>): FieldSpec => ({ type, required, ...extra });

/** Closed payload field specs for every registered (kind, schema=1). */
export const PAYLOAD_SPECS: Record<EventKind, Record<string, FieldSpec>> = {
  ClaimCreated: { owner: S("string"), auth_rev: S("decimal"), state_rev: S("decimal") },
  ClaimStatusChanged: { from: S("string"), to: S("string"), reason: S("string") },
  PrincipalRegistered: { principal: S("string"), type: S("string", true, { enum: ["operator", "worker", "service", "verifier"] }), uid: S("integer", false), channel: S("string", false), epoch: S("decimal") },
  PrincipalDisabled: { principal: S("string"), generation: S("decimal"), reason: S("string") },
  CapabilityIssued: { capability: S("string"), grant: S("object") },
  CapabilityRevoked: { capability: S("string"), reason: S("string"), generation: S("decimal") },
  FenceConfigured: { fence: S("object"), predecessor: S("any"), enforcer_digest: S("hash") },
  PolicyActivated: { policy: S("string"), epoch: S("decimal"), predecessor: S("any"), bundle_digest: S("hash"), enforcer_digest: S("hash"), approval: S("string") },
  SimulationRecorded: { report: S("string"), intent_digest: S("hash"), cut: S("object"), result: S("string", true, { enum: ["PASS", "DENY", "UNKNOWN"] }), checks: S("array"), engine_digest: S("hash"), expires_tick: S("decimal"), branch: S("string") },
  CrossingDenied: { crossing: S("string"), reason: S("string"), trace: S("array"), intent_digest: S("hash") },
  CrossingPrepared: { crossing: S("string"), report: S("string"), authority: S("object"), checks: S("array"), planned: S("object"), reserved: S("object") },
  CrossingDispatched: { crossing: S("string"), dispatch_epoch: S("decimal"), adapter_request_digest: S("hash"), idempotency_key: S("string"), deadline_tick: S("decimal") },
  CrossingCompleted: { crossing: S("string"), previous: S("string"), evidence: S("array"), actual: S("object"), reservation: S("string") },
  CrossingFailed: { crossing: S("string"), previous: S("string"), evidence: S("array"), actual: S("object"), reservation: S("string") },
  CrossingUnknown: { crossing: S("string"), previous: S("string"), evidence: S("array"), held: S("object") },
  CrossingCancelled: { crossing: S("string"), previous: S("string"), released: S("object") },
  StatePatched: { expected_rev: S("decimal"), patch: S("array"), new_rev: S("decimal"), crossing: S("string") },
  ObjectImported: { object: S("string"), digest: S("hash"), source: S("string"), destination: S("string"), schema: S("string"), crossing: S("string") },
  ObservationRecorded: { observation: S("string"), object: S("string"), digest: S("hash"), bytes: S("decimal") },
  WorkerStatusChanged: { worker: S("string"), from: S("string"), to: S("string"), pidfd: S("string|null"), cause: S("string") },
  BranchCreated: { branch: S("string"), parent: S("object"), reducer: S("string"), policy: S("string") },
  BranchStatusChanged: { branch: S("string"), from: S("string"), to: S("string") },
  SnapshotCreated: { snapshot: S("string"), manifest_digest: S("hash"), verification: S("string") },
  ArchiveCommitted: { snapshot: S("string"), destinations: S("array"), verified_copies: S("integer") },
  PruneCommitted: { claim: S("string"), from_seq: S("decimal"), through_seq: S("decimal"), approval: S("string") },
  WriterStarted: { key_id: S("string"), writer_epoch: S("decimal"), store: S("string") },
  HostStatusChanged: { from: S("string"), to: S("string"), reason: S("string") },
  KeyRotated: { retired: S("object"), active: S("object") },
  RecoveryAccepted: { recovery: S("string"), checkpoint: S("hash"), evidence: S("string"), target: S("string") },
  MigrationStatusChanged: { migration: S("string"), from: S("string"), to: S("string"), manifest_digest: S("hash") },
  AuditReleased: { reader: S("string"), digest: S("hash"), filter: S("string"), crossing: S("string") },
  ReceiptExported: { bundle: S("string"), digest: S("hash"), reader: S("string"), format: S("string"), crossing: S("string") },
};

export class SchemaRegistry {
  private readonly digests = new Map<string, string>();

  constructor() {
    for (const kind of EVENT_KINDS_SCHEMA_1) {
      const descriptor = { kind, schema: 1, fields: PAYLOAD_SPECS[kind] } as unknown as JsonValue;
      this.digests.set(`${kind}/1`, sha256Hex(jcsBytes(descriptor)));
    }
  }

  has(kind: string, schema: number): boolean {
    return this.digests.has(`${kind}/${schema}`);
  }

  digest(kind: string, schema: number): string {
    const d = this.digests.get(`${kind}/${schema}`);
    if (!d) throw new WorldError("UNKNOWN_EVENT_SCHEMA", `No pinned schema for ${kind} v${schema}.`);
    return d;
  }

  /** Gate: integrity transport may proceed; semantic replay stops. */
  gate(kind: string, schema: number): { integrity_transport: boolean; semantic_replay: boolean } {
    const ok = this.has(kind, schema);
    return { integrity_transport: true, semantic_replay: ok };
  }

  validate(kind: string, schema: number, payload: unknown): void {
    if (schema !== 1 || !this.has(kind, schema)) {
      throw new WorldError("UNKNOWN_EVENT_SCHEMA", `Unknown event schema ${kind} v${schema}.`);
    }
    validatePayload(payload, PAYLOAD_SPECS[kind as EventKind], kind);
  }
}
