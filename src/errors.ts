/**
 * World error registry (spec §6.9).
 * Every public code maps to exactly one row: HTTP status, retryable flag,
 * CLI exit code, and the layer that may surface it.
 */

export type ErrorCode =
  | "INVALID_JSON_DUPLICATE"
  | "INVALID_JSON_NUMBER"
  | "SCHEMA_NUMBER_RANGE"
  | "UNKNOWN_EVENT_SCHEMA"
  | "CURSOR_INVALID"
  | "CROSS_WORLD_UNSUPPORTED"
  | "PRINCIPAL_MISMATCH"
  | "UNAUTHENTICATED"
  | "NOT_FOUND"
  | "CAP_REVOKED"
  | "CAP_EXPIRED"
  | "CAP_WIDENING"
  | "CAP_DEPTH"
  | "QUOTA_EXCEEDED"
  | "FENCE_DENIED"
  | "SSRF_DENIED"
  | "BRANCH_EFFECT_FORBIDDEN"
  | "IMPORT_AUTH_REQUIRED"
  | "AMENDMENT_REQUIRED"
  | "IDEMPOTENCY_CONFLICT"
  | "STATE_TRANSITION"
  | "ALREADY_DISPATCHED"
  | "REVISION_CONFLICT"
  | "REPORT_CONSUMED"
  | "SIMULATION_STALE"
  | "INTENT_MISMATCH"
  | "QUORUM_NOT_MET"
  | "APPROVAL_INVALID"
  | "CAUSALITY_INVALID"
  | "CAUSAL_CUT_INCOMPLETE"
  | "COUNTER_EXHAUSTED"
  | "ARCHIVE_REQUIRED"
  | "HISTORY_UNAVAILABLE"
  | "OBSERVATION_MISSING"
  | "RATE_LIMITED"
  | "STORAGE_UNAVAILABLE"
  | "ENFORCER_UNAVAILABLE"
  | "ENFORCER_UNCERTIFIED"
  | "HASH_MISMATCH"
  | "SEQ_GAP"
  | "CHAIN_MISMATCH"
  | "LOG_EQUIVOCATION"
  | "SNAPSHOT_MISMATCH"
  | "ARCHIVE_REDUNDANCY"
  | "VERSION_UNSUPPORTED"
  | "REDUCER_FAILED"
  | "CHANNEL_PROTOCOL"
  | "SIMULATION_INCOMPLETE"
  | "NOT_IMPLEMENTED"
  | "SCHEMA_VALIDATION"
  | "BAD_REQUEST";

interface RegistryRow {
  http: number | null;
  retryable: boolean;
  exit: number;
}

const REGISTRY: Record<ErrorCode, RegistryRow> = {
  INVALID_JSON_DUPLICATE: { http: 400, retryable: false, exit: 2 },
  INVALID_JSON_NUMBER: { http: 400, retryable: false, exit: 2 },
  SCHEMA_NUMBER_RANGE: { http: 400, retryable: false, exit: 2 },
  UNKNOWN_EVENT_SCHEMA: { http: 400, retryable: false, exit: 2 },
  SCHEMA_VALIDATION: { http: 400, retryable: false, exit: 2 },
  BAD_REQUEST: { http: 400, retryable: false, exit: 2 },
  CURSOR_INVALID: { http: 400, retryable: false, exit: 2 },
  CROSS_WORLD_UNSUPPORTED: { http: 400, retryable: false, exit: 2 },
  PRINCIPAL_MISMATCH: { http: 401, retryable: false, exit: 3 },
  UNAUTHENTICATED: { http: 401, retryable: false, exit: 3 },
  NOT_FOUND: { http: 404, retryable: false, exit: 3 },
  CAP_REVOKED: { http: 403, retryable: false, exit: 3 },
  CAP_EXPIRED: { http: 403, retryable: false, exit: 3 },
  CAP_WIDENING: { http: 403, retryable: false, exit: 3 },
  CAP_DEPTH: { http: 403, retryable: false, exit: 3 },
  QUOTA_EXCEEDED: { http: 403, retryable: false, exit: 3 },
  FENCE_DENIED: { http: 403, retryable: false, exit: 3 },
  SSRF_DENIED: { http: 403, retryable: false, exit: 3 },
  BRANCH_EFFECT_FORBIDDEN: { http: 403, retryable: false, exit: 3 },
  IMPORT_AUTH_REQUIRED: { http: 403, retryable: false, exit: 3 },
  AMENDMENT_REQUIRED: { http: 403, retryable: false, exit: 3 },
  NOT_IMPLEMENTED: { http: 501, retryable: false, exit: 6 },
  IDEMPOTENCY_CONFLICT: { http: 409, retryable: false, exit: 4 },
  STATE_TRANSITION: { http: 409, retryable: false, exit: 4 },
  ALREADY_DISPATCHED: { http: 409, retryable: false, exit: 4 },
  REVISION_CONFLICT: { http: 409, retryable: false, exit: 4 },
  REPORT_CONSUMED: { http: 409, retryable: false, exit: 4 },
  SIMULATION_STALE: { http: 409, retryable: false, exit: 4 },
  INTENT_MISMATCH: { http: 409, retryable: false, exit: 4 },
  QUORUM_NOT_MET: { http: 409, retryable: false, exit: 4 },
  APPROVAL_INVALID: { http: 409, retryable: false, exit: 4 },
  CAUSALITY_INVALID: { http: 409, retryable: false, exit: 4 },
  CAUSAL_CUT_INCOMPLETE: { http: 409, retryable: false, exit: 4 },
  COUNTER_EXHAUSTED: { http: 409, retryable: false, exit: 4 },
  ARCHIVE_REQUIRED: { http: 410, retryable: false, exit: 5 },
  HISTORY_UNAVAILABLE: { http: 410, retryable: false, exit: 5 },
  OBSERVATION_MISSING: { http: 410, retryable: false, exit: 5 },
  RATE_LIMITED: { http: 503, retryable: true, exit: 6 },
  STORAGE_UNAVAILABLE: { http: 503, retryable: true, exit: 6 },
  ENFORCER_UNAVAILABLE: { http: 503, retryable: true, exit: 6 },
  ENFORCER_UNCERTIFIED: { http: 503, retryable: false, exit: 6 },
  HASH_MISMATCH: { http: null, retryable: false, exit: 5 },
  SEQ_GAP: { http: null, retryable: false, exit: 5 },
  CHAIN_MISMATCH: { http: null, retryable: false, exit: 5 },
  LOG_EQUIVOCATION: { http: null, retryable: false, exit: 5 },
  SNAPSHOT_MISMATCH: { http: null, retryable: false, exit: 5 },
  ARCHIVE_REDUNDANCY: { http: null, retryable: false, exit: 5 },
  VERSION_UNSUPPORTED: { http: null, retryable: false, exit: 5 },
  REDUCER_FAILED: { http: null, retryable: false, exit: 5 },
  CHANNEL_PROTOCOL: { http: null, retryable: false, exit: 0 },
  SIMULATION_INCOMPLETE: { http: 409, retryable: true, exit: 4 },
};

export class WorldError extends Error {
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(message ?? code);
    this.name = "WorldError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }

  get http(): number | null {
    return REGISTRY[this.code].http;
  }
  get retryable(): boolean {
    return REGISTRY[this.code].retryable;
  }
  get exitCode(): number {
    return REGISTRY[this.code].exit;
  }

  toErrorObject(): { code: ErrorCode; message: string; retryable: boolean; details?: Record<string, unknown> } {
    const o: { code: ErrorCode; message: string; retryable: boolean; details?: Record<string, unknown> } = {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
    };
    if (this.details !== undefined) o.details = this.details;
    return o;
  }
}

export function registryRow(code: ErrorCode): RegistryRow {
  return REGISTRY[code];
}

/** Codes with an HTTP mapping are public; the rest are verifier/channel-internal. */
export function isPublicCode(code: ErrorCode): boolean {
  return REGISTRY[code].http !== null;
}

export function errorHttp(code: ErrorCode): number | null {
  return REGISTRY[code].http;
}

export function toWorldError(e: unknown): WorldError {
  if (e instanceof WorldError) return e;
  return new WorldError("BAD_REQUEST", e instanceof Error ? e.message : String(e));
}
