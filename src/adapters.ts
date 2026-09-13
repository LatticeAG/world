/**
 * Certified adapter boundary (spec §10.3, §5.2).
 *
 * Adapters are installed from a signed local registry manifest naming
 * methods, origins, request schema, and response limits. The OSS core ships
 * the boundary plus `adapterT`, the bounded operator-owned test adapter
 * (no network authority, deterministic canned responses, GET only). Real
 * provider integrations require deployment-installed certified adapters —
 * absent ones produce ENFORCER_UNCERTIFIED, never a fake call.
 */

import { WorldError } from "./errors.js";
import { sha256Hex } from "./crypto.js";
import { jcsBytes, type JsonObject, type JsonValue } from "./canon.js";

export interface AdapterManifest {
  id: string;
  methods: string[];
  origins: string[];          // canonical https origins
  max_response_bytes: string;
  certified: boolean;
  /** "lookup" = read-only queries; "effect" = side-effecting. */
  semantics: "lookup" | "effect";
}

export interface AdapterRequest {
  request: JsonObject;
  crossing: string;
  idempotency_key: string;
  max_response_bytes: string;
}

export interface AdapterOutcome {
  kind: "success" | "failure" | "unknown";
  bytes: bigint;
  evidence?: string[];
}

export interface Adapter {
  readonly id: string;
  readonly manifest: AdapterManifest;
  readonly certified: boolean;
  dispatch(req: AdapterRequest): AdapterOutcome;
  /** Read-only reconciliation over the provider; null when unsupported. */
  reconcile?(idempotencyKey: string): AdapterOutcome | null;
}

export class AdapterRegistry {
  private readonly byId = new Map<string, Adapter>();
  /** Injected next-outcome for the test adapter (conformance failpoints). */
  injectedOutcome: AdapterOutcome | null = null;
  /** Counts adapter invocations for conformance accounting. */
  externalCalls = 0;

  register(a: Adapter): void {
    this.byId.set(a.id, a);
  }

  get(id: string): Adapter | undefined {
    return this.byId.get(id);
  }

  dispatch(id: string, req: AdapterRequest): AdapterOutcome {
    const a = this.byId.get(id);
    if (!a || !a.certified) {
      throw new WorldError("ENFORCER_UNCERTIFIED", `Adapter ${id} is not installed and certified.`);
    }
    this.externalCalls++;
    return a.dispatch(req);
  }
}

/**
 * adapterT — the bounded operator-owned test adapter (§12.1). Certified,
 * GET-only over https/adapter.test:443, 1 MiB response cap, deterministic
 * success unless an injected outcome overrides it. It performs no network
 * I/O: it returns a recorded fixture response and evidence reference.
 */
export class TestAdapter implements Adapter {
  readonly id = "adapterT";
  readonly certified = true;
  readonly manifest: AdapterManifest = {
    id: "adapterT",
    methods: ["GET"],
    origins: ["https://adapter.test:443"],
    max_response_bytes: "1048576",
    certified: true,
    semantics: "lookup",
  };
  /** Queue of outcomes for scripted tests; empty → default success. */
  outcomes: AdapterOutcome[] = [];
  nextError: WorldError | null = null;

  dispatch(req: AdapterRequest): AdapterOutcome {
    if (this.nextError) {
      const e = this.nextError;
      this.nextError = null;
      throw e;
    }
    const o = this.outcomes.shift();
    if (o) return o;
    // Definitive success with a 7-byte canned body ("ok"-class fixture).
    return { kind: "success", bytes: 7n, evidence: [`obsT:${req.crossing}`] };
  }
}
