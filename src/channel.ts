/**
 * Guest channel protocol (spec §6.8).
 *
 * A socketpair(AF_UNIX, SOCK_SEQPACKET) bound at registration to
 * {claim,principal,worker,worker_epoch,pidfd,exec_digest}. Frames are a
 * 4-byte big-endian length (1–65536) + canonical JSON. Protocol violations
 * close the channel and log CHANNEL_PROTOCOL — they never create a
 * crossing. At most one in-flight request per channel.
 */

import { WorldError } from "./errors.js";
import { parseEventProfile, jcsBytes, type JsonObject, type JsonValue } from "./canon.js";
import type { Broker, Caller } from "./broker.js";

export const MAX_FRAME = 65536;

export type FrameType = "intent" | "op" | "commit" | "cancel" | "close" | "report" | "result";
const GUEST_TYPES = new Set(["intent", "op", "commit", "cancel", "close"]);

/** Ops excluded on the channel: intent-path methods and operator-only set (§6.8). */
const CHANNEL_FORBIDDEN_OPS = new Set([
  "simulation.run", "crossing.commit", "crossing.cancel",
  "claim.create", "claim.set_status", "principal.register", "principal.disable",
  "fence.configure", "policy.apply", "retention.archive", "host.set_status", "crossing.reconcile",
]);

export interface ChannelBinding {
  channel: string;
  claim: string;
  principal: string;
  worker?: string;
  worker_epoch?: string;
  pidfd?: string;
  exec_digest?: string;
}

export function encodeFrame(msg: JsonObject): Buffer {
  const body = jcsBytes(msg);
  if (body.byteLength < 1 || body.byteLength > MAX_FRAME) {
    throw new WorldError("CHANNEL_PROTOCOL", "Frame payload exceeds 65536 bytes.");
  }
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.byteLength, 0);
  return Buffer.concat([head, body]);
}

/** Streaming frame decoder: feed bytes, get complete frames. */
export class FrameDecoder {
  private buf = Buffer.alloc(0);
  feed(chunk: Buffer): Buffer[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const out: Buffer[] = [];
    for (;;) {
      if (this.buf.byteLength < 4) break;
      const n = this.buf.readUInt32BE(0);
      if (n < 1 || n > MAX_FRAME) {
        throw new WorldError("CHANNEL_PROTOCOL", `Declared frame length ${n} exceeds the 65536 cap.`);
      }
      if (this.buf.byteLength < 4 + n) break;
      out.push(this.buf.subarray(4, 4 + n));
      this.buf = this.buf.subarray(4 + n);
    }
    return out;
  }
}

/**
 * A bound channel session. The broker identity comes from the binding, not
 * from frame fields — a frame contradicting it fails PRINCIPAL_MISMATCH
 * before payload semantics are parsed.
 */
export class ChannelSession {
  closed = false;
  /** A second request frame before the reply arrives is a protocol fault. */
  private inFlight = false;
  auditGaps = 0;

  constructor(
    private readonly broker: Broker,
    private readonly binding: ChannelBinding,
  ) {}

  /** The bound identity used as the caller for every message. */
  get caller(): Caller {
    return { principal: this.binding.principal, channel: this.binding.channel };
  }

  /**
   * Process one decoded frame body; returns the reply message or null for
   * `close`. Violations close the channel and throw — the caller logs
   * CHANNEL_PROTOCOL and increments the audit-gap counter.
   */
  handleFrame(body: Buffer): JsonObject | null {
    if (this.closed) throw new WorldError("CHANNEL_PROTOCOL", "Channel is closed.");
    // Principal liveness is rechecked before any payload semantics (TV-W-54).
    const pr = this.broker.store.get<{ status: string }>("SELECT status FROM principals WHERE principal=?", this.binding.principal);
    if (!pr || pr.status !== "ENABLED") {
      this.close();
      throw new WorldError("PRINCIPAL_MISMATCH", "Channel identity is no longer enabled.");
    }
    let msg: JsonObject;
    try {
      msg = parseEventProfile(body) as JsonObject;
    } catch (e) {
      this.close();
      this.auditGaps++;
      throw e instanceof WorldError ? e : new WorldError("CHANNEL_PROTOCOL", "Undecodable frame.");
    }
    const type = String(msg["type"]);
    if (!GUEST_TYPES.has(type)) {
      this.close();
      this.auditGaps++;
      throw new WorldError("CHANNEL_PROTOCOL", `Unknown guest frame type ${type}.`);
    }
    if (type === "close") {
      this.close();
      return null;
    }
    if (this.inFlight) {
      this.close();
      this.auditGaps++;
      throw new WorldError("CHANNEL_PROTOCOL", "A request is already in flight on this channel.");
    }
    this.inFlight = true;
    try {
      return this.dispatch(type, msg);
    } finally {
      this.inFlight = false;
    }
  }

  private dispatch(type: string, msg: JsonObject): JsonObject {
    const id = typeof msg["id"] === "string" ? (msg["id"] as string) : "";
    switch (type) {
      case "intent": {
        try {
          const intent = msg["intent"] as JsonObject;
          if (intent && (String(intent["principal"]) !== this.binding.principal || String(intent["claim"]) !== this.binding.claim)) {
            throw new WorldError("PRINCIPAL_MISMATCH", "Intent contradicts the channel binding.");
          }
          const report = this.broker.runSimulation(this.caller, intent);
          return { type: "report", id, report: report.id, result: report.result, ...(report.result === "DENY" && report.denial_code ? { code: report.denial_code } : {}), expires_tick: report.expires_tick };
        } catch (e) {
          return this.errorReply(id, e);
        }
      }
      case "commit": {
        try {
          const report = String(msg["report"]);
          const sim = this.broker.reportState(report);
          if (!sim || sim.claim !== this.binding.claim) throw new WorldError("NOT_FOUND", "Unknown report.");
          const result = this.broker.commitCrossing(
            { ...this.caller, requestId: `${this.binding.channel}:${id}` },
            this.binding.claim, report,
            msg["intent_digest"] === undefined ? undefined : String(msg["intent_digest"]));
          return { type: "result", id, ...result };
        } catch (e) {
          return this.errorReply(id, e);
        }
      }
      case "cancel": {
        try {
          const result = this.broker.cancelCrossing(
            { ...this.caller, requestId: `${this.binding.channel}:${id}` },
            this.binding.claim, String(msg["crossing"]), "guest cancel");
          return { type: "result", id, ...result };
        } catch (e) {
          return this.errorReply(id, e);
        }
      }
      case "op": {
        const op = String(msg["op"]);
        if (CHANNEL_FORBIDDEN_OPS.has(op)) {
          return { type: "result", id, error: { code: "NOT_FOUND", message: "Op is unavailable on this transport.", retryable: false } };
        }
        const params = (msg["params"] ?? {}) as JsonObject;
        if (params["claim"] !== undefined && String(params["claim"]) !== this.binding.claim) {
          return { type: "result", id, error: { code: "PRINCIPAL_MISMATCH", message: "Op claim contradicts the channel binding.", retryable: false } };
        }
        const resp = this.broker.handle(this.caller, { id: `${this.binding.channel}:${id}`, op, params });
        if (resp["ok"] === true) {
          return { type: "result", id, ...(resp["result"] as JsonObject) };
        }
        return { type: "result", id, error: resp["error"] as JsonValue };
      }
      default:
        throw new WorldError("CHANNEL_PROTOCOL", `Unknown frame type ${type}.`);
    }
  }

  private errorReply(id: string, e: unknown): JsonObject {
    const w = e instanceof WorldError ? e : new WorldError("BAD_REQUEST", String(e));
    return { type: "result", id, error: w.toErrorObject() as unknown as JsonValue };
  }

  close(): void {
    this.closed = true;
  }
}
