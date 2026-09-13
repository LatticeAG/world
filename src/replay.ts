/**
 * Replay and verification (spec §4.1–4.3, §9.2).
 *
 * Replay verifies scope, key timeline, signatures, hash links, sequence,
 * causality, and transition legality, then applies the pinned pure
 * reducer. It never invokes an effect adapter, starts a guest, resolves
 * DNS, or advances policy. Missing observation bytes yield
 * OBSERVATION_MISSING, never regenerated content.
 */

import { WorldError } from "./errors.js";
import { sha256Hex } from "./crypto.js";
import { jcsBytes, type JsonValue, type JsonObject } from "./canon.js";
import type { Store } from "./store.js";
import type { Journal, Envelope } from "./journal.js";
import { reduce, emptyProjection, stateRootOf, authRootOf, reservationRootOf, type Projection } from "./reducer.js";

export interface ReplayResult {
  verification: "FULL_REPLAY" | "INTEGRITY_ONLY" | "INCOMPLETE";
  throughSeq: string;
  stateHash: string;
  authHash: string;
  reservationHash: string;
  state: JsonValue;
  projection: Projection;
  /** Effect dispatches performed — the contract requires exactly zero. */
  effectDispatches: number;
}

/**
 * Verify the chain and reduce through `throughSeq`. Effect dispatches are
 * structurally impossible here: this function never receives an adapter.
 */
export function verifyAndReduce(store: Store, journal: Journal, claim: string, branch: string, throughSeq: string): ReplayResult {
  journal.verifyChain(claim, branch, throughSeq);
  const events: Envelope[] = [];
  const rows = store.all<{ seq: string }>(
    "SELECT seq FROM events WHERE claim=? AND branch=? AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER)",
    claim, branch, Number(throughSeq));
  for (const r of rows) events.push(journal.eventAt(claim, branch, r.seq)!);
  // Required observations must be present in the retained inventory.
  const missing: string[] = [];
  for (const e of events) {
    if (e.body.kind === "ObservationRecorded") {
      const p = e.body.payload as JsonObject;
      const obj = store.get<{ object: string }>(
        "SELECT object FROM objects WHERE claim=? AND object=? AND state IN ('COMMITTED','ARCHIVED')",
        claim, String(p["object"]));
      if (!obj) missing.push(String(p["object"]));
    }
  }
  const projection = reduce(events);
  const state = projection.state[`${claim}/${branch}`] ?? {};
  if (missing.length > 0) {
    throw new WorldError("OBSERVATION_MISSING", `Objects ${missing.join(",")} are not retained.`, { verification: "INCOMPLETE" });
  }
  return {
    verification: "FULL_REPLAY",
    throughSeq,
    stateHash: stateRootOf(projection, claim, branch),
    authHash: authRootOf(projection),
    reservationHash: reservationRootOf(projection),
    state: state as JsonValue,
    projection,
    effectDispatches: 0,
  };
}

/**
 * The §12 replay model over synthetic step lists — what a pure replay is
 * allowed to do: patch state, record observations, zero external calls.
 */
export function replayModel(events: { kind: string; key?: string; value?: JsonValue; bytes_base64url?: string }[]): { state: JsonObject; state_hash: string; external_calls: number } {
  const state: Record<string, JsonValue> = {};
  for (const e of events) {
    if (e.kind === "StatePatched") state[String(e.key)] = e.value!;
    // ObservationRecorded contributes bytes to inventory, not app state.
  }
  return { state: state as JsonObject, state_hash: sha256Hex(jcsBytes(state as JsonObject)), external_calls: 0 };
}

/**
 * Fork evidence (TV-W-49): two validly signed heads at the same sequence
 * with different hashes are LOG_EQUIVOCATION and quarantine the host.
 */
export function forkGate(store: Store, world: string, claim: string, branch: string, seq: string, candidates: { hash: string; signatureValid: boolean }[]): { evidence: string[] } {
  const distinct = new Set(candidates.map((c) => c.hash));
  const allSigned = candidates.every((c) => c.signatureValid);
  if (distinct.size > 1 && allSigned) {
    store.setMeta("host_status", "QUARANTINED");
    const env = { world, claim, branch, seq, heads: [...distinct] };
    store.run("INSERT INTO tombstones(namespace,id,data_json) VALUES('fork',?,?) ON CONFLICT(namespace,id) DO UPDATE SET data_json=excluded.data_json",
      `${claim}/${branch}/${seq}`, JSON.stringify(env));
    throw new WorldError("LOG_EQUIVOCATION", `Conflicting signed heads at ${claim}/${branch}@${seq}.`, { evidence_count: distinct.size });
  }
  return { evidence: [...distinct] };
}

/** Cut consistency: a named cut must cover every causal dependency it cites. */
export function causalCutComplete(events: Envelope[], cut: Set<string>): { ok: boolean; missing: string[] } {
  const missing: string[] = [];
  for (const e of events) {
    for (const c of e.body.causes) {
      const key = `${c.claim}/${c.branch}/${c.seq}`;
      if (!cut.has(key)) missing.push(key);
    }
  }
  return { ok: missing.length === 0, missing };
}
