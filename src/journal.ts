/**
 * Canonical event journal (spec §1).
 *
 * The authoritative representation is the accepted sequence of immutable
 * signed event bodies. Clients submit commands; only the broker assigns
 * sequence, time samples, causes, and writer epoch. One SQLite transaction
 * allocates consecutive stream positions, writes the signed event, and
 * updates projections — a failed transaction consumes neither a sequence
 * nor an idempotency key.
 */

import { WorldError } from "./errors.js";
import { jcsBytes, jcsString, parseEventProfile, type JsonValue, type JsonObject } from "./canon.js";
import { eventHashHex, eventSigningMessage, signDetached, verifyDetached, b64uEncode, b64uDecodeExact, sealAead, openAead, sha256Hex, publicKeyFromRaw } from "./crypto.js";
import { GENESIS_PREV, assertId, assertHash64, decNext, isDecimal } from "./ids.js";
import type { Store } from "./store.js";
import type { KeyService } from "./keys.js";
import type { TickSource } from "./clock.js";
import { SchemaRegistry } from "./registry.js";
import { applyEventSql } from "./reducer.js";

export interface CauseRef extends JsonObject {
  claim: string;
  branch: string;
  seq: string;
  hash: string;
}

export interface EventBody extends JsonObject {
  v: number;
  world: string;
  claim: string;
  branch: string;
  seq: string;
  prev: string;
  kind: string;
  schema: number;
  actor: string;
  command: string;
  causes: CauseRef[];
  lamport: string;
  tick_ms: string;
  writer_epoch: string;
  policy: string;
  payload: JsonValue;
}

export interface Envelope {
  body: EventBody;
  hash: string;
  key_id: string;
  signature: string;
}

export interface StreamHead {
  claim: string;
  branch: string;
  headSeq: string;
  headHash: string;
  stateRev: string;
  authRev: string;
  lamport: string;
  status: string;
}

const BODY_FIELDS = new Set([
  "v", "world", "claim", "branch", "seq", "prev", "kind", "schema", "actor",
  "command", "causes", "lamport", "tick_ms", "writer_epoch", "policy", "payload",
]);

export class Journal {
  constructor(
    readonly store: Store,
    private readonly keys: KeyService,
    private readonly clock: TickSource,
    readonly world: string,
    readonly registry: SchemaRegistry = new SchemaRegistry(),
  ) {}

  // ---- stream management ----

  createStream(claim: string, branch: string): void {
    assertId(claim, "claim");
    assertId(branch, "branch");
    this.store.run(
      "INSERT INTO streams(claim,branch,head_seq,head_hash,state_rev,auth_rev,lamport,status) VALUES(?,?,?,?,?,?,?,'OPEN')",
      claim, branch, "0", GENESIS_PREV, "0", "0", "0",
    );
  }

  head(claim: string, branch: string): StreamHead | undefined {
    const r = this.store.get<{ claim: string; branch: string; head_seq: string; head_hash: string; state_rev: string; auth_rev: string; lamport: string; status: string }>(
      "SELECT claim,branch,head_seq,head_hash,state_rev,auth_rev,lamport,status FROM streams WHERE claim=? AND branch=?",
      claim, branch,
    );
    if (!r) return undefined;
    return { claim: r.claim, branch: r.branch, headSeq: r.head_seq, headHash: r.head_hash, stateRev: r.state_rev, authRev: r.auth_rev, lamport: r.lamport, status: r.status };
  }

  bumpAuthRev(claim: string, branch: string): void {
    const h = this.head(claim, branch);
    if (!h) throw new WorldError("NOT_FOUND", `No stream ${claim}/${branch}.`);
    this.store.run("UPDATE streams SET auth_rev=? WHERE claim=? AND branch=?", decNext(h.authRev), claim, branch);
  }

  bumpStateRev(claim: string, branch: string, to?: string): void {
    const h = this.head(claim, branch);
    if (!h) throw new WorldError("NOT_FOUND", `No stream ${claim}/${branch}.`);
    this.store.run("UPDATE streams SET state_rev=? WHERE claim=? AND branch=?", to ?? decNext(h.stateRev), claim, branch);
  }

  // ---- crypto ----

  private dataKeyFor(claim: string): Buffer {
    return claim === "_control" ? this.keys.controlDataKey() : this.keys.claimDataKey(claim);
  }

  private aad(claim: string, branch: string, seq: string): Buffer {
    return Buffer.from(`${this.world}/${claim}/${branch}/${seq}/1`, "utf8");
  }

  signBody(body: EventBody, writerEpoch: string): { hash: string; keyId: string; signature: string } {
    const wk = this.keys.writerKey(this.writerKeyId(writerEpoch), writerEpoch);
    const hash = eventHashHex(body);
    const signature = b64uEncode(signDetached(wk.priv, eventSigningMessage(hash)));
    return { hash, keyId: wk.keyId, signature };
  }

  /** The key authorized to sign in an epoch: read from the control stream's writer timeline. */
  writerKeyId(epoch: string): string {
    const r = this.store.get<{ key_id: string }>("SELECT key_id FROM writer_keys WHERE epoch=? AND status='ACTIVE'", epoch);
    if (r) return r.key_id;
    const any = this.store.get<{ key_id: string }>("SELECT key_id FROM writer_keys WHERE epoch=?", epoch);
    if (any) return any.key_id;
    throw new WorldError("ENFORCER_UNAVAILABLE", `No writer key authorized for epoch ${epoch}.`);
  }

  registerWriterKey(keyId: string, epoch: string, publicKeyHex: string): void {
    this.store.run("INSERT INTO writer_keys(key_id,epoch,public_key,status) VALUES(?,?,?,'ACTIVE')", keyId, epoch, publicKeyHex);
  }

  writerPublicKey(keyId: string): Buffer {
    const r = this.store.get<{ public_key: string }>("SELECT public_key FROM writer_keys WHERE key_id=?", keyId);
    if (!r) throw new WorldError("NOT_FOUND", `Unknown writer key ${keyId}.`);
    return Buffer.from(r.public_key, "hex");
  }

  /** Public key usable for verifying an event signed under `writer_epoch`. */
  verificationKey(keyId: string, writerEpoch: string): Buffer {
    const r = this.store.get<{ public_key: string; epoch: string; retired_through_epoch: string | null }>(
      "SELECT public_key,epoch,retired_through_epoch FROM writer_keys WHERE key_id=?", keyId);
    if (!r) throw new WorldError("NOT_FOUND", `Unknown writer key ${keyId}.`);
    const keyEpoch = r.epoch;
    if (r.retired_through_epoch !== null) {
      // Retired keys verify only epochs inside their retired range.
      if (BigInt(writerEpoch) < BigInt(keyEpoch) || BigInt(writerEpoch) > BigInt(r.retired_through_epoch)) {
        throw new WorldError("CHAIN_MISMATCH", `Key ${keyId} cannot verify epoch ${writerEpoch}.`);
      }
    } else if (keyEpoch !== writerEpoch) {
      throw new WorldError("CHAIN_MISMATCH", `Key ${keyId} is authorized for epoch ${keyEpoch}, not ${writerEpoch}.`);
    }
    return Buffer.from(r.public_key, "hex");
  }

  // ---- append ----

  /**
   * Append a signed event to (claim, branch). Must run inside store.tx.
   * Causes are validated against durable cuts before commit; references to
   * future, missing, forked, or different-world cuts fail CAUSALITY_INVALID.
   */
  append(input: {
    claim: string;
    branch: string;
    kind: string;
    payload: JsonValue;
    actor: string;
    command: string;
    causes?: CauseRef[];
    tickMs?: string;
  }): Envelope {
    const h = this.head(input.claim, input.branch);
    if (!h) throw new WorldError("NOT_FOUND", `No stream ${input.claim}/${input.branch}.`);

    const seq = decNext(h.headSeq);
    const causes = this.normalizeCauses(input.causes ?? []);
    const writerEpoch = this.store.getMeta("writer_epoch") ?? "1";
    const policy = this.store.getMeta("active_policy") ?? "policy1";
    const tick = input.tickMs ?? this.clock.now().toString();

    // Lamport: 1 + max(previous_stream_lamport, causes.lamport), empty max 0.
    let lamport = BigInt(h.lamport);
    for (const c of causes) {
      const ce = this.eventAt(c.claim, c.branch, c.seq);
      const cl = BigInt(ce ? (ce.body.lamport as string) : "0");
      if (cl > lamport) lamport = cl;
    }
    lamport += 1n;

    const body: EventBody = {
      v: 1,
      world: this.world,
      claim: input.claim,
      branch: input.branch,
      seq,
      prev: h.headHash,
      kind: input.kind,
      schema: 1,
      actor: input.actor,
      command: input.command,
      causes,
      lamport: lamport.toString(),
      tick_ms: tick,
      writer_epoch: writerEpoch,
      policy,
      payload: input.payload,
    };

    this.registry.validate(input.kind, 1, input.payload);
    const { hash, keyId, signature } = this.signBody(body, writerEpoch);

    const plain = jcsBytes(body);
    const enc = sealAead(this.dataKeyFor(input.claim), plain, this.aad(input.claim, input.branch, seq));
    const commitIndex = this.store.nextCommitIndex();

    this.store.run(
      `INSERT INTO events(claim,branch,seq,hash,kind,schema,body_enc,key_id,signature,writer_epoch,commit_index,lamport,tick_ms,command)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      input.claim, input.branch, seq, hash, input.kind, 1, enc, keyId, signature, writerEpoch, commitIndex, lamport.toString(), tick, input.command,
    );
    for (const c of causes) {
      this.store.run(
        "INSERT INTO event_causes(claim,branch,seq,cause_claim,cause_branch,cause_seq,cause_hash) VALUES(?,?,?,?,?,?,?)",
        input.claim, input.branch, seq, c.claim, c.branch, c.seq, c.hash,
      );
    }
    this.store.run("UPDATE streams SET head_seq=?, head_hash=?, lamport=? WHERE claim=? AND branch=?",
      seq, hash, lamport.toString(), input.claim, input.branch);
    this.store.committedEvents++;
    return { body, hash, key_id: keyId, signature };
  }

  /**
   * Store a verbatim signed envelope (fixture/bootstrap). The body must be
   * canonical, the signature must verify against the writer timeline, and
   * seq/prev must extend the stream head — this is the same acceptance
   * path as append(), with the signature precomputed.
   */
  insertVerified(env: Envelope): Envelope {
    const body = env.body;
    for (const k of Object.keys(body)) {
      if (!BODY_FIELDS.has(k)) throw new WorldError("SCHEMA_VALIDATION", `Unknown body field ${k}.`);
    }
    const h = this.head(body.claim, body.branch);
    if (!h) throw new WorldError("NOT_FOUND", `No stream ${body.claim}/${body.branch}.`);
    const seq = decNext(h.headSeq);
    if (body.seq !== seq) throw new WorldError("SEQ_GAP", `Expected seq ${seq}, found ${body.seq}.`, { expected_seq: seq });
    if (body.prev !== h.headHash) throw new WorldError("CHAIN_MISMATCH", "Predecessor hash mismatch.");
    if (eventHashHex(body) !== env.hash) throw new WorldError("HASH_MISMATCH", "Event hash does not cover the body.");
    const pub = this.verificationKey(env.key_id, body.writer_epoch);
    const sig = b64uDecodeExact(env.signature, 64);
    if (!verifyDetached(publicKeyFromRaw(pub), eventSigningMessage(env.hash), sig)) {
      throw new WorldError("HASH_MISMATCH", "Signature verification failed.");
    }
    this.registry.validate(body.kind, body.schema, body.payload);
    const causes = this.normalizeCauses(body.causes);
    const enc = sealAead(this.dataKeyFor(body.claim), jcsBytes(body), this.aad(body.claim, body.branch, body.seq));
    this.store.run(
      `INSERT INTO events(claim,branch,seq,hash,kind,schema,body_enc,key_id,signature,writer_epoch,commit_index,lamport,tick_ms,command)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      body.claim, body.branch, body.seq, env.hash, body.kind, body.schema, enc, env.key_id, env.signature,
      body.writer_epoch, this.store.nextCommitIndex(), String(body.lamport), String(body.tick_ms), String(body.command),
    );
    for (const c of causes) {
      this.store.run(
        "INSERT INTO event_causes(claim,branch,seq,cause_claim,cause_branch,cause_seq,cause_hash) VALUES(?,?,?,?,?,?,?)",
        body.claim, body.branch, body.seq, c.claim, c.branch, c.seq, c.hash,
      );
    }
    this.store.run("UPDATE streams SET head_seq=?, head_hash=?, lamport=? WHERE claim=? AND branch=?",
      body.seq, env.hash, String(body.lamport), body.claim, body.branch);
    this.store.committedEvents++;
    applyEventSql(this.store, env);
    return env;
  }

  private normalizeCauses(causes: CauseRef[]): CauseRef[] {
    const seen = new Set<string>();
    const out: CauseRef[] = [];
    for (const c of causes) {
      assertId(c.claim, "cause claim");
      assertId(c.branch, "cause branch");
      if (!isDecimal(c.seq)) throw new WorldError("CAUSALITY_INVALID", "Cause seq must be a decimal string.");
      assertHash64(c.hash, "cause hash");
      const key = `${c.claim}/${c.branch}/${c.seq}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(c);
      }
    }
    if (out.length > 64) throw new WorldError("CAUSALITY_INVALID", "More than 64 causes.");
    // Sorted distinct references, same-world only, at already durable cuts.
    out.sort((a, b) => (a.claim + "/" + a.branch + "/" + a.seq.padStart(20, "0")).localeCompare(b.claim + "/" + b.branch + "/" + b.seq.padStart(20, "0")));
    for (const c of out) {
      const e = this.eventAt(c.claim, c.branch, c.seq);
      if (!e || e.hash !== c.hash) {
        throw new WorldError("CAUSALITY_INVALID", `Cause ${c.claim}/${c.branch}@${c.seq} is missing or forked.`);
      }
      const head = this.head(c.claim, c.branch);
      if (!head || BigInt(c.seq) > BigInt(head.headSeq)) {
        throw new WorldError("CAUSALITY_INVALID", `Cause ${c.claim}/${c.branch}@${c.seq} is not durable.`);
      }
    }
    return out;
  }

  // ---- read / decrypt ----

  eventAt(claim: string, branch: string, seq: string): Envelope | undefined {
    const r = this.store.get<{ body_enc: Uint8Array; key_id: string; signature: string; hash: string }>(
      "SELECT body_enc,key_id,signature,hash FROM events WHERE claim=? AND branch=? AND seq=?", claim, branch, seq);
    if (!r) return undefined;
    const plain = openAead(this.dataKeyFor(claim), Buffer.from(r.body_enc), this.aad(claim, branch, seq));
    const body = parseEventProfile(plain) as EventBody;
    return { body, hash: r.hash, key_id: r.key_id, signature: r.signature };
  }

  /** Exportable envelope for an event (canonical wrapper bytes). */
  envelopeJson(env: Envelope): string {
    return jcsString({ body: env.body, hash: env.hash, key_id: env.key_id, signature: env.signature });
  }

  events(claim: string, branch: string, afterSeq: string, throughSeq: string, limit = 1000): Envelope[] {
    const rows = this.store.all<{ seq: string }>(
      "SELECT seq FROM events WHERE claim=? AND branch=? AND CAST(seq AS INTEGER)>? AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER) LIMIT ?",
      claim, branch, Number(afterSeq), Number(throughSeq), limit);
    return rows.map((r) => this.eventAt(claim, branch, r.seq)!);
  }

  // ---- verification ----

  /** Verify hash construction + signature of one envelope. */
  verifyEnvelope(env: Envelope): { valid: true; scope: string; seq: string } {
    for (const k of Object.keys(env.body)) {
      if (!BODY_FIELDS.has(k)) throw new WorldError("SCHEMA_VALIDATION", `Unknown body field ${k}.`);
    }
    const computed = eventHashHex(env.body);
    if (computed !== env.hash) {
      throw new WorldError("HASH_MISMATCH", "Event hash does not cover the body.");
    }
    const pub = this.verificationKey(env.key_id, env.body.writer_epoch);
    const sig = b64uDecodeExact(env.signature, 64);
    if (!verifyDetached(publicKeyFromRaw(pub), eventSigningMessage(env.hash), sig)) {
      throw new WorldError("HASH_MISMATCH", "Signature verification failed.");
    }
    return { valid: true, scope: `${env.body.world}/${env.body.claim}/${env.body.branch}`, seq: env.body.seq };
  }

  /** Full chain verification for a stream cut. */
  verifyChain(claim: string, branch: string, throughSeq?: string): { headSeq: string; headHash: string } {
    const head = this.head(claim, branch);
    if (!head) throw new WorldError("NOT_FOUND", `No stream ${claim}/${branch}.`);
    const thru = throughSeq !== undefined && BigInt(throughSeq) < BigInt(head.headSeq) ? throughSeq : head.headSeq;
    let expectedSeq = "0";
    let prevHash = GENESIS_PREV;
    let prevLamport = 0n;
    const rows = this.store.all<{ seq: string }>(
      "SELECT seq FROM events WHERE claim=? AND branch=? AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER)", claim, branch, Number(thru));
    const pruneTombstones = this.store.all<{ id: string }>("SELECT id FROM tombstones WHERE namespace='prune' AND id LIKE ?", `${claim}/${branch}/%`);
    for (const { seq } of rows) {
      // If earlier positions were pruned under a committed tombstone, surface
      // ARCHIVE_REQUIRED rather than a bare gap.
      if (BigInt(seq) > BigInt(expectedSeq) + 1n) {
        const missing = (BigInt(expectedSeq) + 1n).toString();
        const covered = pruneTombstones.some((t) => {
          const m = /\/(\d+)-(\d+)$/.exec(t.id);
          return m && BigInt(m[1]!) <= BigInt(missing) && BigInt(m[2]!) >= BigInt(missing);
        });
        if (covered) {
          throw new WorldError("ARCHIVE_REQUIRED", `History ${missing} is archived; verified retrieval required.`);
        }
      }
      const env = this.eventAt(claim, branch, seq)!;
      expectedSeq = decNext(expectedSeq);
      if (env.body.seq !== expectedSeq) {
        throw new WorldError("SEQ_GAP", `Expected seq ${expectedSeq}, found ${env.body.seq}.`, { expected_seq: expectedSeq });
      }
      if (env.body.prev !== prevHash) {
        throw new WorldError("CHAIN_MISMATCH", "Predecessor hash mismatch.");
      }
      // causes must reference already-durable cuts and be sorted/distinct
      let lastKey = "";
      for (const c of env.body.causes) {
        const key = `${c.claim}/${c.branch}/${c.seq}`;
        if (key <= lastKey) throw new WorldError("CAUSALITY_INVALID", "Causes not sorted distinct.");
        lastKey = key;
        const ref = this.eventAt(c.claim, c.branch, c.seq);
        const sameStream = c.claim === claim && c.branch === branch;
        if (!ref || ref.hash !== c.hash || (sameStream && BigInt(c.seq) >= BigInt(env.body.seq))) {
          throw new WorldError("CAUSALITY_INVALID", `Cause ${key} is not a durable verified cut.`);
        }
      }
      this.registry.validate(env.body.kind, env.body.schema, env.body.payload);
      this.verifyEnvelope(env);
      const maxCauseL = env.body.causes.reduce((m, c) => {
        const ref = this.eventAt(c.claim, c.branch, c.seq)!;
        const l = BigInt(ref.body.lamport as string);
        return l > m ? l : m;
      }, prevLamport);
      if (BigInt(env.body.lamport as string) !== maxCauseL + 1n) {
        throw new WorldError("CHAIN_MISMATCH", "Lamport violation.");
      }
      prevHash = env.hash;
      prevLamport = BigInt(env.body.lamport as string);
    }
    return { headSeq: thru, headHash: prevHash };
  }
}

export { sha256Hex };
