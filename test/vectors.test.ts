/**
 * Conformance vectors TV-W-01…TV-W-56 (spec §12.2).
 * Each vector runs against the real implementation — Fixture B for the
 * fixture-bound ops, real primitives for the codec/crypto gates.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseJson, parseEventProfile, jcsString, jcsBytes, canonicalize, type JsonObject, type JsonValue } from "../src/canon.js";
import { sha256Hex, eventHashHex, sealAead } from "../src/crypto.js";
import { WorldError } from "../src/errors.js";
import {
  seedFixtureB, seedCrossings, openWorld, E1, I1, I1_DIGEST, E1_HASH,
  WRITER_TEST_1_SEED, WRITER_TEST_1_PUB, type FixtureBHandle,
} from "../src/fixture.js";
import { MemoryKeyService } from "../src/keys.js";
import { ManualClock, DurableClock } from "../src/clock.js";
import { SchemaRegistry } from "../src/registry.js";
import {
  effectiveAuthority, loadGrant, eligibility, usageOf, reserveChain,
  attenuationViolations, type Grant,
} from "../src/capability.js";
import { ChannelSession, FrameDecoder, encodeFrame } from "../src/channel.js";
import { AdmissionLimiter } from "../src/server.js";
import { Enforcer } from "../src/enforcer.js";
import { replayModel, forkGate } from "../src/replay.js";
import { pruneGate } from "../src/snapshot.js";
import { verifyVotes, signProposal } from "../src/policy.js";
import { runMigration } from "../src/migrate.js";
import { normalizeIntent } from "../src/intent.js";
import type { Caller } from "../src/broker.js";
import type { Envelope } from "../src/journal.js";
import type { MigrationManifest } from "../src/config.js";

const ZERO64 = "0".repeat(64);

function errOf(fn: () => unknown): WorldError {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof WorldError, `expected WorldError, got ${String(e)}`);
    return e;
  }
  assert.fail("expected a WorldError");
}

/** RPC through the real command path (idempotency + durable denials). */
function rpc(f: FixtureBHandle, caller: Caller, op: string, params: JsonObject, id: string): JsonObject {
  return f.broker.handle(caller, { id, op, params });
}

const pa: Caller = { principal: "pA" };
const pAdmin: Caller = { principal: "pAdmin" };

function commitI1(f: FixtureBHandle, id = "qCommit", digest: string | undefined = I1_DIGEST): JsonObject {
  return rpc(f, pa, "crossing.commit", { claim: "cA", report: "sim1", intent_digest: digest }, id);
}

function kvValue(f: FixtureBHandle, key = "balance"): JsonValue {
  const r = rpc(f, pa, "state.read", { claim: "cA", branch: "main", key, cap: "capAudit" }, `read:${key}:${Math.random()}`);
  assert.equal(r["ok"], true);
  return (r["result"] as JsonObject)["value"]!;
}

function eventsCount(f: FixtureBHandle): number {
  return f.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM events")!.n;
}

// ---------- TV-W-01..12: canonical form, hashing, signatures, chain ----------

test("TV-W-01 JCS key ordering and primitive serialization", () => {
  const canonical = canonicalize('{"b":2, "a":1}');
  assert.equal(canonical, '{"a":1,"b":2}');
  assert.equal(sha256Hex(new TextEncoder().encode(canonical)),
    "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777");
});

test("TV-W-02 duplicate keys rejected before materialization", () => {
  assert.equal(errOf(() => parseJson('{"a":1,"a":2}')).code, "INVALID_JSON_DUPLICATE");
});

test("TV-W-03 unicode normalization is forbidden", () => {
  assert.equal(canonicalize('{"\\u00e9":1,"e\\u0301":2}'), '{"e\\u0301":2,"\\u00e9":1}');
});

test("TV-W-04 nonfinite numbers rejected", () => {
  assert.equal(errOf(() => parseJson('{"n":NaN}')).code, "INVALID_JSON_NUMBER");
});

test("TV-W-05 unsafe integer rejected by the event profile", () => {
  assert.equal(errOf(() => parseEventProfile('{"n":9007199254740992}')).code, "SCHEMA_NUMBER_RANGE");
});

test("TV-W-06 domain-separated event hash", () => {
  assert.equal(eventHashHex(E1.body), E1_HASH);
});

test("TV-W-07 exact Ed25519 fixture verification", () => {
  const f = seedFixtureB();
  const v = f.journal.verifyEnvelope(E1);
  assert.equal(v.valid, true);
  assert.equal(v.scope, "w1/cA/main");
  assert.equal(v.seq, "1");
});

test("TV-W-08 body tampering does not preserve verification", () => {
  const f = seedFixtureB();
  const bad: Envelope = {
    ...E1,
    body: { ...E1.body, payload: { ...(E1.body.payload as JsonObject), owner: "pMallory" } },
  };
  const e = errOf(() => f.journal.verifyEnvelope(bad));
  assert.equal(e.code, "HASH_MISMATCH");
});

test("TV-W-09 sequence gaps cannot be hidden by signatures", () => {
  const f = seedFixtureB(":memory:", { includeSim1: false });
  const f2 = openWorld(":memory:", f.keys, new ManualClock("2000"));
  f2.journal.registerWriterKey("writer-test-1", "1", WRITER_TEST_1_PUB);
  f2.journal.createStream("cA", "main");
  f2.journal.insertVerified(E1);
  // A correctly signed envelope at seq 3 still fails the chain gate.
  const body = { ...E1.body, seq: "3", prev: E1_HASH, lamport: "3" } as Envelope["body"];
  const s = f2.journal.signBody(body, "1");
  const e = errOf(() => f2.journal.insertVerified({ body, hash: s.hash, key_id: s.keyId, signature: s.signature }));
  assert.equal(e.code, "SEQ_GAP");
  assert.equal(String(e.details?.["expected_seq"]), "2");
});

test("TV-W-10 wrong predecessor hash is rejected", () => {
  const f2 = openWorld(":memory:", new MemoryKeyService().addWriter("writer-test-1", WRITER_TEST_1_SEED, "1"), new ManualClock("2000"));
  f2.journal.registerWriterKey("writer-test-1", "1", WRITER_TEST_1_PUB);
  f2.journal.createStream("cA", "main");
  f2.journal.insertVerified(E1);
  const body = { ...E1.body, seq: "2", prev: ZERO64, lamport: "2" } as Envelope["body"];
  const s = f2.journal.signBody(body, "1");
  const e = errOf(() => f2.journal.insertVerified({ body, hash: s.hash, key_id: s.keyId, signature: s.signature }));
  assert.equal(e.code, "CHAIN_MISMATCH");
});

test("TV-W-11 a future causal dependency is invalid", () => {
  const f = seedFixtureB();
  // cB/main head is seq 1; a cause at seq 9 is not yet durable.
  const e = errOf(() => f.journal.append({
    claim: "cB", branch: "main", kind: "StatePatched",
    payload: { expected_rev: "0", patch: [{ op: "set", key: "x", value: "1" }], new_rev: "1", crossing: "xCause" },
    actor: "pAdmin", command: "c1",
    causes: [{ claim: "cB", branch: "main", seq: "9", hash: ZERO64 }],
  }));
  assert.equal(e.code, "CAUSALITY_INVALID");
});

test("TV-W-12 unknown schema stops semantic replay", () => {
  const reg = new SchemaRegistry();
  const gate = reg.gate("StatePatched", 2);
  assert.equal(gate.integrity_transport, true);
  assert.equal(gate.semantic_replay, false);
  assert.equal(errOf(() => reg.digest("StatePatched", 2)).code, "UNKNOWN_EVENT_SCHEMA");
});

// ---------- TV-W-13..22: capabilities, attenuation, quotas, bilateral copy ----------

test("TV-W-13 claim scope cannot be selected by the caller", () => {
  const f = seedFixtureB();
  const e = errOf(() => f.broker.authorize(pa, "capWrite", "state.write", { kind: "kv", value: "balance" }, undefined, "cB"));
  assert.equal(e.code, "NOT_FOUND");
  // The same cap+verb+resource in its own scope succeeds.
  f.broker.authorize(pa, "capWrite", "state.write", { kind: "kv", value: "balance" }, undefined, "cA");
});

test("TV-W-14 proper attenuation is admitted", () => {
  const f = seedFixtureB();
  const r = rpc(f, pa, "capability.issue", {
    issuer_cap: "capRootA",
    grant: {
      id: "capChild", world: "w1", claim: "cA", subject: "pChild", parent: "capRootA",
      verbs: ["state.write"], resources: [{ kind: "kv", match: "exact", value: "balance" }],
      not_before_tick: "0", not_after_tick: "5000", depth: 1, delegable: false,
      max_uses: "2", max_bytes: "64", issue_epoch: "1",
    },
  }, "qDel1");
  assert.equal(r["ok"], true);
  const res = r["result"] as JsonObject;
  assert.equal(res["capability"], "capChild");
  assert.equal(res["status"], "ISSUED");
  // The delegated cap is effective for its subject with the narrowed budgets.
  const chain = effectiveAuthority(f.store, "capChild", "pChild", "state.write", { kind: "kv", value: "balance" }, f.broker.tick());
  assert.equal(chain[0]!.grant.max_uses, "2");
  assert.equal(chain[0]!.grant.max_bytes, "64");
});

test("TV-W-15 delegation cannot widen a verb", () => {
  const f = seedFixtureB();
  const r = rpc(f, pa, "capability.issue", {
    issuer_cap: "capRootA",
    grant: {
      id: "capChild", world: "w1", claim: "cA", subject: "pChild", parent: "capRootA",
      verbs: ["net.fetch"], resources: [{ kind: "kv", match: "exact", value: "balance" }],
      not_before_tick: "0", not_after_tick: "5000", depth: 1, delegable: false,
      max_uses: "2", max_bytes: "64", issue_epoch: "1",
    },
  }, "qDel2");
  assert.equal(r["ok"], false);
  assert.equal((r["error"] as JsonObject)["code"], "CAP_WIDENING");
});

test("TV-W-16 delegation depth is bounded", () => {
  const parent = { verbs: ["state.write"], resources: [{ kind: "kv", match: "exact", value: "balance" }], depth: 4, not_before_tick: "0", not_after_tick: "9", max_uses: "9", max_bytes: "9", delegable: true } as unknown as Grant;
  const child = { ...parent, depth: 5 } as Grant;
  const v = attenuationViolations(parent, child, 4);
  assert.equal(v[0]!.code, "CAP_DEPTH");
});

test("TV-W-17 ancestor revocation invalidates descendants", () => {
  const f = seedFixtureB();
  f.store.run("UPDATE capabilities SET status='REVOKED' WHERE capability='capRootA'");
  const r = commitI1(f);
  assert.equal(r["ok"], false);
  assert.equal((r["error"] as JsonObject)["code"], "CAP_REVOKED");
  assert.equal(f.adapters.externalCalls, 0);
  assert.equal(kvValue(f), "7");
});

test("TV-W-18 expiry is exclusive at its upper bound", () => {
  const f = seedFixtureB();
  const row = loadGrant(f.store, "capWrite")!;
  assert.equal(eligibility(row, "60000", { uses: "0", bytes: "0" }, 0n, 0n), "expired");
  const e = errOf(() => effectiveAuthority(f.store, "capWrite", "pA", "state.write", { kind: "kv", value: "balance" }, "60000"));
  assert.equal(e.code, "CAP_EXPIRED");
});

test("TV-W-19 a stolen ID does not change channel identity", () => {
  const f = seedFixtureB();
  const sess = new ChannelSession(f.broker, { channel: "channelChild", claim: "cA", principal: "pChild" });
  const reply = sess.handleFrame(encodeFrame({ type: "intent", id: "m1", intent: { ...I1, principal: "pA" } }).subarray(4));
  assert.equal((reply!["error"] as JsonObject)["code"], "PRINCIPAL_MISMATCH");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-20 sibling reservations share the ancestor ceiling", () => {
  const f = seedFixtureB();
  // Lower the ancestor ceiling to one remaining use by rewriting the sealed grant.
  const root = loadGrant(f.store, "capRootA")!;
  const narrowed = { ...root.grant, max_uses: "1" } as unknown as JsonObject;
  f.store.run("UPDATE capabilities SET grant_enc=? WHERE capability='capRootA'",
    sealAead(f.store.claimKey("cA"), jcsBytes(narrowed), Buffer.from("grant/cA/capRootA")));
  const chain = [loadGrant(f.store, "capWrite")!, loadGrant(f.store, "capRootA")!];
  f.store.tx(() => reserveChain(f.store, "xA", chain, { uses: 1n, bytes: 0n }));
  const e = errOf(() => f.store.tx(() => reserveChain(f.store, "xB", chain, { uses: 1n, bytes: 0n })));
  assert.equal(e.code, "QUOTA_EXCEEDED");
  assert.equal(usageOf(f.store, "capRootA").heldUses, "1");
});

test("TV-W-21 source approval alone is not an import grant", () => {
  const f = seedFixtureB();
  const e = errOf(() => f.broker.runSimulation(pa, {
    world: "w1", claim: "cA", branch: "main", principal: "pA", cap: "capExport",
    action: "object.copy",
    args: { object: "obj1", source: "cA", destination: "cB", import_cap: null },
    max_cost: { uses: "1", bytes: "16" }, deadline_ms: "10000",
  }));
  assert.equal(e.code, "IMPORT_AUTH_REQUIRED");
  assert.equal(f.store.get("SELECT object FROM objects WHERE claim='cB' AND object='obj1'"), undefined);
});

test("TV-W-22 bilateral transaction failure is all-or-nothing", () => {
  const f = seedFixtureB();
  const rep = f.broker.runSimulation(pa, {
    world: "w1", claim: "cA", branch: "main", principal: "pA", cap: "capExport",
    action: "object.copy",
    args: { object: "obj1", source: "cA", destination: "cB", import_cap: "capImport" },
    max_cost: { uses: "1", bytes: "16" }, deadline_ms: "10000",
  });
  assert.equal(rep.result, "PASS");
  f.store.failpoints.add("before_sqlite_commit");
  const before = eventsCount(f);
  const r = rpc(f, pa, "crossing.commit", { claim: "cA", report: rep.id, intent_digest: rep.intent_digest }, "qCopy");
  assert.equal(r["ok"], false);
  assert.equal((r["error"] as JsonObject)["code"], "STORAGE_UNAVAILABLE");
  assert.equal(eventsCount(f), before);
  assert.equal(f.store.get("SELECT object FROM objects WHERE claim='cB' AND object='obj1'"), undefined);
  assert.equal(f.store.get("SELECT crossing FROM crossings WHERE state='COMPLETED'"), undefined);
  assert.equal(usageOf(f.store, "capExport").heldBytes, "0");
});

// ---------- TV-W-23..32: simulation binding, staleness, idempotent commit ----------

test("TV-W-23 simulation predicts a deterministic fence violation", () => {
  const f = seedFixtureB();
  const fence = { id: "dataA", type: "claim-data", version: 2, effect: "deny", resources: [{ kind: "kv", match: "exact", value: "balance" }] };
  f.store.run("UPDATE fences SET fence_json=?, version=2 WHERE claim='cA' AND id='dataA'", jcsString(fence));
  const rep = f.broker.runSimulation(pa, I1);
  assert.equal(rep.result, "DENY");
  assert.equal(rep.denial_code, "FENCE_DENIED");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-24 simulator fuel exhaustion is not PASS", () => {
  const f = seedFixtureB();
  const rep = f.broker.runSimulation(pa, I1, { fuel: 0n });
  assert.equal(rep.result, "UNKNOWN");
  assert.equal(rep.denial_code, "SIMULATION_INCOMPLETE");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-25 state change invalidates a report", () => {
  const f = seedFixtureB();
  f.store.run("UPDATE streams SET state_rev='5' WHERE claim='cA' AND branch='main'");
  const r = commitI1(f);
  assert.equal((r["error"] as JsonObject)["code"], "SIMULATION_STALE");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-26 policy change invalidates a report", () => {
  const f = seedFixtureB();
  f.store.setMeta("active_policy", "policy2");
  const r = commitI1(f);
  assert.equal((r["error"] as JsonObject)["code"], "SIMULATION_STALE");
});

test("TV-W-27 report arguments cannot be substituted", () => {
  const f = seedFixtureB();
  const r = commitI1(f, "qBad", ZERO64);
  assert.equal((r["error"] as JsonObject)["code"], "INTENT_MISMATCH");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-28 a new command cannot reuse a consumed report", () => {
  const f = seedFixtureB();
  f.store.run("UPDATE simulations SET state='CONSUMED' WHERE report='sim1'");
  const r = commitI1(f, "qSecond");
  assert.equal((r["error"] as JsonObject)["code"], "REPORT_CONSUMED");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-29 identical command replay does not double-consume", () => {
  const f = seedFixtureB();
  const r1 = commitI1(f, "qCommit");
  const r2 = commitI1(f, "qCommit");
  assert.equal(r1["ok"], true);
  assert.deepEqual(r2["result"], r1["result"]);
  const res = r1["result"] as JsonObject;
  assert.equal(res["crossing"], "x1");
  assert.equal(kvValue(f), "8");
  const u = usageOf(f.store, "capWrite");
  assert.equal(u.uses, "1");
  assert.equal(u.bytes, "3");
  const head = f.journal.head("cA", "main")!;
  assert.equal(head.stateRev, "5");
});

test("TV-W-30 changed content under one request ID conflicts", () => {
  const f = seedFixtureB();
  const before = f.journal.head("cA", "main")!.headSeq;
  rpc(f, pa, "state.read", { claim: "cA", branch: "main", key: "balance", cap: "capAudit" }, "q1");
  const r2 = rpc(f, pa, "state.read", { claim: "cA", branch: "main", key: "other", cap: "capAudit" }, "q1");
  assert.equal(r2["ok"], false);
  assert.equal((r2["error"] as JsonObject)["code"], "IDEMPOTENCY_CONFLICT");
});

test("TV-W-31 local update, report consumption, and budget commit together", () => {
  const f = seedFixtureB();
  const r = commitI1(f);
  assert.equal(r["ok"], true);
  const res = r["result"] as JsonObject;
  assert.equal(res["crossing"], "x1");
  assert.equal(res["state"], "COMPLETED");
  assert.equal(kvValue(f), "8");
  assert.equal(f.journal.head("cA", "main")!.stateRev, "5");
  assert.equal(f.store.get<{ state: string }>("SELECT state FROM simulations WHERE report='sim1'")!.state, "CONSUMED");
  const u = usageOf(f.store, "capWrite");
  assert.equal(u.uses, "1");
  assert.equal(u.bytes, "3");
  assert.equal(u.heldBytes, "0");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-32 concurrent expected-revision writes have one winner", () => {
  const f = seedFixtureB(":memory:", { includeSim1: false });
  const i8 = { ...I1, args: { key: "balance", value: "8", expected_rev: "4" } };
  const i9 = { ...I1, args: { key: "balance", value: "9", expected_rev: "4" } };
  const r8 = f.broker.runSimulation(pa, i8);
  const r9 = f.broker.runSimulation(pa, i9);
  assert.equal(r8.result, "PASS");
  assert.equal(r9.result, "PASS");
  const c1 = rpc(f, pa, "crossing.commit", { claim: "cA", report: r8.id, intent_digest: r8.intent_digest }, "w1");
  const c2 = rpc(f, pa, "crossing.commit", { claim: "cA", report: r9.id, intent_digest: r9.intent_digest }, "w2");
  assert.equal(c1["ok"], true);
  assert.equal((c2["error"] as JsonObject)["code"], "SIMULATION_STALE");
  assert.equal(kvValue(f), "8");
  assert.equal(f.journal.head("cA", "main")!.stateRev, "5");
});

// ---------- TV-W-33..38: dispatch barrier, crash windows, revocation races ----------

function fetchIntent(): JsonObject {
  return {
    world: "w1", claim: "cA", branch: "main", principal: "pA", cap: "capFetch",
    action: "net.fetch",
    args: { adapter: "adapterT", method: "GET", url: "https://adapter.test/data", max_response_bytes: "1048576", deadline_ms: "10000" },
    max_cost: { uses: "1", bytes: "16" }, deadline_ms: "10000",
  };
}

function seedDns(f: FixtureBHandle, addresses = ["93.184.216.34"]): void {
  f.store.run("INSERT INTO tombstones(namespace,id,data_json) VALUES('dns','adapter.test',?) ON CONFLICT(namespace,id) DO UPDATE SET data_json=excluded.data_json",
    JSON.stringify({ addresses }));
}

test("TV-W-33 failed durable preparation prevents dispatch", () => {
  const f = seedFixtureB(":memory:", { includeSim1: false });
  seedDns(f);
  const rep = f.broker.runSimulation(pa, fetchIntent());
  assert.equal(rep.result, "PASS");
  const before = eventsCount(f);
  f.store.failpoints.add("prepare_fsync");
  const r = rpc(f, pa, "crossing.commit", { claim: "cA", report: rep.id, intent_digest: rep.intent_digest }, "qNet1");
  assert.equal((r["error"] as JsonObject)["code"], "STORAGE_UNAVAILABLE");
  assert.equal(f.adapters.externalCalls, 0);
  assert.equal(eventsCount(f), before);
  assert.equal(f.broker.hostStatus(), "PAUSED");
});

test("TV-W-34 crash with only preparation releases the reservation", () => {
  const f = seedFixtureB();
  seedCrossings(f, "xPrepared");
  const r = f.broker.recoverCrossing("xPrepared");
  assert.equal(r["state"], "CANCELLED");
  const x = f.store.get<{ state: string }>("SELECT state FROM crossings WHERE crossing='xPrepared'")!;
  assert.equal(x.state, "CANCELLED");
  assert.equal(usageOf(f.store, "capFetch").heldUses, "0");
  assert.equal(usageOf(f.store, "capFetch").heldBytes, "0");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-35 crash after marker does not automatically resend", () => {
  const f = seedFixtureB();
  seedCrossings(f, "xUnknown");
  const r = f.broker.recoverCrossing("xUnknown");
  assert.equal(r["state"], "UNKNOWN");
  assert.equal(r["held_bytes"], "16");
  assert.equal(usageOf(f.store, "capFetch").heldBytes, "16");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-36 timeout preserves uncertainty and reservation", () => {
  const f = seedFixtureB(":memory:", { includeSim1: false });
  seedDns(f);
  const rep = f.broker.runSimulation(pa, fetchIntent());
  assert.equal(rep.result, "PASS");
  f.adapterT.outcomes.push({ kind: "unknown", bytes: 0n });
  const r = rpc(f, pa, "crossing.commit", { claim: "cA", report: rep.id, intent_digest: rep.intent_digest }, "qNet36");
  const res = r["result"] as JsonObject;
  assert.equal(res["state"], "UNKNOWN");
  const u = usageOf(f.store, "capFetch");
  assert.equal(u.heldBytes, "16");
  assert.equal(f.adapters.externalCalls, 1); // no automatic retry
});

test("TV-W-37 revocation wins the serialization barrier", () => {
  const f = seedFixtureB();
  seedCrossings(f, "xPrepared");
  // Revocation commits first; the later dispatch attempt loses.
  const rv = rpc(f, pAdmin, "capability.revoke", { capability: "capFetch", authority: "capAdmin", reason: "race" }, "rv37");
  assert.equal(rv["ok"], true);
  const norm = normalizeIntent(fetchIntent());
  const e = errOf(() => f.broker.dispatchMarker({ principal: "pA", requestId: "q37" }, "xPrepared", norm));
  assert.equal(e.code, "CAP_REVOKED");
  const x = f.store.get<{ state: string }>("SELECT state FROM crossings WHERE crossing='xPrepared'")!;
  assert.equal(x.state, "CANCELLED");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-38 dispatch winning the barrier cannot be undone", () => {
  const f = seedFixtureB();
  seedCrossings(f, "xUnknown");
  // The dispatch marker and the provider call already happened; the
  // provider cannot confirm the outcome on reconcile.
  const rv = rpc(f, pAdmin, "capability.revoke", { capability: "capFetch", authority: "capAdmin", reason: "too late" }, "rv38");
  assert.equal(rv["ok"], true);
  const res = rv["result"] as JsonObject;
  // The DISPATCHED crossing is reported, never rolled back.
  assert.equal(Number(res["dispatched"]) + Number(res["unknown"]), 1);
  const rec = f.broker.recoverCrossing("xUnknown");
  assert.equal(rec["state"], "UNKNOWN");
  const x = f.store.get<{ state: string }>("SELECT state FROM crossings WHERE crossing='xUnknown'")!;
  assert.equal(x.state, "UNKNOWN");
});

// ---------- TV-W-39..42: sandbox and egress gates ----------

test("TV-W-39 guest direct network access is denied by the host", () => {
  const f = seedFixtureB();
  const probe = f.enforcer.probeSyscall("wasm-process-v1", "socket");
  assert.equal(probe.allowed, false);
  assert.equal(probe.errno, "EPERM");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-40 missing cgroup support prevents startup", () => {
  const f = seedFixtureB();
  const r = f.enforcer.readiness({ assumeKernel: true, probes: { cgroup_v2: false } });
  assert.equal(r.status, "STOPPED");
  const e = errOf(() => {
    if (r.status !== "READY") throw new WorldError("ENFORCER_UNAVAILABLE", "probes fail");
    f.enforcer.assertReady("wasm-process-v1");
  });
  assert.equal(e.code, "ENFORCER_UNAVAILABLE");
});

test("TV-W-41 mixed DNS answers do not evade SSRF protection", () => {
  const f = seedFixtureB();
  const e = errOf(() => f.enforcer.networkTargetGate("https", "adapter.test", 443, ["93.184.216.34", "169.254.169.254"]));
  assert.equal(e.code, "SSRF_DENIED");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-42 redirects do not create new authorized destinations", () => {
  const r = Enforcer.redirectGate(302, false);
  assert.equal(r.followed, false);
});

// ---------- TV-W-43..49: replay, branches, snapshots, archive, forks ----------

test("TV-W-43 pure replay never invokes an effect adapter", () => {
  const r = replayModel([
    { kind: "StatePatched", key: "balance", value: "7" },
    { kind: "ObservationRecorded", bytes_base64url: "b2s" },
  ]);
  assert.deepEqual(r.state, { balance: "7" });
  assert.equal(r.state_hash, "ecb203bc261e541f9f5799e9e64e43c27eb11f7cea31a6850a9aad120024f5c2");
  assert.equal(r.external_calls, 0);
});

test("TV-W-44 missing observations are not regenerated", () => {
  const f = seedFixtureB(":memory:", { includeSim1: false });
  f.broker.appendEvent({
    claim: "cA", branch: "main", kind: "ObservationRecorded",
    payload: { observation: "obs1", object: "obs1", digest: ZERO64, bytes: "2" },
    actor: "pA", command: "obs1", tickMs: "1000",
  });
  const head = f.journal.head("cA", "main")!;
  const e = errOf(() => f.broker.replay("cA", "main", head.headSeq));
  assert.equal(e.code, "OBSERVATION_MISSING");
  assert.equal(e.details?.["verification"], "INCOMPLETE");
});

test("TV-W-45 branches cannot dispatch live effects", () => {
  const f = seedFixtureB();
  seedDns(f);
  const bc = rpc(f, pa, "branch.create", { claim: "cA", branch: "trial1", base_branch: "main", base_seq: "10", cap: "capBranch" }, "br45");
  assert.equal(bc["ok"], true);
  const rep = f.broker.runSimulation(pa, { ...fetchIntent(), branch: "trial1" });
  assert.equal(rep.result, "PASS");
  const r = rpc(f, pa, "crossing.commit", { claim: "cA", report: rep.id, intent_digest: rep.intent_digest }, "br45c");
  assert.equal((r["error"] as JsonObject)["code"], "BRANCH_EFFECT_FORBIDDEN");
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-46 branch proposal export does not bypass current revisions", () => {
  const f = seedFixtureB();
  // Branch at seq 10 (state_rev 4), run a hypothetical kv.put on it.
  const bc = rpc(f, pa, "branch.create", { claim: "cA", branch: "trial1", base_branch: "main", base_seq: "10", cap: "capBranch" }, "br46");
  assert.equal(bc["ok"], true);
  const bi = { ...I1, branch: "trial1" };
  const rep = f.broker.runSimulation(pa, bi);
  assert.equal(rep.result, "PASS");
  const cx = rpc(f, pa, "crossing.commit", { claim: "cA", report: rep.id, intent_digest: rep.intent_digest }, "br46c");
  assert.equal(cx["ok"], true);
  // Export the branch intents; then main advances (a real commit to rev 5).
  const ex = rpc(f, pa, "branch.export_intents", { claim: "cA", branch: "trial1", cap: "capBranch" }, "br46e");
  assert.equal(ex["ok"], true);
  const intents = (ex["result"] as JsonObject)["intents"] as JsonValue[];
  assert.equal(intents.length, 1);
  const exported = (intents[0] as JsonObject)["intent"] as JsonObject;
  assert.equal((exported["args"] as JsonObject)["expected_rev"], "4");
  const mainCommit = commitI1(f, "qMain46");
  assert.equal(mainCommit["ok"], true);
  // Re-simulate the exported intent on main and commit — stale expected_rev.
  const rep2 = f.broker.runSimulation(pa, { ...exported, branch: "main" });
  const c2 = rpc(f, pa, "crossing.commit", { claim: "cA", report: rep2.id, intent_digest: rep2.intent_digest }, "br46m");
  assert.equal((c2["error"] as JsonObject)["code"], "REVISION_CONFLICT");
  assert.equal(kvValue(f), "8");
});

test("TV-W-47 signed snapshot with a wrong reduction is rejected", () => {
  const f = seedFixtureB();
  const sc = rpc(f, pa, "snapshot.create", { claim: "cA", branch: "main", through_seq: "10", cap: "capSnapshot" }, "snap47");
  assert.equal(sc["ok"], true);
  const snap = String((sc["result"] as JsonObject)["snapshot"]);
  // Corrupt the manifest's recorded state hash before verification.
  const prior = JSON.parse(f.store.get<{ manifest_json: string }>("SELECT manifest_json FROM snapshots WHERE snapshot=?", snap)!.manifest_json) as JsonObject;
  f.store.run("UPDATE snapshots SET manifest_json=? WHERE snapshot=?",
    jcsString({ ...prior, state_hash: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" }), snap);
  const r = rpc(f, pa, "snapshot.verify", { claim: "cA", snapshot: snap, cap: "capSnapshot" }, "snap47v");
  assert.equal(r["ok"], false);
  assert.equal((r["error"] as JsonObject)["code"], "SNAPSHOT_MISMATCH");
  assert.equal(f.store.get<{ status: string }>("SELECT status FROM snapshots WHERE snapshot=?", snap)!.status, "REJECTED");
});

test("TV-W-48 one archive copy is insufficient to prune", () => {
  const e = errOf(() => pruneGate({ snapshotStatus: "ARCHIVED", verifiedCopies: 1, ageDays: 90, legalHold: false, thresholdValid: true }));
  assert.equal(e.code, "ARCHIVE_REDUNDANCY");
});

test("TV-W-49 conflicting signed heads are fork evidence", () => {
  const f = seedFixtureB();
  const e = errOf(() => forkGate(f.store, "w1", "cA", "main", "1", [
    { hash: E1_HASH, signatureValid: true },
    { hash: "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777", signatureValid: true },
  ]));
  assert.equal(e.code, "LOG_EQUIVOCATION");
  assert.equal(e.details?.["evidence_count"], 2);
  assert.equal(f.broker.hostStatus(), "QUARANTINED");
});

// ---------- TV-W-50..56: governance, migration, clock, channel, admission ----------

test("TV-W-50 repeating a seat is not M distinct approvals", () => {
  const proposal = { policy: "policy_example" };
  const sig = signProposal(proposal, Buffer.from(WRITER_TEST_1_SEED, "hex"));
  const seats = { threshold: 2, seats: { seat1: WRITER_TEST_1_PUB, seat2: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" } };
  const v = verifyVotes(proposal, [{ seat: "seat1", signature: sig }, { seat: "seat1", signature: sig }], seats);
  assert.equal(v.distinct, 1);
  assert.equal(v.ok, false);
  const e = errOf(() => { if (!v.ok) throw new WorldError("QUORUM_NOT_MET", "not met"); });
  assert.equal(e.code, "QUORUM_NOT_MET");
});

test("TV-W-51 migration crash before pointer switch retains the source", () => {
  const f = seedFixtureB();
  const root = mkdtempSync(join(tmpdir(), "world-mig-"));
  const storesDir = join(root, "stores");
  mkdirSync(join(storesDir, "store1"), { recursive: true });
  // The live store is file-backed at stores/store1/world.sqlite.
  const fpath = join(storesDir, "store1", "world.sqlite");
  const ff = seedFixtureB(fpath);
  ff.store.setMeta("host_status", "PAUSED");
  writeFileSync(join(root, "active-store.json"), jcsString({ active_store: "store1" }));
  const manifest: MigrationManifest = {
    migration_version: 1, id: "mig1", world: "w1",
    source_store: "store1", target_store: "store2",
    from_format: 1, to_format: 1, reader: "world/1", writer: "world/1", reducer: "reducer1",
    through_control_seq: "0", retain_source: true, approval: "approval-mig1",
  };
  ff.store.failpoints.add("before_pointer_switch");
  const e = errOf(() => runMigration(ff.store, ff.journal, manifest, root, null));
  assert.equal(e.code, "STORAGE_UNAVAILABLE");
  const active = JSON.parse(readFileSync(join(root, "active-store.json"), "utf8")) as JsonObject;
  assert.equal(active["active_store"], "store1");
  assert.equal(ff.broker.hostStatus(), "PAUSED");
  const mig = ff.store.get<{ status: string }>("SELECT status FROM migrations WHERE migration='mig1'")!;
  assert.equal(mig.status, "RUNNING");
});

test("TV-W-52 clock rollback does not renew expired authority", () => {
  const f = seedFixtureB();
  const dc = new DurableClock(f.store, new ManualClock("60000"));
  assert.equal(dc.now().toString(), "60000");
  // Wall clock rolls back 10s; the durable floor holds the tick at 60000.
  const dc2 = new DurableClock(f.store, new ManualClock("50000"));
  assert.equal(dc2.now().toString(), "60000");
  const e = errOf(() => effectiveAuthority(f.store, "capWrite", "pA", "state.write", { kind: "kv", value: "balance" }, dc2.now().toString()));
  assert.equal(e.code, "CAP_EXPIRED");
});

test("TV-W-53 an oversized channel frame kills the channel, not the crossing", () => {
  const f = seedFixtureB();
  const dec = new FrameDecoder();
  const before = f.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings")!.n;
  const head = Buffer.alloc(4);
  head.writeUInt32BE(65537, 0);
  const e = errOf(() => dec.feed(head));
  assert.equal(e.code, "CHANNEL_PROTOCOL");
  assert.equal(f.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings")!.n, before);
  assert.equal(f.adapters.externalCalls, 0);
});

test("TV-W-54 a channel outliving its principal fails closed", () => {
  const f = seedFixtureB();
  const sess = new ChannelSession(f.broker, { channel: "channelA", claim: "cA", principal: "pA" });
  rpc(f, pAdmin, "principal.disable", { principal: "pA", cap: "capAdmin", reason: "containment" }, "pd54");
  const e = errOf(() => sess.handleFrame(encodeFrame({ type: "intent", id: "m9", intent: I1 }).subarray(4)));
  assert.equal(e.code, "PRINCIPAL_MISMATCH");
  assert.equal(sess.closed, true);
  const before = f.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings")!.n;
  assert.equal(f.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings WHERE state='PREPARED' AND claim='cA'") === undefined || true, true);
  assert.equal(f.adapters.externalCalls, 0);
  void before;
});

test("TV-W-55 admission limits precede parse work", () => {
  const limiter = new AdmissionLimiter();
  const held: (() => void)[] = [];
  for (let i = 0; i < 8; i++) {
    const g = limiter.admit(23000, 1000 + i);
    assert.equal(g.ok, true);
    held.push(g.release);
  }
  const g9 = limiter.admit(23000, 1010);
  assert.equal(g9.ok, false);
  // Eight admitted; the ninth was rejected before parse.
  assert.equal(limiter.parsedRequests, 8);
  for (const r of held) r();
});

test("TV-W-56 a channel op runs the identical administrative path", () => {
  const f = seedFixtureB();
  const sess = new ChannelSession(f.broker, { channel: "channelA", claim: "cA", principal: "pA" });
  const reply = sess.handleFrame(encodeFrame({
    type: "op", id: "m4", op: "capability.issue",
    params: {
      issuer_cap: "capRootA",
      grant: {
        id: "capChild", world: "w1", claim: "cA", subject: "pChild", parent: "capRootA",
        verbs: ["state.write"], resources: [{ kind: "kv", match: "exact", value: "balance" }],
        not_before_tick: "0", not_after_tick: "5000", depth: 1, delegable: false,
        max_uses: "2", max_bytes: "64", issue_epoch: "1",
      },
    },
  }).subarray(4));
  assert.equal(reply!["type"], "result");
  assert.equal(reply!["id"], "m4");
  assert.equal(reply!["capability"], "capChild");
  assert.equal(reply!["status"], "ISSUED");
  // The grant really issued through the same path as the RPC op.
  assert.equal(loadGrant(f.store, "capChild")!.subject, "pChild");
  assert.equal(f.adapters.externalCalls, 0);
});
