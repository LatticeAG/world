/**
 * Fixture B (spec §12.1): the exact trusted projection seed used by the
 * conformance vectors. The retained readable prefix is REAL signed
 * history — E1/E2 verbatim plus writer-signed events through seq 10 — and
 * the remaining seed state is installed as projection rows (B is a
 * projection seed, not a replay product; integration tests build real
 * histories of their own).
 */

import { Store } from "./store.js";
import { Journal, type Envelope } from "./journal.js";
import { MemoryKeyService, type KeyService } from "./keys.js";
import { ManualClock } from "./clock.js";
import { SchemaRegistry } from "./registry.js";
import { Broker, modelDigestHex, type BrokerConfig } from "./broker.js";
import { Enforcer } from "./enforcer.js";
import { AdapterRegistry, TestAdapter } from "./adapters.js";
import { sha256Hex, sealAead } from "./crypto.js";
import { jcsBytes, jcsString, type JsonObject, type JsonValue } from "./canon.js";

export const WRITER_TEST_1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
export const WRITER_TEST_1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
export const WRITER_TEST_2_SEED = "257967c1f94e2a1137dd36ff29a10e01eecbd3186aac16b9354ccfd339d6bd79";
export const WRITER_TEST_2_PUB = "196c37bb0769d0dd1e6f03a8e9de06c44542df0242c6815216422ad86b1e3538";
export const SEAT2_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
export const SEAT2_PUB = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
export const SEAT3_SEED = "82388f5282155c3468dc54f5440cf077507ad56970dc942ea5786b8727a964e7";
export const SEAT3_PUB = "799b19ebba4f8227cbe27b3d471efc65948dada64bc7fb2caf0adad3463c0d13";

export const E1_HASH = "8bc4334746ebf1500f4862e2357f82e5401a03bc0d9e4c9ac6c80f56a13efca9";
export const I1: JsonObject = {
  world: "w1", claim: "cA", branch: "main", principal: "pA", cap: "capWrite",
  action: "kv.put",
  args: { key: "balance", value: "8", expected_rev: "4" },
  max_cost: { uses: "1", bytes: "16" },
  deadline_ms: "10000",
};
export const I1_DIGEST = "2b3491367ef1d09b5e4885b4a73888b5346088d26e6adb728b02985a014140ad";
export const PINNED_ENGINE_DIGEST = "193eb9207ad25f2868bba18a753cd0a769b57967e2d274f9b5dd6700aa2d0bc1";
export const PINNED_ENFORCER_DIGEST = "48c1752ff1069aa8250451b98f75ca84e4a0e28219648de5c1a2ad5ca14b8286";
export const PINNED_BUNDLE_DIGEST = "dcba0ea5a74565c0d480b194547cd9ecb3827087e1285e4b60b11b940666be0e";

/** The verbatim signed E1 genesis (spec §1.3). */
export const E1: Envelope = {
  body: {
    v: 1, world: "w1", claim: "cA", branch: "main", seq: "1",
    prev: "0".repeat(64), kind: "ClaimCreated", schema: 1, actor: "pAdmin",
    command: "q1", causes: [], lamport: "1", tick_ms: "1000", writer_epoch: "1",
    policy: "policy1",
    payload: { owner: "pAdmin", auth_rev: "1", state_rev: "0" },
  },
  hash: "8bc4334746ebf1500f4862e2357f82e5401a03bc0d9e4c9ac6c80f56a13efca9",
  key_id: "writer-test-1",
  signature: "-IUor-21OqWX57iXPhKlLBCoXyPNMR7GINmFQcSqna-FNCQlWpomvyGPLMuxdab-UHwOMRVlxl8VdXV1rnn2Bg",
};

/** The verbatim signed E2 _control genesis pair (spec §1.3). */
export const E2: Envelope[] = [
  {
    body: {
      v: 1, world: "w1", claim: "_control", branch: "main", seq: "1",
      prev: "0".repeat(64), kind: "WriterStarted", schema: 1, actor: "pRuntime",
      command: "boot1", causes: [], lamport: "1", tick_ms: "1000", writer_epoch: "1",
      policy: "policy1",
      payload: { key_id: "writer-test-1", writer_epoch: "1", store: "store1" },
    },
    hash: "db35dd9024c3e5e624da4b36aefba9fbafc80d96d3dc4d3c7f9d14498b7abf43",
    key_id: "writer-test-1",
    signature: "cYuzMkDWrtLJ__Nrg1T9BtCHkRcbF7YFMii81rIdheN0QyECU43O3FI_bPlCMTlbEQfhpbUEnlwvlooZc1rODg",
  },
  {
    body: {
      v: 1, world: "w1", claim: "_control", branch: "main", seq: "2",
      prev: "db35dd9024c3e5e624da4b36aefba9fbafc80d96d3dc4d3c7f9d14498b7abf43",
      kind: "PolicyActivated", schema: 1, actor: "pRuntime", command: "boot2",
      causes: [{ claim: "_control", branch: "main", seq: "1", hash: "db35dd9024c3e5e624da4b36aefba9fbafc80d96d3dc4d3c7f9d14498b7abf43" }],
      lamport: "2", tick_ms: "1001", writer_epoch: "1", policy: "policy1",
      payload: { policy: "policy1", epoch: "1", predecessor: null, bundle_digest: PINNED_BUNDLE_DIGEST, enforcer_digest: PINNED_ENFORCER_DIGEST, approval: "bootstrap-genesis" },
    },
    hash: "fd8c116a1f8f0ec4c533bc7cc46bf139df80a588eca7c2ac9b860a5cc20e145a",
    key_id: "writer-test-1",
    signature: "OteIaA1dqJxMb0kBgA5tzchl4WuaorU9_FQDnQ1xJ3GcYwJ8IM-hBZDCTszcB0YmIeDzu1JV1kyTmTyo04HJAA",
  },
];

export interface FixtureBHandle {
  store: Store;
  journal: Journal;
  keys: KeyService;
  clock: ManualClock;
  broker: Broker;
  enforcer: Enforcer;
  adapters: AdapterRegistry;
  adapterT: TestAdapter;
}

function grantOf(id: string, claim: string, subject: string, parent: string | null, verbs: string[], resources: JsonValue[], opts: { delegable?: boolean; uses?: string; bytes?: string; nat?: string } = {}): JsonObject {
  return {
    id, world: "w1", claim, subject, parent, verbs, resources,
    not_before_tick: "0", not_after_tick: opts.nat ?? "60000",
    depth: parent === null ? 0 : 1, delegable: opts.delegable ?? false,
    max_uses: opts.uses ?? "100", max_bytes: opts.bytes ?? "1048576", issue_epoch: "1",
  };
}

const adminOps = [
  "claim.create", "claim.set_status", "principal.register", "principal.disable",
  "capability.issue", "capability.revoke", "fence.configure", "policy.apply",
  "retention.archive", "host.set_status", "crossing.reconcile", "crossing.cancel", "branch.set_status",
];

function seedCap(store: Store, grant: JsonObject): void {
  const claim = String(grant["claim"]);
  const sealed = sealAead(store.claimKey(claim), jcsBytes(grant), Buffer.from(`grant/${claim}/${String(grant["id"])}`));
  store.run(
    "INSERT INTO capabilities(capability,claim,subject,parent,grant_enc,generation,status) VALUES(?,?,?,?,?,'1','ISSUED')",
    String(grant["id"]), claim, String(grant["subject"]), grant["parent"] as string | null, sealed,
  );
}

function seedFence(store: Store, claim: string, fence: JsonObject): void {
  store.run("INSERT INTO fences(claim,id,version,fence_json,status) VALUES(?,?,?,?,'ACTIVE')",
    claim, String(fence["id"]), Number(fence["version"]), jcsString(fence));
}

export interface FixtureSeedOptions {
  /** Bind pAdmin to this OS uid for local smoke (default 23000). */
  uid?: number;
  /** Include the seeded sim1 report + its seq-10 event (default true). */
  includeSim1?: boolean;
}

/** Build the full component stack on a store (empty or existing). */
export function openWorld(path: string, keys: KeyService, clock: ManualClock, world = "w1"): FixtureBHandle {
  const store = new Store(path);
  store.keys = keys;
  const journal = new Journal(store, keys, clock, world, new SchemaRegistry());
  const enforcer = new Enforcer("wasm-process-v1", PINNED_ENFORCER_DIGEST);
  const adapters = new AdapterRegistry();
  const adapterT = new TestAdapter();
  adapters.register(adapterT);
  const config: BrokerConfig = {
    world, simulationTtlMs: "5000", simulationFuel: "10000000",
    maxDelegationDepth: 4, profile: "wasm-process-v1",
  };
  const broker = new Broker(store, journal, keys, clock, enforcer, adapters, config);
  broker.seats = {
    threshold: 2,
    seats: { seat1: WRITER_TEST_1_PUB, seat2: SEAT2_PUB, seat3: SEAT3_PUB },
  };
  return { store, journal, keys, clock, broker, enforcer, adapters, adapterT };
}

export function seedFixtureB(path = ":memory:", opts: FixtureSeedOptions = {}): FixtureBHandle {
  const h = openWorld(path, new MemoryKeyService().addWriter("writer-test-1", WRITER_TEST_1_SEED, "1"), new ManualClock("1000"));
  seedFixtureInto(h, opts);
  return h;
}

/** Install the §12.1 Fixture B state on a fresh component stack. */
export function seedFixtureInto(h: FixtureBHandle, opts: FixtureSeedOptions = {}): FixtureBHandle {
  const { store, journal, broker } = h;
  const includeSim1 = opts.includeSim1 !== false;
  const adminUid = opts.uid ?? 23000;

  journal.registerWriterKey("writer-test-1", "1", WRITER_TEST_1_PUB);
  store.setMeta("writer_epoch", "1");
  store.setMeta("active_policy", "policy1");
  store.setMeta("host_status", "READY");
  store.setMeta("store_id", "store1");

  // _control stream: verbatim E2 pair (real signatures over pinned bodies).
  // The policy bundle is provisioned before the PolicyActivated reducer
  // runs so the row carries the real bundle bytes.
  store.setMeta("policy_bundle:policy1", jcsString({ version: 1, epoch: "1", mode: "enforce", max_delegation_depth: 4, simulation_ttl_ms: 5000, cross_claim: "explicit_import_export", egress: "deny" }));
  journal.createStream("_control", "main");
  for (const env of E2) journal.insertVerified(env);
  store.run("UPDATE policies SET activation_commit=? WHERE policy='policy1'", E2[1]!.hash);

  // Principals as real _control history.
  for (const [p, type, uid, channel] of [
    ["pAdmin", "operator", adminUid, null],
    ["pA", "worker", null, "channelA"],
    ["pChild", "worker", null, "channelChild"],
  ] as const) {
    broker.appendEvent({
      claim: "_control", branch: "main", kind: "PrincipalRegistered",
      payload: { principal: p, type, ...(uid === null ? {} : { uid }), ...(channel === null ? {} : { channel }), epoch: "1" },
      actor: "pRuntime", command: `boot:${p}`, tickMs: "1000",
    });
  }
  store.run("INSERT INTO channels(channel,claim,principal,status) VALUES('channelA','cA','pA','BOUND'),('channelChild','cA','pChild','BOUND')");
  store.run("UPDATE channels SET claim='cA' WHERE channel IN ('channelA','channelChild')");

  // cA/main: verbatim E1, then signed history to the retained prefix cut.
  journal.createStream("cA", "main");
  journal.insertVerified(E1);
  const cA = "cA";
  const capRootA = grantOf("capRootA", "cA", "pA", null,
    ["state.write", "state.read", "cap.delegate"],
    [
      { kind: "kv", match: "exact", value: "balance" },
      { kind: "object", match: "exact", value: "obj1" },
      { kind: "principal", match: "exact", value: "pChild" },
    ], { delegable: true });
  const capWrite = grantOf("capWrite", "cA", "pA", "capRootA",
    ["state.write"], [{ kind: "kv", match: "exact", value: "balance" }],
    { uses: "10", bytes: "1024" });
  broker.appendEvent({ claim: cA, branch: "main", kind: "CapabilityIssued", payload: { capability: "capRootA", grant: capRootA }, actor: "pAdmin", command: "seed:capRootA", tickMs: "999" });
  broker.appendEvent({ claim: cA, branch: "main", kind: "CapabilityIssued", payload: { capability: "capWrite", grant: capWrite }, actor: "pAdmin", command: "seed:capWrite", tickMs: "999" });
  const patchSeq: [string, string][] = [["0", "1"], ["1", "2"], ["2", "3"], ["3", "4"]];
  const patchVals = ["3", "5", "6", "7"];
  for (let i = 0; i < patchSeq.length; i++) {
    broker.appendEvent({
      claim: cA, branch: "main", kind: "StatePatched",
      payload: { expected_rev: patchSeq[i]![0], patch: [{ op: "set", key: "balance", value: patchVals[i]! }], new_rev: patchSeq[i]![1], crossing: `seed:${patchVals[i]}` },
      actor: "pAdmin", command: `seed:patch:${patchVals[i]}`, tickMs: "999",
    });
  }
  const dataA: JsonObject = { id: "dataA", type: "claim-data", version: 1, effect: "allow", resources: [{ kind: "kv", match: "exact", value: "balance" }] };
  const quotaA: JsonObject = { id: "quotaA", type: "resource", version: 1, effect: "allow", resources: [{ kind: "kv", match: "exact", value: "balance" }], constraints: { uses: "100", bytes: "1048576" } };
  broker.appendEvent({ claim: cA, branch: "main", kind: "FenceConfigured", payload: { fence: dataA, predecessor: null, enforcer_digest: PINNED_ENFORCER_DIGEST }, actor: "pAdmin", command: "seed:dataA", tickMs: "999" });
  broker.appendEvent({ claim: cA, branch: "main", kind: "FenceConfigured", payload: { fence: quotaA, predecessor: null, enforcer_digest: PINNED_ENFORCER_DIGEST }, actor: "pAdmin", command: "seed:quotaA", tickMs: "1000" });

  // seq 10: the durable sim1 record (bound to state_rev 4 / auth_rev …).
  // The serve smoke variant omits it so `world simulate` allocates sim1 live.
  const stream = journal.head("cA", "main")!;
  if (includeSim1) {
  const sim1Report = {
    id: "sim1", intent_digest: I1_DIGEST, principal: "pA", claim: "cA", branch: "main",
    read_set: { state_rev: stream.stateRev, auth_rev: stream.authRev, policy: "policy1" },
    auth_set: {
      cap: "capWrite", cap_generation: "1", principal_generation: "1",
      writer_epoch: "1", claim_generation: "1",
      ancestors: [{ cap: "capWrite", generation: "1" }, { cap: "capRootA", generation: "1" }],
    },
    policy_id: "policy1",
    fence_versions: { dataA: 1, quotaA: 1 },
    engine_digest: PINNED_ENGINE_DIGEST, model_digest: modelDigestHex(),
    result: "PASS", checks: [{ fence: "dataA", result: "PASS" }, { fence: "quotaA", result: "PASS" }],
    denial_code: null,
    cost_bound: { uses: "1", bytes: "16" },
    created_tick: "1000", expires_tick: "6000",
    intent: I1,
  } as unknown as JsonObject;
  store.setMeta("report_full:sim1", jcsString(sim1Report));
  broker.appendEvent({
    claim: cA, branch: "main", kind: "SimulationRecorded",
    payload: {
      report: "sim1", intent_digest: I1_DIGEST,
      cut: { state_rev: stream.stateRev, auth_rev: stream.authRev },
      result: "PASS", checks: [{ fence: "dataA", result: "PASS" }],
      engine_digest: PINNED_ENGINE_DIGEST, expires_tick: "6000", branch: "main",
    },
    actor: "pA", command: "seed:sim1", tickMs: "1000",
  });
  }

  // Direct projection rows for the rest of the seed (B is a model seed).
  journal.createStream("cB", "main");
  broker.appendEvent({ claim: "cB", branch: "main", kind: "ClaimCreated", payload: { owner: "pAdmin", auth_rev: "1", state_rev: "0" }, actor: "pAdmin", command: "seed:cB", tickMs: "1000" });

  const grants: JsonObject[] = [
    grantOf("capRead", "cA", "pA", null, ["state.read"], [
      { kind: "kv", match: "exact", value: "balance" },
      { kind: "object", match: "exact", value: "obj1" },
      { kind: "audit", match: "prefix", value: "main" },
      { kind: "worker", match: "prefix", value: "worker" },
    ]),
    grantOf("capAudit", "cA", "pA", null, ["state.read", "audit.read"], [
      { kind: "kv", match: "exact", value: "balance" },
      { kind: "object", match: "exact", value: "obj1" },
      { kind: "audit", match: "prefix", value: "main" },
      { kind: "worker", match: "prefix", value: "worker" },
    ]),
    grantOf("capBranch", "cA", "pA", null, ["branch.create"], [{ kind: "branch", match: "prefix", value: "trial" }]),
    grantOf("capSnapshot", "cA", "pA", null, ["snapshot.create"], [{ kind: "snapshot", match: "exact", value: "cA" }]),
    grantOf("capFetch", "cA", "pA", null, ["net.fetch"], [{ kind: "network", match: "exact", value: "https/adapter.test/443/adapterT" }]),
    grantOf("capWorker", "cA", "pA", null, ["worker.start"], [{ kind: "worker", match: "prefix", value: "mod" }]),
    grantOf("capObjectWrite", "cA", "pA", null, ["state.write"], [{ kind: "object", match: "exact", value: "obj1" }]),
    grantOf("capExport", "cA", "pA", null, ["object.export"], [{ kind: "export", match: "exact", value: "cB/obj1/json1" }, { kind: "object", match: "exact", value: "obj1" }]),
    grantOf("capImport", "cB", "pA", null, ["object.import"], [{ kind: "import", match: "exact", value: "cA/obj1/json1" }]),
    grantOf("capAdmin", "w1", "pAdmin", null, ["admin.manage"], adminOps.map((op) => ({ kind: "admin", match: "exact", value: op }))),
  ];
  for (const g of grants) seedCap(store, g);

  seedFence(store, "cA", { id: "netT", type: "network", version: 1, effect: "allow", resources: [{ kind: "network", match: "exact", value: "https/adapter.test/443/adapterT" }], constraints: { adapters: ["adapterT"], bytes: "1048576" } });
  seedFence(store, "cA", { id: "exportA", type: "claim-data", version: 1, effect: "allow", resources: [{ kind: "export", match: "exact", value: "cB/obj1/json1" }], constraints: { peers: ["cB"], schemas: ["json1"] } });
  seedFence(store, "cA", { id: "procA", type: "process", version: 1, effect: "allow", resources: [{ kind: "worker", match: "prefix", value: "mod" }], constraints: { profiles: ["wasm-process-v1"] } });
  seedFence(store, "cB", { id: "netA", type: "network", version: 1, effect: "deny", resources: [{ kind: "network", match: "prefix", value: "https/" }] });

  // obj1: UTF-8 {"k":1} (7 bytes), populated per the artifact.put example.
  const obj1Bytes = Buffer.from('{"k":1}', "utf8");
  store.run("INSERT INTO objects(claim,object,digest,size,key_version,schema,state) VALUES('cA','obj1',?,?,2,'json1','COMMITTED')",
    "a0da1fce57d0e4f9f0ae4e4cbe040d34dcc046255c6c8d18e97f55aaed0655f0", obj1Bytes.byteLength.toString());
  store.run("INSERT INTO registry_artifacts(artifact,kind,bytes,digest) VALUES('cA/obj1','object',?,?)",
    obj1Bytes, "a0da1fce57d0e4f9f0ae4e4cbe040d34dcc046255c6c8d18e97f55aaed0655f0");

  // wmodA module artifact for worker.start sims (mod1 alias below).
  const modBytes = Buffer.from("fake-wasm-module", "utf8");
  store.run("INSERT INTO objects(claim,object,digest,size,key_version,schema,state) VALUES('cA','mod1',?,?,1,'application/wasm','COMMITTED')",
    sha256Hex(modBytes), modBytes.byteLength.toString());
  store.run("INSERT INTO registry_artifacts(artifact,kind,bytes,digest) VALUES('cA/mod1','object',?,?)", modBytes, sha256Hex(modBytes));

  // worker1 exists only for worker.status (RUNNING under wasm-process-v1).
  store.run("INSERT INTO workers(worker,claim,branch,status,profile,epoch,pidfd,exec_digest,crossing) VALUES('worker1','cA','main','RUNNING','wasm-process-v1','1','pidfd:17',?,NULL)",
    sha256Hex(jcsBytes({ module: "mod1", profile: "wasm-process-v1" })));

  // Preconfigured archive destinations for retention.archive.
  for (const d of ["archiveA", "archiveB"]) {
    store.run("INSERT INTO tombstones(namespace,id,data_json) VALUES('archive_destination',?,?)", d, jcsString({ id: d, local: true }));
  }

  store.setMeta("idalloc:report", includeSim1 ? "1" : "0");
  store.setMeta("idalloc:crossing", "0");
  return h;
}

/**
 * Seed the named prepared/dispatched crossings (xPrepared / xUnknown)
 * exactly as §12.1 describes: PREPARED net.fetch under capFetch with one
 * use and 16 bytes held; xUnknown adds dispatch with the use spent.
 */
export function seedCrossings(f: FixtureBHandle, which: "xPrepared" | "xUnknown" | "both"): void {
  const mk = (name: string, dispatched: boolean) => {
    f.broker.appendEvent({
      claim: "cA", branch: "main", kind: "CrossingPrepared",
      payload: {
        crossing: name, report: "simNet1",
        authority: { cap: "capFetch", generation: "1" },
        checks: ["authority:PASS", "fence:netT:PASS", "simulation:PASS"],
        planned: { uses: "1", bytes: "16" }, reserved: { uses: "1", bytes: "16" },
      },
      actor: "pA", command: `seed:${name}`, tickMs: "1000",
    });
    f.store.run("UPDATE crossings SET claim='cA' WHERE crossing=?", name);
    for (const cap of ["capFetch"]) {
      // Dispatch consumes the use immediately (§7.3); bytes stay HELD.
      f.store.run("INSERT INTO reservations(crossing,capability,dimension,held,spent,state) VALUES(?,?,?,?,?,'HELD')",
        name, cap, "uses", dispatched ? "0" : "1", dispatched ? "1" : "0");
      f.store.run("INSERT INTO reservations(crossing,capability,dimension,held,spent,state) VALUES(?,?,?,?,?,'HELD')",
        name, cap, "bytes", "16", "0");
    }
    if (dispatched) {
      f.broker.appendEvent({
        claim: "cA", branch: "main", kind: "CrossingDispatched",
        payload: {
          crossing: name, dispatch_epoch: "1",
          adapter_request_digest: "ec7d150aa6ebdc217085c186b61749a4e5c334d7299886d313ae0625a5d3f616",
          idempotency_key: `adapterT:${name}`, deadline_tick: "11000",
        },
        actor: "pA", command: `seed:${name}:dispatch`, tickMs: "1000",
      });
      f.store.run("UPDATE reservations SET held='0',spent='1' WHERE crossing=? AND dimension='uses'", name);
    }
  };
  if (which === "xPrepared" || which === "both") mk("xPrepared", false);
  // xUnknown models "crash after the dispatch marker": DISPATCHED with the
  // use spent and bytes held; recovery or reconciliation decides the rest.
  if (which === "xUnknown" || which === "both") mk("xUnknown", true);
}
