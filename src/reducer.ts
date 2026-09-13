/**
 * Deterministic reducer (spec §1.5, §8.1).
 *
 * The reducer is a pure function (previous_projection, verified_event,
 * pinned_artifacts) -> next_projection. It has no clock, randomness,
 * network, filesystem, locale, or environment access. Map iteration is
 * canonical-key ordered. A correctly signed but illegal transition is
 * invalid history: reduceEvent throws REDUCER_FAILED.
 *
 * applyEventSql mirrors the same transitions onto the SQLite projection
 * inside the append transaction, so the live store and the pure reducer
 * never diverge.
 */

import { WorldError } from "./errors.js";
import type { JsonValue, JsonObject } from "./canon.js";
import { jcsBytes, jcsString } from "./canon.js";
import { sha256Hex, sealAead, openAead } from "./crypto.js";
import { decNext } from "./ids.js";
import type { Store } from "./store.js";
import type { Envelope } from "./journal.js";

// ---------- pure JSON projection ----------

export interface Projection {
  claims: Record<string, { status: string; owner: string }>;
  streams: Record<string, { state_rev: string; auth_rev: string; status: string }>;
  principals: Record<string, { type: string; status: string; generation: string; uid?: number; channel?: string }>;
  capabilities: Record<string, { status: string; generation: string; grant: JsonValue }>;
  fences: Record<string, { version: number; status: string; fence: JsonValue }>;
  policies: Record<string, { status: string; epoch: string; bundle: JsonValue }>;
  active_policy: string;
  reports: Record<string, { claim: string; branch: string; state: string; result: string; intent_digest: string; expires_tick: string; consumed_crossing: string | null }>;
  crossings: Record<string, { claim: string; branch: string; state: string; intent_digest: string; action: string; hypothetical: boolean }>;
  objects: Record<string, { digest: string; size: string; schema: string | null; state: string }>;
  workers: Record<string, { claim: string; status: string; profile: string; epoch: string }>;
  snapshots: Record<string, { claim: string; status: string; through_seq: string; manifest_digest: string; verified_copies: number }>;
  state: Record<string, Record<string, JsonValue>>;
  host: { status: string; writer_epoch: string; store: string };
  amendments: Record<string, { status: string; kind: string }>;
}

export function emptyProjection(): Projection {
  return {
    claims: {}, streams: {}, principals: {}, capabilities: {}, fences: {},
    policies: {}, active_policy: "", reports: {}, crossings: {}, objects: {},
    workers: {}, snapshots: {}, state: {}, host: { status: "STOPPED", writer_epoch: "0", store: "" },
    amendments: {},
  };
}

const skey = (claim: string, branch: string) => `${claim}/${branch}`;

function fail(msg: string): never {
  throw new WorldError("REDUCER_FAILED", msg);
}

function streamOf(p: Projection, claim: string, branch: string) {
  const s = p.streams[skey(claim, branch)];
  if (!s) fail(`no stream ${claim}/${branch}`);
  return s;
}

/** auth_rev is claim-scoped: an authority event bumps every stream of the claim. */
function bumpAuthAll(p: Projection, claim: string): void {
  for (const [k, s] of Object.entries(p.streams)) {
    if (k.startsWith(`${claim}/`)) s.auth_rev = decNext(s.auth_rev);
  }
}

const CLAIM_STATES = ["ACTIVE", "FROZEN", "QUARANTINED", "ARCHIVED"] as const;
const CLAIM_TRANSITIONS: Record<string, string[]> = {
  ACTIVE: ["FROZEN", "QUARANTINED"],
  FROZEN: ["ACTIVE", "QUARANTINED", "ARCHIVED"],
  QUARANTINED: ["FROZEN"],
  ARCHIVED: ["ARCHIVED"],
};
const CROSSING_TERMINAL = new Set(["DENIED", "COMPLETED", "FAILED", "CANCELLED"]);
const BRANCH_TRANSITIONS: Record<string, string[]> = {
  OPEN: ["SEALED", "ABANDONED"],
  SEALED: ["ABANDONED"],
  ABANDONED: [],
};

/**
 * Pure reduce: apply one verified event to the JSON projection.
 * Payloads arrive already schema-validated; transition legality is checked
 * here — a signed illegal transition is invalid history.
 */
export function reduceEvent(p: Projection, env: Envelope): Projection {
  const b = env.body;
  const pay = b.payload as Record<string, JsonValue>;
  const sk = skey(b.claim, b.branch);
  switch (b.kind) {
    case "ClaimCreated": {
      if (p.claims[b.claim]) fail("claim already exists");
      p.claims[b.claim] = { status: "ACTIVE", owner: String(pay["owner"]) };
      p.streams[sk] = { state_rev: String(pay["state_rev"]), auth_rev: String(pay["auth_rev"]), status: "OPEN" };
      p.state[sk] = {};
      break;
    }
    case "ClaimStatusChanged": {
      const c = p.claims[b.claim] ?? fail("claim missing");
      const from = String(pay["from"]), to = String(pay["to"]);
      if (c.status !== from || !(CLAIM_TRANSITIONS[from] ?? []).includes(to)) {
        fail(`illegal claim transition ${from}->${to}`);
      }
      c.status = to;
      bumpAuthAll(p, b.claim);
      break;
    }
    case "PrincipalRegistered": {
      const pid = String(pay["principal"]);
      if (p.principals[pid]) fail("principal exists");
      const rec: { type: string; status: string; generation: string; uid?: number; channel?: string } = {
        type: String(pay["type"]), status: "ENABLED", generation: "1",
      };
      if (pay["uid"] !== undefined && pay["uid"] !== null) rec.uid = Number(pay["uid"]);
      if (pay["channel"] !== undefined && pay["channel"] !== null) rec.channel = String(pay["channel"]);
      p.principals[pid] = rec;
      break;
    }
    case "PrincipalDisabled": {
      const pid = String(pay["principal"]);
      const pr = p.principals[pid] ?? fail("principal missing");
      if (pr.status !== "ENABLED") fail("principal not ENABLED");
      pr.status = "DISABLED";
      pr.generation = String(pay["generation"]);
      break;
    }
    case "CapabilityIssued": {
      const cap = String(pay["capability"]);
      if (p.capabilities[cap]) fail("capability exists");
      p.capabilities[cap] = { status: "ISSUED", generation: "1", grant: pay["grant"]! };
      const g = pay["grant"] as Record<string, JsonValue>;
      bumpAuthAll(p, String(g["claim"]));
      break;
    }
    case "CapabilityRevoked": {
      const cap = String(pay["capability"]);
      const c = p.capabilities[cap] ?? fail("capability missing");
      if (c.status !== "ISSUED") fail("capability not ISSUED");
      c.status = "REVOKED";
      c.generation = String(pay["generation"]);
      const g = c.grant as Record<string, JsonValue>;
      bumpAuthAll(p, String(g["claim"]));
      break;
    }
    case "FenceConfigured": {
      const f = pay["fence"] as Record<string, JsonValue>;
      const key = `${b.claim}/${String(f["id"])}`;
      const prev = p.fences[key];
      if (prev && Number(f["version"]) !== prev.version + 1) fail("fence version must increase by exactly one");
      if (prev) prev.status = "SUPERSEDED";
      p.fences[key] = { version: Number(f["version"]), status: "ACTIVE", fence: f };
      break;
    }
    case "PolicyActivated": {
      const pid = String(pay["policy"]);
      const pred = pay["predecessor"];
      if (pred !== null && pred !== undefined) {
        const pp = p.policies[String(pred)] ?? fail("predecessor policy missing");
        pp.status = "SUPERSEDED";
      }
      p.policies[pid] = { status: "ACTIVE", epoch: String(pay["epoch"]), bundle: {} };
      p.active_policy = pid;
      break;
    }
    case "SimulationRecorded": {
      const r = String(pay["report"]);
      if (p.reports[r]) fail("report exists");
      p.reports[r] = {
        claim: b.claim, branch: String(pay["branch"]), state: "AVAILABLE",
        result: String(pay["result"]), intent_digest: String(pay["intent_digest"]),
        expires_tick: String(pay["expires_tick"]), consumed_crossing: null,
      };
      break;
    }
    case "CrossingDenied": {
      const x = String(pay["crossing"]);
      if (p.crossings[x]) fail("crossing exists");
      p.crossings[x] = { claim: b.claim, branch: b.branch, state: "DENIED", intent_digest: String(pay["intent_digest"]), action: "", hypothetical: false };
      break;
    }
    case "CrossingPrepared": {
      const x = String(pay["crossing"]);
      if (p.crossings[x]) fail("crossing exists");
      p.crossings[x] = { claim: b.claim, branch: b.branch, state: "PREPARED", intent_digest: "", action: "", hypothetical: false };
      break;
    }
    case "CrossingDispatched": case "CrossingUnknown": case "CrossingCancelled": {
      const x = String(pay["crossing"]);
      const c = p.crossings[x] ?? fail("crossing missing");
      const to = b.kind === "CrossingDispatched" ? "DISPATCHED" : b.kind === "CrossingUnknown" ? "UNKNOWN" : "CANCELLED";
      const allowed = to === "DISPATCHED" ? ["PREPARED"] : to === "UNKNOWN" ? ["DISPATCHED"] : ["PREPARED"];
      if (!allowed.includes(c.state)) fail(`illegal crossing transition ${c.state}->${to}`);
      c.state = to;
      break;
    }
    case "CrossingCompleted": case "CrossingFailed": {
      const x = String(pay["crossing"]);
      const c = p.crossings[x] ?? fail("crossing missing");
      const to = b.kind === "CrossingCompleted" ? "COMPLETED" : "FAILED";
      const prev = String(pay["previous"]);
      const allowed = prev === "DISPATCHED" ? ["DISPATCHED"] : prev === "UNKNOWN" ? ["UNKNOWN"] : ["PREPARED"];
      if (!allowed.includes(c.state) || c.state !== prev) fail(`illegal crossing transition ${c.state}->${to} via ${prev}`);
      c.state = to;
      break;
    }
    case "StatePatched": {
      const s = streamOf(p, b.claim, b.branch);
      if (s.state_rev !== String(pay["expected_rev"])) fail("state revision conflict in history");
      const st = p.state[sk] ?? (p.state[sk] = {});
      for (const op of pay["patch"] as JsonValue[]) {
        const o = op as Record<string, JsonValue>;
        if (o["op"] === "set") st[String(o["key"])] = o["value"]!;
        else if (o["op"] === "delete") delete st[String(o["key"])];
        else fail("unknown patch op");
      }
      s.state_rev = String(pay["new_rev"]);
      break;
    }
    case "ObjectImported": {
      const key = `${String(pay["destination"])}/${String(pay["object"])}`;
      if (p.objects[key]) fail("object exists");
      p.objects[key] = { digest: String(pay["digest"]), size: "", schema: String(pay["schema"]), state: "COMMITTED" };
      break;
    }
    case "ObservationRecorded": break; // bytes availability tracked by the object inventory
    case "WorkerStatusChanged": {
      const w = String(pay["worker"]);
      const from = String(pay["from"]), to = String(pay["to"]);
      const cur = p.workers[w];
      const allowed: Record<string, string[]> = {
        STARTING: ["RUNNING", "FAILED", "LOST"],
        RUNNING: ["STOPPING", "EXITED", "LOST"],
        STOPPING: ["KILLED", "LOST"],
        LOST: ["EXITED", "KILLED"],
      };
      if (!cur) {
        if (from !== "absent" && to !== "STARTING") fail("worker must begin STARTING");
      } else {
        if (cur.status !== from || !(allowed[from] ?? []).includes(to)) fail(`illegal worker transition ${from}->${to}`);
      }
      p.workers[w] = { claim: b.claim, status: to, profile: "", epoch: "" };
      break;
    }
    case "BranchCreated": {
      const br = String(pay["branch"]);
      const bkey = skey(b.claim, br);
      if (p.streams[bkey]) fail("branch exists");
      const parent = pay["parent"] as Record<string, JsonValue>;
      const pkey = skey(String(parent["claim"]), String(parent["branch"]));
      p.streams[bkey] = { state_rev: p.streams[pkey]?.state_rev ?? "0", auth_rev: p.streams[pkey]?.auth_rev ?? "0", status: "OPEN" };
      p.state[bkey] = JSON.parse(JSON.stringify(p.state[pkey] ?? {})) as Record<string, JsonValue>;
      break;
    }
    case "BranchStatusChanged": {
      const br = streamOf(p, b.claim, String(pay["branch"]));
      const from = String(pay["from"]), to = String(pay["to"]);
      if (br.status !== from || !(BRANCH_TRANSITIONS[from] ?? []).includes(to)) fail(`illegal branch transition ${from}->${to}`);
      br.status = to;
      break;
    }
    case "SnapshotCreated": {
      const s = String(pay["snapshot"]);
      if (p.snapshots[s]) fail("snapshot exists");
      p.snapshots[s] = { claim: b.claim, status: String(pay["verification"]), through_seq: "", manifest_digest: String(pay["manifest_digest"]), verified_copies: 0 };
      break;
    }
    case "ArchiveCommitted": {
      const s = p.snapshots[String(pay["snapshot"])] ?? fail("snapshot missing");
      if (s.status !== "VERIFIED") fail("archive requires VERIFIED snapshot");
      s.status = "ARCHIVED";
      s.verified_copies = Number(pay["verified_copies"]);
      break;
    }
    case "PruneCommitted": break; // retention evidence; bodies pruned by storage layer
    case "WriterStarted": {
      p.host.writer_epoch = String(pay["writer_epoch"]);
      p.host.store = String(pay["store"]);
      break;
    }
    case "HostStatusChanged": {
      p.host.status = String(pay["to"]);
      break;
    }
    case "KeyRotated": break; // timeline rows updated by governance path
    case "RecoveryAccepted": break;
    case "MigrationStatusChanged": break;
    case "AuditReleased": case "ReceiptExported": break;
    default:
      fail(`unknown event kind ${b.kind}`);
  }
  return p;
}

/** Reduce a verified event sequence from genesis (or an empty base). */
export function reduce(events: Envelope[], base?: Projection): Projection {
  const p = base ?? emptyProjection();
  for (const e of events) reduceEvent(p, e);
  return p;
}

export function stateRootOf(p: Projection, claim: string, branch: string): string {
  return sha256Hex(jcsBytes((p.state[skey(claim, branch)] ?? {}) as JsonValue));
}

export function authRootOf(p: Projection): string {
  const auth = {
    claims: p.claims, principals: p.principals, capabilities: p.capabilities,
    fences: p.fences, policies: p.policies, active_policy: p.active_policy,
    streams: Object.fromEntries(Object.entries(p.streams).map(([k, v]) => [k, { state_rev: v.state_rev, auth_rev: v.auth_rev, status: v.status }])),
  } as unknown as JsonValue;
  return sha256Hex(jcsBytes(auth));
}

export function reservationRootOf(p: Projection): string {
  const res = {
    crossings: Object.fromEntries(Object.entries(p.crossings).filter(([, c]) => ["PREPARED", "DISPATCHED", "UNKNOWN"].includes(c.state))),
  } as unknown as JsonValue;
  return sha256Hex(jcsBytes(res));
}

// ---------- SQLite projection mirror ----------

/** Apply the same transition to the SQL projection inside the append tx. */
export function applyEventSql(store: Store, env: Envelope): void {
  const b = env.body;
  const pay = b.payload as Record<string, JsonValue>;
  const claim = b.claim, branch = b.branch;

  /** auth_rev is claim-scoped: bump every stream of the affected claim. */
  const bumpAuth = (forClaim: string) =>
    store.run("UPDATE streams SET auth_rev=CAST(CAST(auth_rev AS INTEGER)+1 AS TEXT) WHERE claim=?", forClaim);

  switch (b.kind) {
    case "ClaimCreated":
      store.run("INSERT INTO claims(claim,status,owner,generation) VALUES(?,?,?,'1')", claim, "ACTIVE", String(pay["owner"]));
      store.run("UPDATE streams SET state_rev=?,auth_rev=? WHERE claim=? AND branch=?", String(pay["state_rev"]), String(pay["auth_rev"]), claim, branch);
      break;
    case "ClaimStatusChanged":
      store.run("UPDATE claims SET status=?,generation=CAST(CAST(generation AS INTEGER)+1 AS TEXT) WHERE claim=?", String(pay["to"]), claim);
      bumpAuth(claim);
      break;
    case "PrincipalRegistered":
      store.run("INSERT INTO principals(principal,type,uid,channel,status,generation) VALUES(?,?,?,?,?, '1')",
        String(pay["principal"]), String(pay["type"]), pay["uid"] === undefined || pay["uid"] === null ? null : Number(pay["uid"]), pay["channel"] === undefined || pay["channel"] === null ? null : String(pay["channel"]), "ENABLED");
      break;
    case "PrincipalDisabled":
      store.run("UPDATE principals SET status='DISABLED',generation=? WHERE principal=?", String(pay["generation"]), String(pay["principal"]));
      break;
    case "CapabilityIssued": {
      const grant = pay["grant"] as JsonObject;
      const gclaim = String(grant["claim"]);
      const enc = sealAead(store.claimKey(gclaim), jcsBytes(grant), Buffer.from(`grant/${gclaim}/${String(pay["capability"])}`));
      store.run("INSERT INTO capabilities(capability,claim,subject,parent,grant_enc,generation,status) VALUES(?,?,?,?,?,'1','ISSUED')",
        String(pay["capability"]), gclaim, String(grant["subject"]), grant["parent"] as string | null, enc);
      bumpAuth(gclaim);
      break;
    }
    case "CapabilityRevoked": {
      const row = store.get<{ claim: string }>("SELECT claim FROM capabilities WHERE capability=?", String(pay["capability"]));
      store.run("UPDATE capabilities SET status='REVOKED',generation=?,revoke_reason=? WHERE capability=?",
        String(pay["generation"]), String(pay["reason"]), String(pay["capability"]));
      if (row) bumpAuth(row.claim);
      break;
    }
    case "FenceConfigured": {
      const f = pay["fence"] as JsonObject;
      store.run("UPDATE fences SET status='SUPERSEDED' WHERE claim=? AND id=? AND status='ACTIVE'", claim, String(f["id"]));
      store.run("INSERT INTO fences(claim,id,version,fence_json,status) VALUES(?,?,?,?,'ACTIVE')",
        claim, String(f["id"]), Number(f["version"]), jcsString(f));
      break;
    }
    case "PolicyActivated": {
      const pid = String(pay["policy"]);
      const pred = pay["predecessor"];
      if (pred !== null && pred !== undefined) {
        store.run("UPDATE policies SET status='SUPERSEDED' WHERE policy=?", String(pred));
      }
      store.run(
        "INSERT INTO policies(policy,epoch,bundle_json,bundle_digest,enforcer_digest,predecessor,ceremony,status,activation_commit) VALUES(?,?,?,?,?,?,?,'ACTIVE',?) ON CONFLICT(policy) DO UPDATE SET status='ACTIVE',activation_commit=excluded.activation_commit",
        pid, String(pay["epoch"]), store.getMeta(`policy_bundle:${pid}`) ?? "{}", String(pay["bundle_digest"]), String(pay["enforcer_digest"]),
        pred === undefined ? null : (pred as string | null), String(pay["approval"]), env.hash);
      store.setMeta("active_policy", pid);
      break;
    }
    case "SimulationRecorded": {
      const enc = sealAead(store.claimKey(claim), jcsBytes(pay), Buffer.from(`report/${claim}/${String(pay["report"])}`));
      store.run("INSERT INTO simulations(report,claim,branch,intent_digest,report_enc,state,expires_tick) VALUES(?,?,?,?,?,'AVAILABLE',?)",
        String(pay["report"]), claim, String(pay["branch"]), String(pay["intent_digest"]), enc, String(pay["expires_tick"]));
      break;
    }
    case "CrossingDenied":
      store.run("INSERT INTO crossings(crossing,claim,branch,report,state,intent_digest,action) VALUES(?,?,?,NULL,'DENIED',?,?)",
        String(pay["crossing"]), claim, branch, String(pay["intent_digest"]), "");
      break;
    case "CrossingPrepared": {
      const rep = store.get<{ intent_digest: string }>("SELECT intent_digest FROM simulations WHERE report=?", String(pay["report"]));
      store.run("INSERT INTO crossings(crossing,claim,branch,report,state,intent_digest,action) VALUES(?,?,?,?,'PREPARED',?,?)",
        String(pay["crossing"]), claim, branch, String(pay["report"]), rep?.intent_digest ?? "", store.getMeta(`action:${String(pay["crossing"])}`) ?? "");
      break;
    }
    case "CrossingDispatched":
      store.run("UPDATE crossings SET state='DISPATCHED',dispatch_epoch=?,adapter_request_digest=?,deadline_tick=? WHERE crossing=?",
        String(pay["dispatch_epoch"]), String(pay["adapter_request_digest"]), String(pay["deadline_tick"]), String(pay["crossing"]));
      break;
    case "CrossingCompleted": case "CrossingFailed": {
      const to = b.kind === "CrossingCompleted" ? "COMPLETED" : "FAILED";
      const res = sealAead(store.claimKey(claim), jcsBytes(pay), Buffer.from(`crossing-result/${claim}/${String(pay["crossing"])}`));
      store.run("UPDATE crossings SET state=?,evidence_json=?,result_enc=? WHERE crossing=?",
        to, jcsString(pay["evidence"]!), res, String(pay["crossing"]));
      break;
    }
    case "CrossingUnknown":
      store.run("UPDATE crossings SET state='UNKNOWN',evidence_json=? WHERE crossing=?",
        jcsString(pay["evidence"]!), String(pay["crossing"]));
      break;
    case "CrossingCancelled":
      store.run("UPDATE crossings SET state='CANCELLED' WHERE crossing=?", String(pay["crossing"]));
      break;
    case "StatePatched": {
      const s = store.get<{ state_rev: string }>("SELECT state_rev FROM streams WHERE claim=? AND branch=?", claim, branch);
      if (!s || s.state_rev !== String(pay["expected_rev"])) {
        throw new WorldError("REVISION_CONFLICT", "StatePatched expected_rev does not match the stream.");
      }
      for (const op of pay["patch"] as JsonValue[]) {
        const o = op as JsonObject;
        const key = String(o["key"]);
        if (o["op"] === "set") {
          const enc = sealAead(store.claimKey(claim), jcsBytes(o["value"]!), Buffer.from(`kv/${claim}/${branch}/${key}`));
          store.run("INSERT INTO kv_state(claim,branch,key,value_enc) VALUES(?,?,?,?) ON CONFLICT(claim,branch,key) DO UPDATE SET value_enc=excluded.value_enc",
            claim, branch, key, enc);
        } else if (o["op"] === "delete") {
          store.run("DELETE FROM kv_state WHERE claim=? AND branch=? AND key=?", claim, branch, key);
        } else {
          throw new WorldError("REDUCER_FAILED", `Unknown patch op ${String(o["op"])}.`);
        }
      }
      store.run("UPDATE streams SET state_rev=? WHERE claim=? AND branch=?", String(pay["new_rev"]), claim, branch);
      break;
    }
    case "ObjectImported": {
      const obj = store.get<{ digest: string; size: string; schema: string | null }>(
        "SELECT digest,size,schema FROM objects WHERE claim=? AND object=? AND state='STAGED'",
        String(pay["destination"]), String(pay["object"]));
      if (!obj || obj.digest !== String(pay["digest"])) {
        throw new WorldError("REDUCER_FAILED", "ObjectImported without matching staged object.");
      }
      store.run("UPDATE objects SET state='COMMITTED',lineage_json=? WHERE claim=? AND object=?",
        jcsString({ source: pay["source"], destination: pay["destination"], schema: pay["schema"], crossing: pay["crossing"] } as JsonObject),
        String(pay["destination"]), String(pay["object"]));
      break;
    }
    case "ObservationRecorded":
      store.run("INSERT INTO observations(observation,claim,object,digest,bytes) VALUES(?,?,?,?,?)",
        String(pay["observation"]), claim, String(pay["object"]), String(pay["digest"]), String(pay["bytes"]));
      break;
    case "WorkerStatusChanged":
      store.run("UPDATE workers SET status=? WHERE worker=?", String(pay["to"]), String(pay["worker"]));
      break;
    case "BranchCreated": {
      const parent = pay["parent"] as JsonObject;
      const ps = store.get<{ state_rev: string; auth_rev: string }>("SELECT state_rev,auth_rev FROM streams WHERE claim=? AND branch=?",
        String(parent["claim"]), String(parent["branch"]));
      // journal.createStream pre-created the row so the first append has a
      // head to chain from; the event fills in the inherited revisions.
      store.run("UPDATE streams SET state_rev=?,auth_rev=?,status='OPEN' WHERE claim=? AND branch=?",
        ps?.state_rev ?? "0", ps?.auth_rev ?? "0", claim, String(pay["branch"]));
      // Branch state is a private copy of the parent's cut (simulation-only).
      store.run("INSERT INTO kv_state(claim,branch,key,value_enc) SELECT ?,?,key,value_enc FROM kv_state WHERE claim=? AND branch=?",
        claim, String(pay["branch"]), String(parent["claim"]), String(parent["branch"]));
      break;
    }
    case "BranchStatusChanged":
      store.run("UPDATE streams SET status=? WHERE claim=? AND branch=?", String(pay["to"]), claim, String(pay["branch"]));
      break;
    case "SnapshotCreated":
      // The snapshot row exists from snapshot.create (BUILDING); the event
      // marks independent verification success.
      store.run("UPDATE snapshots SET status='VERIFIED',manifest_digest=? WHERE snapshot=?",
        String(pay["manifest_digest"]), String(pay["snapshot"]));
      break;
    case "ArchiveCommitted":
      store.run("UPDATE snapshots SET status='ARCHIVED',verified_copies=? WHERE snapshot=?",
        Number(pay["verified_copies"]), String(pay["snapshot"]));
      break;
    case "PruneCommitted":
      store.run("INSERT INTO tombstones(namespace,id,data_json) VALUES('prune',?,?) ON CONFLICT(namespace,id) DO UPDATE SET data_json=excluded.data_json",
        `${claim}/${branch}/${String(pay["from_seq"])}-${String(pay["through_seq"])}`, jcsString(pay));
      store.run("DELETE FROM events WHERE claim=? AND branch=? AND CAST(seq AS INTEGER) BETWEEN ? AND ?",
        claim, branch, Number(pay["from_seq"]), Number(pay["through_seq"]));
      break;
    case "WriterStarted":
      store.setMeta("writer_epoch", String(pay["writer_epoch"]));
      store.setMeta("store_id", String(pay["store"]));
      break;
    case "HostStatusChanged":
      store.setMeta("host_status", String(pay["to"]));
      break;
    case "KeyRotated": {
      const retired = pay["retired"] as JsonObject, active = pay["active"] as JsonObject;
      store.run("UPDATE writer_keys SET status='RETIRED',retired_through_epoch=? WHERE key_id=?",
        String(retired["through_epoch"]), String(retired["key_id"]));
      store.setMeta("active_writer_key", String(active["key_id"]));
      break;
    }
    case "RecoveryAccepted":
      store.setMeta("recovery", jcsString(pay));
      break;
    case "MigrationStatusChanged":
      store.run("UPDATE migrations SET status=? WHERE migration=?", String(pay["to"]), String(pay["migration"]));
      break;
    case "AuditReleased":
      store.run("INSERT INTO tombstones(namespace,id,data_json) VALUES('audit',?,?) ON CONFLICT(namespace,id) DO NOTHING",
        `${String(pay["reader"])}/${String(pay["digest"])}`, jcsString(pay));
      break;
    case "ReceiptExported":
      store.run("INSERT INTO tombstones(namespace,id,data_json) VALUES('receipt',?,?) ON CONFLICT(namespace,id) DO NOTHING",
        String(pay["bundle"]), jcsString(pay));
      break;
    default:
      throw new WorldError("UNKNOWN_EVENT_SCHEMA", `Unknown kind ${b.kind}.`);
  }
}
