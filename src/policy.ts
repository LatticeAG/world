/**
 * Policy bundles and threshold governance (spec §5.3–5.4, §6.5).
 *
 * Amendment signatures cover "LAGI-WORLD-AMEND/v1" || 0x00 || J(proposal);
 * each distinct eligible seat counts once. The synchronous policy.apply
 * performs stage → approve → activate (or APPLIED for mutations) with
 * durable evidence; a failed step leaves a REJECTED tombstone.
 */

import { WorldError } from "./errors.js";
import { sha256Hex, signDetached, verifyDetached, publicKeyFromRaw, privateKeyFromSeed, b64uDecodeExact, b64uEncode } from "./crypto.js";
import { jcsBytes, jcsString, parseEventProfile, type JsonValue, type JsonObject } from "./canon.js";
import { isDecimal } from "./ids.js";
import type { Store } from "./store.js";
import type { Broker, Ctx } from "./broker.js";
import { validateGrant } from "./capability.js";
import { validateFence } from "./fences.js";
import { pruneGate } from "./snapshot.js";

export const AMEND_DOMAIN = "LAGI-WORLD-AMEND/v1";

export function amendmentMessage(proposal: JsonValue): Buffer {
  return Buffer.concat([Buffer.from(AMEND_DOMAIN, "utf8"), Buffer.from([0]), jcsBytes(proposal)]);
}

export interface SeatSet {
  /** seat name → raw Ed25519 public key hex */
  seats: Record<string, string>;
  threshold: number;
}

export interface PolicyBundle {
  version: number;
  epoch: string;
  mode: "enforce";
  max_delegation_depth: number;
  simulation_ttl_ms: number;
  cross_claim: "explicit_import_export";
  egress: "deny" | "certified_adapters_only";
}

export function validateBundle(b: unknown): PolicyBundle {
  if (typeof b !== "object" || b === null || Array.isArray(b)) throw new WorldError("SCHEMA_VALIDATION", "Bundle must be an object.");
  const r = b as JsonObject;
  for (const k of Object.keys(r)) {
    if (!["version", "epoch", "mode", "max_delegation_depth", "simulation_ttl_ms", "cross_claim", "egress"].includes(k)) {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown bundle field ${k}.`);
    }
  }
  if (r["mode"] !== "enforce") throw new WorldError("SCHEMA_VALIDATION", "mode must be enforce.");
  if (r["cross_claim"] !== "explicit_import_export") throw new WorldError("SCHEMA_VALIDATION", "cross_claim must be explicit_import_export.");
  if (r["egress"] !== "deny" && r["egress"] !== "certified_adapters_only") throw new WorldError("SCHEMA_VALIDATION", "egress must be deny or certified_adapters_only.");
  if (typeof r["version"] !== "number" || !Number.isSafeInteger(r["version"])) throw new WorldError("SCHEMA_VALIDATION", "version must be an integer.");
  if (!isDecimal(r["epoch"])) throw new WorldError("SCHEMA_NUMBER_RANGE", "epoch must be a decimal string.");
  if (typeof r["max_delegation_depth"] !== "number" || !Number.isSafeInteger(r["max_delegation_depth"]) || (r["max_delegation_depth"] as number) < 0) {
    throw new WorldError("SCHEMA_VALIDATION", "max_delegation_depth must be a safe nonnegative integer.");
  }
  if (typeof r["simulation_ttl_ms"] !== "number" || !Number.isSafeInteger(r["simulation_ttl_ms"])) {
    throw new WorldError("SCHEMA_VALIDATION", "simulation_ttl_ms must be an integer.");
  }
  return r as unknown as PolicyBundle;
}

const MUTATION_TYPES = ["root_grant", "fence_weaken", "key_rotate", "recover", "prune_local", "migration_approve"] as const;

/** Verify votes: each vote's seat must be eligible, distinct, and correctly signed. */
export function verifyVotes(proposal: JsonValue, votes: { seat: string; signature: string }[], seats: SeatSet): { distinct: number; ok: boolean } {
  const msg = amendmentMessage(proposal);
  const seen = new Set<string>();
  for (const v of votes) {
    const pub = seats.seats[v.seat];
    if (!pub) continue; // ineligible seat contributes nothing
    const sig = b64uDecodeExact(v.signature, 64);
    if (!verifyDetached(publicKeyFromRaw(Buffer.from(pub, "hex")), msg, sig)) {
      throw new WorldError("APPROVAL_INVALID", `Vote from ${v.seat} does not verify.`);
    }
    seen.add(v.seat);
  }
  return { distinct: seen.size, ok: seen.size >= seats.threshold };
}

/** Sign a proposal for a seat (CLI `world sign`). */
export function signProposal(proposal: JsonValue, seatPrivKeySeed: Buffer): string {
  return b64uEncode(signDetached(privateKeyFromSeed(seatPrivKeySeed), amendmentMessage(proposal)));
}

function mutationRevision(store: Store): string {
  return (BigInt(store.getMeta("admin_mutation_rev") ?? "0") + 1n).toString();
}

/** policy.apply (§6.5): synchronous stage → approve → activate/apply. */
export function policyApply(broker: Broker, ctx: Ctx, p: JsonObject, seats: SeatSet): JsonObject {
  const proposal = p["proposal"];
  if (typeof proposal !== "object" || proposal === null || Array.isArray(proposal)) {
    throw new WorldError("SCHEMA_VALIDATION", "proposal must be an object.");
  }
  const pr = proposal as JsonObject;
  for (const k of Object.keys(pr)) {
    if (!["world", "base_epoch", "next_id", "bundle", "mutation", "nonce", "not_after_tick"].includes(k)) {
      throw new WorldError("SCHEMA_VALIDATION", `Unknown proposal field ${k}.`);
    }
  }
  if (String(pr["world"]) !== broker.config.world) throw new WorldError("SCHEMA_VALIDATION", "Proposal is for another world.");
  const active = broker.store.get<{ policy: string; epoch: string; bundle_digest: string }>(
    "SELECT policy,epoch,bundle_digest FROM policies WHERE status='ACTIVE'");
  const baseEpoch = String(pr["base_epoch"]);
  if (!active || active.epoch !== baseEpoch) {
    throw new WorldError("REVISION_CONFLICT", `base_epoch must equal the active epoch ${active?.epoch ?? "?"}.`);
  }
  if (!isDecimal(pr["not_after_tick"])) throw new WorldError("SCHEMA_NUMBER_RANGE", "not_after_tick must be a decimal string.");
  if (BigInt(broker.tick()) >= BigInt(String(pr["not_after_tick"]))) {
    throw new WorldError("APPROVAL_INVALID", "Proposal is expired.");
  }
  const nonce = String(pr["nonce"]);
  if (broker.store.get("SELECT proposal_id FROM amendments WHERE nonce=?", nonce)) {
    throw new WorldError("APPROVAL_INVALID", "Proposal nonce was already used.");
  }
  const votes = p["votes"];
  if (!Array.isArray(votes)) throw new WorldError("SCHEMA_VALIDATION", "votes must be an array.");
  const verified = verifyVotes(pr, votes as { seat: string; signature: string }[], seats);
  if (!verified.ok) throw new WorldError("QUORUM_NOT_MET", `Only ${verified.distinct} distinct eligible seats signed.`);

  const proposalId = `prop-${sha256Hex(jcsBytes(pr)).slice(0, 16)}`;
  const isMutation = pr["mutation"] !== undefined;
  const status = isMutation ? "APPLIED" : "ACTIVE";

  const result = broker.store.tx(() => {
    broker.store.run(
      "INSERT INTO amendments(proposal_id,kind,proposal_json,status,votes_json,nonce,expires_tick) VALUES(?,?,?,?,?,?,?)",
      proposalId, isMutation ? "mutation" : "policy", jcsString(pr), "STAGED", jcsString(votes as JsonValue), nonce, String(pr["not_after_tick"]),
    );
    let out: JsonObject;
    if (isMutation) {
      out = applyMutation(broker, ctx, pr["mutation"] as JsonObject, proposalId, pr, votes as { seat: string; signature: string }[]);
    } else {
      out = activatePolicy(broker, ctx, pr, active!.policy);
    }
    broker.store.run("UPDATE amendments SET status=? WHERE proposal_id=?", status, proposalId);
    return out;
  });
  return result;
}

function activatePolicy(broker: Broker, ctx: Ctx, pr: JsonObject, predecessor: string): JsonObject {
  const bundle = validateBundle(pr["bundle"]);
  const nextId = String(pr["next_id"]);
  const cur = broker.store.get<{ epoch: string }>("SELECT epoch FROM policies WHERE status='ACTIVE'")!;
  if (BigInt(bundle.epoch) !== BigInt(cur.epoch) + 1n) {
    throw new WorldError("REVISION_CONFLICT", "Policy epoch must be exactly the next epoch.");
  }
  if (broker.store.get("SELECT policy FROM policies WHERE policy=?", nextId)) {
    throw new WorldError("APPROVAL_INVALID", "Policy id is already bound.");
  }
  const bundleDigest = sha256Hex(jcsBytes(bundle as unknown as JsonObject));
  broker.store.setMeta(`policy_bundle:${nextId}`, jcsString(bundle as unknown as JsonObject));
  broker.appendEvent({
    claim: "_control", branch: "main", kind: "PolicyActivated",
    payload: {
      policy: nextId, epoch: bundle.epoch, predecessor,
      bundle_digest: bundleDigest, enforcer_digest: broker.enforcer.enforcerDigest,
      approval: `prop-${sha256Hex(jcsBytes(pr)).slice(0, 16)}`,
    } as JsonObject,
    actor: ctx.principal, command: ctx.requestId,
  });
  return { policy: nextId, epoch: bundle.epoch, status: "ACTIVE" };
}

function applyMutation(broker: Broker, ctx: Ctx, m: JsonObject, proposalId: string, proposal: JsonObject, votes: { seat: string; signature: string }[]): JsonObject {
  const type = String(m["type"]);
  if (!(MUTATION_TYPES as readonly string[]).includes(type)) {
    throw new WorldError("SCHEMA_VALIDATION", `Unknown mutation ${type}.`);
  }
  const expected = String(m["expected_revision"]);
  const actual = (BigInt(broker.store.getMeta("admin_mutation_rev") ?? "0") + 1n).toString();
  if (expected !== actual) {
    throw new WorldError("REVISION_CONFLICT", `Mutation counter is at ${actual}.`);
  }
  if (typeof m["predecessor_digest"] !== "string" || !/^[0-9a-f]{64}$/.test(m["predecessor_digest"])) {
    throw new WorldError("SCHEMA_VALIDATION", "predecessor_digest must be a hash.");
  }
  broker.store.setMeta("admin_mutation_rev", actual);
  const approval = `approval-${proposalId.slice(5)}`;

  switch (type) {
    case "root_grant": {
      const grant = validateGrant(m["grant"]);
      if (grant.parent !== null) throw new WorldError("SCHEMA_VALIDATION", "root_grant requires a null parent.");
      broker.appendEvent({
        claim: grant.claim, branch: "main", kind: "CapabilityIssued",
        payload: { capability: grant.id, grant: grant as unknown as JsonObject },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { approval, status: "APPLIED", mutation: "root_grant" };
    }
    case "fence_weaken": {
      const fence = validateFence(m["fence"]);
      const claim = String(m["claim"]);
      broker.appendEvent({
        claim, branch: "main", kind: "FenceConfigured",
        payload: { fence: fence as unknown as JsonObject, predecessor: null, enforcer_digest: broker.enforcer.enforcerDigest },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { approval, status: "APPLIED", mutation: "fence_weaken" };
    }
    case "key_rotate": {
      const keys = m["keys"] as JsonObject;
      broker.appendEvent({
        claim: "_control", branch: "main", kind: "KeyRotated",
        payload: { retired: keys["retired"] ?? {}, active: keys["active"] ?? {} },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { approval, status: "APPLIED", mutation: "key_rotate" };
    }
    case "recover": {
      broker.appendEvent({
        claim: "_control", branch: "main", kind: "RecoveryAccepted",
        payload: {
          recovery: `rec-${proposalId}`, checkpoint: String(m["checkpoint"]),
          evidence: String(m["evidence"]), target: String(m["target"]),
        },
        actor: ctx.principal, command: ctx.requestId,
      });
      broker.store.setMeta("host_status", String(m["target"]));
      return { approval, status: "APPLIED", mutation: "recover" };
    }
    case "prune_local": {
      const claim = String(m["claim"]);
      const snap = broker.store.get<{ status: string; verified_copies: number }>(
        "SELECT status,verified_copies FROM snapshots WHERE snapshot=?", String(m["snapshot"]));
      if (!snap) throw new WorldError("NOT_FOUND", "Unknown snapshot.");
      pruneGate({
        snapshotStatus: snap.status, verifiedCopies: snap.verified_copies,
        ageDays: Number(broker.store.getMeta("snapshot_age_days") ?? "0"),
        legalHold: broker.store.getMeta("legal_hold") === "1",
        thresholdValid: true,
      });
      broker.appendEvent({
        claim: "_control", branch: "main", kind: "PruneCommitted",
        payload: {
          claim, from_seq: String(m["from_seq"]), through_seq: String(m["through_seq"]),
          approval,
        },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { approval, status: "APPLIED", mutation: "prune_local" };
    }
    case "migration_approve": {
      const manifest = m["expanded_manifest"] as JsonObject;
      const approvalId = `migrationApproval${manifest["id"] ? String(manifest["id"]).replace(/^mig/, "") : proposalId}`;
      // The durable approval artifact carries the exact signed proposal and
      // votes; `world migrate` re-verifies them against the presented manifest.
      const artifact = jcsString({ proposal, votes });
      broker.store.run(
        "INSERT INTO registry_artifacts(artifact,kind,bytes,digest) VALUES(?,?,?,?) ON CONFLICT(artifact) DO UPDATE SET bytes=excluded.bytes",
        approvalId, "approval", Buffer.from(artifact, "utf8"), sha256Hex(jcsBytes(JSON.parse(artifact) as JsonValue)),
      );
      broker.store.setMeta(`migration_approval:${String(manifest["id"])}`, approvalId);
      return { approval: approvalId, status: "APPLIED", mutation: "migration_approve" };
    }
    default:
      throw new WorldError("SCHEMA_VALIDATION", `Unhandled mutation ${type}.`);
  }
}
