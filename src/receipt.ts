/**
 * world-lineage/1 receipts (spec §9.2).
 *
 * A receipt bundles the crossing's intent, bound simulation, authority cut,
 * preparation/dispatch evidence, result, dependencies, checkpoints, and
 * artifact inventory. Verification performs no fetching, no executable
 * deserialization, and no live provider reconciliation.
 */

import { intentDigestHex } from "./crypto.js";
import { jcsBytes, jcsString, type JsonValue, type JsonObject } from "./canon.js";
import { WorldError } from "./errors.js";
import type { Store } from "./store.js";
import type { Journal, Envelope } from "./journal.js";

export function buildLineageReceipt(store: Store, journal: Journal, claim: string, branch: string, crossing: string, includePayloads: boolean): JsonObject {
  const x = store.get<{ state: string; intent_digest: string; report: string | null; evidence_json: string | null }>(
    "SELECT state,intent_digest,report,evidence_json FROM crossings WHERE crossing=? AND claim=?", crossing, claim);
  if (!x) throw new WorldError("NOT_FOUND", `Unknown crossing ${crossing}.`);

  const envs: Envelope[] = [];
  const rows = store.all<{ seq: string; kind: string }>(
    "SELECT seq,kind FROM events WHERE claim=? AND branch=? ORDER BY CAST(seq AS INTEGER)", claim, branch);
  for (const r of rows) {
    const e = journal.eventAt(claim, branch, r.seq)!;
    const p = e.body.payload as JsonObject;
    if (String(p["crossing"] ?? "") === crossing || (x.report && String(p["report"] ?? "") === x.report)) {
      envs.push(e);
    }
  }
  const events = envs.map((e) => ({
    hash: e.hash, kind: e.body.kind, seq: e.body.seq,
    envelope: includePayloads ? (JSON.parse(journal.envelopeJson(e)) as JsonValue) : null,
  }));

  const report = x.report ? store.getMeta(`report_full:${x.report}`) : undefined;
  const reportJson = report ? (JSON.parse(report) as JsonObject) : null;
  const intent = reportJson ? (reportJson["intent"] as JsonObject) : null;

  return {
    world: journal.world, claim, branch, crossing,
    intent: intent ? { canonical: jcsString(intent), digest: x.intent_digest } : { canonical: null, digest: x.intent_digest },
    simulation: reportJson
      ? {
          report: x.report, engine_digest: reportJson["engine_digest"] ?? null, model_digest: reportJson["model_digest"] ?? null,
          read_set: reportJson["read_set"] ?? null, auth_set: reportJson["auth_set"] ?? null,
          checks: reportJson["checks"] ?? null, result: reportJson["result"] ?? null, consumed_by: crossing,
        }
      : null,
    authority: reportJson ? { auth_set: reportJson["auth_set"] ?? null, fence_versions: reportJson["fence_versions"] ?? null, policy_id: reportJson["policy_id"] ?? null } : null,
    preparation: events.filter((e) => e.kind === "CrossingPrepared").map((e) => e.hash),
    dispatch: events.filter((e) => e.kind === "CrossingDispatched").map((e) => e.hash)[0] ?? null,
    result: {
      state: x.state,
      evidence: x.evidence_json ? (JSON.parse(x.evidence_json) as JsonValue) : null,
      hypothetical: false,
    },
    dependencies: envs.flatMap((e) => e.body.causes.map((c) => ({ caused_by: `${c.claim}/${c.branch}/${c.seq}`, hash: c.hash }))),
    checkpoints: { head: journal.head(claim, branch)?.headHash ?? null },
    artifacts: store.all<{ object: string; digest: string; size: string; state: string }>(
      "SELECT object,digest,size,state FROM objects WHERE claim=?", claim)
      .map((o) => ({ object: o.object, sha256: o.digest, bytes: o.size, state: o.state, plaintext_included: includePayloads })),
    disclosure: includePayloads ? "FULL" : "HASHES_ONLY",
  };
}

/** Offline receipt verification: structure + digests only, no I/O. When a
 * trust file is supplied, bundle scope must match it exactly. */
export function verifyReceiptBundle(bundle: JsonValue, trust?: { world: string; scope: { claim: string; branch: string } }): { verification: string; effects_enabled: false } {
  if (typeof bundle !== "object" || bundle === null) {
    throw new WorldError("HASH_MISMATCH", "Receipt bundle is not an object.");
  }
  const b = bundle as JsonObject;
  for (const k of ["world", "claim", "branch", "crossing", "intent", "simulation", "authority", "preparation", "dispatch", "result", "dependencies", "checkpoints", "artifacts", "disclosure"]) {
    if (!(k in b)) throw new WorldError("SCHEMA_VALIDATION", `Receipt missing ${k}.`);
  }
  if (trust) {
    if (b["world"] !== trust.world || b["claim"] !== trust.scope.claim || b["branch"] !== trust.scope.branch) {
      throw new WorldError("CHAIN_MISMATCH", "Bundle scope does not match the trust file.");
    }
  }
  const intent = b["intent"] as JsonObject;
  if (intent && intent["canonical"]) {
    const d = intentDigestHex(JSON.parse(String(intent["canonical"])) as JsonValue);
    if (d !== intent["digest"]) {
      return { verification: "INVALID", effects_enabled: false };
    }
  }
  return { verification: "FULL_REPLAY", effects_enabled: false };
}
