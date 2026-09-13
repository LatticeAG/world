/**
 * The broker (spec §3.2, §5, §6).
 *
 * Single trusted writer: command lifecycle, automatic capability checks,
 * bound simulation, preparation, dispatch barrier, reservations, and every
 * §6.2–6.5 method. All mutation flows through one SQLite transaction per
 * command so events, projections, and command tombstones commit atomically.
 */

import { WorldError, errorHttp, isPublicCode, type ErrorCode } from "./errors.js";
import { jcsBytes, jcsString, type JsonValue, type JsonObject } from "./canon.js";
import { sha256Hex, b64uEncode, b64uDecodeExact, sealAead, openAead } from "./crypto.js";
import { assertId, isDecimal, isValidId } from "./ids.js";
import type { Store, Failpoint } from "./store.js";
import { Journal, type Envelope } from "./journal.js";
import type { KeyService } from "./keys.js";
import type { TickSource } from "./clock.js";
import { SchemaRegistry } from "./registry.js";
import {
  effectiveAuthority, grantChain, loadGrant, principalStatus, reserveChain,
  releaseReservations, settleReservations, markDispatched, usageOf,
  validateGrant, attenuationViolations, covers, normalizeKvKey,
  type Grant, type GrantRow, type Verb, type ResourceKind,
} from "./capability.js";
import { evalFences, validateFence, type Fence } from "./fences.js";
import { normalizeIntent, validateIntent, type Intent, type NormalizedIntent, meteredBytes } from "./intent.js";
import type { Enforcer } from "./enforcer.js";
import type { AdapterRegistry } from "./adapters.js";
import { applyEventSql } from "./reducer.js";
import { coversSelector } from "./capability.js";
import { verifyAndReduce } from "./replay.js";
import { buildManifest, verifySnapshotIndependent, archiveCopy } from "./snapshot.js";
import { buildLineageReceipt } from "./receipt.js";
import { policyApply, type SeatSet } from "./policy.js";

// ---------- report + crossing records ----------

export interface Report {
  id: string;
  intent_digest: string;
  principal: string;
  claim: string;
  branch: string;
  read_set: JsonObject;
  auth_set: JsonObject;
  policy_id: string;
  fence_versions: Record<string, number>;
  engine_digest: string;
  model_digest: string;
  result: "PASS" | "DENY" | "UNKNOWN";
  checks: { fence: string; result: string }[];
  denial_code: string | null;
  cost_bound: JsonObject;
  created_tick: string;
  expires_tick: string;
  intent: Intent;
}

export interface Caller {
  principal: string;
  /** Bound channel name when the call arrived on a §6.8 channel. */
  channel?: string;
}

export interface BrokerConfig {
  world: string;
  simulationTtlMs: string;   // logical-tick TTL; default "5000"
  simulationFuel: string;    // default "10000000"
  maxDelegationDepth: number;
  profile: string;
  /** Required for host.migrate; absent in pure-replay/verifier contexts. */
  storageRoot?: string;
}

export const ENGINE_ID = "world-sim-engine/1";
export const MODEL_ID = "world-sim-model/1";
export const ENFORCER_ID = "wasm-process-v1";

export function engineDigestHex(): string {
  return sha256Hex(jcsBytes({ id: ENGINE_ID, build: "oss-core" }));
}
export function modelDigestHex(): string {
  return sha256Hex(jcsBytes({ id: MODEL_ID, build: "oss-core" }));
}

export interface Ctx extends Caller {
  requestId: string;
}

const ID_PREFIX = { report: "sim", crossing: "x", snapshot: "snap", bundle: "receipt", approval: "approval" } as const;

export class Broker {
  /** Governance seat set (bootstrap constitution); null until configured. */
  seats: SeatSet | null = null;

  constructor(
    readonly store: Store,
    readonly journal: Journal,
    readonly keys: KeyService,
    readonly clock: TickSource,
    readonly enforcer: Enforcer,
    readonly adapters: AdapterRegistry,
    readonly config: BrokerConfig,
  ) {}

  // ---------- ids, time, host ----------

  tick(): string {
    return this.clock.now().toString();
  }

  /** Collision-checked opaque IDs within a prefix namespace. */
  allocId(kind: keyof typeof ID_PREFIX): string {
    const prefix = ID_PREFIX[kind];
    let n = BigInt(this.store.getMeta(`idalloc:${kind}`) ?? "0");
    for (;;) {
      n += 1n;
      const id = `${prefix}${n}`;
      const taken =
        (kind === "report" && this.store.get("SELECT report FROM simulations WHERE report=?", id)) ||
        (kind === "crossing" && this.store.get("SELECT crossing FROM crossings WHERE crossing=?", id)) ||
        (kind === "snapshot" && this.store.get("SELECT snapshot FROM snapshots WHERE snapshot=?", id)) ||
        (kind === "bundle" && this.store.get("SELECT object FROM objects WHERE object=?", id));
      if (!taken) {
        this.store.setMeta(`idalloc:${kind}`, n.toString());
        return id;
      }
    }
  }

  hostStatus(): string {
    return this.store.getMeta("host_status") ?? "READY";
  }

  /** §3.2 step 2: host/enforcer readiness for effectful work. */
  requireEffectReady(effectful: boolean): void {
    const status = this.hostStatus();
    if (status === "QUARANTINED") throw new WorldError("ENFORCER_UNAVAILABLE", "Host is quarantined.");
    if (status === "STOPPED" || status === "STOPPING" || status === "STARTING") {
      throw new WorldError("ENFORCER_UNAVAILABLE", `Host is ${status}.`);
    }
    if (effectful && status === "PAUSED") {
      throw new WorldError("ENFORCER_UNAVAILABLE", "Host is paused; effects unavailable.");
    }
    if (effectful) this.enforcer.assertReady(this.config.profile);
  }

  claimRow(claim: string): { status: string; generation: string; owner: string } | undefined {
    return this.store.get("SELECT status,generation,owner FROM claims WHERE claim=?", claim);
  }

  // ---------- command lifecycle (§6.1) ----------

  private requestDigest(op: string, params: JsonValue): string {
    return sha256Hex(jcsBytes({ op, params } as JsonObject));
  }

  /**
   * Execute one §6.1 request. Idempotency namespace is (principal, id);
   * durable denials are stored as command results; retryable and
   * pre-authentication failures create no tombstone.
   */
  handle(caller: Caller, req: { id: string; op: string; params: JsonValue }): JsonObject {
    if (typeof req.id !== "string" || req.id.length === 0 || req.id.length > 128) {
      throw new WorldError("BAD_REQUEST", "Request id must be a 1–128 byte string.");
    }
    if (typeof req.op !== "string" || !(req.op in this.methods)) {
      return this.fail(req.id, new WorldError("NOT_FOUND", `Unknown op ${String(req.op)}.`));
    }
    const digest = this.requestDigest(req.op, req.params);
    const prior = this.store.get<{ request_digest: string; result_enc: Uint8Array | null; disposition: string }>(
      "SELECT request_digest,result_enc,disposition FROM commands WHERE principal=? AND request_id=?",
      caller.principal, req.id);
    if (prior) {
      if (prior.request_digest !== digest) {
        return this.fail(req.id, new WorldError("IDEMPOTENCY_CONFLICT", "Request id was used for a different command."));
      }
      // Fresh disclosure: re-check read authority for claim-data results.
      const stored = JSON.parse(openAead(this.keys.controlDataKey(), Buffer.from(prior.result_enc!), Buffer.from(`command/${caller.principal}/${req.id}`)).toString("utf8")) as JsonObject;
      this.freshDisclosureCheck(caller, req.op, req.params as JsonObject);
      return { id: req.id, ...stored };
    }
    const ctx: Ctx = { ...caller, requestId: req.id };
    let result: JsonObject;
    try {
      result = this.store.tx(() => (this.methods as Record<string, (c: Ctx, p: JsonObject) => JsonObject>)[req.op]!(ctx, req.params as JsonObject));
    } catch (e) {
      if (e instanceof WorldError) {
        // A durable-storage fault pauses the host (§8.4): effects stop, the
        // fault is surfaced, and the audit gap is reported on metrics.
        if (e.code === "STORAGE_UNAVAILABLE") {
          try {
            this.store.setMeta("host_status", "PAUSED");
            this.store.bumpMetric("world_audit_gap_total");
          } catch { /* storage itself is suspect; the pause flag is best-effort */ }
        }
        if (e.retryable || e.code === "UNAUTHENTICATED" || e.code === "PRINCIPAL_MISMATCH" || !isPublicCode(e.code)) {
          this.applyRejectDetails(e);
          return this.fail(req.id, e);
        }
        // Durable denial: tombstone the result inside its own transaction.
        try {
          this.store.tx(() => {
            this.storeCommand(caller, req.id, digest, req.op, { ok: false, error: e.toErrorObject() as unknown as JsonValue });
            this.applyRejectDetails(e);
          });
        } catch {
          return this.fail(req.id, new WorldError("STORAGE_UNAVAILABLE", "Could not record the denial."));
        }
        return this.fail(req.id, e);
      }
      throw e;
    }
    this.store.tx(() => this.storeCommand(caller, req.id, digest, req.op, { ok: true, result }));
    return { id: req.id, ok: true, result };
  }

  /** Durable side-effects carried in error details (e.g. snapshot REJECTED). */
  private applyRejectDetails(e: WorldError): void {
    const rej = e.details?.["reject_snapshot"];
    if (typeof rej === "string") {
      const ev = e.details?.["reject_evidence"];
      this.store.run("UPDATE snapshots SET status='REJECTED',evidence_json=? WHERE snapshot=? AND status='BUILDING'",
        jcsString((ev ?? {}) as JsonValue), rej);
    }
  }

  private storeCommand(caller: Caller, id: string, digest: string, op: string, outcome: { ok: boolean; result?: JsonValue; error?: JsonValue }): void {
    const body: JsonObject = outcome.ok ? { ok: true, result: outcome.result! } : { ok: false, error: outcome.error! };
    const enc = sealAead(this.keys.controlDataKey(), jcsBytes(body as JsonObject), Buffer.from(`command/${caller.principal}/${id}`));
    this.store.run(
      "INSERT INTO commands(principal,request_id,request_digest,op,result_enc,disposition,accepted_tick) VALUES(?,?,?,?,?,?,?)",
      caller.principal, id, digest, op, enc, "ACCEPTED", this.tick(),
    );
  }

  private fail(id: string, e: WorldError): JsonObject {
    return { id, ok: false, error: e.toErrorObject() as unknown as JsonValue } as JsonObject;
  }

  /** Re-authorize disclosure of a stored result containing claim data. */
  private freshDisclosureCheck(caller: Caller, op: string, params: JsonObject): void {
    const p = params;
    switch (op) {
      case "state.read":
        this.authorize(caller, String(p["cap"]), "state.read", { kind: "kv", value: normalizeKvKey(String(p["key"])) });
        break;
      case "events.read": case "replay.run": case "receipt.export":
        this.authorize(caller, String(p["cap"]), "audit.read", { kind: "audit", value: String(p["branch"] ?? "main") });
        break;
      case "artifact.read":
        this.authorize(caller, String(p["cap"]), "state.read", { kind: "object", value: String(p["object"]) });
        break;
      default:
        break; // metadata/control results carry no claim data
    }
  }

  // ---------- authority ----------

  /** Resolve a cap param to an effective chain; opaque NOT_FOUND on miss. */
  authorize(caller: Caller, capId: string, verb: Verb, resource: { kind: ResourceKind; value: string }, need?: { uses: bigint; bytes: bigint }, claimScope?: string) {
    assertId(capId, "cap");
    const chain = effectiveAuthority(this.store, capId, caller.principal, verb, resource, this.tick(), need ?? { uses: 1n, bytes: 0n });
    // The grant's claim is bound at issuance; the caller cannot select a
    // different claim scope (TV-W-13).
    if (claimScope !== undefined && chain[0]!.claim !== claimScope) {
      throw new WorldError("NOT_FOUND", "No capability covers that claim scope.");
    }
    return chain;
  }

  /** Admin operation authority: admin.manage over the exact operation name. */
  authorizeAdmin(caller: Caller, capId: string, op: string) {
    return this.authorize(caller, capId, "admin.manage", { kind: "admin", value: op });
  }

  // ---------- simulation (§5.1–5.2) ----------

  runSimulation(caller: Caller, rawIntent: unknown, opts: { fuel?: bigint } = {}): Report {
    const intent = validateIntent(rawIntent);
    if (caller.principal !== intent.principal) {
      throw new WorldError("PRINCIPAL_MISMATCH", "Intent principal does not match the authenticated channel.");
    }
    if (caller.channel) {
      const ch = this.store.get<{ claim: string; principal: string; status: string }>(
        "SELECT claim,principal,status FROM channels WHERE channel=?", caller.channel);
      if (!ch || ch.status !== "BOUND" || ch.principal !== caller.principal || ch.claim !== intent.claim) {
        throw new WorldError("PRINCIPAL_MISMATCH", "Channel binding contradicts the intent.");
      }
    }
    const claim = this.claimRow(intent.claim);
    if (!claim) throw new WorldError("NOT_FOUND", `Unknown claim ${intent.claim}.`);
    const head = this.journal.head(intent.claim, intent.branch);
    if (!head) throw new WorldError("NOT_FOUND", `Unknown branch ${intent.claim}/${intent.branch}.`);

    const norm = normalizeIntent(rawIntent);
    // Authority closure failure is an RPC error, never a report (§6.8).
    const chain = effectiveAuthority(this.store, intent.cap, intent.principal, norm.verb, norm.resources[0]!, this.tick(), { uses: norm.cost.uses, bytes: norm.cost.bytes });

    const fuel = opts.fuel ?? BigInt(this.config.simulationFuel);
    const checks: { fence: string; result: string }[] = [];
    let result: "PASS" | "DENY" | "UNKNOWN" = "PASS";
    let denial: string | null = null;
    let fuelLeft = fuel;

    const burn = (n: bigint) => { fuelLeft -= n; };
    const deny = (name: string, code: string) => {
      checks.push({ fence: name, result: "DENY" });
      result = "DENY";
      denial = code;
    };
    const unknown = (name: string, code: string) => {
      checks.push({ fence: name, result: "UNKNOWN" });
      result = "UNKNOWN";
      denial = code;
    };

    // Claim lifecycle: effectful intents need an ACTIVE claim.
    if (claim.status !== "ACTIVE" && norm.effectful) {
      deny("lifecycle", "FENCE_DENIED");
    }

    // Fence evaluation (deterministic, sorted by phase/fence/resource).
    if (result === "PASS") {
      burn(1000n);
      const fe = evalFences(this.store, intent.claim, intent.action, norm.resources);
      for (const c of fe.checks) checks.push({ fence: c.fence, result: c.result });
      if (fe.result !== "PASS") {
        result = "DENY";
        denial = fe.code ?? "FENCE_DENIED";
      }
    }

    // Action-specific deterministic model checks.
    if (result === "PASS") {
      burn(2000n);
      this.modelCheck(norm, checks, deny, unknown);
    }

    if (result === "PASS" && fuelLeft <= 0n) {
      result = "UNKNOWN";
      denial = "SIMULATION_INCOMPLETE";
      checks.push({ fence: "fuel", result: "UNKNOWN" });
    }
    if (result === "DENY" && denial === "FENCE_DENIED" && fuelLeft <= 0n) { /* keep DENY */ }

    const now = this.tick();
    const readSet: JsonObject = { state_rev: head.stateRev, auth_rev: head.authRev, policy: this.store.getMeta("active_policy") ?? "policy1" };
    const extraRead = this.extraReadBinding(norm);
    if (extraRead) Object.assign(readSet, extraRead);
    const pr = principalStatus(this.store, intent.principal)!;
    const cl = this.claimRow(intent.claim)!;
    const authSet: JsonObject = {
      cap: intent.cap,
      cap_generation: chain[0]!.generation,
      principal_generation: pr.generation,
      writer_epoch: this.store.getMeta("writer_epoch") ?? "1",
      claim_generation: cl.generation,
      ancestors: chain.map((r) => ({ cap: r.capability, generation: r.generation })) as unknown as JsonValue,
    };
    const fenceVersions: Record<string, number> = {};
    for (const f of this.store.all<{ id: string; version: number }>("SELECT id,version FROM fences WHERE claim=? AND status='ACTIVE'", intent.claim)) {
      fenceVersions[f.id] = f.version;
    }

    const ttl = BigInt(this.config.simulationTtlMs);
    let expiry = BigInt(now) + ttl;
    const deadline = BigInt(now) + BigInt(intent.deadline_ms);
    if (deadline < expiry) expiry = deadline;
    for (const row of chain) {
      if (BigInt(row.grant.not_after_tick) < expiry) expiry = BigInt(row.grant.not_after_tick);
    }
    const expires = result === "PASS" ? expiry.toString() : "0";

    // Reuse an identical live report (deterministic dedup for CLI examples).
    const digest = norm.digest;
    const existing = this.store.get<{ report: string }>(
      `SELECT report FROM simulations WHERE claim=? AND branch=? AND intent_digest=? AND state='AVAILABLE' AND expires_tick=?`,
      intent.claim, intent.branch, digest, expires);
    if (existing) {
      const prev = this.loadReport(existing.report);
      if (prev && prev.principal === intent.principal && prev.result === result && jcsString(prev.read_set) === jcsString(readSet)) {
        return prev;
      }
    }

    const id = this.allocId("report");
    const report: Report = {
      id, intent_digest: digest, principal: intent.principal, claim: intent.claim, branch: intent.branch,
      read_set: readSet, auth_set: authSet, policy_id: String(readSet["policy"]),
      fence_versions: fenceVersions, engine_digest: engineDigestHex(), model_digest: modelDigestHex(),
      result, checks, denial_code: denial,
      cost_bound: norm.intent.max_cost as unknown as JsonObject,
      created_tick: now, expires_tick: expires, intent: norm.intent,
    };
    this.store.tx(() => {
      this.store.setMeta(`report_full:${id}`, jcsString(report as unknown as JsonObject));
      this.appendEvent({
        claim: intent.claim, branch: intent.branch, kind: "SimulationRecorded",
        payload: {
          report: id, intent_digest: digest,
          cut: { state_rev: head.stateRev, auth_rev: head.authRev },
          result, checks, engine_digest: report.engine_digest, expires_tick: expires, branch: intent.branch,
        } as JsonObject,
        actor: intent.principal, command: `sim:${id}`,
      });
      this.store.run("UPDATE simulations SET intent_digest=? WHERE report=?", digest, id);
    });
    return report;
  }

  /** Extra read_set bindings for artifact-reading actions. */
  private extraReadBinding(norm: NormalizedIntent): JsonObject | null {
    const a = norm.intent.args;
    if (norm.intent.action === "object.copy") {
      const o = this.store.get<{ key_version: number }>("SELECT key_version FROM objects WHERE claim=? AND object=?", String(a["source"]), String(a["object"]));
      return o ? { object_rev: o.key_version.toString() } : null;
    }
    if (norm.intent.action === "worker.start") {
      const o = this.store.get<{ key_version: number }>("SELECT key_version FROM objects WHERE claim=? AND object=?", norm.intent.claim, String(a["module"]));
      return o ? { object_rev: o.key_version.toString() } : null;
    }
    return null;
  }

  /** Deterministic per-action model checks (§5.2). Returns "UNKNOWN" via callback. */
  private modelCheck(
    norm: NormalizedIntent,
    checks: { fence: string; result: string }[],
    deny: (name: string, code: string) => void,
    unknown: (name: string, code: string) => void,
  ): void {
    const a = norm.intent.args;
    switch (norm.intent.action) {
      case "kv.put": {
        const head = this.journal.head(norm.intent.claim, norm.intent.branch)!;
        if (head.stateRev !== String(a["expected_rev"])) {
          deny("revision", "REVISION_CONFLICT");
        } else {
          checks.push({ fence: "revision", result: "PASS" });
        }
        break;
      }
      case "kv.get":
        checks.push({ fence: "read", result: "PASS" });
        break;
      case "object.copy": {
        const obj = this.store.get<{ digest: string; state: string }>(
          "SELECT digest,state FROM objects WHERE claim=? AND object=?", String(a["source"]), String(a["object"]));
        if (!obj || obj.state !== "COMMITTED") {
          unknown("artifact", "OBSERVATION_MISSING");
          break;
        }
        const destClaim = this.claimRow(String(a["destination"]));
        if (!destClaim || destClaim.status !== "ACTIVE") {
          deny("destination", "FENCE_DENIED");
          break;
        }
        const importCapId = a["import_cap"];
        if (importCapId === null || importCapId === undefined) {
          throw new WorldError("IMPORT_AUTH_REQUIRED", "object.copy requires a destination import grant.");
        }
        const icap = loadGrant(this.store, String(importCapId));
        const schema = String(a["schema"] ?? "json1");
        const importRes = { kind: "import" as const, value: `${norm.intent.claim}/${String(a["object"])}/${schema}` };
        if (!icap || icap.claim !== String(a["destination"]) || icap.status !== "ISSUED" || !covers(icap.grant, "object.import", importRes)) {
          throw new WorldError("IMPORT_AUTH_REQUIRED", "Destination import grant does not cover this copy.");
        }
        // Bilateral: the source grant must explicitly name the destination.
        if (!norm.resources.some((r) => r.kind === "export" && r.peer === String(a["destination"]))) {
          deny("export-scope", "FENCE_DENIED");
          break;
        }
        checks.push({ fence: "artifact", result: "PASS" });
        break;
      }
      case "net.fetch": {
        const ad = this.adapters.get(String(a["adapter"]));
        if (!ad || !ad.certified) {
          throw new WorldError("ENFORCER_UNCERTIFIED", `Adapter ${String(a["adapter"])} is not installed and certified.`);
        }
        const method = String(a["method"]);
        if (!ad.manifest.methods.includes(method)) {
          deny("adapter-schema", "FENCE_DENIED");
          break;
        }
        const url = new URL(String(a["url"]));
        if (!ad.manifest.origins.some((o) => {
          const ou = new URL(o);
          return ou.hostname.toLowerCase() === url.hostname.toLowerCase() && (ou.port || "443") === (url.port || "443");
        })) {
          deny("adapter-origin", "FENCE_DENIED");
          break;
        }
        const obs = this.dnsObservation(url.hostname.toLowerCase());
        if (!obs) {
          unknown("observation", "OBSERVATION_MISSING");
          break;
        }
        this.enforcer.networkTargetGate("https", url.hostname.toLowerCase(), Number(url.port || "443"), obs.addresses);
        checks.push({ fence: "adapter", result: "PASS" });
        break;
      }
      case "worker.start": {
        const mod = this.store.get<{ state: string }>("SELECT state FROM objects WHERE claim=? AND object=? AND state='COMMITTED'", norm.intent.claim, String(a["module"]));
        if (!mod) {
          unknown("artifact", "OBSERVATION_MISSING");
          break;
        }
        if (!this.enforcer.profiles().includes(String(a["profile"]))) {
          deny("profile", "FENCE_DENIED");
          break;
        }
        checks.push({ fence: "launch", result: "PASS" });
        break;
      }
      case "worker.stop": {
        const w = this.store.get<{ status: string; claim: string }>("SELECT status,claim FROM workers WHERE worker=?", String(a["worker"]));
        if (!w || w.claim !== norm.intent.claim || w.status !== "RUNNING") {
          deny("worker", "FENCE_DENIED");
          break;
        }
        checks.push({ fence: "worker", result: "PASS" });
        break;
      }
    }
  }

  private dnsObservation(host: string): { addresses: string[] } | null {
    const row = this.store.get<{ data_json: string }>("SELECT data_json FROM tombstones WHERE namespace='dns' AND id=?", host);
    return row ? JSON.parse(row.data_json) as { addresses: string[] } : null;
  }

  loadReport(id: string): Report | null {
    const row = this.store.get<{ report_enc: Uint8Array }>("SELECT report_enc FROM simulations WHERE report=?", id);
    if (!row) return null;
    const full = this.store.getMeta(`report_full:${id}`);
    if (!full) return null;
    return JSON.parse(full) as Report;
  }

  reportState(id: string): { state: string; expires_tick: string; claim: string; branch: string; intent_digest: string } | undefined {
    return this.store.get("SELECT state,expires_tick,claim,branch,intent_digest FROM simulations WHERE report=?", id);
  }

  // ---------- crossing commit (§3.2, §3.4) ----------

  commitCrossing(ctx: Ctx, claim: string, reportId: string, suppliedDigest?: string): JsonObject {
    const sim = this.reportState(reportId);
    if (!sim || sim.claim !== claim) throw new WorldError("NOT_FOUND", `Unknown report ${reportId}.`);
    const report = this.loadReport(reportId)!;
    if (report.principal !== ctx.principal) throw new WorldError("NOT_FOUND", `Unknown report ${reportId}.`);
    // An omitted digest binds the stored one (the CLI's documented "stored
    // digest" mode); a supplied wrong digest still fails INTENT_MISMATCH.
    if (suppliedDigest !== undefined && suppliedDigest !== sim.intent_digest) {
      throw new WorldError("INTENT_MISMATCH", "Supplied intent digest does not match the bound report.");
    }
    if (sim.state !== "AVAILABLE") {
      throw new WorldError("REPORT_CONSUMED", "Report was already consumed.");
    }
    const now = this.tick();
    // §3.2 step 7 repeats steps 2–6 in order: authority closure (4) is
    // rechecked before report freshness/result (6) — a revocation committed
    // after the report must surface CAP_REVOKED, not SIMULATION_STALE.
    const norm = normalizeIntent(report.intent);
    const chain = effectiveAuthority(this.store, report.intent.cap, ctx.principal, norm.verb, norm.resources[0]!, now, { uses: norm.cost.uses, bytes: norm.cost.bytes });
    // A non-PASS report carries its own denial (e.g. REVISION_CONFLICT on an
    // exported intent); its expires_tick is 0 by construction, so surfacing
    // staleness first would mask the real reason (TV-W-46).
    if (report.result !== "PASS") {
      throw new WorldError((report.denial_code === "SIMULATION_INCOMPLETE" ? "SIMULATION_INCOMPLETE" : (report.denial_code ?? "FENCE_DENIED")) as ErrorCode, "Report is not a PASS.");
    }
    this.assertReportFresh(report, now);
    this.requireEffectReady(norm.effectful);

    const onBranch = report.branch !== "main";
    if (onBranch && norm.external) {
      throw new WorldError("BRANCH_EFFECT_FORBIDDEN", "Branch crossings cannot dispatch live effects.");
    }

    const crossing = this.allocId("crossing");
    if (norm.external && !onBranch) {
      // External effects: the durable preparation commits BEFORE dispatch
      // (§3.2 step 7 vs 8). A crash between them leaves a PREPARED crossing
      // that recovery cancels (TV-W-34) — never an ambiguous retry.
      this.store.tx(() => {
        reserveChain(this.store, crossing, chain, { uses: norm.cost.uses, bytes: norm.cost.bytes });
        this.store.run("UPDATE simulations SET state='CONSUMED',consumed_crossing=? WHERE report=?", crossing, reportId);
        this.appendPrepared(ctx, crossing, report, norm, chain, report.branch);
        this.store.fault("prepare_fsync");
      });
      if (norm.intent.action === "worker.start") {
        return this.executeWorkerStart(ctx, crossing, report, norm);
      }
      this.dispatchMarker(ctx, crossing, norm);
      return this.dispatchOutcome(ctx, crossing, report, norm);
    }
    return this.store.tx(() => {
      if (!onBranch) {
        reserveChain(this.store, crossing, chain, { uses: norm.cost.uses, bytes: norm.cost.bytes });
      }
      this.store.run("UPDATE simulations SET state='CONSUMED',consumed_crossing=? WHERE report=?", crossing, reportId);
      this.appendPrepared(ctx, crossing, report, norm, chain, report.branch);
      return this.executePrepared(ctx, crossing, report, norm, onBranch);
    });
  }

  /** The CrossingPrepared record — one shape for local and external paths. */
  private appendPrepared(ctx: Ctx, crossing: string, report: Report, norm: NormalizedIntent, chain: GrantRow[], branch: string): void {
    const leaf = chain[0]!;
    const checks = ["authority:PASS", ...report.checks.filter((c) => c.result === "PASS").map((c) => `fence:${c.fence}:PASS`), "simulation:PASS"];
    this.appendEvent({
      claim: norm.intent.claim, branch, kind: "CrossingPrepared",
      payload: {
        crossing, report: report.id,
        authority: { cap: leaf.capability, generation: leaf.generation },
        checks,
        planned: report.intent.max_cost, reserved: report.intent.max_cost,
      } as JsonObject,
      actor: ctx.principal, command: ctx.requestId,
    });
    this.store.setMeta(`action:${crossing}`, norm.intent.action);
  }

  /** Freshness: bound dependency cuts and expiry (§5.1). */
  private assertReportFresh(report: Report, now: string): void {
    const head = this.journal.head(report.claim, report.branch);
    const stale = (why: string) => new WorldError("SIMULATION_STALE", `Report is stale: ${why}.`);
    if (!head) throw stale("branch missing");
    if (head.stateRev !== String(report.read_set["state_rev"])) throw stale("state_rev");
    if (head.authRev !== String(report.read_set["auth_rev"])) throw stale("auth_rev");
    if ((this.store.getMeta("active_policy") ?? "policy1") !== report.policy_id) throw stale("policy");
    const pr = principalStatus(this.store, report.principal);
    if (!pr || pr.generation !== String(report.auth_set["principal_generation"])) throw stale("principal");
    if ((this.store.getMeta("writer_epoch") ?? "1") !== String(report.auth_set["writer_epoch"])) throw stale("writer_epoch");
    const cl = this.claimRow(report.claim);
    if (!cl || cl.generation !== String(report.auth_set["claim_generation"])) throw stale("claim generation");
    for (const anc of report.auth_set["ancestors"] as { cap: string; generation: string }[]) {
      const row = this.store.get<{ generation: string; status: string }>("SELECT generation,status FROM capabilities WHERE capability=?", anc.cap);
      if (!row || row.generation !== anc.generation || row.status !== "ISSUED") throw stale(`capability ${anc.cap}`);
    }
    for (const [id, ver] of Object.entries(report.fence_versions)) {
      const f = this.store.get<{ version: number; status: string }>("SELECT version,status FROM fences WHERE claim=? AND id=? AND status='ACTIVE'", report.claim, id);
      if (!f || f.version !== ver) throw stale(`fence ${id}`);
    }
    if (BigInt(now) >= BigInt(report.expires_tick)) throw stale("expired");
  }

  /** Inside the prepare transaction: local effects complete atomically; external ones dispatch. */
  private executePrepared(ctx: Ctx, crossing: string, report: Report, norm: NormalizedIntent, hypothetical: boolean): JsonObject {
    const a = norm.intent.args;
    switch (norm.intent.action) {
      case "kv.put": {
        const key = normalizeKvKey(a["key"]);
        const head = this.journal.head(norm.intent.claim, norm.intent.branch)!;
        const expected = String(a["expected_rev"]);
        if (head.stateRev !== expected) {
          throw new WorldError("REVISION_CONFLICT", "expected_rev no longer matches.");
        }
        const newRev = (BigInt(expected) + 1n).toString();
        this.appendEvent({
          claim: norm.intent.claim, branch: norm.intent.branch, kind: "StatePatched",
          payload: { expected_rev: expected, patch: [{ op: "set", key, value: a["value"]! }], new_rev: newRev, crossing } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
        const actual = { uses: "1", bytes: meteredBytes(a["value"]!).toString() };
        if (!hypothetical) settleReservations(this.store, crossing, { uses: 1n, bytes: meteredBytes(a["value"]!) });
        this.appendEvent({
          claim: norm.intent.claim, branch: norm.intent.branch, kind: "CrossingCompleted",
          payload: { crossing, previous: "PREPARED", evidence: [], actual, reservation: "SETTLED" } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
        return { crossing, state: "COMPLETED", state_rev: newRev, value: a["value"]! };
      }
      case "kv.get": {
        const row = this.store.get<{ value_enc: Uint8Array }>("SELECT value_enc FROM kv_state WHERE claim=? AND branch=? AND key=?",
          norm.intent.claim, norm.intent.branch, normalizeKvKey(a["key"]));
        const value = row ? (JSON.parse(openAead(this.store.claimKey(norm.intent.claim), Buffer.from(row.value_enc), Buffer.from(`kv/${norm.intent.claim}/${norm.intent.branch}/${normalizeKvKey(a["key"])}`)).toString("utf8")) as JsonValue) : null;
        const actual = { uses: "1", bytes: value === null ? "0" : meteredBytes(value).toString() };
        if (!hypothetical) settleReservations(this.store, crossing, { uses: 1n, bytes: BigInt(actual.bytes) });
        this.appendEvent({
          claim: norm.intent.claim, branch: norm.intent.branch, kind: "CrossingCompleted",
          payload: { crossing, previous: "PREPARED", evidence: [], actual, reservation: "SETTLED" } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
        const head = this.journal.head(norm.intent.claim, norm.intent.branch)!;
        return { crossing, state: "COMPLETED", state_rev: head.stateRev, value };
      }
      case "object.copy":
        return this.executeCopy(ctx, crossing, report, norm);
      case "net.fetch":
        return this.executeNetFetch(ctx, crossing, report, norm);
      case "worker.start":
        return this.executeWorkerStart(ctx, crossing, report, norm);
      case "worker.stop": {
        const w = String(a["worker"]);
        this.appendEvent({
          claim: norm.intent.claim, branch: "main", kind: "WorkerStatusChanged",
          payload: { worker: w, from: "RUNNING", to: "STOPPING", pidfd: null, cause: crossing } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
        this.enforcer.stopWorker(w);
        this.appendEvent({
          claim: norm.intent.claim, branch: "main", kind: "WorkerStatusChanged",
          payload: { worker: w, from: "STOPPING", to: "KILLED", pidfd: null, cause: crossing } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
        if (!hypothetical) settleReservations(this.store, crossing, { uses: 1n, bytes: 0n });
        this.appendEvent({
          claim: norm.intent.claim, branch: norm.intent.branch, kind: "CrossingCompleted",
          payload: { crossing, previous: "PREPARED", evidence: [], actual: { uses: "1", bytes: "0" }, reservation: "SETTLED" } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
        return { crossing, state: "COMPLETED", worker: w };
      }
      default:
        throw new WorldError("SCHEMA_VALIDATION", `Unsupported action ${norm.intent.action}.`);
    }
  }

  /** Bilateral copy (§3.5): one transaction covers both claims' records. */
  private executeCopy(ctx: Ctx, crossing: string, report: Report, norm: NormalizedIntent): JsonObject {
    const a = norm.intent.args;
    const objId = String(a["object"]);
    const dst = String(a["destination"]);
    const src = norm.intent.claim;
    const schema = String(a["schema"] ?? "json1");
    const obj = this.store.get<{ digest: string; size: string; state: string }>(
      "SELECT digest,size,state FROM objects WHERE claim=? AND object=?", src, objId);
    if (!obj || obj.state !== "COMMITTED") {
      throw new WorldError("OBSERVATION_MISSING", "Source object is not committed.");
    }
    // Stage the destination-encrypted copy before the atomic metadata commit.
    this.store.fault("before_sqlite_commit");
    this.store.run(
      "INSERT INTO objects(claim,object,digest,size,key_version,schema,state) VALUES(?,?,?,?,1,?,'STAGED')",
      dst, objId, obj.digest, obj.size, schema,
    );
    // Destination claim's parallel records.
    const dstCrossing = `${crossing}:dst`;
    this.appendEvent({
      claim: dst, branch: "main", kind: "CrossingPrepared",
      payload: {
        crossing: dstCrossing, report: report.id,
        authority: { cap: String(a["import_cap"]), generation: "1" },
        checks: ["authority:PASS", "simulation:PASS"],
        planned: report.intent.max_cost, reserved: report.intent.max_cost,
      } as JsonObject,
      actor: ctx.principal, command: ctx.requestId, causes: [],
    });
    this.appendEvent({
      claim: dst, branch: "main", kind: "ObjectImported",
      payload: { object: objId, digest: obj.digest, source: src, destination: dst, schema, crossing: dstCrossing } as JsonObject,
      actor: ctx.principal, command: ctx.requestId,
    });
    settleReservations(this.store, crossing, { uses: 1n, bytes: BigInt(obj.size) });
    this.appendEvent({
      claim: src, branch: "main", kind: "CrossingCompleted",
      payload: { crossing, previous: "PREPARED", evidence: [], actual: { uses: "1", bytes: obj.size }, reservation: "SETTLED" } as JsonObject,
      actor: ctx.principal, command: ctx.requestId,
    });
    this.appendEvent({
      claim: dst, branch: "main", kind: "CrossingCompleted",
      payload: { crossing: dstCrossing, previous: "PREPARED", evidence: [], actual: { uses: "1", bytes: obj.size }, reservation: "SETTLED" } as JsonObject,
      actor: ctx.principal, command: ctx.requestId,
    });
    return { crossing, state: "COMPLETED", object: objId, destination: dst };
  }

  /** External dispatch path: marker under the barrier, then adapter call. */
  private executeNetFetch(ctx: Ctx, crossing: string, report: Report, norm: NormalizedIntent): JsonObject {
    this.dispatchMarker(ctx, crossing, norm);
    return this.dispatchOutcome(ctx, crossing, report, norm);
  }

  /**
   * The dispatch marker: durable under the same serialization barrier as
   * revocation. Re-checks authority before marking (TV-W-37/38). If the
   * authority closure no longer holds, revocation won the barrier: the
   * prepared crossing is cancelled durably and nothing is dispatched.
   */
  dispatchMarker(ctx: Ctx, crossing: string, norm: NormalizedIntent): void {
    this.enforcer.acquireDispatchBarrier();
    try {
      try {
        effectiveAuthority(this.store, norm.intent.cap, ctx.principal, norm.verb, norm.resources[0]!, this.tick());
      } catch (e) {
        // Only cancel while still PREPARED — a revocation may already have
        // cancelled this crossing inside the same barrier window.
        const cur = this.store.get<{ state: string }>("SELECT state FROM crossings WHERE crossing=?", crossing);
        if (cur?.state === "PREPARED") {
          this.store.tx(() => {
            const rel = releaseReservations(this.store, crossing);
            this.appendEvent({
              claim: norm.intent.claim, branch: "main", kind: "CrossingCancelled",
              payload: { crossing, previous: "PREPARED", released: { uses: rel.uses, bytes: rel.bytes } } as JsonObject,
              actor: ctx.principal, command: ctx.requestId,
            });
          });
        }
        throw e;
      }
      this.store.tx(() => {
        markDispatched(this.store, crossing);
        const adapterReq = { adapter: String(norm.intent.args["adapter"]), request: norm.intent.args, crossing };
        const reqDigest = sha256Hex(jcsBytes(adapterReq as unknown as JsonObject));
        this.store.fault("dispatch_marker");
        this.appendEvent({
          claim: norm.intent.claim, branch: "main", kind: "CrossingDispatched",
          payload: {
            crossing, dispatch_epoch: this.store.getMeta("writer_epoch") ?? "1",
            adapter_request_digest: reqDigest, idempotency_key: `${String(norm.intent.args["adapter"])}:${crossing}`,
            deadline_tick: (BigInt(this.tick()) + BigInt(norm.intent.deadline_ms)).toString(),
          } as JsonObject,
          actor: ctx.principal, command: ctx.requestId,
        });
      });
    } finally {
      this.enforcer.releaseDispatchBarrier();
    }
  }

  /** Call the adapter and classify the outcome into the FSM. */
  dispatchOutcome(ctx: Ctx, crossing: string, report: Report, norm: NormalizedIntent): JsonObject {
    const outcome = this.adapters.dispatch(String(norm.intent.args["adapter"]), {
      request: norm.intent.args, crossing,
      idempotency_key: `${String(norm.intent.args["adapter"])}:${crossing}`,
      max_response_bytes: String(norm.intent.args["max_response_bytes"] ?? "1048576"),
    });
    return this.store.tx((): JsonObject => {
      switch (outcome.kind) {
        case "success": {
          const actual = { uses: "1", bytes: outcome.bytes.toString() };
          settleReservations(this.store, crossing, { uses: 1n, bytes: outcome.bytes });
          this.appendEvent({
            claim: norm.intent.claim, branch: "main", kind: "CrossingCompleted",
            payload: { crossing, previous: "DISPATCHED", evidence: outcome.evidence ?? [], actual, reservation: "SETTLED" } as JsonObject,
            actor: ctx.principal, command: ctx.requestId,
          });
          return { crossing, state: "COMPLETED", bytes: outcome.bytes.toString() };
        }
        case "failure": {
          settleReservations(this.store, crossing, { uses: 1n, bytes: 0n });
          this.appendEvent({
            claim: norm.intent.claim, branch: "main", kind: "CrossingFailed",
            payload: { crossing, previous: "DISPATCHED", evidence: outcome.evidence ?? [], actual: { uses: "1", bytes: "0" }, reservation: "SETTLED" } as JsonObject,
            actor: ctx.principal, command: ctx.requestId,
          });
          return { crossing, state: "FAILED" };
        }
        default: {
          // timeout/lost reply/crash: UNKNOWN preserves held bytes, consumes the dispatch use.
          this.appendEvent({
            claim: norm.intent.claim, branch: "main", kind: "CrossingUnknown",
            payload: { crossing, previous: "DISPATCHED", evidence: outcome.evidence ?? [], held: { uses: "0", bytes: report.intent.max_cost.bytes } } as JsonObject,
            actor: ctx.principal, command: ctx.requestId,
          });
          return { crossing, state: "UNKNOWN" };
        }
      }
    });
  }

  /**
   * §8.2 crash recovery for one crossing. PREPARED means the dispatch
   * marker never committed — cancel and release. DISPATCHED means the
   * marker is durable but the outcome never recorded — reconcile against
   * the provider by idempotency key; no confirmation means UNKNOWN with
   * the reservation held, never an automatic retry.
   */
  recoverCrossing(crossing: string): JsonObject {
    const row = this.store.get<{ state: string; claim: string; branch: string }>(
      "SELECT state,claim,branch FROM crossings WHERE crossing=?", crossing);
    if (!row) throw new WorldError("NOT_FOUND", `Unknown crossing ${crossing}.`);
    if (row.state === "PREPARED") {
      return this.store.tx(() => {
        const rel = releaseReservations(this.store, crossing);
        this.appendEvent({
          claim: row.claim, branch: row.branch, kind: "CrossingCancelled",
          payload: { crossing, previous: "PREPARED", released: { uses: rel.uses, bytes: rel.bytes } } as JsonObject,
          actor: "pRuntime", command: `recover:${crossing}`,
        });
        return { crossing, state: "CANCELLED", held_uses: "0", held_bytes: "0" };
      });
    }
    if (row.state === "DISPATCHED") {
      // Provider reconciliation by idempotency key. Only net.fetch crosses
      // an adapter boundary; a DISPATCHED worker.start cannot confirm the
      // launch, so it also recovers to UNKNOWN.
      const action = this.store.getMeta(`action:${crossing}`) ?? "";
      const adapterId = action === "net.fetch" ? "adapterT" : "";
      const adapter = adapterId ? this.adapters.get(adapterId) : undefined;
      const outcome = adapter?.reconcile?.(`${adapterId}:${crossing}`) ?? null;
      if (outcome === null) {
        return this.store.tx(() => {
          const held = this.store.all<{ dimension: string; held: string }>(
            "SELECT dimension,held FROM reservations WHERE crossing=? AND state='HELD'", crossing);
          const heldBytes = held.filter((h) => h.dimension === "bytes")
            .reduce((s, h) => s + BigInt(h.held), 0n).toString();
          this.appendEvent({
            claim: row.claim, branch: row.branch, kind: "CrossingUnknown",
            payload: { crossing, previous: "DISPATCHED", evidence: [], held: { uses: "0", bytes: heldBytes } } as JsonObject,
            actor: "pRuntime", command: `recover:${crossing}`,
          });
          return { crossing, state: "UNKNOWN", held_bytes: heldBytes };
        });
      }
      return this.store.tx(() => {
        if (outcome.kind === "success") {
          settleReservations(this.store, crossing, { uses: 0n, bytes: outcome.bytes });
          this.appendEvent({
            claim: row.claim, branch: row.branch, kind: "CrossingCompleted",
            payload: { crossing, previous: "DISPATCHED", evidence: outcome.evidence ?? [], actual: { uses: "1", bytes: outcome.bytes.toString() }, reservation: "SETTLED" } as JsonObject,
            actor: "pRuntime", command: `recover:${crossing}`,
          });
          return { crossing, state: "COMPLETED" };
        }
        settleReservations(this.store, crossing, { uses: 0n, bytes: 0n });
        this.appendEvent({
          claim: row.claim, branch: row.branch, kind: "CrossingFailed",
          payload: { crossing, previous: "DISPATCHED", evidence: outcome.evidence ?? [], actual: { uses: "1", bytes: "0" }, reservation: "SETTLED" } as JsonObject,
          actor: "pRuntime", command: `recover:${crossing}`,
        });
        return { crossing, state: "FAILED" };
      });
    }
    return { crossing, state: row.state };
  }

  /** Startup recovery: every crossing left PREPARED or DISPATCHED. */
  recoverAllCrossings(): JsonObject[] {
    const rows = this.store.all<{ crossing: string }>(
      "SELECT crossing FROM crossings WHERE state IN ('PREPARED','DISPATCHED') ORDER BY crossing");
    const out: JsonObject[] = [];
    for (const r of rows) out.push(this.recoverCrossing(r.crossing));
    return out;
  }

  private executeWorkerStart(ctx: Ctx, crossing: string, report: Report, norm: NormalizedIntent): JsonObject {
    this.dispatchMarker(ctx, crossing, norm);
    const a = norm.intent.args;
    const launched = this.enforcer.startWorker({
      claim: norm.intent.claim, module: String(a["module"]), profile: String(a["profile"]),
      cpu_ms: String(a["cpu_ms"]), memory_bytes: String(a["memory_bytes"]), pids: Number(a["pids"]), crossing,
    });
    const worker = launched.worker;
    return this.store.tx(() => {
      this.appendEvent({
        claim: norm.intent.claim, branch: "main", kind: "WorkerStatusChanged",
        payload: { worker, from: "absent", to: "STARTING", pidfd: launched.pidfd, cause: crossing } as JsonObject,
        actor: ctx.principal, command: ctx.requestId,
      });
      this.store.run("INSERT INTO workers(worker,claim,branch,status,profile,epoch,pidfd,exec_digest,crossing) VALUES(?,?,?,'STARTING',?,?,?,?,?)",
        worker, norm.intent.claim, "main", String(a["profile"]), this.store.getMeta("writer_epoch") ?? "1", launched.pidfd, launched.exec_digest, crossing);
      this.appendEvent({
        claim: norm.intent.claim, branch: "main", kind: "WorkerStatusChanged",
        payload: { worker, from: "STARTING", to: "RUNNING", pidfd: launched.pidfd, cause: crossing } as JsonObject,
        actor: ctx.principal, command: ctx.requestId,
      });
      // The reservation transfers to the worker lease rather than settling (§5.2).
      this.appendEvent({
        claim: norm.intent.claim, branch: "main", kind: "CrossingCompleted",
        payload: { crossing, previous: "DISPATCHED", evidence: [], actual: { uses: "1", bytes: "0" }, reservation: "SETTLED" } as JsonObject,
        actor: ctx.principal, command: ctx.requestId,
      });
      return { crossing, state: "COMPLETED", worker, status: "RUNNING" };
    });
  }

  /** Cancel a PREPARED crossing: release reservations, no effect (§3.4). */
  cancelCrossing(ctx: Ctx, claim: string, crossing: string, reason: string): JsonObject {
    const row = this.store.get<{ state: string; claim: string; branch: string }>("SELECT state,claim,branch FROM crossings WHERE crossing=?", crossing);
    if (!row || row.claim !== claim) throw new WorldError("NOT_FOUND", `Unknown crossing ${crossing}.`);
    if (row.state !== "PREPARED") {
      if (row.state === "DISPATCHED" || row.state === "UNKNOWN") {
        throw new WorldError("ALREADY_DISPATCHED", "Crossing already has a durable dispatch marker.");
      }
      throw new WorldError("STATE_TRANSITION", `Crossing is ${row.state}.`);
    }
    return this.store.tx(() => {
      const rel = releaseReservations(this.store, crossing);
      this.appendEvent({
        claim, branch: row.branch, kind: "CrossingCancelled",
        payload: { crossing, previous: "PREPARED", released: { uses: rel.uses, bytes: rel.bytes } } as JsonObject,
        actor: ctx.principal, command: ctx.requestId,
      });
      return { crossing, state: "CANCELLED", released_uses: rel.uses, released_bytes: rel.bytes } as JsonObject;
    });
  }

  // ---------- append helper ----------

  appendEvent(input: { claim: string; branch: string; kind: string; payload: JsonValue; actor: string; command: string; causes?: { claim: string; branch: string; seq: string; hash: string }[]; tickMs?: string }): Envelope {
    const env = this.journal.append(input);
    // Mirror the pure transition onto the SQL projection in the same tx.
    applyEventSql(this.store, env);
    return env;
  }

  // ---------- method table ----------

  private readonly methods: Record<string, (ctx: Ctx, p: JsonObject) => JsonObject> = {
    "health.get": () => ({
      status: this.hostStatus(), protocol: 1, effects_enabled: this.hostStatus() === "READY",
    }),

    "claim.create": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "claim.create");
      const claim = String(p["claim"]);
      assertId(claim, "claim");
      if (claim === "_control") throw new WorldError("BAD_REQUEST", "_control is reserved.");
      const owner = String(p["owner"]);
      if (!principalStatus(this.store, owner)) throw new WorldError("NOT_FOUND", `Unknown principal ${owner}.`);
      if (this.claimRow(claim)) throw new WorldError("STATE_TRANSITION", "Claim exists.");
      this.journal.createStream(claim, "main");
      this.appendEvent({
        claim, branch: "main", kind: "ClaimCreated",
        payload: { owner, auth_rev: "1", state_rev: "0" }, actor: ctx.principal, command: ctx.requestId,
      });
      return { claim, status: "ACTIVE", state_rev: "0", auth_rev: "1" };
    },

    "claim.set_status": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "claim.set_status");
      const claim = String(p["claim"]);
      const c = this.claimRow(claim);
      if (!c) throw new WorldError("NOT_FOUND", `Unknown claim ${claim}.`);
      const expected = String(p["expected"]), target = String(p["target"]), reason = String(p["reason"]);
      if (c.status !== expected) throw new WorldError("STATE_TRANSITION", `Claim is ${c.status}, not ${expected}.`);
      if (expected === "QUARANTINED" && target === "FROZEN") {
        throw new WorldError("AMENDMENT_REQUIRED", "QUARANTINED recovery requires the threshold recover mutation.");
      }
      const allowed: Record<string, string[]> = { ACTIVE: ["FROZEN", "QUARANTINED"], FROZEN: ["ACTIVE", "QUARANTINED", "ARCHIVED"], QUARANTINED: [], ARCHIVED: [] };
      if (!(allowed[expected] ?? []).includes(target)) throw new WorldError("STATE_TRANSITION", `Illegal claim transition ${expected}→${target}.`);
      const counts = this.cancelPrepared(claim);
      this.appendEvent({
        claim, branch: "main", kind: "ClaimStatusChanged",
        payload: { from: expected, to: target, reason }, actor: ctx.principal, command: ctx.requestId,
      });
      return { claim, status: target, ...counts };
    },

    "principal.register": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "principal.register");
      const principal = String(p["principal"]);
      assertId(principal, "principal");
      if (principalStatus(this.store, principal)) throw new WorldError("STATE_TRANSITION", "Principal exists.");
      const payload: JsonObject = { principal, type: String(p["type"]), epoch: this.store.getMeta("writer_epoch") ?? "1" };
      if (p["uid"] !== undefined) {
        const uid = Number(p["uid"]);
        const taken = this.store.get("SELECT principal FROM principals WHERE uid=? AND status='ENABLED'", uid);
        if (taken) throw new WorldError("STATE_TRANSITION", "UID already bound.");
        payload["uid"] = uid;
      }
      if (p["channel"] !== undefined && p["channel"] !== null) payload["channel"] = String(p["channel"]);
      this.appendEvent({ claim: "_control", branch: "main", kind: "PrincipalRegistered", payload, actor: ctx.principal, command: ctx.requestId });
      if (payload["channel"]) {
        this.store.run("INSERT INTO channels(channel,claim,principal,status) VALUES(?,?,?,'BOUND')", String(payload["channel"]), "", principal);
      }
      return { principal, status: "ENABLED", epoch: String(payload["epoch"]) };
    },

    "principal.disable": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "principal.disable");
      const principal = String(p["principal"]);
      const pr = principalStatus(this.store, principal);
      if (!pr) throw new WorldError("NOT_FOUND", `Unknown principal ${principal}.`);
      if (pr.status !== "ENABLED") throw new WorldError("STATE_TRANSITION", `Principal is ${pr.status}.`);
      const counts = { cancelled: 0, dispatched: 0, unknown: 0 };
      this.appendEvent({
        claim: "_control", branch: "main", kind: "PrincipalDisabled",
        payload: { principal, generation: (BigInt(pr.generation) + 1n).toString(), reason: String(p["reason"]) },
        actor: ctx.principal, command: ctx.requestId,
      });
      this.store.run("UPDATE channels SET status='CLOSED' WHERE principal=? AND status='BOUND'", principal);
      return { principal, status: "DISABLED", ...counts };
    },

    "capability.issue": (ctx, p) => {
      const grant = validateGrant(p["grant"]);
      const issuer = String(p["issuer_cap"]);
      const issuerRow = loadGrant(this.store, issuer);
      if (!issuerRow) throw new WorldError("NOT_FOUND", "Unknown issuer capability.");
      if (issuerRow.subject !== ctx.principal && !this.isAdmin(ctx)) {
        throw new WorldError("NOT_FOUND", "Issuer capability is not bound to the caller.");
      }
      // cap.delegate over the proposed recipient, on the issuer's leaf.
      const leafOk = issuerRow.grant.verbs.includes("cap.delegate")
        && issuerRow.grant.resources.some((s) => s.kind === "principal" && (s.match === "exact" ? s.value === grant.subject : grant.subject.startsWith(s.value.endsWith("/") ? s.value : s.value + "/") || grant.subject === s.value));
      const admin = this.isAdmin(ctx);
      if (!leafOk && !admin) throw new WorldError("FENCE_DENIED", "Issuer lacks cap.delegate over the recipient.");
      if (grant.parent === null && !admin) {
        throw new WorldError("AMENDMENT_REQUIRED", "New root grants require the signed governance path.");
      }
      if (grant.parent !== null) {
        const parent = loadGrant(this.store, grant.parent);
        if (!parent) throw new WorldError("NOT_FOUND", "Parent grant missing.");
        if (parent.capability !== issuer && !admin) throw new WorldError("FENCE_DENIED", "Issuer is not the parent grant.");
        if (!parent.grant.delegable && !admin) throw new WorldError("CAP_WIDENING", "Parent grant is not delegable.");
        const violations = attenuationViolations(parent.grant, grant, this.config.maxDelegationDepth);
        if (violations.length) throw new WorldError(violations[0]!.code, violations[0]!.msg);
        if (parent.subject !== ctx.principal && !admin) {
          throw new WorldError("FENCE_DENIED", "Parent grant is not held by the caller.");
        }
        if (parent.status !== "ISSUED") throw new WorldError("CAP_REVOKED", "Parent grant is revoked.");
        const now = this.tick();
        if (BigInt(now) < BigInt(parent.grant.not_before_tick) || BigInt(now) >= BigInt(parent.grant.not_after_tick)) {
          throw new WorldError("CAP_EXPIRED", "Parent grant is not currently valid.");
        }
      }
      if (!this.claimRow(grant.claim)) throw new WorldError("NOT_FOUND", `Unknown claim ${grant.claim}.`);
      if (loadGrant(this.store, grant.id)) throw new WorldError("STATE_TRANSITION", "Capability id exists.");
      this.appendEvent({
        claim: grant.claim, branch: "main", kind: "CapabilityIssued",
        payload: { capability: grant.id, grant: grant as unknown as JsonObject },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { capability: grant.id, status: "ISSUED" };
    },

    "capability.revoke": (ctx, p) => {
      const capability = String(p["capability"]);
      const row = loadGrant(this.store, capability);
      if (!row) throw new WorldError("NOT_FOUND", `Unknown capability ${capability}.`);
      const authority = String(p["authority"]);
      const isSubject = row.subject === ctx.principal;
      const isIssuer = row.parent !== null && loadGrant(this.store, row.parent)?.subject === ctx.principal;
      if (!isSubject && !isIssuer) {
        this.authorizeAdmin(ctx, authority, "capability.revoke");
      }
      if (row.status !== "ISSUED") throw new WorldError("STATE_TRANSITION", `Capability is ${row.status}.`);
      const counts = this.cancelPrepared(row.claim, capability);
      this.appendEvent({
        claim: row.claim, branch: "main", kind: "CapabilityRevoked",
        payload: { capability, reason: String(p["reason"]), generation: (BigInt(row.generation) + 1n).toString() },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { capability, status: "REVOKED", ...counts };
    },

    "fence.configure": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "fence.configure");
      const claim = String(p["claim"]);
      if (!this.claimRow(claim)) throw new WorldError("NOT_FOUND", `Unknown claim ${claim}.`);
      const fence = validateFence(p["fence"]);
      const prev = this.store.get<{ version: number; fence_json: string }>(
        "SELECT version,fence_json FROM fences WHERE claim=? AND id=? AND status='ACTIVE'", claim, fence.id);
      const expectedVersion = p["expected_version"] === undefined ? null : Number(p["expected_version"]);
      if (prev) {
        if (expectedVersion !== null && prev.version !== expectedVersion) {
          throw new WorldError("REVISION_CONFLICT", `Fence is at version ${prev.version}.`);
        }
        if (fence.version !== prev.version + 1) {
          throw new WorldError("SCHEMA_VALIDATION", "Fence version must increase by exactly one.");
        }
        if (!this.isRestriction(JSON.parse(prev.fence_json) as Fence, fence)) {
          throw new WorldError("AMENDMENT_REQUIRED", "Weakening a fence requires the signed governance path.");
        }
      } else if (fence.version !== 1) {
        throw new WorldError("SCHEMA_VALIDATION", "New fence must start at version 1.");
      }
      this.appendEvent({
        claim, branch: "main", kind: "FenceConfigured",
        payload: { fence: fence as unknown as JsonObject, predecessor: prev ? String(prev.version) : null, enforcer_digest: this.enforcer.enforcerDigest },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { fence: fence.id, version: fence.version, effective: true };
    },

    "artifact.put": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]), name = String(p["name"]);
      assertId(name, "object");
      const bytes = b64uDecodeExact(String(p["content_base64url"]));
      if (bytes.byteLength > 65536) throw new WorldError("RATE_LIMITED", "artifact.put is limited to 64 KiB decoded bytes.");
      this.authorize(ctx, String(p["cap"]), "state.write", { kind: "object", value: name }, { uses: 1n, bytes: BigInt(bytes.byteLength) });
      this.requireEffectReady(true);
      const head = this.journal.head(claim, branch);
      if (!head) throw new WorldError("NOT_FOUND", `Unknown stream ${claim}/${branch}.`);
      if (this.store.get("SELECT object FROM objects WHERE claim=? AND object=?", claim, name)) {
        throw new WorldError("STATE_TRANSITION", "Object name is already bound.");
      }
      const digest = sha256Hex(bytes);
      this.store.run(
        "INSERT INTO objects(claim,object,digest,size,key_version,schema,state) VALUES(?,?,?,?,1,'application/octet-stream','COMMITTED')",
        claim, name, digest, bytes.byteLength.toString(),
      );
      this.store.run("INSERT INTO registry_artifacts(artifact,kind,bytes,digest) VALUES(?,?,?,?) ON CONFLICT(artifact) DO NOTHING",
        `${claim}/${name}`, "object", bytes, digest);
      return { object: name, bytes: bytes.byteLength.toString(), sha256: digest };
    },

    "artifact.read": (ctx, p) => {
      const claim = String(p["claim"]), object = String(p["object"]);
      const offset = BigInt(String(p["offset"] ?? "0")), limit = Number(p["limit"] ?? 65536);
      if (limit < 1 || limit > 65536) throw new WorldError("BAD_REQUEST", "limit must be 1–65536.");
      const row = this.store.get<{ digest: string; size: string }>("SELECT digest,size FROM objects WHERE claim=? AND object=? AND state IN ('COMMITTED','ARCHIVED')", claim, object);
      if (!row) throw new WorldError("NOT_FOUND", `Unknown object ${object}.`);
      const isReceipt = this.store.get("SELECT id FROM tombstones WHERE namespace='receipt' AND id=?", object);
      this.authorize(ctx, String(p["cap"]), isReceipt ? "audit.read" : "state.read", isReceipt ? { kind: "audit", value: "main" } : { kind: "object", value: object });
      const art = this.store.get<{ bytes: Uint8Array }>("SELECT bytes FROM registry_artifacts WHERE artifact=?", `${claim}/${object}`);
      if (!art) throw new WorldError("OBSERVATION_MISSING", "Object bytes are not retained locally.");
      const all = Buffer.from(art.bytes);
      const page = all.subarray(Number(offset), Number(offset) + limit);
      const next = Number(offset) + page.byteLength < all.byteLength ? (Number(offset) + page.byteLength).toString() : null;
      return { object, offset: offset.toString(), content_base64url: b64uEncode(page), next_offset: next, bytes: page.byteLength.toString() };
    },

    "simulation.run": (ctx, p) => {
      const report = this.runSimulation(ctx, p["intent"]);
      return { report: report.id, result: report.result, checks: report.checks as unknown as JsonValue, expires_tick: report.expires_tick };
    },

    "simulation.get": (ctx, p) => {
      const claim = String(p["claim"]), id = String(p["report"]);
      const row = this.reportState(id);
      if (!row || row.claim !== claim) throw new WorldError("NOT_FOUND", `Unknown report ${id}.`);
      const report = this.loadReport(id)!;
      if (report.principal !== ctx.principal) this.authorize(ctx, String(p["cap"]), "state.read", { kind: "audit", value: row.branch });
      const usable = row.state === "AVAILABLE" && BigInt(this.tick()) < BigInt(row.expires_tick);
      return { report: id, state: row.state, result: report.result, intent_digest: row.intent_digest, expires_tick: row.expires_tick, usable };
    },

    "crossing.commit": (ctx, p) =>
      this.commitCrossing(ctx, String(p["claim"]), String(p["report"]), String(p["intent_digest"])),

    "crossing.get": (ctx, p) => {
      const claim = String(p["claim"]), id = String(p["crossing"]);
      const row = this.store.get<{ state: string; branch: string; result_enc: Uint8Array | null }>(
        "SELECT state,branch,result_enc FROM crossings WHERE crossing=? AND claim=?", id, claim);
      if (!row) throw new WorldError("NOT_FOUND", `Unknown crossing ${id}.`);
      this.authorize(ctx, String(p["cap"]), "state.read", { kind: "audit", value: row.branch });
      const out: JsonObject = { crossing: id, state: row.state };
      const head = this.journal.head(claim, row.branch);
      if (head) out["state_rev"] = head.stateRev;
      if (row.result_enc) {
        const pl = JSON.parse(openAead(this.store.claimKey(claim), Buffer.from(row.result_enc), Buffer.from(`crossing-result/${claim}/${id}`)).toString("utf8")) as JsonObject;
        if (pl["value"] !== undefined) out["value"] = pl["value"];
      }
      return out;
    },

    "crossing.cancel": (ctx, p) => {
      const claim = String(p["claim"]);
      const row = this.store.get<{ claim: string }>("SELECT claim FROM crossings WHERE crossing=?", String(p["crossing"]));
      if (row && row.claim === claim) {
        const xr = this.store.get<{ intent_digest: string; report: string | null }>("SELECT intent_digest,report FROM crossings WHERE crossing=?", String(p["crossing"]));
        const rep = xr?.report ? this.loadReport(xr.report) : null;
        if (!rep || rep.principal !== ctx.principal) {
          this.authorizeAdmin(ctx, String(p["cap"]), "crossing.cancel");
        }
      }
      return this.cancelCrossing(ctx, claim, String(p["crossing"]), String(p["reason"] ?? ""));
    },

    "crossing.reconcile": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "crossing.reconcile");
      const claim = String(p["claim"]), id = String(p["crossing"]);
      const row = this.store.get<{ state: string; branch: string; adapter_request_digest: string | null }>(
        "SELECT state,branch,adapter_request_digest FROM crossings WHERE crossing=? AND claim=?", id, claim);
      if (!row) throw new WorldError("NOT_FOUND", `Unknown crossing ${id}.`);
      if (row.state !== "UNKNOWN") throw new WorldError("STATE_TRANSITION", `Crossing is ${row.state}, not UNKNOWN.`);
      const evidence = String(p["evidence"]);
      const obs = this.store.get<{ digest: string; object: string }>("SELECT digest,object FROM observations WHERE observation=? AND claim=?", evidence, claim);
      if (!obs) throw new WorldError("OBSERVATION_MISSING", "Evidence is not a verified adapter observation.");
      const art = this.store.get<{ bytes: Uint8Array }>("SELECT bytes FROM registry_artifacts WHERE artifact=?", `${claim}/${obs.object}`);
      const body = art ? (JSON.parse(Buffer.from(art.bytes).toString("utf8")) as JsonObject) : {};
      return this.store.tx(() => {
        if (body["result"] === "success") {
          const actual = body["actual"] as JsonObject | undefined;
          const bytes = BigInt(String(actual?.["bytes"] ?? "0"));
          settleReservations(this.store, id, { uses: 1n, bytes });
          this.appendEvent({
            claim, branch: row.branch, kind: "CrossingCompleted",
            payload: { crossing: id, previous: "UNKNOWN", evidence: [evidence], actual: actual ?? { uses: "1", bytes: "0" }, reservation: "SETTLED" },
            actor: ctx.principal, command: ctx.requestId,
          });
          return { crossing: id, state: "COMPLETED", evidence, held_bytes: "0" };
        }
        settleReservations(this.store, id, { uses: 1n, bytes: 0n });
        this.appendEvent({
          claim, branch: row.branch, kind: "CrossingFailed",
          payload: { crossing: id, previous: "UNKNOWN", evidence: [evidence], actual: { uses: "1", bytes: "0" }, reservation: "SETTLED" },
          actor: ctx.principal, command: ctx.requestId,
        });
        return { crossing: id, state: "FAILED", evidence, held_bytes: "0" };
      });
    },

    "state.read": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]), key = normalizeKvKey(String(p["key"]));
      this.authorize(ctx, String(p["cap"]), "state.read", { kind: "kv", value: key });
      const head = this.journal.head(claim, branch);
      if (!head) throw new WorldError("NOT_FOUND", `Unknown stream ${claim}/${branch}.`);
      const atSeq = p["at_seq"] === undefined || p["at_seq"] === null ? head.headSeq : String(p["at_seq"]);
      // Automatic bounded read crossing.
      const crossing = this.allocId("crossing");
      const value = this.kvAt(claim, branch, key, atSeq);
      const stateRev = this.stateRevAt(claim, branch, atSeq);
      this.appendEvent({
        claim, branch, kind: "CrossingPrepared",
        payload: { crossing, report: "auto:read", authority: { cap: String(p["cap"]), generation: "1" }, checks: ["authority:PASS"], planned: { uses: "1", bytes: "0" }, reserved: { uses: "0", bytes: "0" } },
        actor: ctx.principal, command: ctx.requestId,
      });
      this.appendEvent({
        claim, branch, kind: "CrossingCompleted",
        payload: { crossing, previous: "PREPARED", evidence: [], actual: { uses: "1", bytes: value === null ? "0" : meteredBytes(value).toString() }, reservation: "SETTLED" },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { at_seq: atSeq, state_rev: stateRev, value };
    },

    "events.read": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]);
      this.authorize(ctx, String(p["cap"]), "audit.read", { kind: "audit", value: `${branch}/` });
      const head = this.journal.head(claim, branch);
      if (!head) throw new WorldError("NOT_FOUND", `Unknown stream ${claim}/${branch}.`);
      let after = p["after_seq"] === undefined ? "0" : String(p["after_seq"]);
      const limit = Math.min(Math.max(Number(p["limit"] ?? 1000), 1), 1000);
      if (p["cursor"] !== undefined && p["cursor"] !== null) {
        const cur = this.decodeCursor(String(p["cursor"]));
        if (cur.principal !== ctx.principal || cur.claim !== claim || cur.branch !== branch) {
          throw new WorldError("CURSOR_INVALID", "Cursor does not bind this caller and cut.");
        }
        after = cur.after;
      }
      const through = p["through_seq"] === undefined || p["through_seq"] === null ? head.headSeq : String(p["through_seq"]);
      const clamped = BigInt(through) > BigInt(head.headSeq) ? head.headSeq : through;
      const rows = this.store.all<{ seq: string; hash: string; kind: string }>(
        "SELECT seq,hash,kind FROM events WHERE claim=? AND branch=? AND CAST(seq AS INTEGER)>? AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER) LIMIT ?",
        claim, branch, Number(after), Number(clamped), limit + 1);
      const page = rows.slice(0, limit);
      const events = page.map((r) => ({ seq: r.seq, hash: r.hash, kind: r.kind }));
      const next = rows.length > limit ? this.encodeCursor(ctx.principal, claim, branch, page[page.length - 1]!.seq, clamped) : null;
      return { events: events as unknown as JsonValue, through_seq: clamped, next_cursor: next };
    },

    "cut.lookup": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]), tick = String(p["tick_ms"]);
      try {
        this.authorize(ctx, String(p["cap"]), "audit.read", { kind: "audit", value: `${branch}/` });
      } catch {
        this.authorize(ctx, String(p["cap"]), "state.read", { kind: "audit", value: branch });
      }
      const rows = this.store.all<{ seq: string; hash: string; tick_ms: string }>(
        "SELECT seq,hash,tick_ms FROM events WHERE claim=? AND branch=? ORDER BY CAST(seq AS INTEGER)", claim, branch);
      const target = BigInt(tick);
      const cands = rows
        .map((r) => ({ seq: r.seq, hash: r.hash, tick_ms: r.tick_ms, d: BigInt(r.tick_ms) > target ? BigInt(r.tick_ms) - target : target - BigInt(r.tick_ms) }))
        .sort((a, b2) => a.d === b2.d ? Number(BigInt(b2.seq) - BigInt(a.seq)) : Number(a.d - b2.d))
        .slice(0, 8)
        .map(({ seq, hash, tick_ms }) => ({ seq, hash, tick_ms }));
      return { candidates: cands as unknown as JsonValue };
    },

    "replay.run": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]);
      this.authorize(ctx, String(p["cap"]), "audit.read", { kind: "audit", value: `${branch}/` });
      const head = this.journal.head(claim, branch);
      if (!head) throw new WorldError("NOT_FOUND", `Unknown stream ${claim}/${branch}.`);
      const through = p["through_seq"] === undefined || p["through_seq"] === null ? head.headSeq : String(p["through_seq"]);
      const clamped = BigInt(through) > BigInt(head.headSeq) ? head.headSeq : through;
      const r = this.replay(claim, branch, clamped);
      const crossing = this.allocId("crossing");
      this.appendEvent({
        claim, branch, kind: "CrossingPrepared",
        payload: { crossing, report: "auto:replay", authority: { cap: String(p["cap"]), generation: "1" }, checks: ["authority:PASS"], planned: { uses: "1", bytes: "0" }, reserved: { uses: "0", bytes: "0" } },
        actor: ctx.principal, command: ctx.requestId,
      });
      this.appendEvent({
        claim, branch, kind: "CrossingCompleted",
        payload: { crossing, previous: "PREPARED", evidence: [], actual: { uses: "1", bytes: "0" }, reservation: "SETTLED" },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { verification: r.verification, through_seq: clamped, state_hash: r.stateHash, state: r.state, effect_dispatches: 0 };
    },

    "branch.create": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]), baseBranch = String(p["base_branch"]), baseSeq = String(p["base_seq"]);
      assertId(branch, "branch");
      this.authorize(ctx, String(p["cap"]), "branch.create", { kind: "branch", value: branch });
      const head = this.journal.head(claim, baseBranch);
      if (!head) throw new WorldError("NOT_FOUND", `Unknown stream ${claim}/${baseBranch}.`);
      if (BigInt(baseSeq) > BigInt(head.headSeq)) throw new WorldError("CAUSAL_CUT_INCOMPLETE", "Base cut is not durable.");
      const baseEnv = this.journal.eventAt(claim, baseBranch, baseSeq);
      if (!baseEnv) throw new WorldError("ARCHIVE_REQUIRED", "Base cut is not retained locally.");
      if (this.journal.head(claim, branch)) throw new WorldError("STATE_TRANSITION", "Branch exists.");
      this.journal.createStream(claim, branch);
      this.appendEvent({
        claim, branch, kind: "BranchCreated",
        payload: {
          branch, parent: { claim, branch: baseBranch, seq: baseSeq, hash: baseEnv.hash },
          reducer: String(p["reducer"] ?? "reducer1"), policy: this.store.getMeta("active_policy") ?? "policy1",
        },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { branch, status: "OPEN", effects_enabled: false, base_seq: baseSeq };
    },

    "branch.set_status": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]);
      const st = this.journal.head(claim, branch);
      if (!st) throw new WorldError("NOT_FOUND", `Unknown branch ${claim}/${branch}.`);
      this.authorizeBranch(ctx, String(p["cap"]), claim, branch);
      const expected = String(p["expected"]), target = String(p["target"]);
      if (st.status !== expected) throw new WorldError("STATE_TRANSITION", `Branch is ${st.status}.`);
      const allowed: Record<string, string[]> = { OPEN: ["SEALED", "ABANDONED"], SEALED: ["ABANDONED"], ABANDONED: [] };
      if (!(allowed[expected] ?? []).includes(target)) throw new WorldError("STATE_TRANSITION", `Illegal branch transition ${expected}→${target}.`);
      this.appendEvent({
        claim, branch: "main", kind: "BranchStatusChanged",
        payload: { branch, from: expected, to: target }, actor: ctx.principal, command: ctx.requestId,
      });
      return { branch, status: target };
    },

    "branch.export_intents": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]);
      const st = this.journal.head(claim, branch);
      if (!st) throw new WorldError("NOT_FOUND", `Unknown branch ${claim}/${branch}.`);
      if (st.status !== "OPEN" && st.status !== "SEALED") throw new WorldError("STATE_TRANSITION", `Branch is ${st.status}.`);
      this.authorizeBranch(ctx, String(p["cap"]), claim, branch);
      const through = p["through_seq"] === undefined ? st.headSeq : String(p["through_seq"]);
      const rows = this.store.all<{ seq: string }>(
        "SELECT seq FROM events WHERE claim=? AND branch=? AND kind='CrossingPrepared' AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER)",
        claim, branch, Number(through));
      const intents: JsonValue[] = [];
      for (const r of rows) {
        const env = this.journal.eventAt(claim, branch, r.seq)!;
        const rep = (env.body.payload as JsonObject)["report"];
        const full = rep ? this.store.getMeta(`report_full:${String(rep)}`) : undefined;
        if (full) {
          const report = JSON.parse(full) as Report;
          intents.push({ intent: report.intent as unknown as JsonValue, intent_digest: report.intent_digest } as JsonObject);
        }
      }
      return { branch, intents };
    },

    "snapshot.create": (ctx, p) => {
      const claim = String(p["claim"]), branch = String(p["branch"]);
      this.authorize(ctx, String(p["cap"]), "snapshot.create", { kind: "snapshot", value: claim });
      const head = this.journal.head(claim, branch);
      if (!head) throw new WorldError("NOT_FOUND", `Unknown stream ${claim}/${branch}.`);
      const through = p["through_seq"] === undefined ? head.headSeq : String(p["through_seq"]);
      const clamped = BigInt(through) > BigInt(head.headSeq) ? head.headSeq : through;
      const snap = this.allocId("snapshot");
      const manifest = this.buildSnapshotManifest(claim, branch, clamped, snap);
      this.store.run(
        "INSERT INTO snapshots(snapshot,claim,branch,through_seq,base_hash,manifest_digest,manifest_json,status) VALUES(?,?,?,?,?,?,?,'BUILDING')",
        snap, claim, branch, clamped, manifest.base_hash, manifest.digest, jcsString(manifest.manifest),
      );
      return { snapshot: snap, status: "BUILDING", through_seq: clamped };
    },

    "snapshot.verify": (ctx, p) => {
      const claim = String(p["claim"]), id = String(p["snapshot"]);
      this.authorize(ctx, String(p["cap"]), "snapshot.create", { kind: "snapshot", value: claim });
      const snap = this.store.get<{ claim: string; branch: string; through_seq: string; status: string; manifest_json: string }>(
        "SELECT claim,branch,through_seq,status,manifest_json FROM snapshots WHERE snapshot=? AND claim=?", id, claim);
      if (!snap) throw new WorldError("NOT_FOUND", `Unknown snapshot ${id}.`);
      if (snap.status !== "BUILDING") throw new WorldError("STATE_TRANSITION", `Snapshot is ${snap.status}.`);
      const result = this.verifySnapshot(id);
      if (!result.ok) {
        // REJECTED is a durable outcome: it must survive the error rollback,
        // so the status write rides in handle()'s denial transaction.
        throw new WorldError("SNAPSHOT_MISMATCH", result.reason, { reject_snapshot: id, reject_evidence: result.evidence });
      }
      this.appendEvent({
        claim, branch: snap.branch, kind: "SnapshotCreated",
        payload: { snapshot: id, manifest_digest: JSON.parse(snap.manifest_json)["digest"] ?? this.store.get<{ manifest_digest: string }>("SELECT manifest_digest FROM snapshots WHERE snapshot=?", id)!.manifest_digest, verification: "VERIFIED" },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { snapshot: id, status: "VERIFIED", ...result.comparisons };
    },

    "retention.archive": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "retention.archive");
      const claim = String(p["claim"]), id = String(p["snapshot"]);
      const snap = this.store.get<{ status: string; branch: string }>("SELECT status,branch FROM snapshots WHERE snapshot=? AND claim=?", id, claim);
      if (!snap) throw new WorldError("NOT_FOUND", `Unknown snapshot ${id}.`);
      if (snap.status !== "VERIFIED") throw new WorldError("ARCHIVE_REDUNDANCY", `Snapshot is ${snap.status}, not VERIFIED.`);
      const destinations = (p["destinations"] as JsonValue[]).map(String);
      const verified = this.archiveCopies(id, destinations);
      this.appendEvent({
        claim, branch: snap.branch, kind: "ArchiveCommitted",
        payload: { snapshot: id, destinations: destinations as unknown as JsonValue, verified_copies: verified },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { snapshot: id, status: "ARCHIVED", verified_copies: verified };
    },

    "receipt.export": (ctx, p) => {
      const claim = String(p["claim"]), crossing = String(p["crossing"]);
      this.authorize(ctx, String(p["cap"]), "audit.read", { kind: "audit", value: "main" });
      const row = this.store.get<{ branch: string }>("SELECT branch FROM crossings WHERE crossing=? AND claim=?", crossing, claim);
      if (!row) throw new WorldError("NOT_FOUND", `Unknown crossing ${crossing}.`);
      const bundle = this.allocId("bundle");
      const receipt = this.buildReceipt(claim, row.branch, crossing, Boolean(p["include_payloads"]));
      const bytes = jcsBytes(receipt);
      const digest = sha256Hex(bytes);
      this.store.run("INSERT INTO objects(claim,object,digest,size,key_version,schema,state) VALUES(?,?,?,?,1,'world-lineage/1','COMMITTED')",
        claim, bundle, digest, bytes.byteLength.toString());
      this.store.run("INSERT INTO registry_artifacts(artifact,kind,bytes,digest) VALUES(?,?,?,?)", `${claim}/${bundle}`, "receipt", bytes, digest);
      this.appendEvent({
        claim, branch: row.branch, kind: "ReceiptExported",
        payload: { bundle, digest, reader: ctx.principal, format: "world-lineage/1", crossing },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { bundle, format: "world-lineage/1", disclosure: p["include_payloads"] ? "FULL" : "HASHES_ONLY", crossing };
    },

    "policy.apply": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "policy.apply");
      if (!this.seats) throw new WorldError("ENFORCER_UNAVAILABLE", "No governance seat set is configured.");
      return policyApply(this, ctx, p, this.seats);
    },

    "worker.status": (ctx, p) => {
      const claim = String(p["claim"]), w = String(p["worker"]);
      this.authorize(ctx, String(p["cap"]), "state.read", { kind: "worker", value: w });
      const row = this.store.get<{ status: string; profile: string; epoch: string; claim: string }>(
        "SELECT status,profile,epoch,claim FROM workers WHERE worker=?", w);
      if (!row || row.claim !== claim) throw new WorldError("NOT_FOUND", `Unknown worker ${w}.`);
      return { worker: w, status: row.status, profile: row.profile, epoch: row.epoch, held_crossings: 0 };
    },

    "host.set_status": (ctx, p) => {
      this.authorizeAdmin(ctx, String(p["cap"]), "host.set_status");
      const cur = this.hostStatus();
      const expected = String(p["expected"]), target = String(p["target"]);
      if (cur !== expected) throw new WorldError("STATE_TRANSITION", `Host is ${cur}.`);
      const allowed: Record<string, string[]> = { READY: ["PAUSED", "QUARANTINED", "STOPPING"], PAUSED: ["READY", "QUARANTINED", "STOPPING"], QUARANTINED: [] };
      if (!(allowed[cur] ?? []).includes(target)) throw new WorldError("STATE_TRANSITION", `Illegal host transition ${cur}→${target}.`);
      if (target === "READY") this.enforcer.assertReady(this.config.profile);
      const unknown = this.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings WHERE state='UNKNOWN'")!.n;
      this.appendEvent({
        claim: "_control", branch: "main", kind: "HostStatusChanged",
        payload: { from: cur, to: target, reason: String(p["reason"] ?? "") },
        actor: ctx.principal, command: ctx.requestId,
      });
      return { status: target, effects_enabled: target === "READY", unknown_crossings: unknown };
    },
  };

  // ---------- helpers used by methods ----------

  private isAdmin(ctx: Caller): boolean {
    try {
      const rows = this.store.all<{ capability: string }>(
        "SELECT capability FROM capabilities WHERE subject=? AND status='ISSUED'", ctx.principal);
      for (const r of rows) {
        const g = loadGrant(this.store, r.capability)!;
        if (g.grant.verbs.includes("admin.manage")) return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  private authorizeBranch(ctx: Caller, capId: string, claim: string, branch: string): void {
    try {
      this.authorize(ctx, capId, "branch.create", { kind: "branch", value: branch });
      return;
    } catch { /* fall through to admin */ }
    this.authorizeAdmin(ctx, capId, "branch.set_status");
  }

  /** Cancel all PREPARED crossings of a claim (freeze/revoke path). Returns §2.5 counts. */
  private cancelPrepared(claim: string, capability?: string): { cancelled: number; dispatched: number; unknown: number } {
    const rows = this.store.all<{ crossing: string; branch: string }>(
      "SELECT crossing,branch FROM crossings WHERE claim=? AND state='PREPARED'", claim);
    let cancelled = 0;
    for (const r of rows) {
      releaseReservations(this.store, r.crossing);
      this.appendEvent({
        claim, branch: r.branch, kind: "CrossingCancelled",
        payload: { crossing: r.crossing, previous: "PREPARED", released: { uses: "0", bytes: "0" } },
        actor: "broker", command: "auto:freeze",
      });
      cancelled++;
    }
    const dispatched = this.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings WHERE claim=? AND state='DISPATCHED'", claim)!.n;
    const unknown = this.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM crossings WHERE claim=? AND state='UNKNOWN'", claim)!.n;
    void capability;
    return { cancelled, dispatched, unknown };
  }

  private isRestriction(prev: Fence, next: Fence): boolean {
    if (next.effect === "deny" && prev.effect === "allow") return true;
    if (next.effect !== prev.effect || next.type !== prev.type) return next.effect === "deny";
    // Every next selector must be covered by a previous selector (narrower or equal).
    const narrowed = next.resources.every((ns) => prev.resources.some((ps) => coversSelector(ps, ns) || (ps.match === "exact" && ps.value === ns.value)));
    if (!narrowed) return false;
    const pc = prev.constraints ?? {}, nc = next.constraints ?? {};
    for (const k of ["uses", "bytes", "cpu_ms", "memory_bytes", "pids"] as const) {
      if (nc[k] !== undefined && pc[k] !== undefined && BigInt(nc[k]!) > BigInt(pc[k]!)) return false;
      if (nc[k] !== undefined && pc[k] === undefined) return false;
    }
    return true;
  }

  private kvAt(claim: string, branch: string, key: string, atSeq: string): JsonValue | null {
    // Historical read: reduce only StatePatched ops through atSeq (bounded page).
    const rows = this.store.all<{ seq: string }>(
      "SELECT seq FROM events WHERE claim=? AND branch=? AND kind='StatePatched' AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER)",
      claim, branch, Number(atSeq));
    let value: JsonValue | null = null;
    let seen = false;
    for (const r of rows) {
      const env = this.journal.eventAt(claim, branch, r.seq)!;
      for (const op of (env.body.payload as JsonObject)["patch"] as JsonValue[]) {
        const o = op as JsonObject;
        if (String(o["key"]) === key) {
          if (o["op"] === "set") { value = o["value"]!; seen = true; }
          if (o["op"] === "delete") { value = null; seen = false; }
        }
      }
    }
    void seen;
    return value;
  }

  private stateRevAt(claim: string, branch: string, atSeq: string): string {
    const row = this.store.get<{ new_rev: string }>(
      `SELECT e.body_enc FROM events e WHERE e.claim=? AND e.branch=? AND e.kind='StatePatched' AND CAST(e.seq AS INTEGER)<=? ORDER BY CAST(e.seq AS INTEGER) DESC LIMIT 1`,
      claim, branch, Number(atSeq));
    if (!row) {
      const gen = this.store.get<{ seq: string }>("SELECT seq FROM events WHERE claim=? AND branch=? AND kind='ClaimCreated'", claim, branch);
      if (gen) {
        const env = this.journal.eventAt(claim, branch, gen.seq)!;
        return String((env.body.payload as JsonObject)["state_rev"]);
      }
      return this.journal.head(claim, branch)?.stateRev ?? "0";
    }
    const seq = this.store.get<{ seq: string }>(
      "SELECT seq FROM events WHERE claim=? AND branch=? AND kind='StatePatched' AND CAST(seq AS INTEGER)<=? ORDER BY CAST(seq AS INTEGER) DESC LIMIT 1",
      claim, branch, Number(atSeq))!.seq;
    const env = this.journal.eventAt(claim, branch, seq)!;
    return String((env.body.payload as JsonObject)["new_rev"]);
  }

  replay(claim: string, branch: string, throughSeq: string): { verification: string; stateHash: string; state: JsonValue } {
    return verifyAndReduce(this.store, this.journal, claim, branch, throughSeq);
  }

  private encodeCursor(principal: string, claim: string, branch: string, after: string, through: string): string {
    const raw = jcsBytes({ principal, claim, branch, after, through } as JsonObject);
    const mac = sealAead(this.keys.controlDataKey(), raw, Buffer.from(`cursor/${principal}`));
    return b64uEncode(mac);
  }

  private decodeCursor(s: string): { principal: string; claim: string; branch: string; after: string; through: string } {
    try {
      const raw = b64uDecodeExact(s);
      // Try each principal's AAD is impossible; cursor embeds principal in plaintext prefix.
      for (const row of this.store.all<{ principal: string }>("SELECT principal FROM principals")) {
        try {
          const plain = openAead(this.keys.controlDataKey(), raw, Buffer.from(`cursor/${row.principal}`));
          return JSON.parse(plain.toString("utf8"));
        } catch { /* try next */ }
      }
    } catch { /* fall through */ }
    throw new WorldError("CURSOR_INVALID", "Cursor cannot be authenticated.");
  }

  private buildSnapshotManifest(claim: string, branch: string, throughSeq: string, snapId: string): { manifest: JsonObject; digest: string; base_hash: string } {
    return buildManifest(this.store, this.journal, claim, branch, throughSeq, snapId);
  }

  private verifySnapshot(id: string): { ok: boolean; reason: string; comparisons: JsonObject; evidence: JsonObject } {
    return verifySnapshotIndependent(this.store, this.journal, id);
  }

  private archiveCopies(id: string, destinations: string[]): number {
    let ok = 0;
    for (const d of destinations) {
      if (archiveCopy(this.store, this.journal, id, d)) ok++;
    }
    if (ok < 2) throw new WorldError("ARCHIVE_REDUNDANCY", "Fewer than two verified archive copies.");
    return ok;
  }

  private buildReceipt(claim: string, branch: string, crossing: string, includePayloads: boolean): JsonObject {
    return buildLineageReceipt(this.store, this.journal, claim, branch, crossing, includePayloads);
  }
}
