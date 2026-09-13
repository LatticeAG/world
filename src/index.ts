/**
 * @latticeag/world — LatticeAGI World zone core (OSS).
 *
 * Canonical signed event log, claims, capabilities, fences, deterministic
 * simulation, crossings, replay, snapshots, retention, and governance —
 * the local zone core per W-1.0-draft.2. Hosted/cloud/zone-gated surfaces
 * are explicit NOT_IMPLEMENTED stubs.
 */

export * as canon from "./canon.js";
export * as crypto2 from "./crypto.js";
export * as errors from "./errors.js";
export * as ids from "./ids.js";
export { Store, type Failpoint } from "./store.js";
export { MemoryKeyService, FileKeyService, seedFromHandle, type KeyService, type WriterKey } from "./keys.js";
export { ManualClock, MonotonicSource, DurableClock, restartTick, type TickSource } from "./clock.js";
export { SchemaRegistry } from "./registry.js";
export { Journal, type Envelope, type EventBody, type CauseRef, type StreamHead } from "./journal.js";
export { reduce, reduceEvent, applyEventSql, emptyProjection, stateRootOf, authRootOf, reservationRootOf, type Projection } from "./reducer.js";
export { effectiveAuthority, loadGrant, releaseReservations, type Grant, type ResourceSelector } from "./capability.js";
export { evalFences, validateFence, type Fence } from "./fences.js";
export { normalizeIntent, validateIntent, intentDigest, meteredBytes, type Intent, type NormalizedIntent } from "./intent.js";
export { Enforcer, WASM_PROCESS_V1_BASELINE, WASM_PROCESS_V1_DENIED } from "./enforcer.js";
export { AdapterRegistry, TestAdapter, type Adapter } from "./adapters.js";
export { verifyAndReduce, replayModel, forkGate, causalCutComplete, type ReplayResult } from "./replay.js";
export { buildManifest, verifySnapshotIndependent, archiveCopy, pruneGate, segmentRoot, inclusionProof, verifyInclusion, SNAPSHOT_DOMAIN, snapshotRoot } from "./snapshot.js";
export { buildLineageReceipt, verifyReceiptBundle } from "./receipt.js";
export { policyApply, verifyVotes, signProposal, amendmentMessage, type SeatSet, type PolicyBundle } from "./policy.js";
export { parseWorldConfig, parseTrustFile, parseMigrationManifest, type WorldConfig, type TrustFile, type MigrationManifest } from "./config.js";
export { ChannelSession, FrameDecoder, encodeFrame, MAX_FRAME, type ChannelBinding } from "./channel.js";
export { WorldServer, peerUid, type ServerOptions } from "./server.js";
export { runMigration, verifyMigrationApproval } from "./migrate.js";
export { seedFixtureB, seedFixtureInto, openWorld, seedCrossings, I1, I1_DIGEST, E1, E2, WRITER_TEST_1_SEED, WRITER_TEST_1_PUB, WRITER_TEST_2_SEED, SEAT2_SEED, SEAT2_PUB, SEAT3_SEED, SEAT3_PUB, PINNED_ENGINE_DIGEST, PINNED_ENFORCER_DIGEST, PINNED_BUNDLE_DIGEST } from "./fixture.js";
export { Broker, type Caller, type Ctx, type Report, type BrokerConfig, engineDigestHex, modelDigestHex } from "./broker.js";
