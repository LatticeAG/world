/**
 * Authoritative SQLite store (spec §7).
 *
 * One database, WAL mode, synchronous=FULL, foreign keys on, one exclusive
 * application writer, explicit write transactions. All control and claim
 * event metadata live in the same database so revocation, bilateral
 * crossings, outbox state, and budget reservations commit atomically.
 *
 * Claim plaintext payloads are sealed with per-claim XChaCha20-Poly1305
 * before insertion (storage format 1); hashes always cover plaintext
 * canonical bytes, never ciphertext.
 */

import { DatabaseSync } from "node:sqlite";
import { WorldError } from "./errors.js";

export const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS control_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claims (
  claim TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  generation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS streams (
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  head_seq TEXT NOT NULL,
  head_hash TEXT NOT NULL,
  state_rev TEXT NOT NULL,
  auth_rev TEXT NOT NULL,
  lamport TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  PRIMARY KEY (claim, branch)
);

CREATE TABLE IF NOT EXISTS events (
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  seq TEXT NOT NULL,
  hash TEXT NOT NULL,
  kind TEXT NOT NULL,
  schema INTEGER NOT NULL,
  body_enc BLOB NOT NULL,
  key_id TEXT NOT NULL,
  signature TEXT NOT NULL,
  writer_epoch TEXT NOT NULL,
  commit_index TEXT NOT NULL,
  lamport TEXT NOT NULL,
  tick_ms TEXT NOT NULL,
  command TEXT NOT NULL,
  PRIMARY KEY (claim, branch, seq),
  UNIQUE (claim, branch, hash)
);
CREATE INDEX IF NOT EXISTS events_claim_kind_seq ON events(claim, kind, seq);
CREATE INDEX IF NOT EXISTS events_claim_command ON events(claim, command);
CREATE INDEX IF NOT EXISTS events_commit_index ON events(commit_index);

CREATE TABLE IF NOT EXISTS event_causes (
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  seq TEXT NOT NULL,
  cause_claim TEXT NOT NULL,
  cause_branch TEXT NOT NULL,
  cause_seq TEXT NOT NULL,
  cause_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_causes_idx ON event_causes(claim, branch, seq);

CREATE TABLE IF NOT EXISTS commands (
  principal TEXT NOT NULL,
  request_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  op TEXT NOT NULL,
  result_enc BLOB,
  crossing TEXT,
  disposition TEXT NOT NULL,
  accepted_tick TEXT NOT NULL,
  PRIMARY KEY (principal, request_id)
);
CREATE INDEX IF NOT EXISTS commands_claim ON commands(request_id);

CREATE TABLE IF NOT EXISTS principals (
  principal TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  uid INTEGER,
  channel TEXT,
  status TEXT NOT NULL,
  generation TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS principals_uid ON principals(uid) WHERE uid IS NOT NULL AND status = 'ENABLED';

CREATE TABLE IF NOT EXISTS capabilities (
  capability TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  subject TEXT NOT NULL,
  parent TEXT,
  grant_enc BLOB NOT NULL,
  generation TEXT NOT NULL,
  status TEXT NOT NULL,
  revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS capabilities_parent ON capabilities(parent);
CREATE INDEX IF NOT EXISTS capabilities_claim ON capabilities(claim);

CREATE TABLE IF NOT EXISTS reservations (
  crossing TEXT NOT NULL,
  capability TEXT NOT NULL,
  dimension TEXT NOT NULL,
  held TEXT NOT NULL,
  spent TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'HELD',
  PRIMARY KEY (crossing, capability, dimension)
);
CREATE INDEX IF NOT EXISTS reservations_cap ON reservations(capability);

CREATE TABLE IF NOT EXISTS cap_usage (
  capability TEXT NOT NULL,
  dimension TEXT NOT NULL,
  used TEXT NOT NULL,
  PRIMARY KEY (capability, dimension)
);

CREATE TABLE IF NOT EXISTS simulations (
  report TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  report_enc BLOB NOT NULL,
  state TEXT NOT NULL,
  expires_tick TEXT NOT NULL,
  consumed_crossing TEXT
);

CREATE TABLE IF NOT EXISTS crossings (
  crossing TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  report TEXT,
  state TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  action TEXT NOT NULL,
  adapter_request_digest TEXT,
  deadline_tick TEXT,
  dispatch_epoch TEXT,
  evidence_json TEXT,
  result_enc BLOB,
  command TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS crossings_report ON crossings(report) WHERE report IS NOT NULL;
CREATE INDEX IF NOT EXISTS crossings_claim_state ON crossings(claim, state);

CREATE TABLE IF NOT EXISTS objects (
  claim TEXT NOT NULL,
  object TEXT NOT NULL,
  digest TEXT NOT NULL,
  size TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  schema TEXT,
  state TEXT NOT NULL,
  lineage_json TEXT,
  PRIMARY KEY (claim, object)
);

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  through_seq TEXT NOT NULL,
  base_hash TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  manifest_json TEXT,
  evidence_json TEXT,
  status TEXT NOT NULL,
  verified_copies INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS policies (
  policy TEXT PRIMARY KEY,
  epoch TEXT NOT NULL UNIQUE,
  bundle_json TEXT NOT NULL,
  bundle_digest TEXT NOT NULL,
  enforcer_digest TEXT NOT NULL,
  predecessor TEXT,
  ceremony TEXT,
  status TEXT NOT NULL,
  activation_commit TEXT
);

CREATE TABLE IF NOT EXISTS fences (
  claim TEXT NOT NULL,
  id TEXT NOT NULL,
  version INTEGER NOT NULL,
  fence_json TEXT NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (claim, id, version)
);

CREATE TABLE IF NOT EXISTS tombstones (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  data_json TEXT NOT NULL,
  PRIMARY KEY (namespace, id)
);

CREATE TABLE IF NOT EXISTS workers (
  worker TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  status TEXT NOT NULL,
  profile TEXT NOT NULL,
  epoch TEXT NOT NULL,
  pidfd TEXT,
  exec_digest TEXT,
  crossing TEXT
);

CREATE TABLE IF NOT EXISTS amendments (
  proposal_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  proposal_json TEXT NOT NULL,
  status TEXT NOT NULL,
  votes_json TEXT NOT NULL,
  result_id TEXT,
  nonce TEXT NOT NULL UNIQUE,
  expires_tick TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adapters (
  adapter TEXT PRIMARY KEY,
  manifest_json TEXT NOT NULL,
  digest TEXT NOT NULL,
  certified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS channels (
  channel TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  principal TEXT NOT NULL,
  worker TEXT,
  worker_epoch TEXT,
  pidfd TEXT,
  exec_digest TEXT,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
  observation TEXT NOT NULL,
  claim TEXT NOT NULL,
  object TEXT NOT NULL,
  digest TEXT NOT NULL,
  bytes TEXT NOT NULL,
  PRIMARY KEY (observation, claim)
);

CREATE TABLE IF NOT EXISTS writer_keys (
  key_id TEXT PRIMARY KEY,
  epoch TEXT NOT NULL,
  public_key TEXT NOT NULL,
  status TEXT NOT NULL,
  retired_from_epoch TEXT,
  retired_through_epoch TEXT
);

CREATE TABLE IF NOT EXISTS kv_state (
  claim TEXT NOT NULL,
  branch TEXT NOT NULL,
  key TEXT NOT NULL,
  value_enc BLOB NOT NULL,
  PRIMARY KEY (claim, branch, key)
);

CREATE TABLE IF NOT EXISTS migrations (
  migration TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  certificate_json TEXT
);

CREATE TABLE IF NOT EXISTS registry_artifacts (
  artifact TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  bytes BLOB NOT NULL,
  digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

/**
 * Named fault-injection points for crash-consistency tests. A set name
 * throws STORAGE_UNAVAILABLE (or the given error) exactly where durable
 * work would be lost in a real crash.
 */
export type Failpoint =
  | "prepare_fsync"
  | "before_sqlite_commit"
  | "dispatch_marker"
  | "adapter_call"
  | "result_record"
  | "pointer_switch"
  | "before_pointer_switch";

export class Store {
  readonly db: DatabaseSync;
  private readonly stmts = new Map<string, ReturnType<DatabaseSync["prepare"]>>();
  private txDepth = 0;
  failpoints = new Set<Failpoint>();
  /** Counts committed appends for conformance accounting. */
  committedEvents = 0;
  /** Wired at construction of the broker; resolves per-claim data keys. */
  keys!: { claimDataKey(claim: string): Buffer; controlDataKey(): Buffer };

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
  }

  claimKey(claim: string): Buffer {
    return claim === "_control" ? this.keys.controlDataKey() : this.keys.claimDataKey(claim);
  }

  close(): void {
    this.db.close();
  }

  fault(p: Failpoint, msg = `injected fault at ${p}`): void {
    if (this.failpoints.has(p)) {
      throw new WorldError("STORAGE_UNAVAILABLE", msg);
    }
  }

  prepare(sql: string) {
    let s = this.stmts.get(sql);
    if (!s) {
      s = this.db.prepare(sql);
      this.stmts.set(sql, s);
    }
    return s;
  }

  run(sql: string, ...params: (string | number | bigint | null | Uint8Array)[]) {
    return this.prepare(sql).run(...(params as never[]));
  }

  get<T = Record<string, unknown>>(sql: string, ...params: (string | number | bigint | null | Uint8Array)[]): T | undefined {
    return this.prepare(sql).get(...(params as never[])) as T | undefined;
  }

  all<T = Record<string, unknown>>(sql: string, ...params: (string | number | bigint | null | Uint8Array)[]): T[] {
    return this.prepare(sql).all(...(params as never[])) as T[];
  }

  /** One exclusive write transaction; nested calls join the outer tx. */
  tx<T>(fn: () => T): T {
    if (this.txDepth > 0) return fn();
    this.db.exec("BEGIN IMMEDIATE");
    this.txDepth++;
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* already rolled back */
      }
      throw e;
    } finally {
      this.txDepth--;
    }
  }

  /** Current global commit index (orders DB transactions; never exposed to claim readers). */
  nextCommitIndex(): string {
    const row = this.get<{ v: string }>("SELECT value AS v FROM control_meta WHERE key='commit_index'");
    const next = (BigInt(row?.v ?? "0") + 1n).toString();
    this.run("INSERT INTO control_meta(key,value) VALUES('commit_index',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", next);
    return next;
  }

  getMeta(key: string): string | undefined {
    return this.get<{ v: string }>("SELECT value AS v FROM control_meta WHERE key=?", key)?.v;
  }

  setMeta(key: string, value: string): void {
    this.run("INSERT INTO control_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value);
  }

  /** §9.1 counter family — monotonically increasing integer metrics. */
  bumpMetric(name: string, by = 1): void {
    this.run("INSERT INTO metrics(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+? AS TEXT)", name, String(by), by);
  }
}
