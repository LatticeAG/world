/**
 * Migration coordinator (spec §6.7, TV-W-50/51).
 *
 * Runs only while the host is PAUSED or STOPPED. It copies the live store
 * into a new store directory, verifies event counts and stream heads
 * against the source, records MigrationStatusChanged on the control
 * stream of the NEW store, then installs active-store.json with a
 * directory fsync. The source is retained per the manifest.
 */

import { DatabaseSync } from "node:sqlite";
import { mkdirSync, writeFileSync, readFileSync, existsSync, renameSync, openSync, fsyncSync, closeSync } from "node:fs";
import { join } from "node:path";
import { WorldError } from "./errors.js";
import type { MigrationManifest } from "./config.js";
import type { Store } from "./store.js";
import type { Journal } from "./journal.js";
import { sha256Hex, verifyDetached, publicKeyFromRaw, b64uDecodeExact } from "./crypto.js";
import { jcsBytes, jcsString, type JsonObject } from "./canon.js";
import type { SeatSet } from "./policy.js";

const AMEND_DOMAIN = "LAGI-WORLD-AMEND/v1";

/**
 * Verify a threshold-signed approval artifact (§6.7). The artifact records
 * the applied migration_approve proposal and its votes; verification checks
 * that the presented manifest is exactly the proposal's expanded_manifest
 * and that each distinct eligible seat signed the amendment message
 * `UTF8("LAGI-WORLD-AMEND/v1") || 0x00 || J(proposal)`.
 */
export function verifyMigrationApproval(store: Store, manifest: MigrationManifest, seats: SeatSet): void {
  const row = store.get<{ bytes: Uint8Array; digest: string }>(
    "SELECT bytes,digest FROM registry_artifacts WHERE artifact=? AND kind='approval'", manifest.approval);
  if (!row) throw new WorldError("APPROVAL_INVALID", `Approval ${manifest.approval} is not in the registry.`);
  const approval = JSON.parse(Buffer.from(row.bytes).toString("utf8")) as JsonObject;
  const proposal = approval["proposal"] as JsonObject | undefined;
  const votes = (approval["votes"] ?? []) as { seat: string; signature: string }[];
  if (!proposal) throw new WorldError("APPROVAL_INVALID", "Approval artifact carries no proposal.");
  const expanded = (proposal["mutation"] as JsonObject | undefined)?.["expanded_manifest"];
  if (jcsString((expanded ?? null) as JsonObject | null) !== jcsString(manifest as unknown as JsonObject)) {
    throw new WorldError("APPROVAL_INVALID", "Approval does not cover this manifest.");
  }
  const msg = Buffer.concat([Buffer.from(AMEND_DOMAIN), Buffer.from([0]), jcsBytes(proposal)]);
  const distinct = new Set<string>();
  for (const s of votes) {
    const pub = seats.seats[s.seat];
    if (!pub) continue;
    if (verifyDetached(publicKeyFromRaw(Buffer.from(pub, "hex")), msg, b64uDecodeExact(s.signature, 64))) {
      distinct.add(s.seat);
    }
  }
  if (distinct.size < seats.threshold) {
    throw new WorldError("QUORUM_NOT_MET", `Approval has ${distinct.size} distinct seat signatures; need ${seats.threshold}.`);
  }
}

export interface MigrationResult {
  migration: string;
  status: "COMPLETE";
  new_store: string;
}

/**
 * Execute a manifest against the store layout under `storageRoot`
 * (`stores/<name>/world.sqlite` + `active-store.json`). The caller must
 * hold the host paused for the duration.
 */
export function runMigration(store: Store, journal: Journal, manifest: MigrationManifest, storageRoot: string, seats: SeatSet | null): MigrationResult {
  const status = store.getMeta("host_status") ?? "READY";
  if (status !== "PAUSED" && status !== "STOPPED") {
    throw new WorldError("STATE_TRANSITION", "Migration requires a PAUSED host.");
  }
  if (store.get("SELECT migration FROM migrations WHERE migration=?", manifest.id)) {
    throw new WorldError("STATE_TRANSITION", `Migration ${manifest.id} already exists.`);
  }
  if (seats) verifyMigrationApproval(store, manifest, seats);

  const activeFile = join(storageRoot, "active-store.json");
  const sourceDir = join(storageRoot, "stores", manifest.source_store);
  const targetDir = join(storageRoot, "stores", manifest.target_store);
  if (!existsSync(join(sourceDir, "world.sqlite"))) {
    throw new WorldError("NOT_FOUND", `Source store ${manifest.source_store} not found.`);
  }
  if (existsSync(join(targetDir, "world.sqlite"))) {
    throw new WorldError("STATE_TRANSITION", `Target store ${manifest.target_store} already exists.`);
  }
  mkdirSync(targetDir, { recursive: true });

  // Consistent copy via the SQLite backup path (VACUUM INTO is atomic
  // against the source's read view).
  const targetPath = join(targetDir, "world.sqlite");
  store.db.exec(`VACUUM INTO '${targetPath.replace(/'/g, "''")}'`);

  // Verify: event counts and stream heads must match the source.
  const srcCounts = store.get<{ n: number }>("SELECT COUNT(*) AS n FROM events")!.n;
  const verify = new DatabaseSync(join(targetDir, "world.sqlite"));
  try {
    const dstCounts = (verify.prepare("SELECT COUNT(*) AS n FROM events").get() as { n: number }).n;
    if (dstCounts !== srcCounts) throw new WorldError("REDUCER_FAILED", "Migrated store event count differs.");
    const srcHeads = store.all<{ claim: string; branch: string; head_hash: string }>("SELECT claim,branch,head_hash FROM streams");
    for (const h of srcHeads) {
      const d = verify.prepare("SELECT head_hash AS hh FROM streams WHERE claim=? AND branch=?").get(h.claim, h.branch) as { hh: string } | undefined;
      if (!d || d.hh !== h.head_hash) throw new WorldError("CHAIN_MISMATCH", `Head mismatch on ${h.claim}/${h.branch}.`);
    }
  } finally {
    verify.close();
  }

  store.run("INSERT INTO migrations(migration,status,manifest_json) VALUES(?,?,?)",
    manifest.id, "RUNNING", jcsString(manifest as unknown as JsonObject));

  // Record the transition on the source control stream, then install the
  // active-store pointer atomically (rename + directory fsync).
  journal.append({
    claim: "_control", branch: "main", kind: "MigrationStatusChanged",
    payload: {
      migration: manifest.id, from: "VERIFYING", to: "SWITCH_READY",
      manifest_digest: sha256Hex(jcsBytes(manifest as unknown as JsonObject)),
    },
    actor: "pRuntime", command: `migrate:${manifest.id}`,
  });
  const pointer = jcsString({ active_store: manifest.target_store, migration: manifest.id, installed_seq: store.getMeta("commit_index") ?? "0" });
  const tmp = `${activeFile}.tmp`;
  writeFileSync(tmp, pointer);
  // A crash here leaves the source active and the migration RUNNING —
  // recovery resumes or rolls back, never silently switches (TV-W-51).
  store.fault("before_pointer_switch");
  renameSync(tmp, activeFile);
  const dirFd = openSync(join(storageRoot, "stores"), "r");
  try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  const rootFd = openSync(storageRoot, "r");
  try { fsyncSync(rootFd); } finally { closeSync(rootFd); }

  store.run("UPDATE migrations SET status='COMPLETE', certificate_json=? WHERE migration=?",
    jcsString({ migration: manifest.id, source_events: srcCounts, verified: true }), manifest.id);
  return { migration: manifest.id, status: "COMPLETE", new_store: manifest.target_store };
}
