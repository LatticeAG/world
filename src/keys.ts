/**
 * Key services (spec §2.2, §7.2, §10.4).
 *
 * Signing keys and claim master keys are reached through protected handles,
 * never inline in configuration or event payloads. The file-backed service
 * stores operator-owned 0600 key material under a keyring directory; the
 * memory service exists for tests and the offline verifier.
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { WorldError } from "./errors.js";
import { privateKeyFromSeed, publicKeyFromRaw, publicKeyRawFromSeed } from "./crypto.js";
import type { KeyObject } from "node:crypto";

export interface WriterKey {
  keyId: string;
  epoch: string;
  priv: KeyObject;
  pubRaw: Buffer;
}

export interface KeyService {
  /** Current writer signing key for the given epoch. */
  writerKey(keyId: string, epoch: string): WriterKey;
  /** Public half only (verifier path). */
  writerPublic(keyId: string): Buffer;
  /** Per-claim 32-byte data key (claim plaintext sealing). */
  claimDataKey(claim: string): Buffer;
  /** Control-stream data key. */
  controlDataKey(): Buffer;
}

/** Deterministic in-memory keyring for tests and fixture builds. */
export class MemoryKeyService implements KeyService {
  private writers = new Map<string, { seed: Buffer; epoch: string }>();
  private claimKeys = new Map<string, Buffer>();
  private control = randomBytes(32);

  addWriter(keyId: string, seedHex: string, epoch: string): this {
    this.writers.set(keyId, { seed: Buffer.from(seedHex, "hex"), epoch });
    return this;
  }

  addClaimKey(claim: string, key: Buffer): this {
    this.claimKeys.set(claim, key);
    return this;
  }

  writerKey(keyId: string, epoch: string): WriterKey {
    const w = this.writers.get(keyId);
    if (!w || w.epoch !== epoch) {
      throw new WorldError("ENFORCER_UNAVAILABLE", `No writer key ${keyId} for epoch ${epoch}.`);
    }
    return { keyId, epoch, priv: privateKeyFromSeed(w.seed), pubRaw: publicKeyRawFromSeed(w.seed) };
  }

  writerPublic(keyId: string): Buffer {
    const w = this.writers.get(keyId);
    if (!w) throw new WorldError("NOT_FOUND", `Unknown writer key ${keyId}.`);
    return publicKeyRawFromSeed(w.seed);
  }

  claimDataKey(claim: string): Buffer {
    let k = this.claimKeys.get(claim);
    if (!k) {
      k = randomBytes(32);
      this.claimKeys.set(claim, k);
    }
    return k;
  }

  controlDataKey(): Buffer {
    return this.control;
  }
}

/** Operator-owned keyring directory; every file is 0600 root-owned material. */
export class FileKeyService implements KeyService {
  private mem = new MemoryKeyService();
  private loaded = false;

  constructor(private readonly dir: string) {}

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    let entries: string[] = [];
    try {
      entries = readdirSync(this.dir);
    } catch {
      throw new WorldError("ENFORCER_UNAVAILABLE", `Keyring ${this.dir} is not provisioned.`);
    }
    for (const name of entries) {
      const path = join(this.dir, name);
      const raw = readFileSync(path, "utf8").trim();
      if (name.startsWith("writer-") && name.endsWith(".key")) {
        // format: "<key_id> <epoch> <seed hex>"
        const [keyId, epoch, seed] = raw.split(/\s+/);
        if (!keyId || !epoch || !seed || !/^[0-9a-f]{64}$/.test(seed)) {
          throw new WorldError("ENFORCER_UNAVAILABLE", `Malformed writer key file ${name}.`);
        }
        this.mem.addWriter(keyId, seed, epoch);
      } else if (name.startsWith("claim-") && name.endsWith(".key")) {
        const claim = name.slice("claim-".length, -".key".length);
        if (!/^[0-9a-f]{64}$/.test(raw)) {
          throw new WorldError("ENFORCER_UNAVAILABLE", `Malformed claim key file ${name}.`);
        }
        this.mem.addClaimKey(claim, Buffer.from(raw, "hex"));
      }
    }
  }

  writerKey(keyId: string, epoch: string): WriterKey {
    this.load();
    return this.mem.writerKey(keyId, epoch);
  }
  writerPublic(keyId: string): Buffer {
    this.load();
    return this.mem.writerPublic(keyId);
  }
  claimDataKey(claim: string): Buffer {
    this.load();
    return this.mem.claimDataKey(claim);
  }
  controlDataKey(): Buffer {
    this.load();
    return this.mem.controlDataKey();
  }

  /** Provision a fresh claim data key file (operator action, 0600). */
  provisionClaimKey(claim: string): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(this.dir, `claim-${claim}.key`), randomBytes(32).toString("hex"), { mode: 0o600 });
  }
}

/** Well-known deterministic test seeds (fixture cryptography, §12). */
export const TEST_SEEDS: Record<string, string> = {
  "writer-test-1": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "writer-test-2": "257967c1f94e2a1137dd36ff29a10e01eecbd3186aac16b9354ccfd339d6bd79",
};

/**
 * Resolve a writer key handle from configuration. Supported handle forms:
 *   file:<dir>   — operator keyring directory (FileKeyService)
 *   env:<VAR>    — hex seed in an environment variable (dev only)
 *   test:<name>  — deterministic test seed (fixture/smoke only)
 * Anything else is an unprovisioned handle and fails closed.
 */
export function seedFromHandle(handle: string): KeyService {
  if (handle.startsWith("file:")) return new FileKeyService(handle.slice(5));
  if (handle.startsWith("env:")) {
    const v = process.env[handle.slice(4)];
    if (!v || !/^[0-9a-f]{64}$/.test(v)) {
      throw new WorldError("ENFORCER_UNAVAILABLE", `Environment key handle ${handle.slice(4)} is not provisioned.`);
    }
    const m = new MemoryKeyService();
    m.addWriter(handle, v, "1");
    return m;
  }
  if (handle.startsWith("test:")) {
    const seed = TEST_SEEDS[handle.slice(5)];
    if (!seed) throw new WorldError("ENFORCER_UNAVAILABLE", `Unknown test key ${handle}.`);
    const m = new MemoryKeyService();
    m.addWriter(handle, seed, "1");
    return m;
  }
  throw new WorldError("ENFORCER_UNAVAILABLE", `Key handle ${handle} is not provisioned (expected file:, env:, or test:).`);
}
