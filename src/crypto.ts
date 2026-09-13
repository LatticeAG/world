/**
 * Cryptographic primitives (spec §1.3, §4.3, §5.4, §7.1).
 *
 * H(x) is lowercase-hex SHA-256 of bytes x. Event and intent digests are
 * domain-separated with a NUL byte after the ASCII domain tag. Signatures
 * are Ed25519 over the domain tag, NUL, and the raw (hex-decoded) digest.
 * Claim payloads are sealed with XChaCha20-Poly1305 (storage format 1):
 * HChaCha20 derives the subkey, then ordinary ChaCha20-Poly1305 with the
 * nonce layout 0x00000000 || nonce[16..24].
 */

import { createHash, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, sign, verify, randomBytes, type KeyObject } from "node:crypto";
import { WorldError } from "./errors.js";
import { jcsBytes, type JsonValue } from "./canon.js";

export function sha256Hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

export function sha256(b: Uint8Array): Buffer {
  return createHash("sha256").update(b).digest();
}

const D_EVENT = Buffer.from("LAGI-WORLD-EVENT/v1", "ascii");
const D_SIGN = Buffer.from("LAGI-WORLD-SIGN/v1", "ascii");
const D_INTENT = Buffer.from("LAGI-WORLD-INTENT/v1", "ascii");
const D_SNAPSHOT = Buffer.from("LAGI-WORLD-SNAPSHOT/v1", "ascii");
const D_AMEND = Buffer.from("LAGI-WORLD-AMEND/v1", "ascii");
const NUL = Buffer.from([0]);

export function eventHashHex(body: JsonValue): string {
  return sha256Hex(Buffer.concat([D_EVENT, NUL, jcsBytes(body)]));
}

export function intentDigestHex(intent: JsonValue): string {
  return sha256Hex(Buffer.concat([D_INTENT, NUL, jcsBytes(intent)]));
}

export function snapshotRootHex(manifestExcl: JsonValue): string {
  return sha256Hex(Buffer.concat([D_SNAPSHOT, NUL, jcsBytes(manifestExcl)]));
}

export function stateRootHex(state: JsonValue): string {
  return sha256Hex(jcsBytes(state));
}

export function eventSigningMessage(hashHex: string): Buffer {
  return Buffer.concat([D_SIGN, NUL, Buffer.from(hashHex, "hex")]);
}

export function amendSigningMessage(proposal: JsonValue): Buffer {
  return Buffer.concat([D_AMEND, NUL, jcsBytes(proposal)]);
}

// ---- base64url ----

export function b64uEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function b64uDecode(s: string): Buffer {
  if (!B64U_RE.test(s) || s.includes("=")) {
    throw new WorldError("BAD_REQUEST", "Invalid unpadded base64url.");
  }
  return Buffer.from(s, "base64url");
}

export function b64uDecodeExact(s: string, bytes?: number): Buffer {
  const b = b64uDecode(s);
  if (bytes !== undefined && b.byteLength !== bytes) {
    throw new WorldError("BAD_REQUEST", `Expected ${bytes} decoded bytes, got ${b.byteLength}.`);
  }
  return b;
}

// ---- Ed25519 ----

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Build a KeyObject for an Ed25519 private key from its 32-byte seed. */
export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.byteLength !== 32) throw new WorldError("BAD_REQUEST", "Ed25519 seed must be 32 bytes.");
  const der = Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Build a KeyObject for an Ed25519 public key from its 32 raw bytes. */
export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.byteLength !== 32) throw new WorldError("BAD_REQUEST", "Ed25519 public key must be 32 bytes.");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64uEncode(raw) }, format: "jwk" });
}

export function publicKeyRawFromSeed(seed: Uint8Array): Buffer {
  const priv = privateKeyFromSeed(seed);
  const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return b64uDecodeExact(jwk.x, 32);
}

export function signDetached(key: KeyObject, msg: Uint8Array): Buffer {
  return sign(null, Buffer.from(msg), key);
}

export function verifyDetached(key: KeyObject, msg: Uint8Array, sig: Uint8Array): boolean {
  if (sig.byteLength !== 64) return false;
  try {
    return verify(null, Buffer.from(msg), key, Buffer.from(sig));
  } catch {
    return false;
  }
}

// ---- XChaCha20-Poly1305 (storage format 1) ----

const ROTL = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0;

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a]! + s[b]!) >>> 0; s[d] = ROTL(s[d]! ^ s[a]!, 16);
  s[c] = (s[c]! + s[d]!) >>> 0; s[b] = ROTL(s[b]! ^ s[c]!, 12);
  s[a] = (s[a]! + s[b]!) >>> 0; s[d] = ROTL(s[d]! ^ s[a]!, 8);
  s[c] = (s[c]! + s[d]!) >>> 0; s[b] = ROTL(s[b]! ^ s[c]!, 7);
}

function hchacha20(key: Uint8Array, nonce16: Uint8Array): Buffer {
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  const kv = Buffer.from(key);
  for (let i = 0; i < 8; i++) s[4 + i] = kv.readUInt32LE(i * 4);
  const nv = Buffer.from(nonce16);
  for (let i = 0; i < 4; i++) s[12 + i] = nv.readUInt32LE(i * 4);
  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12); quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14); quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15); quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13); quarterRound(s, 3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (const i of [0, 1, 2, 3, 12, 13, 14, 15]) out.writeUInt32LE(s[i]!, i < 4 ? i * 4 : (i - 8) * 4);
  return out;
}

export const AEAD_FORMAT_XCHACHA20_POLY1305 = 1;
export const AEAD_NONCE_BYTES = 24;
export const AEAD_TAG_BYTES = 16;
export const AEAD_OVERHEAD = AEAD_NONCE_BYTES + AEAD_TAG_BYTES;

/**
 * Seal plaintext under XChaCha20-Poly1305. Returns nonce||ciphertext||tag.
 * `aad` binds world/claim/branch/sequence-or-object and the format version.
 */
export function sealAead(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Buffer {
  const nonce = randomBytes(AEAD_NONCE_BYTES);
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const inner = Buffer.concat([Buffer.alloc(4, 0), nonce.subarray(16)]);
  const c = createCipheriv("chacha20-poly1305", subkey, inner, { authTagLength: AEAD_TAG_BYTES });
  c.setAAD(Buffer.from(aad), { plaintextLength: plaintext.byteLength });
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}

export function openAead(key: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Buffer {
  if (sealed.byteLength < AEAD_OVERHEAD) {
    throw new WorldError("HASH_MISMATCH", "Ciphertext shorter than AEAD overhead.");
  }
  const nonce = sealed.subarray(0, AEAD_NONCE_BYTES);
  const tag = sealed.subarray(sealed.byteLength - AEAD_TAG_BYTES);
  const ct = sealed.subarray(AEAD_NONCE_BYTES, sealed.byteLength - AEAD_TAG_BYTES);
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const inner = Buffer.concat([Buffer.alloc(4, 0), nonce.subarray(16)]);
  const d = createDecipheriv("chacha20-poly1305", subkey, inner, { authTagLength: AEAD_TAG_BYTES });
  d.setAuthTag(Buffer.from(tag));
  d.setAAD(Buffer.from(aad), { plaintextLength: ct.byteLength });
  try {
    return Buffer.concat([d.update(Buffer.from(ct)), d.final()]);
  } catch {
    throw new WorldError("HASH_MISMATCH", "AEAD authentication failed.");
  }
}

/** Opaque collision-checked ID material: 128 bits, base64url. */
export function opaqueId(prefix: string): string {
  return `${prefix}${randomBytes(16).toString("base64url").replace(/-/g, "x").replace(/_/g, "y")}`;
}
