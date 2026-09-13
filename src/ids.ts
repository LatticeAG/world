/**
 * Identifier and counter grammar (spec §1.1).
 *
 * IDs match [A-Za-z][A-Za-z0-9_-]{0,63} except the reserved `_control`.
 * Sequence, logical time, revision counters, byte counts and quotas are
 * unsigned decimal strings with no leading zero except "0", bounded by
 * 2^63-1. Overflow fails closed with COUNTER_EXHAUSTED.
 */

import { WorldError } from "./errors.js";

export const ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
export const RESERVED_CONTROL = "_control";
export const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;
export const MAX_COUNTER = 9223372036854775807n; // 2^63 - 1

export function isValidId(id: string): boolean {
  return id === RESERVED_CONTROL || ID_RE.test(id);
}

export function assertId(id: unknown, what = "identifier"): string {
  if (typeof id !== "string" || !isValidId(id)) {
    throw new WorldError("BAD_REQUEST", `Invalid ${what}: must match [A-Za-z][A-Za-z0-9_-]{0,63}.`);
  }
  return id;
}

export function isDecimal(v: unknown): v is string {
  return typeof v === "string" && DECIMAL_RE.test(v);
}

export function assertDecimal(v: unknown, what = "counter"): string {
  if (!isDecimal(v)) {
    throw new WorldError("SCHEMA_NUMBER_RANGE", `Invalid ${what}: unsigned decimal string required.`);
  }
  if (BigInt(v) > MAX_COUNTER) {
    throw new WorldError("COUNTER_EXHAUSTED", `${what} exceeds 2^63-1.`);
  }
  return v;
}

export function decToBigInt(v: string): bigint {
  return BigInt(v);
}

export function decAdd(a: string, b: string): string {
  const r = BigInt(a) + BigInt(b);
  if (r > MAX_COUNTER) throw new WorldError("COUNTER_EXHAUSTED", "Counter overflow.");
  return r.toString();
}

export function decSub(a: string, b: string): string {
  const r = BigInt(a) - BigInt(b);
  if (r < 0n) throw new WorldError("COUNTER_EXHAUSTED", "Counter underflow.");
  return r.toString();
}

export function decNext(a: string): string {
  return decAdd(a, "1");
}

export function decGt(a: string, b: string): boolean {
  return BigInt(a) > BigInt(b);
}

export function decEq(a: string, b: string): boolean {
  return BigInt(a) === BigInt(b);
}

const HEX64_RE = /^[0-9a-f]{64}$/;
export function isHash64(v: unknown): v is string {
  return typeof v === "string" && HEX64_RE.test(v);
}

export function assertHash64(v: unknown, what = "hash"): string {
  if (!isHash64(v)) throw new WorldError("BAD_REQUEST", `Invalid ${what}: 64 lowercase hex chars required.`);
  return v;
}

export const GENESIS_PREV = "0".repeat(64);
