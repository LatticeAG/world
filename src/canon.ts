/**
 * Canonical JSON per spec §1.2: RFC 8785 (JCS) plus the stricter event
 * numeric profile.
 *
 * - Wire bytes are UTF-8 without BOM; invalid UTF-8 is rejected fatally.
 * - Duplicate object keys are rejected while scanning, before the object is
 *   materialized.
 * - Strings must be valid Unicode scalar sequences; lone surrogates are
 *   rejected. No Unicode normalization ever occurs.
 * - JCS key order is UTF-16 code-unit order; number output is ECMAScript
 *   Number::toString; output has no insignificant whitespace.
 * - Event profile: only safe integers in [-2^53+1, 2^53-1] are permitted
 *   (SCHEMA_NUMBER_RANGE); the standalone JCS utility accepts any finite
 *   binary64.
 */

import { WorldError } from "./errors.js";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };
export type JsonObject = { [k: string]: JsonValue };

export interface ParseLimits {
  maxDepth: number;
  maxObjectMembers: number;
  maxArrayElements: number;
  maxBytes: number;
}

/** Event body limits from §1.2 (256 KiB body, depth 32, 1024 members, 4096 elements). */
export const EVENT_LIMITS: ParseLimits = {
  maxDepth: 32,
  maxObjectMembers: 1024,
  maxArrayElements: 4096,
  maxBytes: 256 * 1024,
};

/** Wire request limits from §6.1 (1 MiB). */
export const WIRE_LIMITS: ParseLimits = {
  maxDepth: 64,
  maxObjectMembers: 8192,
  maxArrayElements: 8192,
  maxBytes: 1024 * 1024,
};

export type NumberMode = "jcs" | "event";

const utf8 = new TextDecoder("utf-8", { fatal: true });

function decodeUtf8(bytes: Uint8Array): string {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new WorldError("INVALID_JSON_NUMBER", "UTF-8 BOM is not permitted on the wire.");
  }
  try {
    return utf8.decode(bytes);
  } catch {
    throw new WorldError("INVALID_JSON_NUMBER", "Invalid UTF-8 on the wire.");
  }
}

function assertScalarString(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) {
        throw new WorldError("INVALID_JSON_NUMBER", "Lone surrogate in string.");
      }
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new WorldError("INVALID_JSON_NUMBER", "Lone surrogate in string.");
    }
  }
}

class Parser {
  private i = 0;
  private depth = 0;
  constructor(
    private readonly s: string,
    private readonly limits: ParseLimits,
    private readonly numbers: NumberMode,
  ) {}

  parse(): JsonValue {
    this.ws();
    const v = this.value();
    this.ws();
    if (this.i !== this.s.length) {
      throw new WorldError("INVALID_JSON_NUMBER", "Trailing bytes after JSON value.");
    }
    return v;
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private peek(): number {
    return this.i < this.s.length ? this.s.charCodeAt(this.i) : -1;
  }

  private value(): JsonValue {
    const c = this.peek();
    if (c === 0x7b) return this.object();
    if (c === 0x5b) return this.array();
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
    throw new WorldError("INVALID_JSON_NUMBER", `Unexpected character at offset ${this.i}.`);
  }

  private lit(word: string, v: JsonValue): JsonValue {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    throw new WorldError("INVALID_JSON_NUMBER", `Invalid literal at offset ${this.i}.`);
  }

  private object(): JsonObject {
    this.i++; // {
    this.depth++;
    if (this.depth > this.limits.maxDepth) {
      throw new WorldError("SCHEMA_NUMBER_RANGE", "Nesting depth exceeds limit.");
    }
    const seen = new Set<string>();
    const out: JsonObject = {};
    let members = 0;
    this.ws();
    if (this.peek() === 0x7d) {
      this.i++;
      this.depth--;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.peek() !== 0x22) {
        throw new WorldError("INVALID_JSON_NUMBER", "Object key must be a string.");
      }
      const key = this.string() as string;
      // Duplicate keys are rejected before the member is materialized.
      if (seen.has(key)) {
        throw new WorldError("INVALID_JSON_DUPLICATE", `Duplicate object key ${JSON.stringify(key)}.`);
      }
      seen.add(key);
      members++;
      if (members > this.limits.maxObjectMembers) {
        throw new WorldError("SCHEMA_NUMBER_RANGE", "Object member count exceeds limit.");
      }
      this.ws();
      if (this.peek() !== 0x3a) {
        throw new WorldError("INVALID_JSON_NUMBER", "Expected ':' after object key.");
      }
      this.i++;
      this.ws();
      out[key] = this.value();
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        this.depth--;
        return out;
      }
      throw new WorldError("INVALID_JSON_NUMBER", "Expected ',' or '}' in object.");
    }
  }

  private array(): JsonValue[] {
    this.i++; // [
    this.depth++;
    if (this.depth > this.limits.maxDepth) {
      throw new WorldError("SCHEMA_NUMBER_RANGE", "Nesting depth exceeds limit.");
    }
    const out: JsonValue[] = [];
    this.ws();
    if (this.peek() === 0x5d) {
      this.i++;
      this.depth--;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      if (out.length > this.limits.maxArrayElements) {
        throw new WorldError("SCHEMA_NUMBER_RANGE", "Array element count exceeds limit.");
      }
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        this.depth--;
        return out;
      }
      throw new WorldError("INVALID_JSON_NUMBER", "Expected ',' or ']' in array.");
    }
  }

  private string(): string {
    // consume opening quote
    this.i++;
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) {
        throw new WorldError("INVALID_JSON_NUMBER", "Unterminated string.");
      }
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        assertScalarString(out);
        return out;
      }
      if (c === 0x5c) {
        this.i++;
        const e = this.peek();
        switch (e) {
          case 0x22: out += '"'; this.i++; break;
          case 0x5c: out += "\\"; this.i++; break;
          case 0x2f: out += "/"; this.i++; break;
          case 0x62: out += "\b"; this.i++; break;
          case 0x66: out += "\f"; this.i++; break;
          case 0x6e: out += "\n"; this.i++; break;
          case 0x72: out += "\r"; this.i++; break;
          case 0x74: out += "\t"; this.i++; break;
          case 0x75: {
            const hex = this.s.slice(this.i + 1, this.i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
              throw new WorldError("INVALID_JSON_NUMBER", "Bad \\u escape.");
            }
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 5;
            break;
          }
          default:
            throw new WorldError("INVALID_JSON_NUMBER", "Bad string escape.");
        }
      } else {
        if (c < 0x20) {
          throw new WorldError("INVALID_JSON_NUMBER", "Unescaped control character in string.");
        }
        out += this.s[this.i];
        this.i++;
      }
    }
  }

  private number(): number {
    const start = this.i;
    if (this.peek() === 0x2d) this.i++;
    // int part
    if (this.peek() === 0x30) {
      this.i++;
    } else if (this.peek() >= 0x31 && this.peek() <= 0x39) {
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.i++;
    } else {
      throw new WorldError("INVALID_JSON_NUMBER", "Malformed number.");
    }
    if (this.peek() === 0x2e) {
      this.i++;
      if (!(this.peek() >= 0x30 && this.peek() <= 0x39)) {
        throw new WorldError("INVALID_JSON_NUMBER", "Malformed fraction.");
      }
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.i++;
    }
    const c = this.peek();
    if (c === 0x65 || c === 0x45) {
      this.i++;
      const sgn = this.peek();
      if (sgn === 0x2b || sgn === 0x2d) this.i++;
      if (!(this.peek() >= 0x30 && this.peek() <= 0x39)) {
        throw new WorldError("INVALID_JSON_NUMBER", "Malformed exponent.");
      }
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.i++;
    }
    const text = this.s.slice(start, this.i);
    const n = Number(text);
    if (!Number.isFinite(n)) {
      throw new WorldError("INVALID_JSON_NUMBER", `Non-finite number ${text}.`);
    }
    if (this.numbers === "event" && !Number.isSafeInteger(n)) {
      throw new WorldError("SCHEMA_NUMBER_RANGE", `Number ${text} is outside the event profile's safe-integer range.`);
    }
    return n;
  }
}

export interface ParseOptions {
  limits?: ParseLimits;
  numbers?: NumberMode;
}

/** Strict parse of UTF-8 wire bytes (or a JS string) under the JCS profile. */
export function parseJson(input: Uint8Array | string, opts: ParseOptions = {}): JsonValue {
  const s = typeof input === "string" ? checkBomString(input) : decodeUtf8(input);
  const limits = opts.limits ?? WIRE_LIMITS;
  if (typeof input !== "string" && input.byteLength > limits.maxBytes) {
    throw new WorldError("SCHEMA_NUMBER_RANGE", "Input exceeds byte limit.");
  }
  return new Parser(s, limits, opts.numbers ?? "jcs").parse();
}

function checkBomString(s: string): string {
  if (s.charCodeAt(0) === 0xfeff) {
    throw new WorldError("INVALID_JSON_NUMBER", "BOM is not permitted.");
  }
  return s;
}

/** Strict parse under the event numeric profile (safe integers only). */
export function parseEventProfile(input: Uint8Array | string, limits: ParseLimits = EVENT_LIMITS): JsonValue {
  return parseJson(input, { limits, numbers: "event" });
}

const ESCAPE: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

function serializeString(s: string, out: string[]): void {
  out.push('"');
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const e = ESCAPE[c];
    if (e !== undefined) {
      out.push(e);
    } else if (c < 0x20 || c > 0x7e) {
      // §1.2 profile: control and non-ASCII code units serialize as \uXXXX
      // (astral characters become their surrogate-pair escapes). No
      // normalization: composed and decomposed forms stay byte-distinct.
      out.push("\\u" + c.toString(16).padStart(4, "0"));
    } else {
      out.push(s[i]!);
    }
  }
  out.push('"');
}

function serializeNumber(n: number, out: string[]): void {
  if (!Number.isFinite(n)) {
    throw new WorldError("INVALID_JSON_NUMBER", "Cannot serialize non-finite number.");
  }
  // ECMAScript Number::toString; -0 serializes as "0" per RFC 8785.
  out.push(n === 0 ? "0" : String(n));
}

function serializeValue(v: JsonValue, out: string[]): void {
  if (v === null) {
    out.push("null");
  } else if (v === true) {
    out.push("true");
  } else if (v === false) {
    out.push("false");
  } else if (typeof v === "number") {
    serializeNumber(v, out);
  } else if (typeof v === "string") {
    serializeString(v, out);
  } else if (Array.isArray(v)) {
    out.push("[");
    for (let i = 0; i < v.length; i++) {
      if (i) out.push(",");
      serializeValue(v[i]!, out);
    }
    out.push("]");
  } else {
    out.push("{");
    // UTF-16 code-unit order is exactly JS's default string comparison order.
    const keys = Object.keys(v).sort();
    for (let i = 0; i < keys.length; i++) {
      if (i) out.push(",");
      const k = keys[i]!;
      serializeString(k, out);
      out.push(":");
      serializeValue(v[k]!, out);
    }
    out.push("}");
  }
}

/** J(x): RFC 8785 canonical serialization, returned as a JS string. */
export function jcsString(v: JsonValue): string {
  const out: string[] = [];
  serializeValue(v, out);
  return out.join("");
}

/** J(x) as UTF-8 bytes. */
export function jcsBytes(v: JsonValue): Uint8Array {
  return new TextEncoder().encode(jcsString(v));
}

/** Parse-then-canonicalize a raw wire string. */
export function canonicalize(raw: string, numbers: NumberMode = "jcs"): string {
  return jcsString(parseJson(raw, { numbers }));
}
