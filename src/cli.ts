/**
 * `world` command-line interface (spec §6.6): a thin client of the broker
 * over the unix socket plus an offline verifier. It never opens the
 * authoritative database for writing. One result object goes to stdout;
 * diagnostics go to stderr; exit codes follow §6.9.
 */

import http from "node:http";
import net from "node:net";
import { readFileSync, openSync, readSync, closeSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseJson, jcsString, jcsBytes, type JsonObject, type JsonValue } from "./canon.js";
import { WorldError } from "./errors.js";
import { parseWorldConfig, parseTrustFile, parseMigrationManifest } from "./config.js";
import { verifyReceiptBundle } from "./receipt.js";
import { signDetached, privateKeyFromSeed, b64uEncode, sha256Hex } from "./crypto.js";
import { encodeFrame, FrameDecoder } from "./channel.js";
import { MemoryKeyService, seedFromHandle } from "./keys.js";
import { ManualClock, DurableClock, MonotonicSource } from "./clock.js";
import { WorldServer } from "./server.js";
import { openWorld, seedFixtureInto, WRITER_TEST_1_SEED } from "./fixture.js";

const DEFAULT_SOCKET = "/run/lattice-world/world.sock";

// ---------- flag parsing ----------

function flags(argv: string[]): { pos: string[]; opt: Map<string, string> } {
  const pos: string[] = [];
  const opt = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) opt.set(a.slice(2, eq), a.slice(eq + 1));
      else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) opt.set(a.slice(2), argv[++i]!);
      else opt.set(a.slice(2), "true");
    } else pos.push(a);
  }
  return { pos, opt };
}

function reqOpt(opt: Map<string, string>, k: string): string {
  const v = opt.get(k);
  if (!v || v === "true") throw new WorldError("BAD_REQUEST", `Missing --${k}.`);
  return v;
}

function readJsonFile(path: string): JsonValue {
  return parseJson(readFileSync(path, "utf8"));
}

// ---------- transports ----------

function rpcCall(socketPath: string, req: JsonObject): Promise<JsonObject> {
  const payload = jcsString(req);
  return new Promise((resolve, reject) => {
    const r = http.request(
      { socketPath, path: "/v1/rpc", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try { resolve(parseJson(Buffer.concat(chunks).toString("utf8")) as JsonObject); }
          catch (e) { reject(e); }
        });
      });
    r.on("error", () => reject(new WorldError("ENFORCER_UNAVAILABLE", `Cannot reach ${socketPath}.`)));
    r.end(payload);
  });
}

function postRoute(socketPath: string, path: string, body: JsonObject): Promise<JsonObject> {
  const payload = jcsString(body);
  return new Promise((resolve, reject) => {
    const r = http.request(
      { socketPath, path, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try { resolve(parseJson(Buffer.concat(chunks).toString("utf8")) as JsonObject); }
          catch (e) { reject(e); }
        });
      });
    r.on("error", () => reject(new WorldError("ENFORCER_UNAVAILABLE", `Cannot reach ${socketPath}.`)));
    r.end(payload);
  });
}

class ChannelClient {
  private decoder = new FrameDecoder();
  private pending: ((msg: JsonObject) => void)[] = [];
  private sock: net.Socket;
  private closed = false;

  private constructor(sock: net.Socket) {
    this.sock = sock;
    sock.on("data", (chunk) => {
      let frames: Buffer[];
      try { frames = this.decoder.feed(chunk); } catch { this.sock.destroy(); return; }
      for (const f of frames) {
        let msg: JsonObject;
        try { msg = parseJson(f.toString("utf8")) as JsonObject; } catch { continue; }
        const cb = this.pending.shift();
        if (cb) cb(msg);
      }
    });
    sock.on("close", () => {
      this.closed = true;
      while (this.pending.length) this.pending.shift()!({ type: "close" });
    });
  }

  static async connect(chanPath: string, attach: JsonObject): Promise<ChannelClient> {
    const sock = net.createConnection(chanPath);
    await new Promise<void>((resolve, reject) => {
      sock.once("connect", () => resolve());
      sock.once("error", () => reject(new WorldError("ENFORCER_UNAVAILABLE", `Cannot reach ${chanPath}.`)));
    });
    const client = new ChannelClient(sock);
    const reply = await client.frame(attach);
    if (reply["type"] !== "result" || reply["error"] !== undefined) {
      const e = reply["error"] as JsonObject | undefined;
      sock.end();
      throw new WorldError((e?.["code"] as never) ?? "PRINCIPAL_MISMATCH", String(e?.["message"] ?? "Channel attach failed."));
    }
    return client;
  }

  frame(msg: JsonObject): Promise<JsonObject> {
    if (this.closed) return Promise.resolve({ type: "close" });
    return new Promise((resolve) => {
      this.pending.push(resolve);
      this.sock.write(encodeFrame(msg));
    });
  }

  async close(): Promise<void> {
    try { await this.frame({ type: "close", id: "bye" }); } catch { /* */ }
    this.sock.end();
  }
}

// ---------- commands ----------

async function cmdRpc(opt: Map<string, string>): Promise<JsonObject> {
  const socket = opt.get("socket") ?? DEFAULT_SOCKET;
  const req = readJsonFile(reqOpt(opt, "request")) as JsonObject;
  return rpcCall(socket, req);
}

async function cmdSimulate(opt: Map<string, string>): Promise<JsonObject> {
  const socket = opt.get("socket") ?? DEFAULT_SOCKET;
  const intent = readJsonFile(reqOpt(opt, "intent")) as JsonObject;
  const ch = await ChannelClient.connect(`${socket}.chan`, { type: "attach", id: "attach0", principal: String(intent["principal"] ?? "") });
  try {
    const reply = await ch.frame({ type: "intent", id: "m1", intent });
    if (reply["type"] === "close") throw new WorldError("CHANNEL_PROTOCOL", "Channel closed before reply.");
    if (reply["error"] !== undefined) {
      const e = reply["error"] as JsonObject;
      throw new WorldError(e["code"] as never, String(e["message"]));
    }
    const out: JsonObject = { report: reply["report"] ?? null, result: reply["result"] ?? null, expires_tick: reply["expires_tick"] ?? null };
    if (reply["code"] !== undefined) out["code"] = reply["code"];
    return out;
  } finally {
    await ch.close();
  }
}

async function cmdCommit(opt: Map<string, string>): Promise<JsonObject> {
  const socket = opt.get("socket") ?? DEFAULT_SOCKET;
  const report = reqOpt(opt, "report");
  const requestId = reqOpt(opt, "request-id");
  const ch = await ChannelClient.connect(`${socket}.chan`, { type: "attach", id: "attach0", report });
  try {
    const reply = await ch.frame({ type: "commit", id: requestId, report });
    if (reply["error"] !== undefined) {
      const e = reply["error"] as JsonObject;
      throw new WorldError(e["code"] as never, String(e["message"]));
    }
    const out: JsonObject = { crossing: reply["crossing"] ?? null, state: reply["state"] ?? null };
    if (reply["state_rev"] !== undefined) out["state_rev"] = reply["state_rev"];
    if (reply["value"] !== undefined) out["value"] = reply["value"];
    return out;
  } finally {
    await ch.close();
  }
}

async function cmdReplay(opt: Map<string, string>): Promise<JsonObject> {
  const socket = opt.get("socket") ?? DEFAULT_SOCKET;
  const ch = await ChannelClient.connect(`${socket}.chan`, { type: "attach", id: "attach0", cap: reqOpt(opt, "cap") });
  try {
    const reply = await ch.frame({
      type: "op", id: "m1", op: "replay.run",
      params: { claim: reqOpt(opt, "claim"), branch: reqOpt(opt, "branch"), through_seq: reqOpt(opt, "through"), reducer: "reducer1", cap: reqOpt(opt, "cap") },
    });
    if (reply["error"] !== undefined) {
      const e = reply["error"] as JsonObject;
      throw new WorldError(e["code"] as never, String(e["message"]));
    }
    return { verification: reply["verification"] ?? null, state: reply["state"] ?? null, effect_dispatches: reply["effect_dispatches"] ?? null };
  } finally {
    await ch.close();
  }
}

async function cmdFreeze(opt: Map<string, string>): Promise<JsonObject> {
  const socket = opt.get("socket") ?? DEFAULT_SOCKET;
  const claim = reqOpt(opt, "claim");
  const resp = await rpcCall(socket, {
    id: `cli-freeze-${Date.now()}`, op: "claim.set_status",
    params: { claim, expected: "ACTIVE", target: "FROZEN", reason: reqOpt(opt, "reason"), cap: reqOpt(opt, "cap") },
  });
  if (resp["ok"] !== true) {
    const e = resp["error"] as JsonObject;
    throw new WorldError(e["code"] as never, String(e["message"]));
  }
  const r = resp["result"] as JsonObject;
  return { claim: r["claim"] ?? null, status: r["status"] ?? null, cancelled: r["cancelled"] ?? null, dispatched: r["dispatched"] ?? null, unknown: r["unknown"] ?? null };
}

function cmdVerify(opt: Map<string, string>): JsonObject {
  const bundle = readJsonFile(reqOpt(opt, "bundle"));
  const trust = parseTrustFile(readJsonFile(reqOpt(opt, "trust")));
  const r = verifyReceiptBundle(bundle, trust);
  return { verification: r.verification, effects_enabled: r.effects_enabled };
}

function cmdSign(opt: Map<string, string>): JsonObject {
  const proposal = readJsonFile(reqOpt(opt, "proposal")) as JsonObject;
  const seat = reqOpt(opt, "seat");
  const fd = Number(reqOpt(opt, "key-fd"));
  if (!Number.isSafeInteger(fd) || fd < 0) throw new WorldError("BAD_REQUEST", "--key-fd must be a non-negative fd.");
  const buf = Buffer.alloc(4096);
  const n = readSync(fd, buf, 0, buf.byteLength, null);
  const seedHex = buf.subarray(0, n).toString("utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new WorldError("BAD_REQUEST", "Key fd must carry a 32-byte hex seed.");
  const priv = privateKeyFromSeed(Buffer.from(seedHex, "hex"));
  // §6.5: amendment signatures cover UTF8("LAGI-WORLD-AMEND/v1") || 0x00 || J(proposal).
  const msg = Buffer.concat([Buffer.from("LAGI-WORLD-AMEND/v1"), Buffer.from([0]), jcsBytes(proposal)]);
  const signature = b64uEncode(signDetached(priv, msg));
  return { seat, signature, proposal_digest: sha256Hex(jcsBytes(proposal)) };
}

function cmdConfigCheck(opt: Map<string, string>): JsonObject {
  const cfg = parseWorldConfig(readJsonFile(reqOpt(opt, "file")));
  return { valid: true, profile: cfg.profile, network_default: cfg.network_default };
}

// ---------- serve ----------

async function cmdServe(opt: Map<string, string>): Promise<JsonObject> {
  const cfg = parseWorldConfig(readJsonFile(reqOpt(opt, "config")));
  mkdirSync(cfg.storage_root, { recursive: true });
  const storeDir = join(cfg.storage_root, "stores", "store1");
  mkdirSync(storeDir, { recursive: true });
  const dbPath = join(storeDir, "world.sqlite");
  const fresh = !existsSync(dbPath);
  const fixture = opt.get("fixture-seed");

  const keys = fixture === "fixtureB"
    ? new MemoryKeyService().addWriter("writer-test-1", WRITER_TEST_1_SEED, "1")
    : seedFromHandle(cfg.writer_key_handle);
  const clock = new ManualClock("1000");
  const h = openWorld(dbPath, keys, clock, cfg.world);
  h.broker.config.storageRoot = cfg.storage_root;

  const readiness = h.enforcer.readiness();
  if (readiness.status !== "READY") {
    throw new WorldError("ENFORCER_UNAVAILABLE", `Host probes fail: ${readiness.probes.filter((p) => !p.ok).map((p) => p.name).join(",")}`);
  }
  if (fresh) {
    if (fixture === "fixtureB") {
      const uid = typeof process.getuid === "function" ? process.getuid() : 1000;
      seedFixtureInto(h, { uid, includeSim1: false });
    } else {
      // Cold bootstrap: control genesis only; everything else is provisioned
      // through the normal administrative path.
      h.journal.createStream("_control", "main");
      h.journal.registerWriterKey(cfg.writer_key_handle, "1", keys.writerPublic(cfg.writer_key_handle).toString("hex"));
      h.journal.append({
        claim: "_control", branch: "main", kind: "WriterStarted",
        payload: { key_id: cfg.writer_key_handle, writer_epoch: "1", store: "store1" },
        actor: "pRuntime", command: "boot1", tickMs: "0",
      });
      h.store.setMeta("writer_epoch", "1");
      h.store.setMeta("host_status", "READY");
      h.store.setMeta("store_id", "store1");
    }
  }

  const here = dirname(fileURLToPath(import.meta.url));
  const helper = [join(here, "..", "native", "peercred"), join(here, "native", "peercred")].find(existsSync);
  const server = new WorldServer(h.broker, h.store, { peercredHelper: helper, storageRoot: cfg.storage_root });
  await server.listen(cfg.socket, cfg.observability.metrics_socket);
  process.stdout.write(jcsString({ status: "READY", socket: cfg.socket }) + "\n");
  return { status: "READY", socket: cfg.socket };
}

async function cmdMigrate(opt: Map<string, string>): Promise<JsonObject> {
  const socket = opt.get("socket") ?? DEFAULT_SOCKET;
  const manifest = parseMigrationManifest(readJsonFile(reqOpt(opt, "manifest")));
  const cap = reqOpt(opt, "cap");
  // Pause → migrate (transport route) → resume.
  const pause = await rpcCall(socket, { id: "cli-pause", op: "host.set_status", params: { expected: "READY", target: "PAUSED", reason: "migration", cap } });
  if (pause["ok"] !== true) throw rpcErr(pause);
  const mig = await postRoute(socket, "/v1/migrate", { manifest: manifest as unknown as JsonObject });
  const resume = await rpcCall(socket, { id: "cli-resume", op: "host.set_status", params: { expected: "PAUSED", target: "READY", reason: "migration complete", cap } });
  if (mig["ok"] !== true) throw rpcErr(mig);
  if (resume["ok"] !== true) process.stderr.write("warning: host left PAUSED after migration\n");
  const r = mig["result"] as JsonObject;
  return { migration: r["migration"] ?? null, status: r["status"] ?? null, new_store: r["new_store"] ?? null };
}

function rpcErr(resp: JsonObject): WorldError {
  const e = resp["error"] as JsonObject | undefined;
  return new WorldError((e?.["code"] as never) ?? "BAD_REQUEST", String(e?.["message"] ?? "request failed"));
}

// ---------- entry ----------

export async function main(argv: string[]): Promise<number> {
  const { pos, opt } = flags(argv);
  try {
    let out: JsonObject | undefined;
    const [cmd, sub] = pos;
    switch (cmd) {
      case "rpc": out = await cmdRpc(opt); break;
      case "simulate": out = await cmdSimulate(opt); break;
      case "commit": out = await cmdCommit(opt); break;
      case "replay": out = await cmdReplay(opt); break;
      case "freeze": out = await cmdFreeze(opt); break;
      case "verify": out = cmdVerify(opt); break;
      case "sign": out = cmdSign(opt); break;
      case "config":
        if (sub !== "check") throw new WorldError("BAD_REQUEST", "Usage: world config check --file f");
        out = cmdConfigCheck(opt); break;
      case "serve": out = await cmdServe(opt); return 0;
      case "migrate": out = await cmdMigrate(opt); break;
      default:
        throw new WorldError("BAD_REQUEST", "Usage: world {rpc|simulate|commit|replay|freeze|verify|sign|config check|serve|migrate}");
    }
    if (out) process.stdout.write(jcsString(out) + "\n");
    return 0;
  } catch (e) {
    const w = e instanceof WorldError ? e : new WorldError("BAD_REQUEST", String(e));
    process.stderr.write(jcsString({ error: w.toErrorObject() as unknown as JsonValue }) + "\n");
    return w.exitCode === 0 ? 1 : w.exitCode;
  }
}
