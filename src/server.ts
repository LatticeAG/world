/**
 * RPC transport (spec §6.1, §6.8): HTTP/1.1 over a mode-0660 Unix socket
 * with SO_PEERCRED-mapped identity, strict admission limits, and a
 * separate length-prefixed channel socket implementing the §6.8 guest
 * frame protocol. A second HTTP socket serves /metrics only.
 *
 * No TCP listener exists. Channel attach is a transport upgrade, not an
 * RPC op — the §6.1 method list stays closed.
 */

import http from "node:http";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { WorldError, errorHttp, isPublicCode, type ErrorCode } from "./errors.js";
import { parseJson, jcsString, type JsonObject, type JsonValue } from "./canon.js";
import type { Broker, Caller } from "./broker.js";
import { ChannelSession, FrameDecoder, encodeFrame } from "./channel.js";
import { parseMigrationManifest } from "./config.js";
import { runMigration } from "./migrate.js";
import type { Store } from "./store.js";

const MAX_REQUEST = 1048576;   // 1 MiB
const MAX_RESPONSE = 1048576;
const PER_UID_RPS = 100;
const PER_UID_CONCURRENT = 8;
const HOST_CONNECTIONS = 16;

export interface ServerOptions {
  peercredHelper?: string; // path to native/peercred
  uidOverride?: number;    // test seam only; production always uses SO_PEERCRED
  /** Storage root for the /v1/migrate coordinator route. */
  storageRoot?: string;
}

/** Resolve the peer UID via SO_PEERCRED using the native helper on the socket fd. */
export function peerUid(socket: net.Socket, helper?: string): number {
  const fd = (socket as unknown as { _handle?: { fd?: number } })._handle?.fd;
  if (fd === undefined || fd < 0) throw new WorldError("UNAUTHENTICATED", "No socket fd for peer credentials.");
  const bin = helper ?? "native/peercred";
  const r = spawnSync(bin, ["3"], { stdio: ["ignore", "pipe", "ignore", fd], encoding: "utf8" });
  if (r.status !== 0) throw new WorldError("UNAUTHENTICATED", "SO_PEERCRED unavailable.");
  const m = /^uid=(\d+)$/.exec(r.stdout.trim());
  if (!m) throw new WorldError("UNAUTHENTICATED", "Unparseable peer credentials.");
  return Number(m[1]);
}

class RateWindow {
  private hits: number[] = [];
  allow(nowMs: number): boolean {
    this.hits = this.hits.filter((t) => nowMs - t < 1000);
    if (this.hits.length >= PER_UID_RPS) return false;
    this.hits.push(nowMs);
    return true;
  }
}

/**
 * Admission gate (§6.1, TV-W-55): per-UID rate + concurrency caps and a
 * host-wide connection cap, applied before any parse work. Rejection is
 * RATE_LIMITED/503 retryable with no command tombstone.
 */
export class AdmissionLimiter {
  private perUid = new Map<number, { rate: RateWindow; concurrent: number }>();
  private hostConns = 0;
  /** Requests admitted without parsing — for conformance accounting. */
  parsedRequests = 0;

  admit(uid: number, nowMs = Date.now()): { ok: boolean; release: () => void } {
    if (this.hostConns >= HOST_CONNECTIONS) return { ok: false, release: () => {} };
    let e = this.perUid.get(uid);
    if (!e) { e = { rate: new RateWindow(), concurrent: 0 }; this.perUid.set(uid, e); }
    if (!e.rate.allow(nowMs) || e.concurrent >= PER_UID_CONCURRENT) {
      return { ok: false, release: () => {} };
    }
    e.concurrent += 1;
    this.hostConns += 1;
    this.parsedRequests += 1;
    return {
      ok: true,
      release: () => { e!.concurrent -= 1; this.hostConns -= 1; },
    };
  }
}

export class WorldServer {
  private httpServer: http.Server;
  private chanServer: net.Server;
  private metricsServer: http.Server | null = null;
  readonly limiter = new AdmissionLimiter();

  constructor(
    readonly broker: Broker,
    readonly store: Store,
    readonly opts: ServerOptions = {},
  ) {
    this.httpServer = http.createServer((req, res) => this.onHttp(req, res));
    this.chanServer = net.createServer((s) => this.onChannelSocket(s));
  }

  principalForSocket(socket: net.Socket): { principal: string; type: string } {
    const uid = this.opts.uidOverride ?? peerUid(socket, this.opts.peercredHelper);
    const row = this.store.get<{ principal: string; type: string; status: string }>(
      "SELECT principal,type,status FROM principals WHERE uid=?", uid);
    if (!row || row.status !== "ENABLED") {
      throw new WorldError("UNAUTHENTICATED", "Peer credentials map to no provisioned principal.");
    }
    return { principal: row.principal, type: row.type };
  }

  private onHttp(req: http.IncomingMessage, res: http.ServerResponse): void {
    const socket = req.socket as net.Socket;
    let uid: number;
    try {
      uid = this.opts.uidOverride ?? peerUid(socket, this.opts.peercredHelper);
    } catch {
      this.send(res, 401, { error: { code: "UNAUTHENTICATED", message: "Peer credentials unavailable.", retryable: false } });
      return;
    }
    const gate = this.limiter.admit(uid);
    if (!gate.ok) {
      this.send(res, 503, { error: { code: "RATE_LIMITED", message: "Admission limit exceeded.", retryable: true } });
      return;
    }
    const done = () => gate.release();
    res.on("close", done);

    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on("data", (c: Buffer) => {
      size += c.byteLength;
      if (size > MAX_REQUEST && !aborted) {
        aborted = true;
        this.send(res, 413, { error: { code: "RATE_LIMITED", message: "Request exceeds 1 MiB.", retryable: false } });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (aborted) return;
      // Transport routes only — the §6.1 method list stays closed.
      if (req.method === "POST" && req.url === "/v1/migrate") {
        let caller: { principal: string; type: string };
        try {
          caller = this.principalForSocket(socket);
        } catch (e) {
          this.sendError(res, null, e, 401);
          return;
        }
        if (caller.type !== "operator") {
          this.send(res, 403, { ok: false, error: { code: "FENCE_DENIED", message: "Migration requires an operator principal.", retryable: false } });
          return;
        }
        try {
          const body = parseJson(Buffer.concat(chunks).toString("utf8")) as JsonObject;
          if (!this.opts.storageRoot) throw new WorldError("ENFORCER_UNAVAILABLE", "No storage root configured.");
          const manifest = parseMigrationManifest(body["manifest"]);
          const result = runMigration(this.broker.store, this.broker.journal, manifest, this.opts.storageRoot, this.broker.seats);
          this.send(res, 200, { ok: true, result: result as unknown as JsonValue });
        } catch (e) {
          this.sendError(res, null, e, 400);
        }
        return;
      }
      if (req.method !== "POST" || req.url !== "/v1/rpc") {
        this.send(res, 404, { error: { code: "NOT_FOUND", message: "Unknown route.", retryable: false } });
        return;
      }
      let caller: { principal: string; type: string };
      try {
        caller = this.principalForSocket(socket);
      } catch (e) {
        this.sendError(res, null, e, 401);
        return;
      }
      let parsed: JsonValue;
      try {
        parsed = parseJson(Buffer.concat(chunks).toString("utf8"));
      } catch (e) {
        this.sendError(res, null, e, 400);
        return;
      }
      const body = parsed as JsonObject;
      if (typeof body["id"] !== "string" || typeof body["op"] !== "string") {
        this.send(res, 400, { id: null, ok: false, error: { code: "BAD_REQUEST", message: "Request must carry string id and op.", retryable: false } });
        return;
      }
      const resp = this.broker.handle({ principal: caller.principal }, { id: body["id"], op: body["op"], params: body["params"] ?? {} });
      const status = resp["ok"] === true ? 200 : httpStatusFor(resp["error"] ?? {});
      this.send(res, status, resp);
    });
    req.on("error", () => done());
  }

  private send(res: http.ServerResponse, status: number, body: JsonObject): void {
    let payload = jcsString(body);
    if (Buffer.byteLength(payload) > MAX_RESPONSE) {
      status = 503;
      payload = jcsString({ id: null, ok: false, error: { code: "RATE_LIMITED", message: "Response exceeds 1 MiB.", retryable: true } });
    }
    res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
    res.end(payload);
  }

  private sendError(res: http.ServerResponse, id: string | null, e: unknown, httpHint = 400): void {
    const w = e instanceof WorldError ? e : new WorldError("BAD_REQUEST", String(e));
    const status = isPublicCode(w.code) ? (errorHttp(w.code) ?? httpHint) : httpHint;
    this.send(res, status, { id, ok: false, error: w.toErrorObject() as unknown as JsonValue });
  }

  /** §6.8 channel socket: length-prefixed frames; first frame must be attach. */
  private onChannelSocket(socket: net.Socket): void {
    const decoder = new FrameDecoder();
    let session: ChannelSession | null = null;
    let attachDone = false;
    socket.on("data", (chunk) => {
      let frames: Buffer[];
      try {
        frames = decoder.feed(chunk);
      } catch {
        this.store.bumpMetric("world_audit_gap_total");
        socket.end();
        return;
      }
      for (const raw of frames) {
        if (!attachDone) {
          attachDone = true;
          let f: JsonObject;
          try {
            f = parseJson(raw.toString("utf8")) as JsonObject;
          } catch {
            this.store.bumpMetric("world_audit_gap_total");
            socket.end(encodeFrame({ type: "close" }));
            return;
          }
          if (f["type"] !== "attach") { socket.end(encodeFrame({ type: "close" })); return; }
          let caller: { principal: string; type: string };
          try {
            caller = this.principalForSocket(socket);
          } catch {
            socket.end(encodeFrame({ type: "result", id: String(f["id"] ?? "attach"), error: { code: "UNAUTHENTICATED", message: "Peer credentials unavailable.", retryable: false } }));
            return;
          }
          let name: string | null;
          try {
            name = this.resolveChannel(f, caller.principal, caller.type);
          } catch {
            name = null;
          }
          if (name === null) {
            socket.end(encodeFrame({ type: "result", id: String(f["id"] ?? "attach"), error: { code: "PRINCIPAL_MISMATCH", message: "Channel binding not permitted.", retryable: false } }));
            return;
          }
          const row = this.store.get<{ principal: string; claim: string; status: string }>(
            "SELECT principal,claim,status FROM channels WHERE channel=?", name);
          if (!row || row.status !== "BOUND") {
            socket.end(encodeFrame({ type: "result", id: String(f["id"] ?? "attach"), error: { code: "NOT_FOUND", message: "No bound channel.", retryable: false } }));
            return;
          }
          session = new ChannelSession(this.broker, { channel: name, claim: row.claim, principal: row.principal });
          socket.write(encodeFrame({ type: "result", id: String(f["id"] ?? "attach"), attached: name, principal: row.principal }));
          continue;
        }
        if (!session) { socket.end(); return; }
        let reply: JsonObject | null;
        try {
          reply = session.handleFrame(raw);
        } catch (e) {
          const w = e instanceof WorldError ? e : new WorldError("CHANNEL_PROTOCOL", String(e));
          if (w.code === "CHANNEL_PROTOCOL") {
            this.store.bumpMetric("world_audit_gap_total");
            socket.end(encodeFrame({ type: "close" }));
            return;
          }
          reply = { type: "result", id: "?", error: w.toErrorObject() as unknown as JsonValue };
        }
        if (reply === null) { socket.end(encodeFrame({ type: "close" })); return; }
        socket.write(encodeFrame(reply));
        if (reply["type"] === "close") { socket.end(); return; }
      }
    });
    socket.on("error", () => {});
  }

  /** Resolve a channel name from the attach frame, enforcing binding authority. */
  private resolveChannel(f: JsonObject, callerPrincipal: string, callerType: string): string | null {
    const want = f["channel"] !== undefined ? String(f["channel"]) : null;
    const principal = f["principal"] !== undefined ? String(f["principal"]) : null;
    const cap = f["cap"] !== undefined ? String(f["cap"]) : null;
    const report = f["report"] !== undefined ? String(f["report"]) : null;
    let targetPrincipal = principal;
    if (cap) {
      const g = this.store.get<{ subject: string }>("SELECT subject FROM capabilities WHERE capability=?", cap);
      if (!g) return null;
      targetPrincipal = g.subject;
    }
    if (report) {
      // The simulation row is opaque at rest; the principal lives in the
      // decrypted report record held by the broker.
      const s = this.broker.loadReport(report);
      if (!s) return null;
      targetPrincipal = s.principal;
    }
    let name = want;
    if (!name && targetPrincipal) {
      const row = this.store.get<{ channel: string }>("SELECT channel FROM channels WHERE principal=? AND status='BOUND'", targetPrincipal);
      name = row?.channel ?? null;
    }
    if (!name) return null;
    const row = this.store.get<{ principal: string }>("SELECT principal FROM channels WHERE channel=?", name);
    if (!row) return null;
    // The bound principal may attach itself; operators may attach for local console use.
    if (row.principal !== callerPrincipal && callerType !== "operator") return null;
    return name;
  }

  /** /metrics on its own socket: operator-mapped principal only (§9.1). */
  private onMetrics(req: http.IncomingMessage, res: http.ServerResponse): void {
    const socket = req.socket as net.Socket;
    try {
      const caller = this.principalForSocket(socket);
      const g = this.store.get<{ capability: string }>(
        "SELECT capability FROM capabilities WHERE subject=? AND status='ISSUED'", caller.principal);
      if (caller.type !== "operator" && !g) throw new WorldError("UNAUTHENTICATED", "Metrics require an operator principal.");
    } catch (e) {
      const w = e instanceof WorldError ? e : new WorldError("UNAUTHENTICATED", String(e));
      this.sendOn(this.metricsServer!, res, 401, { error: w.toErrorObject() as unknown as JsonValue });
      return;
    }
    if (req.method !== "GET" || !(req.url === "/metrics" || req.url?.startsWith("/metrics?"))) {
      this.sendOn(this.metricsServer!, res, 404, { error: { code: "NOT_FOUND", message: "Unknown route.", retryable: false } });
      return;
    }
    const url = new URL(req.url, "http://localhost");
    const family = url.searchParams.get("family");
    const rows = this.store.all<{ name: string; value: string }>("SELECT name,value FROM metrics ORDER BY name");
    const lines = rows.filter((r) => !family || r.name === family).map((r) => `${r.name} ${r.value}`);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(lines.join("\n") + "\n");
  }

  private sendOn(_srv: http.Server, res: http.ServerResponse, status: number, body: JsonObject): void {
    const payload = jcsString(body);
    res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
    res.end(payload);
  }

  async listen(socketPath: string, metricsPath?: string): Promise<void> {
    for (const p of [socketPath, `${socketPath}.chan`, metricsPath]) {
      if (p && existsSync(p)) unlinkSync(p);
    }
    await new Promise<void>((resolve, reject) => {
      this.httpServer.listen(socketPath, () => {
        chmodSync(socketPath, 0o660);
        resolve();
      });
      this.httpServer.on("error", reject);
    });
    await new Promise<void>((resolve, reject) => {
      this.chanServer.listen(`${socketPath}.chan`, () => resolve());
      this.chanServer.on("error", reject);
    });
    if (metricsPath) {
      this.metricsServer = http.createServer((req, res) => this.onMetrics(req, res));
      await new Promise<void>((resolve, reject) => {
        this.metricsServer!.listen(metricsPath, () => resolve());
        this.metricsServer!.on("error", reject);
      });
    }
  }

  async close(): Promise<void> {
    for (const s of [this.httpServer, this.chanServer, this.metricsServer]) {
      if (s) await new Promise<void>((r) => (s as net.Server).close(() => r()));
    }
  }
}

function httpStatusFor(err: JsonValue): number {
  const code = (err as JsonObject)?.["code"];
  return errorHttp(typeof code === "string" ? (code as ErrorCode) : "BAD_REQUEST") ?? 400;
}
