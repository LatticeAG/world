import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { peerUid } from "../src/server.js";

const helper = resolve("native/peercred");
test("peer credentials identify a real Unix client and report a missing helper", { skip: process.platform !== "linux" || !existsSync(helper) }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "world-peercred-"));
  const path = join(dir, "socket");
  const server = net.createServer();
  let client: net.Socket | undefined;
  try {
    await new Promise<void>((resolve, reject) => server.once("error", reject).listen(path, resolve));
    const accepted = new Promise<net.Socket>((resolve) => server.once("connection", resolve));
    client = net.createConnection(path);
    const socket = await accepted;
    assert.equal(peerUid(socket, helper), process.getuid!());
    assert.throws(() => peerUid(socket, join(dir, "missing")), /Cannot run peercred helper/);
    socket.destroy();
  } finally {
    client?.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});
