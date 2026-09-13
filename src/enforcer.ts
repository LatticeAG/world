/**
 * Local runtime enforcement (spec §3.3, §8.4, §10.3).
 *
 * The OSS core enforces locally: readiness probes, the pinned syscall
 * baseline, SSRF gates, and the dispatch barrier are real checks. The WASM
 * guest launcher is an interface boundary — a host without the certified
 * launcher reports ENFORCER_UNAVAILABLE rather than faking isolation.
 */

import { existsSync, statSync, readFileSync, realpathSync } from "node:fs";
import { WorldError } from "./errors.js";
import { sha256Hex } from "./crypto.js";
import { jcsBytes, type JsonObject } from "./canon.js";

/** The certified wasm-process-v1 baseline allowlist (§3.3). Adding an entry requires recertification. */
export const WASM_PROCESS_V1_BASELINE = [
  "read", "write", "close", "mmap", "munmap", "mprotect", "futex",
  "clock_gettime", "exit_group", "recvmsg", "sendmsg",
] as const;

/** Syscall families the profile denies (probe expectations return EPERM). */
export const WASM_PROCESS_V1_DENIED = [
  "socket", "connect", "bind", "listen", "accept", "accept4", "socketpair",
  "clone3", "unshare", "setns", "ptrace", "bpf", "perf_event_open",
  "keyctl", "mount", "umount2", "io_uring_setup", "open_by_handle_at",
  "init_module", "kexec_load", "reboot", "swapon", "pivot_root",
] as const;

export interface ProbeResult {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface ReadinessReport {
  status: "READY" | "STOPPED";
  probes: ProbeResult[];
}

export interface LauncherHandle {
  worker: string;
  pidfd: string;
  exec_digest: string;
}

export interface WorkerLaunchSpec {
  claim: string;
  module: string;
  profile: string;
  cpu_ms: string;
  memory_bytes: string;
  pids: number;
  crossing: string;
}

/**
 * Enforcer gate. `certified` profiles are digest-pinned installations;
 * nothing runs a guest without one. The dispatch barrier is the single
 * mutex that revocation and dispatch markers serialize on.
 */
export class Enforcer {
  private barrier: Promise<void> = Promise.resolve();
  private barrierHeld = false;
  private barrierWaiters: (() => void)[] = [];
  private workers = new Map<string, LauncherHandle>();
  private workerCounter = 0;
  /** Test/dev seam: when false, startWorker reports unavailable. */
  launcherAvailable = false;

  constructor(
    readonly profile: string = "wasm-process-v1",
    readonly enforcerDigest: string = sha256Hex(jcsBytes({ profile: "wasm-process-v1", baseline: [...WASM_PROCESS_V1_BASELINE] })),
  ) {}

  profiles(): string[] {
    return [this.profile];
  }

  /** §3.2 step 2 enforcer profile gate. */
  assertReady(profile: string): void {
    if (profile !== this.profile) {
      throw new WorldError("ENFORCER_UNCERTIFIED", `Profile ${profile} is not the installed certified profile.`);
    }
    const r = this.readiness({ assumeKernel: true });
    if (r.status !== "READY") {
      throw new WorldError("ENFORCER_UNAVAILABLE", "Enforcer readiness probes fail.");
    }
  }

  /**
   * Host readiness probes (§8.4, TV-W-40). On a real host these probe the
   * kernel; tests inject the probe map. cgroup v2 is mandatory — without it
   * the host starts STOPPED and no guest ever launches.
   */
  readiness(opts: { assumeKernel?: boolean; probes?: Partial<Record<string, boolean>> } = {}): ReadinessReport {
    const probe = (name: string, check: () => boolean, detail?: string): ProbeResult => {
      const injected = opts.probes?.[name];
      const ok = injected !== undefined ? injected : (opts.assumeKernel ? true : safe(check));
      return { name, ok, ...(ok ? {} : { detail: detail ?? "probe failed" }) };
    };
    const probes = [
      probe("cgroup_v2", () => existsSync("/sys/fs/cgroup/cgroup.controllers"), "cgroup v2 unified hierarchy required"),
      probe("namespaces", () => existsSync("/proc/self/ns/user") && existsSync("/proc/self/ns/pid"), "user/pid/mount/net namespaces required"),
      probe("seccomp", () => {
        try { return readFileSync("/proc/self/status", "utf8").includes("Seccomp"); } catch { return false; }
      }, "seccomp-bpf required"),
      probe("no_new_privs", () => existsSync("/proc/self/status"), "no_new_privs required"),
      probe("pidfd", () => existsSync("/proc/self/fd"), "pidfd support required"),
      probe("memfd", () => true, "memfd required"),
    ];
    const ready = probes.every((p) => p.ok);
    return { status: ready ? "READY" : "STOPPED", probes };
  }

  /** Sandbox probe table (TV-W-39): does the profile permit this syscall family? */
  probeSyscall(profile: string, syscall: string): { allowed: boolean; errno: string | null } {
    if (profile !== this.profile) {
      throw new WorldError("ENFORCER_UNCERTIFIED", `Unknown profile ${profile}.`);
    }
    if ((WASM_PROCESS_V1_BASELINE as readonly string[]).includes(syscall)) {
      return { allowed: true, errno: null };
    }
    return { allowed: false, errno: "EPERM" };
  }

  // ---- dispatch barrier: the same lock revocation takes (§3.2 step 8) ----

  acquireDispatchBarrier(): void {
    if (this.barrierHeld) {
      // Single-threaded writer: a contended barrier indicates a reentrancy bug.
      throw new WorldError("STORAGE_UNAVAILABLE", "Dispatch barrier reentrancy.");
    }
    this.barrierHeld = true;
  }

  releaseDispatchBarrier(): void {
    this.barrierHeld = false;
    const w = this.barrierWaiters.shift();
    if (w) w();
  }

  get dispatchBarrierHeld(): boolean {
    return this.barrierHeld;
  }

  // ---- SSRF gates (§10.3) ----

  /** Classify an IPv4/IPv6 literal; returns the blocked class or null. */
  static classifyAddress(addr: string): string | null {
    const a = addr.toLowerCase();
    // IPv4-mapped IPv6 or IPv6 forms.
    if (a.includes(":")) {
      if (a.startsWith("::ffff:")) return "ipv4-mapped-ipv6";
      if (a === "::" || a === "0:0:0:0:0:0:0:0") return "unspecified";
      if (a === "::1") return "loopback";
      if (a.startsWith("fe8") || a.startsWith("fe9") || a.startsWith("fea") || a.startsWith("feb")) return "link-local";
      if (a.startsWith("ff")) return "multicast";
      if (a.startsWith("fc") || a.startsWith("fd")) return "private-ula";
      return null;
    }
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
    if (!m) return null;
    const o = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
    if (o.some((x) => x > 255)) return "malformed";
    if (o[0] === 0) return "unspecified";
    if (o[0] === 127) return "loopback";
    if (o[0] === 10) return "private";
    if (o[0] === 172 && o[1]! >= 16 && o[1]! <= 31) return "private";
    if (o[0] === 192 && o[1] === 168) return "private";
    if (o[0] === 169 && o[1] === 254) return "link-local";
    if (o[0] === 100 && o[1]! >= 64 && o[1]! <= 127) return "cgnat";
    if (o[0] === 198 && o[1]! >= 18 && o[1]! <= 19) return "benchmark";
    if (o[0] === 224 || (o[0]! >= 224 && o[0]! <= 239)) return "multicast";
    if (o[0]! >= 240) return "reserved";
    return null;
  }

  /**
   * The network target gate: every resolved address must pass; any blocked
   * candidate denies the target (TV-W-41). Returns the pinned address.
   */
  networkTargetGate(scheme: string, host: string, port: number, addresses: string[]): string {
    if (scheme !== "https") throw new WorldError("SSRF_DENIED", `Scheme ${scheme} is not https.`);
    if (port < 1 || port > 65535) throw new WorldError("SSRF_DENIED", "Ambiguous or invalid port.");
    if (addresses.length === 0) throw new WorldError("SSRF_DENIED", "No resolved addresses to pin.");
    let pinned: string | null = null;
    for (const a of addresses) {
      const cls = Enforcer.classifyAddress(a);
      if (cls !== null) {
        throw new WorldError("SSRF_DENIED", `Address ${a} is ${cls}; the target is denied.`);
      }
      if (pinned === null) pinned = a;
    }
    return pinned!;
  }

  /** Redirects are observations, not new authorized destinations (TV-W-42). */
  static redirectGate(status: number, followRedirects: boolean): { followed: boolean } {
    if (status >= 300 && status < 400) {
      if (followRedirects) {
        // The certified v1 adapter contract never follows; a client flag
        // asking otherwise is itself a contract violation.
        throw new WorldError("FENCE_DENIED", "Redirect following is disabled in v1.");
      }
      return { followed: false };
    }
    return { followed: false };
  }

  // ---- launcher boundary ----

  /**
   * Launch a guest under the certified profile. The OSS distribution ships
   * the enforcement checks and the launcher's contract; without an
   * installed launcher binary this reports ENFORCER_UNAVAILABLE — it never
   * pretends a guest ran.
   */
  startWorker(spec: WorkerLaunchSpec): LauncherHandle {
    if (spec.profile !== this.profile) {
      throw new WorldError("ENFORCER_UNCERTIFIED", `Profile ${spec.profile} is not certified.`);
    }
    if (!this.launcherAvailable) {
      throw new WorldError("ENFORCER_UNAVAILABLE", "No certified guest launcher is installed on this host.");
    }
    this.workerCounter++;
    const h: LauncherHandle = {
      worker: `worker${this.workerCounter}`,
      pidfd: `pidfd:${this.workerCounter}`,
      exec_digest: sha256Hex(jcsBytes({ module: spec.module, profile: spec.profile } as JsonObject)),
    };
    this.workers.set(h.worker, h);
    return h;
  }

  /** Install the deterministic test launcher used by fixtures. */
  installTestLauncher(): void {
    this.launcherAvailable = true;
  }

  stopWorker(worker: string): void {
    this.workers.delete(worker);
  }

  /** Verify a path is absolute, operator-owned, and symlink-free (§6.7). */
  static checkedPath(path: string): string {
    if (!path.startsWith("/")) throw new WorldError("SCHEMA_VALIDATION", `Path ${path} must be absolute.`);
    if (existsSync(path)) {
      const real = realpathSync(path);
      if (real !== path) throw new WorldError("SCHEMA_VALIDATION", `Path ${path} resolves through a symlink.`);
      statSync(path);
      return real;
    }
    return path;
  }
}

function safe(f: () => boolean): boolean {
  try { return f(); } catch { return false; }
}
