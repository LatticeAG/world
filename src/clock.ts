/**
 * Logical time (spec §8.3).
 *
 * `tick_ms` is a recorded logical clock initialized from a trusted bootstrap
 * and advanced from CLOCK_BOOTTIME elapsed time inside a host epoch. A
 * durable floor is persisted: restart never lowers the tick, and a backwards
 * wall-clock adjustment cannot renew expired authority. Deterministic
 * fixtures supply ticks directly through ManualClock.
 */

import { WorldError } from "./errors.js";
import type { Store } from "./store.js";

export interface TickSource {
  /** Current logical tick in milliseconds (decimal string domain). */
  now(): bigint;
}

/** Deterministic tick source for fixtures and tests. */
export class ManualClock implements TickSource {
  private t: bigint;
  constructor(start: string | bigint) {
    this.t = BigInt(start);
  }
  now(): bigint {
    return this.t;
  }
  set(tick: string | bigint): void {
    this.t = BigInt(tick);
  }
  advance(ms: string | bigint): void {
    this.t += BigInt(ms);
  }
}

/** Monotonic elapsed-time source (CLOCK_BOOTTIME-equivalent hrtime basis). */
export class MonotonicSource implements TickSource {
  private readonly base = process.hrtime.bigint();
  private readonly baseTick: bigint;
  constructor(baseTick: string | bigint) {
    this.baseTick = BigInt(baseTick);
  }
  now(): bigint {
    return this.baseTick + (process.hrtime.bigint() - this.base) / 1_000_000n;
  }
}

/**
 * Durable clock: every security decision samples through this, and the
 * sampled tick is persisted so a restart resumes at least at the floor.
 */
export class DurableClock implements TickSource {
  constructor(
    private readonly store: Store,
    private readonly source: TickSource,
  ) {}

  now(): bigint {
    const floor = BigInt(this.store.getMeta("tick_floor") ?? "0");
    const t = this.source.now();
    const effective = t > floor ? t : floor;
    if (effective > floor) {
      this.store.setMeta("tick_floor", effective.toString());
    }
    return effective;
  }

  /** Persist the recovery floor explicitly (used at shutdown/recovery). */
  pinFloor(tick: bigint): void {
    const floor = BigInt(this.store.getMeta("tick_floor") ?? "0");
    if (tick > floor) this.store.setMeta("tick_floor", tick.toString());
  }
}

/**
 * Establish the restart tick: prior durable tick plus bounded downtime.
 * If downtime cannot be bounded the caller treats prior grants and reports
 * as expired (spec §8.3); this function just never moves time backwards.
 */
export function restartTick(lastDurableTick: string, boundedDowntimeMs: string | null): string {
  const last = BigInt(lastDurableTick);
  if (boundedDowntimeMs === null) {
    return last.toString();
  }
  return (last + BigInt(boundedDowntimeMs)).toString();
}

export function assertTick(v: unknown): string {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw new WorldError("SCHEMA_NUMBER_RANGE", "Invalid tick.");
  }
  return v;
}
