# World — LatticeAG zone core

[![LatticeAG](https://img.shields.io/badge/LatticeAG-World%20zone-f5a623)](https://github.com/LatticeAG)
[![status: OSS core](https://img.shields.io/badge/status-OSS%20core%2C%20pre--release-f5a623)](#status)
[![spec: W-1.0-draft.2](https://img.shields.io/badge/spec-W--1.0--draft.2-blue)](#)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![conformance: 56/56](https://img.shields.io/badge/conformance-56%2F56-brightgreen)](#conformance)

**Event-sourced world state, isolated by claim. Each fence is a boundary the runtime can enforce.**

World is the LatticeAG zone that owns claim state, executable fences, bound
simulation, event history, and recovery. The unit of work is a canonical
**crossing intent**: every accepted fence crossing carries an inseparable triple
of an effective capability check, a durable crossing record, and a bound
pre-execution simulation.

> No capability, no crossing. No durable preparation, no release.
> No valid bound simulation, no act. No evidence, no claim of certainty.

## Status

This repository is the **OSS core** of the World zone: the canonical event
journal, claim/principal/capability authority, fence evaluation, deterministic
simulator, replay/verification, branching, snapshots, the Unix-socket RPC
surface, the guest crossing channel, and the `world` CLI.

It is pre-release software. Hosted services, remote cross-world commits
(Treaty), external checkpoint sinks, certified network adapters, and other
zone-gated surfaces are defined interfaces that fail closed or report
`NOT_IMPLEMENTED` — they are never emulated.

## Layout

- `src/` — the broker core (journal, capabilities, fences, simulation,
  replay, governance, API, channel, enforcer).
- `bin/world` — the CLI entry point.
- `native/` — small Linux helpers (`peercred` for `SO_PEERCRED`,
  `world-launcher` for the WASM-in-process-sandbox profile).
- `test/` — conformance harness: all 56 `TV-W-*` normative vectors plus unit
  and integration coverage.

## Quick start

```sh
npm ci
npm run build:native   # optional: SO_PEERCRED + sandbox launcher helpers
npm test               # builds, then runs the full suite
```

Run the conformance harness against the normative vectors:

```sh
npm run conformance
```

CLI sketch (a broker is configured by `world.json`; see `world config check`):

```sh
world config check --file world.json --json
world serve --config world.json --json
world simulate --intent intent.json --json
world commit --claim cA --report sim1 --request-id qCommit --json
world replay --claim cA --branch main --through 10 --cap capAudit --json
world verify --bundle receipt.json --trust trust.json --json   # offline
```

## Security boundary

Single host, single administrative tenant, multiple mutually untrusted claims,
Linux. The launch enforcer profile is `wasm-process-v1` (WASM in a dedicated
unprivileged process). Missing kernel controls fail readiness closed — the
broker never simulates a fence it cannot enforce.

See `STATUS.md` (build-local) for phase coverage and known limits.

## License

MIT — see [LICENSE](LICENSE).
