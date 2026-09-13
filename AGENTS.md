# wroom-wroom — agent rules

Read `DECISIONS.md` before changing anything. Locked decisions are the
contract; changing one requires explicit user approval. `Architecture.md`
describes the system. `proto/` holds the protocol schema — the source of
truth for signaling.

## North star

Blazingly fast, massively concurrent conferencing. Sub-millisecond server
forwarding residence (p99, absent congestion backpressure), <100 ms
glass-to-glass on healthy paths, ~1 s join, hundreds of active cameras per
room. MIT-licensed, open, self-hostable.

## Engineering principles

1. **First principles, always.** Derive from requirements — what work must
   happen per packet, per frame, per participant. Do not copy patterns from
   other projects because they are familiar; justify choices from physics.
2. **Hot-path invariants.** On the media forwarding path: no allocation, no
   locks, no blocking calls, no unbounded work. Pooled buffers, flat
   structures, snapshot reads.
3. **Everything bounded.** Every queue, cache, and buffer has a size limit
   and an eviction policy. Eviction follows media priority — audio and
   keyframes outrank enhancement layers — never recency by accident.
   Nothing grows without bound.
4. **Share-nothing concurrency.** A room's state lives on one worker thread;
   cross-thread communication is message passing (SPSC), never shared
   mutation. Forwarding state is `&mut` on one thread.
5. **Memory-safe Rust.** `#![forbid(unsafe_code)]` in all `wroom-*` crates.
   `unsafe` requires explicit written justification and user approval.
6. **Signaling carries intent and room state only.** Media-path feedback
   (keyframe requests, loss, bandwidth) rides RTP/RTCP, never the socket.
7. **Forward on receipt.** Never transcode, never buffer media on the
   server.
8. **Steal across domains.** Map tiling → subscription paging; game-server
   interest management → subscribe sets; ring buffers → resend caches;
   bitsets → fan-out membership. Adopt only when the mapping survives
   scrutiny and measurement.
9. **Measure, don't claim.** Performance statements come with a benchmark
   or a metric. Where a claim can't be checked, add instrumentation.

## Workflow

- Never work on the local `main` checkout. All changes happen in a separate
  git worktree on a feature branch
  (`git worktree add ../wroom-<slug> -b <branch> main`), land via PR, and
  merge only with green CI. `main` receives code only through reviewed,
  CI-passing pull requests.

## Verified commands

- Rust: `cargo check` / `cargo clippy` / `cargo test` at the repo root
- Scale benchmark (release): `cargo test -p wroomd --release forwarding_scale_ladder -- --ignored --nocapture`
  — floods N∈{4,12,24,48,96} fake peers through the real DTLS/SRTP path
  and prints forwards/residence/CPU/RSS per rung.
- Web: `pnpm --filter web build` (typecheck + bundle)
- Proto → TS codegen: `pnpm gen:proto` at the repo root. Proto → Rust
  codegen runs automatically via `build.rs` when `proto/` changes.

## Layout

- `proto/` — signaling schema (`wroom.signaling.v1`)
- `server/crates/` — `wroomd` (binary), `wroom-core` (media objects),
  `wroom-edge` (ICE / DTLS / SRTP / RTP / RTCP), `wroom-signaling` (WS +
  protobuf)
- `web/` — Vite + React + TypeScript + Tailwind + shadcn/ui client
