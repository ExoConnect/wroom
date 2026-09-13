# Contributing

wroom is early and moving fast. Read `DECISIONS.md` before proposing changes —
locked decisions are the contract, and changing one needs maintainer sign-off.
`Architecture.md` describes the system; `AGENTS.md` lists the engineering
principles and verified commands.

## Issues — open to everyone

Bug reports, feature ideas, performance questions, design challenges: open an
issue. This is the front door for all discussion. Good reports include a repro,
expected vs actual behavior, and versions/environment where relevant.

## Pull requests — collaborators only

We do not accept unsolicited PRs. PRs from non-collaborators are automatically
closed — no offense, the codebase is just moving too fast for drive-by review
to be honest review.

To contribute code:

1. Open an issue describing the change and why it belongs.
2. If it's a fit, a maintainer will discuss it there and, where it makes
   sense, bring you in as a collaborator.

## Ground rules for PRs

- **Locked decisions stand.** `DECISIONS.md` changes require explicit
  maintainer approval.
- **Hot-path invariants.** On the media forwarding path: no allocation, no
  locks, no blocking calls, no unbounded work.
- **Memory-safe Rust.** `#![forbid(unsafe_code)]` in all `wroom-*` crates.
- **Everything bounded.** Every queue, cache, and buffer has a size limit and
  an eviction policy.
- **Measure, don't claim.** Performance statements ship with a benchmark or a
  metric.

## Verified commands

- `cargo check` / `cargo clippy` / `cargo test` (repo root)
- `cargo test -p wroomd --release forwarding_scale_ladder -- --ignored --nocapture`
  — the scale benchmark; quote its numbers when claiming perf
- `pnpm --filter web build` — web typecheck + bundle
- `pnpm gen:proto` — regenerate TS from `proto/` (Rust codegen is automatic
  via `build.rs`)

## License

MIT. By contributing, you license your work under the same terms.
