# wroom

Blazingly fast, massively concurrent conferencing — an MIT-licensed,
self-hostable SFU engine with a reference web client.

![ci](https://github.com/ExoConnect/wroom/actions/workflows/ci.yml/badge.svg)

## Design targets

| Metric | Target |
|---|---|
| Server forwarding residence | sub-millisecond (p99, absent congestion) |
| Glass-to-glass latency | < 100 ms on healthy paths |
| Join time | ~1 s |
| Active cameras per room | hundreds |

Targets, not vibes — `cargo test -p wroomd --release
forwarding_scale_ladder -- --ignored --nocapture` floods up to 192 fake
peers through the real DTLS/SRTP path and prints forwards, residence,
CPU, and RSS per rung. Run it.

## Status

Early and moving fast. The signaling schema is the protocol contract and
still evolving; internals are stable enough to hack on.

## Quickstart

```bash
cargo run -p wroomd            # signaling + media on :8080
pnpm install
pnpm --filter web dev          # client on :5173, proxies /ws to wroomd
```

Useful env: `WROOM_ADVERTISE_ADDR` (comma-separated host candidates —
LAN + tailnet together), `WROOM_MEDIA_PORT`, `WROOM_SHARDS`,
`VITE_WROOMD_URL` (point the client at a remote server).

## Layout

| Path | What |
|---|---|
| `proto/` | Signaling schema (`wroom.signaling.v1`) — the contract |
| `server/crates/wroomd` | Server binary |
| `server/crates/wroom-edge` | ICE / DTLS / SRTP / RTP / RTCP |
| `server/crates/wroom-signaling` | WebSocket + protobuf control plane |
| `server/crates/wroom-core` | Media objects |
| `web/` | Vite + React + TypeScript reference client |

`Architecture.md` describes the system. `DECISIONS.md` is the locked
contract — read it before proposing changes.

## Engineering rules

- No allocation, no locks, no blocking calls, no unbounded work on the
  media hot path
- Every queue, cache, and buffer bounded; eviction by media priority
- Share-nothing concurrency — a room's state lives on one worker thread
- `#![forbid(unsafe_code)]` in all `wroom-*` crates
- Measure, don't claim

## Contributing

Issues are open to everyone — bugs, features, design challenges. Pull
requests are limited to collaborators for now (unsolicited PRs are
auto-closed); open an issue first. See `CONTRIBUTING.md`.

## License

MIT — see `LICENSE`. The name is pronounced however you like, but it's
*definitely* not a coincidence.
