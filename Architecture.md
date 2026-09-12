# Architecture

## Direction

Build an MIT-licensed video conferencing and livestreaming product with a custom
Rust backend and media engine. Keep it one coherent system, organized into
internal modules and workers. Scale by running additional instances of the same
server when needed.

Performance comes from efficient media delivery, predictable resource usage, and
avoiding unnecessary work throughout the pipeline.

## Clients

- React and shadcn for the interface.
- Electron for the desktop application.
- Browser access through standard WebRTC APIs.
- Use each browser's built-in media pipeline initially; Electron uses Chromium's.
  This handles capture, audio processing, encoding, decoding, and playback.

## Rust server

Build our own media and protocol engine rather than adopting a complete engine
such as str0m or webrtc-rs. Reuse low-level libraries, codec implementations, and
cryptographic implementations where useful — for example a standalone DTLS
implementation and an ICE agent.

The server handles meeting access, signaling, subscriptions, packet forwarding,
bandwidth adaptation, and connection lifecycle within the same application.

### Media model

Internally, media is modeled as tracks composed of frame groups, frames, and
spatial/temporal layers with explicit priority — not as RTP flows. RTP is an
edge adapter; alternative edges (QUIC for native clients, inter-node relay) can
attach to the same core later without redesign.

### Forwarding path

Forward encoded media without decoding or transcoding in the normal call path.
The hot path classifies and demuxes datagrams, decrypts once under the
publisher's keys, resolves subscribers from a snapshot of the subscription
table, then per subscriber selects the layer, rewrites headers, re-encrypts
under the subscriber's keys, and emits through batched sends.

Residence target: received datagram to emitted datagram in under 1 ms at p99,
absent congestion-control backpressure. No allocation, no global locks, and no
blocking calls on the hot path. Per-subscriber egress queues are bounded;
overflow drops media rather than stalling the room. Audio egress is prioritized
over video.

Adapt stream delivery to visibility, displayed size, available bandwidth, and
receiver capacity — including directing publishers to produce only the layers
receivers consume.

### Distribution

A meeting lives on one instance initially; room placement selects the node
nearest the participants. Subscriptions are modeled uniformly so that another
node is simply a subscriber, keeping multi-node meetings possible later without
redesigning the core.

## Connectivity and media

- HTTPS and secure WebSockets for application requests and meeting
  coordination; signaling messages are defined in a shared protobuf schema.
- WebRTC-compatible encrypted media transport over UDP: ICE (lite where a
  public address permits), DTLS (1.3 preferred) for keying, SRTP media.
- TURN fallback for connections that cannot reach the media server directly.
- Opus as the preferred audio codec; VP8 and H.264 as the initial video
  compatibility baseline, with AV1 SVC as the primary scalability target.

## Rough system sketch

```text
Desktop: Electron + React/shadcn       Web: React/shadcn
              |                             |
              +-------------+---------------+
                            |
            Browser media pipeline + WebRTC
                            |
                    Direct UDP or TURN
                            |
               One Rust server application
        +------------------------------------------+
        | Edge: ICE / DTLS / SRTP / RTP / RTCP     |
        | Core: media objects — subscriptions,     |
        |       layer selection, forwarding,       |
        |       bandwidth adaptation (<1 ms p99)   |
        | Meeting access / signaling / rooms       |
        +------------------------------------------+
                            |
                Encoded media to receivers
```

## Build sequence

Establish working calls and efficient media delivery first, using transport
encryption from the beginning. The first milestone is a walking skeleton: two
browsers in one room with forward-everything media, proving the
ICE/DTLS/SRTP/RTP path end to end. Layer selection and loss repair, bandwidth
adaptation, and scale mechanics follow. Add participant-only end-to-end
encryption afterward, preserving its integration point in the media design.

Use public media workloads to compare latency, quality, capacity, CPU use, and
memory use as the implementation develops.
