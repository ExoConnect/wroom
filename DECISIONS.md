# Project decisions

Status: discussion stage  
Recorded: 2026-09-12

This document records the agreed direction and the reasons behind it. Locked
decisions are the current commitments; changing one requires an explicit
discussion. Open questions and proposed technologies are not implementation
commitments. Performance ambitions remain targets until measured.

## Locked decisions

### 1. Build a fully open-source video-calling product

**Decision:** Publish the project and its source on GitHub under the MIT license.

**Reason:** Openness is a foundational product requirement. It also makes the
implementation inspectable and allows others to contribute improvements. MIT
aligns with the goal of permissive reuse and broad adoption.

**Boundary:** The supported self-hosting experience remains open.

### 2. Use Rust for the backend and build a custom media engine

**Decision:** Rust is the main backend language. Build the project's own media
and protocol engine, including packet processing, forwarding, scheduling,
congestion control, and quality adaptation. The engine will not be built on
str0m, webrtc-rs, or another complete WebRTC/media engine.

**Reason:** Control over memory, allocation, scheduling, packet processing, and
media policies supports sustained optimization. Media behavior is central to the
product. Owning the implementation allows its internal data structures and
execution model to be designed specifically for conferencing and livestreaming.

**Boundary:** Existing low-level libraries, codec implementations, and
cryptographic implementations may be reused. Building the engine does not imply
inventing a new wire protocol; protocol selection remains a separate decision.
The frontend and its client-side media integration are not selected by this
decision.

### 3. Target large interactive meetings with hundreds of active cameras

**Decision:** Design for hundreds of people publishing camera video in one
interactive meeting.

**Reason:** The intended product must support large participatory meetings, beyond
small team calls or broadcasts with only a few publishers.

**Boundary:** Publishing hundreds of cameras does not require every receiver to
decode every camera at full resolution. Exact launch capacity, visible stream
counts, and supported device classes remain open.

### 4. Make performance and call quality primary product requirements

**Decision:** Prioritize fast joining, low conversational latency, responsive
interaction, high visual quality, and recovery on unreliable connections.

**Reason:** Call quality and the feeling of speed are the main motivations for
building the product. Optimization must cover the complete capture-to-display
path, as well as the interface.

**Boundary:** High quality on poor connections means using available bandwidth
effectively and adapting gracefully. It is not a promise of high bitrate beyond
the connection's capacity. Numerical acceptance thresholds remain open.

### 5. Avoid unnecessary work throughout the media pipeline

**Decision:** Let visibility, displayed video size, and receiver capacity influence
which media is produced, forwarded, received, and decoded.

**Reason:** A small gallery tile often does not benefit visibly from a much larger
source stream. Avoiding unnecessary bytes, decoded pixels, allocations, and
processing can preserve the useful experience while lowering resource use.

**Boundary:** Merely shrinking a high-resolution video in the UI does not save
transmission or decoding work. Exact layer selection, pausing, and prefetch
policies remain open and must account for smooth scrolling and pinning.

### 6. Treat interface quality and frontend responsiveness as core requirements

**Decision:** Build a polished, intentional interface with excellent responsiveness.
Evaluate package size, memory, CPU use, and rendering behavior as frontend
architecture consequences.

**Reason:** Dissatisfaction with existing products includes both call quality and
interface design. A visually polished interface must also feel fast during calls.

**Boundary:** Electron and GPUI remain candidates. No desktop framework has been
selected. React with shadcn is the stated direction for a web interface, whose
delivery order remains open.

### 7. Establish working media before adding end-to-end encryption

**Decision:** First establish working calls and the media primitives. Implement
participant-only end-to-end encryption afterward, preserving an appropriate
integration point in the media design.

**Reason:** A functioning media path provides a concrete basis for testing,
profiling, and iteration before adding group key management and frame encryption.

**Boundary:** This sequencing does not mean plaintext network transport. Transport
encryption remains part of the initial WebRTC path if WebRTC is selected. The
initial product must not claim E2EE before it is implemented. The E2EE mechanism
and key-management design remain open.

### 8. Measure against reproducible public media workloads

**Decision:** Benchmark streaming capacity, latency, quality, and resource usage
against existing media systems using reproducible workloads.

**Reason:** Comparable measurements establish whether custom engineering improves
the engine and the user experience. Participant counts or language choices alone
cannot demonstrate an advantage.

**Boundary:** Distinguish two kinds of comparison:

- Identical forwarding workloads to isolate media-engine efficiency.
- Identical viewing experiences to measure the benefits of adaptation and avoiding
  unnecessary work.

Match subscriptions, quality layers, codecs, encryption, hardware, and network
conditions where relevant. Candidate tools and studies have been identified, but
the benchmark suite has not been selected or run.

### 9. Continue architectural discussion before implementation

**Decision:** Document the agreements now and continue discussing the open choices
before initializing or implementing the application.

**Reason:** Client architecture, media transport, infrastructure, and encryption
boundaries have substantial consequences and are still being evaluated.

**Boundary:** Creating this decision record is authorized. It does not settle open
choices or authorize application scaffolding, deployments, or paid infrastructure.
*(Amended 2026-09-12: scaffolding for M0 is authorized.)*

### 10. Keep the system coherent and focused

**Decision:** Build one coherent system dedicated to conferencing and
livestreaming. Organize responsibilities as internal modules and workers rather
than fragmenting the application into independently operated services.

**Reason:** A unified design reduces operational complexity and unnecessary
communication boundaries while allowing optimization across the media path.

**Boundary:** The same server application may run across multiple machines when
capacity or geographic distribution requires it. A coherent system does not
require all traffic to fit within one process or machine.

### 11. RTP/WebRTC-compatible media transport over an object-model core

**Decision:** Client-to-server media uses the WebRTC-compatible stack — ICE
(lite where a public address permits), DTLS-SRTP, RTP/RTCP over UDP, with TURN
fallback. Internally the engine models media as tracks, frame groups, frames,
and spatial/temporal layers with priority rather than as RTP flows; RTP is an
edge adapter.

**Reason:** Browser media pipelines provide capture, encode, decode, jitter
buffering, and loss recovery at no implementation cost, making this the fastest
path to working calls. The object-model core keeps later edges — QUIC for
native clients, inter-node relay — attachable without redesigning the engine.

**Boundary:** Reusing low-level building blocks (a DTLS implementation such as
dimpl, an ICE agent) is permitted under decision 2. A QUIC/WebTransport edge is
deferred, not ruled out. The engine's internal APIs must not expose
RTP-specific concepts to the core.

### 12. Sub-millisecond server-side forwarding

**Decision:** The engine targets sub-millisecond residence time: received
datagram to emitted datagram in under 1 ms at p99, absent congestion-control
backpressure. Forward on receipt; never buffer media in the server.

**Reason:** Server residence is the one latency component fully under engine
control. Meeting it requires the hot path to avoid allocation, global locks,
and blocking calls — constraints that must shape the implementation from the
start rather than be retrofitted.

**Boundary:** This measures server processing only. Pacer and
congestion-control delay are legitimate and measured separately. End-to-end
glass-to-glass latency targets under 100 ms on healthy same-region paths but is
dominated by capture, encoding, jitter buffering, and network transit outside
server control. Join-to-first-media targets roughly one second.

### 13. Cascade-ready topology with single-node meetings first

**Decision:** A meeting lives on one instance initially. Subscriptions are
modeled uniformly — a consumer may be a local participant or another node — so
multi-node meetings can be added later without rearchitecting. Room placement
selects the node nearest the participant centroid.

**Reason:** Single-node rooms are the simplest correct model, and hundreds of
cameras fit within one machine's capacity. Holding the invariants — object
subscriptions rather than transport-bound ones, a room directory abstraction,
stable publisher identity across hops, and relayable feedback — preserves
geographic distribution and beyond-one-machine meetings at low present cost.

**Boundary:** Relay transport, loop prevention, cross-hop failover, and
multi-node orchestration are explicitly deferred and must not be claimed until
built.

### 14. Web interface first, Electron as a thin wrapper

**Decision:** Build the interface in React with shadcn for the web; ship the
desktop application as a thin Electron wrapper reusing the web build and
Chromium's media pipeline.

**Reason:** This is the fastest route to a polished cross-platform client with
no duplicated media code.

**Boundary:** A future Rust-native client remains possible and is made cheaper
by the object-model core, but it is not a commitment.

### 15. Protobuf signaling over WebSocket, defined in one schema

**Decision:** The client-server control protocol is defined in a single
protobuf schema carried over secure WebSocket. Call setup initially carries the
browser's session description (SDP) as an opaque field; structured capability
negotiation may be added later as new fields. Subscription changes are sent as
batched deltas rather than per-track messages.

**Reason:** One schema generating typed code for both Rust and TypeScript keeps
the implementations from drifting, and proto field-number versioning makes
protocol evolution safe across mismatched client/server versions — both needed
for an open protocol others will build against. Wire compactness is a minor
benefit; signaling volume is small relative to media.

**Boundary:** The schema is the protocol contract; changes must follow field
evolution rules (no renumbering, removed fields reserved). The SDP field may
later be superseded by structured capabilities without a protocol break.
Human-readable inspection tooling (a JSON mode or equivalent) is part of the
deliverable.

### 16. Ephemeral links first, accounts later; auth behind an interface

**Decision:** Initial rooms are ephemeral shareable links — a URL is a room, the
room ends when empty, and no account is required. An account layer (registered
users, scheduled meetings) is added later on top. Token verification lives
behind an interface so providers are pluggable: unsigned dev tokens for early
milestones, a self-hostable provider (OIDC-compatible) as the default for
accounts, and hosted providers such as Clerk only as optional adapters.

**Reason:** Ephemeral links ship the core product with no auth infrastructure
and keep the open self-hosting promise — the server must not require a
third-party hosted service. Pluggable verification keeps hosted auth available
for our own deployments without imposing it on self-hosters.

**Boundary:** Accounts-later commits to the verification interface, not to a
specific provider. A hosted third party is ruled out for the default
self-hosted path.
