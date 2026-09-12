#![forbid(unsafe_code)]

//! The WebRTC-compatible edge: ICE / DTLS / SRTP / RTP / RTCP.
//!
//! Adapts RTP transports to the media objects in `wroom_core`.
//! All protocol modules are Sans-IO state machines: callers feed datagrams
//! and timestamps in, and poll for output packets, timeouts, and events.
//! Nothing here performs IO, allocates per packet, or blocks.

/// STUN message handling and the ICE-lite agent.
pub mod ice;

/// DTLS handshake integration (dimpl).
pub mod dtls;

/// SRTP encryption and decryption contexts.
pub mod srtp;

/// RTP packet parsing and header rewriting for the forwarding path.
pub mod rtp;

/// RTCP feedback: NACK, PLI/FIR, transport-wide congestion control.
pub mod rtcp;

/// SDP offer parsing and answer generation.
pub mod sdp;

/// One browser peer connection's composed ICE/DTLS/SRTP stack.
pub mod transport;
