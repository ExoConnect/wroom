#![forbid(unsafe_code)]

//! The WebRTC-compatible edge: ICE / DTLS / SRTP / RTP / RTCP.
//!
//! Adapts RTP transports to the media objects in `wroom_core`.

/// STUN message handling and the ICE-lite agent.
pub mod ice {}

/// DTLS handshake integration (dimpl).
pub mod dtls {}

/// SRTP encryption and decryption contexts.
pub mod srtp {}

/// RTP packet parsing and header rewriting for the forwarding path.
pub mod rtp {}

/// RTCP feedback: NACK, PLI/FIR, transport-wide congestion control.
pub mod rtcp {}
