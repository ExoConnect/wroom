#![forbid(unsafe_code)]

//! WebSocket signaling: protobuf messages per `proto/wroom/signaling/v1`.

/// Generated types from `proto/wroom/signaling/v1/signaling.proto`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/wroom.signaling.v1.rs"));
}

/// Join-token verification, behind an interface (D16).
pub mod auth;

/// Signaling → media-plane control channel.
pub mod media;

/// The Sans-IO session state machine.
pub mod session;

/// The axum WebSocket adapter and shared broadcast hub.
pub mod ws;
