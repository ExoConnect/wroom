//! WebSocket signaling: protobuf messages per `proto/signaling/v1`.

/// Generated types from `proto/signaling/v1/signaling.proto`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/wroom.signaling.v1.rs"));
}

pub mod ws;
