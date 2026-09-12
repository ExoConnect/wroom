//! The media-object model: the transport-agnostic core of the engine.
//!
//! Tracks, layers, and subscriptions. No RTP, socket, or transport types
//! belong in this crate — edges adapt transport to these objects.

/// A scalable layer: 0 is lowest on each axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Layer {
    pub spatial: u32,
    pub temporal: u32,
}

/// Identifies a track within a room.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrackRef {
    pub participant_id: String,
    pub track_id: String,
}

/// A receiver's intent: which track, capped at which layer, at which priority.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub track: TrackRef,
    pub max_layer: Layer,
    pub priority: u32,
}
